# Bug: ext_authz Session TTL Drift

## Summary

The ext_authz Redis key uses a fixed TTL from creation time, while the Spring Session uses a sliding-window TTL that resets on every access. Under normal usage, the ext_authz key expires before the Spring Session, causing authenticated users to get 401 errors on `/api/*` requests while still appearing logged in.

## Affected Components

- `ExtAuthzSessionWriter` — writes `extauthz:session:{id}` with fixed 1800s TTL
- `SessionConfig` — `@EnableRedisWebSession(maxInactiveIntervalInSeconds = 1800)`
- `TokenRefreshGatewayFilterFactory` — rewrites ext_authz key on token refresh, but only when the access token is within 5 minutes of expiry

## How It Happens

1. User logs in. Both keys are written with 1800s (30 min) TTL.
2. User actively browses the app. Every request through Session Gateway touches the Spring Session, resetting its 30-minute sliding window.
3. The ext_authz key TTL keeps counting down from creation time — no reset on access.
4. After 30 minutes of continuous use, the ext_authz key expires. The Spring Session is still alive.
5. The next `/api/*` request hits ext_authz, which finds no key in Redis, and returns 401.
6. The user appears logged in (Session Gateway still has a valid session) but can't access any API.

The only thing that resets the ext_authz TTL is `TokenRefreshGatewayFilterFactory`, which rewrites the ext_authz key when it refreshes the OAuth2 access token (within 5 minutes of token expiry). If the access token lifetime from the IDP is longer than 30 minutes, the ext_authz key expires before any token refresh occurs.

## Reproduction

1. Configure the IDP with access token lifetime > 30 minutes
2. Log in
3. Stay active on the app for 30+ minutes (any activity that touches Session Gateway keeps the Spring Session alive)
4. After 30 minutes, attempt an API call — expect 401

## Severity

Medium. Users experience an unexplained loss of API access during active sessions. The workaround is to log out and back in, but the failure mode is confusing — the session cookie is still valid, Session Gateway still recognizes the user, but API calls fail.

## Possible Fixes

**Option A: Sliding TTL on ext_authz key.** Have ext_authz (the Go service) bump the TTL on every successful session lookup. This keeps the two TTLs roughly aligned without any change to Session Gateway. Downside: adds a write to every authenticated API request.

**Option B: Refresh ext_authz TTL from Session Gateway.** Add a filter that re-expires the ext_authz key whenever the Spring Session is accessed. Same write-amplification concern, but keeps the logic in one service.

**Option C: Derive ext_authz TTL from access token expiry.** Set the ext_authz key TTL to match the access token's `expires_at` rather than a fixed 30 minutes. The token refresh filter already rewrites the ext_authz key, so the TTL stays aligned with the token lifecycle. This avoids per-request writes but couples the ext_authz session lifetime to the IDP token configuration.

## Related Code

- `ExtAuthzSessionWriter.writeSession()` — `src/main/java/.../session/ExtAuthzSessionWriter.java:67`
- `SessionConfig` — `src/main/java/.../config/SessionConfig.java:37`
- `TokenRefreshGatewayFilterFactory.refreshPermissionsAndUpdateSession()` — `src/main/java/.../filter/TokenRefreshGatewayFilterFactory.java:179`
- `SecurityConfig.fetchAndStorePermissions()` — `src/main/java/.../config/SecurityConfig.java:380`
