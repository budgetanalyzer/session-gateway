# Recommended Auth0 Settings

These settings align Auth0 with Session Gateway's current runtime defaults:

- `SESSION_TTL_SECONDS=900`
- frontend heartbeat cadence `VITE_HEARTBEAT_INTERVAL_MS=120000` (2 minutes)
- OAuth2 authorization code flow with PKCE

Session Gateway contacts Auth0 only at login (authorization-code exchange) and at logout. There
are no refresh-token grants, no userinfo polling, and no token exchange surface. Heartbeat
validates the local Redis session only.

## API Configuration

In Auth0, open `Applications > APIs > budget-analyzer-api`.

- **Identifier**: match `IDP_AUDIENCE`
  For this repository, the default value is `https://api.budgetanalyzer.org`.
- **Maximum Access Token Lifetime**: `900` seconds
- **Implicit / Hybrid Flow Lifetime**: not relevant for Session Gateway

Session Gateway requests the API audience during browser login, so the API access-token lifetime
controls the access token used by the browser authorization-code flow. Session Gateway does not use
implicit or hybrid login.

## Application Configuration

In Auth0, open `Applications > [browser app] > Settings`.

- **Refresh Token Rotation**: not required (Session Gateway does not request refresh tokens)
- **ID Token Expiration**: `3600` seconds

Session Gateway does not request the `offline_access` scope and does not store any IDP token after
login. Auth0 refresh-token settings have no effect on Session Gateway behavior.

## Tenant Session Configuration

In Auth0, open `Settings > Advanced > Session Expiration`.

- **Default Session Policy**: non-persistent
- **Idle Session Lifetime**: `15` minutes
- **Maximum Session Lifetime**: `480` minutes

These values keep the Auth0 SSO session closer to the app session model. If the Redis session
expires and the user goes back through login, they should not keep getting silently reauthenticated
for days from a long-lived Auth0 session.

Non-persistent helps here, but it is not a guarantee that every browser will drop the session on
close in every restore scenario. Explicit logout still matters.

### Why session policy matters for a financial application

With "Persistent" and a 3-day idle timeout, the app's 15-minute session expiration gives a false
sense of security:

1. User's app session expires (15 min idle, Redis key gone)
2. User clicks Login
3. Auth0 still has a live session (3-day idle, persistent cookie survived browser close)
4. Auth0 silently re-authenticates — no password prompt
5. User gets a new app session without proving they know the password

Someone who walks away from an unlocked browser gets back in without credentials as long as the
Auth0 session is alive. Setting the policy to non-persistent with a 15-minute idle timeout closes
this gap. The `/v2/logout` call in Session Gateway's `LogoutController` already kills the Auth0
session on explicit logout — these settings are the safety net for when logout doesn't happen
cleanly (browser crash, tab close, session timeout).

## Scope Notes

- These recommendations apply to the browser OAuth2 authorization-code flow.
- Session Gateway requests only `openid`, `profile`, and `email` scopes. There is no
  `offline_access` request and no refresh-token storage.
- The Redis session lifetime is governed entirely by `SESSION_TTL_SECONDS` and the frontend
  heartbeat cadence.
