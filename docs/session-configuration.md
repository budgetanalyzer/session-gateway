# Session Configuration

## Shared Session Contract

Session Gateway and ext_authz must stay aligned on three things:

- `SESSION_KEY_PREFIX`, default `session:`
- `SESSION_COOKIE_NAME`, default `BA_SESSION`
- the Redis session hash field `expires_at`, written by Session Gateway and enforced by ext_authz

Changing either shared value is a cross-repo contract change. Existing live sessions are keyed by
the current prefix and browsers hold the current cookie name.

Session Gateway also maintains a per-user Redis set under `user_sessions:{userId}`. That index is
an internal revocation contract with permission-service, used to locate all active sessions for a
user without scanning `session:*`.

## Session Gateway Source Of Truth

Session settings are bound through `SessionProperties` and defaulted in
`src/main/resources/application.yml`.

Defaults:

- `SESSION_KEY_PREFIX=session:`
- `SESSION_TTL_SECONDS=900`
- `SESSION_REFRESH_THRESHOLD_SECONDS=300`
- `SESSION_OAUTH2_STATE_TTL_SECONDS=900`
- `SESSION_COOKIE_NAME=BA_SESSION`
- `SESSION_COOKIE_DOMAIN_OVERRIDE` unset
- `SESSION_COOKIE_SECURE=true`
- `SESSION_COOKIE_SAME_SITE=Strict`

`SESSION_COOKIE_DOMAIN_OVERRIDE` is wired in `src/main/resources/application.yml` with a blank
default so the public cookie remains host-only unless an explicit override is configured.

Startup validation rejects:

- blank `session.key-prefix`
- blank `session.cookie.name`
- `session.refresh-threshold-seconds >= session.ttl-seconds`
- unsupported `session.cookie.same-site` values

Startup does not enforce an allowlist of cookie names beyond the non-blank requirement. Changing
`SESSION_COOKIE_NAME` still changes a cross-repo cookie contract and must stay aligned with
ext_authz.

After startup completes, Session Gateway logs the configured public cookie name and whether a
domain override is enabled.

## Operational Defaults

The current runtime defaults across the active browser-session path are:

- `SESSION_TTL_SECONDS=900` (15 minutes)
- `SESSION_REFRESH_THRESHOLD_SECONDS=300` (5 minutes before IDP token expiry)
- frontend heartbeat cadence `VITE_HEARTBEAT_INTERVAL_MS=120000` (2 minutes in `budget-analyzer-web`)

That heartbeat cadence is frontend-owned, not Session Gateway-owned. Session Gateway extends the
session on every `GET /auth/v1/session` call; the frontend decides when to call based on user
activity.

The operational Auth0 dashboard values that pair with these defaults are documented in
[auth0-settings.md](auth0-settings.md).

## IdP Callback HTTP Client

Browser OAuth2 callback traffic now uses a dedicated outbound IdP/OIDC client instead of the
default shared Reactor Netty client state. This dedicated path covers:

- authorization-code token exchange during `oauth2Login`
- OIDC userinfo retrieval during browser login
- JWKS retrieval for ID token verification

Defaults:

- `IDP_HTTP_CLIENT_POOL_NAME=idp-oidc-callback`
- `IDP_HTTP_CLIENT_MAX_CONNECTIONS=50`
- `IDP_HTTP_CLIENT_PENDING_ACQUIRE_MAX_COUNT=100`
- `IDP_HTTP_CLIENT_PENDING_ACQUIRE_TIMEOUT=5s`
- `IDP_HTTP_CLIENT_MAX_IDLE_TIME=30s`
- `IDP_HTTP_CLIENT_MAX_LIFE_TIME=5m`
- `IDP_HTTP_CLIENT_EVICTION_INTERVAL=30s`
- `IDP_HTTP_CLIENT_CONNECT_TIMEOUT=5s`
- `IDP_HTTP_CLIENT_RESPONSE_TIMEOUT=10s`
- `IDP_HTTP_CLIENT_READ_TIMEOUT=10s`
- `IDP_HTTP_CLIENT_WRITE_TIMEOUT=10s`

These settings are intentionally scoped to IdP/OIDC callback traffic. They do not change the
permission-service WebClient or create a new generic application-wide HTTP client default.

## Callback Diagnostics

The dedicated IdP callback client emits sanitized diagnostics for failure cases that matter during
browser login:

- `pool_acquire_timeout`
- `connect_failure`
- `response_timeout`
- `upstream_4xx`
- `upstream_5xx`

These logs intentionally record only stable failure classification, HTTP method, sanitized path,
HTTP status when one exists, and exception type. They do not log raw OAuth codes, tokens, cookies,
or raw `state` values.

Framework-level `org.springframework.security.oauth2` and
`org.springframework.web.reactive.function.client` logging stay at `INFO` by default so generic
debug logging does not become the primary callback diagnostic path.

## Cookie Behavior

The public browser session contract is `BA_SESSION` by default. Session Gateway reads, sets, and
clears that cookie exclusively through `SessionCookieHelper`. ext_authz must look up that same
configured public cookie name.

An internal framework cookie named `SESSION` may still appear during Spring-managed flows. That is
not the browser auth contract. Session Gateway does not read, refresh, or clear that framework
cookie when managing authenticated browser sessions.

Default public-cookie behavior is host-only. Session Gateway does not emit a `Domain` attribute
unless `SESSION_COOKIE_DOMAIN_OVERRIDE` is set.

Use `SESSION_COOKIE_DOMAIN_OVERRIDE` only as an ingress workaround when a parent-domain cookie is
required. It is not the primary path.

Heartbeat and logout clearing behavior follows the same public-cookie rule:

- no override configured: clear a host-only cookie
- override configured: clear a cookie with that explicit `Domain` attribute

If the browser presents a cookie for a missing or expired Redis session, `GET /auth/v1/session`
returns `401` and clears the stale cookie.

## Internal Revocation Endpoint

Permission-service can revoke all active sessions for a user through:

- `DELETE /internal/v1/sessions/users/{userId}`

Behavior:

- returns `204 No Content` whether sessions were deleted or none existed
- uses one Redis script execution to delete all indexed `session:{id}` hashes for the user and to
  remove the `user_sessions:{userId}` index key atomically
- relies on login, heartbeat, and token refresh to keep the `user_sessions:{userId}` index both
  TTL-aligned and self-healing
- when heartbeat or token refresh touches a live session, Session Gateway re-adds that session ID
  to `user_sessions:{userId}` before refreshing both TTLs, so a missing index entry does not leave
  the session invisible to targeted revocation

Application security permits only that exact internal path without browser authentication. The
endpoint still depends on network-level controls to limit which services can call it.

## OAuth2 State TTL

`SESSION_OAUTH2_STATE_TTL_SECONDS` applies only to `oauth2:state:*` keys used during the OAuth2
round-trip. It is separate from the browser session TTL and should remain long enough for MFA,
account selection, and slow IdP handoffs.
