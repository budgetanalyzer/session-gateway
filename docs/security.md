# Security

## Session Cookies

- **HttpOnly**: Prevents XSS attacks
- **Secure**: HTTPS only (production)
- **SameSite=Strict**: CSRF protection
- **Public cookie contract**: `BA_SESSION` by default
- **Framework cookie distinction**: A Spring-managed `SESSION` cookie may appear as an internal implementation detail during framework flows, but Session Gateway and ext_authz do not treat it as the browser auth contract
- **Host-only by default**: No `Domain` attribute unless `SESSION_COOKIE_DOMAIN_OVERRIDE` is set
- **Domain override is an escape hatch**: Use it only when ingress/header behavior requires a parent-domain cookie
- **Timeout**: 15 minutes

## OAuth Callback Browser Binding

Each login transaction is bound to the initiating browser, in addition to its transaction-specific
PKCE verifier and OIDC nonce ([RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1)).
The authorization request uses `response_type=code` without `response_mode=form_post`; Auth0 returns
through a top-level GET to `/login/oauth2/code/idp` with query parameters.

On login start, `RedisAuthorizationRequestRepository` reuses a valid `__Host-BA_OAUTH_BINDING`
cookie or generates a new independent 256-bit secret with `SecureRandom`, encoded as 64 lowercase
hex characters. A valid incoming binding must be a single cookie in that format. A newly issued
cookie always has `Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, no `Domain`, and no `Max-Age` or
`Expires` (browser-session lifetime). These attributes are fixed, independent of application-session
cookie configuration, including domain overrides. HTTPS is required. Lax permits the cross-site
GET callback; Strict would prevent that cookie from accompanying the callback.

Only the SHA-256 hash of the binding is stored as `browser_binding_hash` in the existing
`oauth2:state:{state}` Redis hash. The raw secret is neither stored there nor derived from state,
and it is distinct from `BA_SESSION`. The binding cookie alone cannot authenticate an application
request.

State records are immutable. Login initiation generates a fresh random state for every request;
state values must never be reused or recreated after consumption or expiry. Creation uses a small
Redis script to reject an existing key and write the complete hash plus its configured
`session.oauth2-state-ttl-seconds` TTL atomically. Its `TYPE`, `HSET`, and `EXPIRE` commands, plus
`EVALSHA`/`EVAL`, are already in the Session Gateway Redis allowlist from hardening plan 01.
No additional Redis permissions are required.

On both successful and denial/error callbacks, the repository:

1. Reads state only when a valid binding cookie is present.
2. Compares its SHA-256 hash with the stored hash using `MessageDigest.isEqual`.
3. Deletes that exact state key only after the binding matches.
4. Returns the authorization request and sets callback attributes only when `DEL` returns **1**.

Missing, malformed, duplicate, or mismatched binding cookies cannot consume the record. A replay,
expiry (including between read and delete), or competing callback that receives `DEL == 0` fails
closed before code exchange or session issuance. Redis errors also fail closed. Immutable,
never-reused state keys make the deletion count sufficient for a single winner; callback
consumption does not require Lua. Callback attributes, including the existing return URL, are
available only to that winner. Binding failures use the existing login-failure redirect, without
recovering callback attributes from an unconsumed transaction.

The binding cookie is retained across callbacks, including denial and error callbacks. It is not
rotated or cleared per login, so tabs that start with an existing binding can complete in either
order. If two first starts are sent before either cookie response is stored, they can generate
different bindings: the callback for the cookie retained by the browser can succeed, and the other
fails closed and needs a fresh login. Cookie loss similarly invalidates pending callbacks. One
cookie does not cap pending Redis records: the existing state TTL and platform rate/capacity
controls remain necessary.

API-test login helpers must retain this cookie from login initiation and send it on callback.
Existing local pending OAuth records without a binding hash cannot complete; start a fresh login
and let those records expire. No migration or compatibility reader is provided. No cluster reset
is required for this additive hash field; an optional local state reset uses the orchestration
`./scripts/ops/flush-redis.sh` procedure.

See [hardening evidence](research/security-consensus-hardening-evidence.md) for phase 1 checks and
handoff details. Live browser proof belongs to hardening plan 02.1 phase 3.

## Token Protection

- The ID token is validated and userinfo is retrieved during login; the access token is used only
  for that userinfo request
- No Auth0 token is persisted or used for downstream API validation after the session is created
- Browser receives opaque session and binding cookies; IdP tokens remain server-side
- Session hash deleted on logout, cookie cleared

## Session Heartbeat

- **Sliding window**: Frontend calls `GET /auth/v1/session` periodically (~2 min); Session Gateway extends the session only after permission-service returns current authorization for an active account
- **Absolute lifetime**: Heartbeat never sets `expires_at` past `created_at + session.max-lifetime-seconds` (default 8 hours). At the cap, heartbeat deletes the session, clears the cookie, and returns 401. The cap does not require fresh credentials or MFA, and it is not account-wide revocation (see [session-configuration.md](session-configuration.md#absolute-session-lifetime))
- **Activity-gated**: The frontend is responsible for tracking user activity (mouse, keyboard, tab focus) and only calling while the user is active. Idle users get no heartbeat and the session expires naturally via Redis key TTL
- **Authoritative refresh**: A successful heartbeat atomically replaces `roles`, `permissions`, and `expires_at`, refreshes the session and user-index TTLs, and returns the stored expiry. Auth0 is not contacted
- **Account invalidation**: A deactivated, deleted, or missing account deletes this session, clears its cookie, and returns 401
- **Failure behavior**: Timeout, malformed response, upstream error, or Redis mutation failure returns 503 without extending the session or clearing its cookie. Repeated failures therefore cannot keep stale grants alive beyond the remaining Redis TTL
- **Race safety**: Conditional Redis mutation prevents a session deleted or expired during the permission lookup from being recreated; heartbeat returns 401 and clears the stale cookie
- **Stale-cookie cleanup**: If the browser presents a cookie for a missing or expired Redis session, heartbeat returns 401 and clears the cookie
- **Operational defaults**: 15-minute session TTL, 8-hour absolute session lifetime, 2-minute frontend heartbeat cadence

## ext_authz Session Validation

- The ext_authz HTTP service reads session hashes (`session:{id}`) directly from Redis — the same hashes Session Gateway writes
- On valid session: injects `X-User-Id`, `X-Roles`, `X-Permissions` headers into proxied requests
- On invalid/missing session: returns 401 to the ingress proxy, request rejected before reaching backend
- No cryptographic verification needed — Redis is trusted internal infrastructure
- Session IDs are opaque UUIDs — no sensitive data encoded in the cookie value

## Internal Session Revocation

- Session Gateway maintains `user_sessions:{userId}` Redis sets so permission-service can locate every active session for a user without scanning `session:*`
- `DELETE /internal/v1/sessions/users/{userId}` revokes all indexed sessions for that user and returns `204 No Content` whether the user had sessions or not
- The route is intentionally narrow in application security: only that exact path is unauthenticated, with network-level controls expected to restrict callers

## Return URL Support

- **Explicit parameter**: `/oauth2/authorization/idp?returnUrl=/settings`
- **Security validation**: All redirects validated to prevent open redirect attacks
- **Priority order**: Explicit returnUrl → Default `/`

After authentication, users are redirected based on priority:
1. Explicit `?returnUrl=` parameter if provided
2. Default `/` homepage

All returnUrl values are validated by `RedirectUrlValidator` to ensure same-origin only, preventing open redirect vulnerabilities.

At login start, unsafe or oversized (over 2048 characters) return URLs are dropped without
interrupting login. Validation rejects backslashes, controls, whitespace, and malformed URIs,
as well as external redirects. See [bounded login input and callback configuration](session-configuration.md#bounded-login-return-url).

The validated `returnUrl` value is attached to the OAuth2 authorization request, stored in Redis under the
`oauth2:state:{state}` key, and recovered after the Auth0 callback. This avoids depending on
WebSession state during the OAuth2 round-trip.

If the OAuth2 callback fails after the flow started with a `returnUrl`, Session Gateway redirects
to `/login?error=auth_failed&returnUrl=...` so the frontend can retry without losing the original
deep link.

## Browser Error Strategy

Session Gateway never serves Spring Boot white-label HTML for uncommitted browser document requests:

- **Callback IdP/auth failures** redirect to `/login?error=auth_failed`
- **Callback non-auth failures** redirect to `/oops`
- **All other browser navigation failures** redirect to `/oops` via a global `WebExceptionHandler` (`BrowserErrorRedirectHandler`)
- **API and machine requests** always receive JSON error responses, never redirects

Error handling is classified by request path. The public `/auth/` and `/api/` prefixes, the
internal `/internal/` prefix, and the OpenAPI, Swagger UI, and actuator path families are machine
routes, so exceptions on those paths continue to the shared JSON error handler. Uncommitted errors
on every other path redirect to `/oops`. Dedicated OAuth2 callback handlers take precedence and
preserve the controlled login or `/oops` redirects described above; the classification does not
inspect browser request headers.

## Machine Error Contract

The versioned `/auth/` endpoints and internal service endpoints return `application/json` errors
using the shared `ApiErrorResponse` shape. For `GET /auth/v1/user` and `GET /auth/v1/session`, a
missing, blank, unknown, expired, deactivated, or concurrently invalidated session returns `401`
with `type: UNAUTHORIZED` and the generic message `Authentication required`. The response never
identifies the rejected cookie, account state, or underlying authentication exception. Optional
error properties such as `code` and `fieldErrors` are omitted when they have no value; Session
Gateway does not emit null-valued JSON properties in any response type.

`GET /auth/v1/session` continues to clear the public session cookie when the cookie points to a
missing or expired session, the account is missing or inactive, or the session disappears
during refresh. Authorization-refresh and Redis mutation failures return `503` with
`type: SERVICE_UNAVAILABLE` and leave the finite session and cookie unchanged.

This JSON policy does not apply to `/login`, `/oauth2/*`, `/login/oauth2/*`, or `/logout`. Those
paths participate in browser navigation and preserve their existing redirects.
