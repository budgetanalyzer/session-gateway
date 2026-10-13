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

## Token Protection

- IDP tokens are consumed at login time only; nothing from Auth0 is stored after the session is created
- Browser only sees opaque session cookie; all sensitive data lives in Redis
- Session hash deleted on logout, cookie cleared

## Session Heartbeat

- **Sliding window**: Frontend calls `GET /auth/v1/session` periodically (~2 min); Session Gateway extends the session only after permission-service returns current authorization for an active account
- **Activity-gated**: The frontend is responsible for tracking user activity (mouse, keyboard, tab focus) and only calling while the user is active. Idle users get no heartbeat and the session expires naturally via Redis key TTL
- **Authoritative refresh**: A successful heartbeat atomically replaces `roles`, `permissions`, and `expires_at`, refreshes the session and user-index TTLs, and returns the stored expiry. Auth0 is not contacted
- **Account invalidation**: A deactivated, deleted, or missing account deletes this session, clears its cookie, and returns 401
- **Failure behavior**: Timeout, malformed response, upstream error, or Redis mutation failure returns 503 without extending the session or clearing its cookie. Repeated failures therefore cannot keep stale grants alive beyond the remaining Redis TTL
- **Race safety**: Conditional Redis mutation prevents a session deleted or expired during the permission lookup from being recreated; heartbeat returns 401 and clears the stale cookie
- **Stale-cookie cleanup**: If the browser presents a cookie for a missing or expired Redis session, heartbeat returns 401 and clears the cookie
- **Operational defaults**: 15-minute session TTL, 2-minute frontend heartbeat cadence

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

The `returnUrl` value is attached to the OAuth2 authorization request, stored in Redis under the
`oauth2:state:{state}` key, and recovered after the Auth0 callback. This avoids depending on
WebSession state during the OAuth2 round-trip.

If the OAuth2 callback fails after the flow started with a `returnUrl`, Session Gateway redirects
to `/login?error=auth_failed&returnUrl=...` so the frontend can retry without losing the original
deep link.

## Browser Error Strategy

Session Gateway never serves Spring Boot white-label HTML for uncommitted browser document requests:

- **Callback IdP/auth failures** redirect to `/login?error=auth_failed`
- **Callback non-auth failures** redirect to `/oops`
- **All other browser navigation failures** redirect to `/oops` via a global `ErrorWebExceptionHandler`
- **API and machine requests** always receive JSON error responses, never redirects

Browser navigation is classified using `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, and `Accept: text/html`
signals, with explicit API path exclusion to protect JSON contracts.
