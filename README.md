# Session Gateway

> "Archetype: service. Role: Session-based edge authorization; manages OAuth2 flows, session cookies, and IDP grant validation."
>
> — [AGENTS.md](AGENTS.md#tree-position)

[![Build](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml)

Session-based edge authorization service that manages OAuth2 authentication flows for browser clients and writes session data as Redis hashes that the ext_authz HTTP service reads directly for per-request authorization at the Istio ingress.

## Overview

Session Gateway provides secure authentication and session management for the Budget Analyzer application:

- Manages OAuth2 authorization-code flows with Auth0 for browser clients
- Fetches user roles and permissions from the permission-service on login
- Writes session data (userId, roles, permissions, expiry) as Redis hashes (`session:{id}`)
- Maintains per-user session indexes in Redis (`user_sessions:{userId}`) for targeted revocation
- The ext_authz HTTP service reads these same hashes for ingress authorization — no separate schema
- Issues HttpOnly session cookies to frontend
- Provides session heartbeat (`GET /auth/v1/session`) — extends session TTL based on local Redis state
- Owns the OAuth2 and session lifecycle endpoints: `/oauth2/**`, `/auth/**`, `/login/oauth2/**`, `/logout`
- Exposes internal session revocation for permission-service: `DELETE /internal/v1/sessions/users/{userId}`

Bare `/login` is a frontend route served through NGINX. It starts the real OAuth2 flow through `/oauth2/authorization/idp`.

Recommended Auth0 dashboard values are documented in [docs/auth0-settings.md](docs/auth0-settings.md).

## Architecture

```text
Browser → Istio Ingress (:443)
  ├─ /oauth2/*, /auth/*, /login/oauth2/*, /logout
  │      → Session Gateway (:8081) ← OAuth2 → Auth0
  │           ├─ Permission Service (:8086) [email/displayName]
  │           └─ Redis (:6379) [session:*]
  ├─ /login, /* → NGINX (:8080) → budget-analyzer-web
  └─ /api/* → ext-authz HTTP service (:9002) → NGINX (:8080) → Backend Services
```

## Technology Stack

- **Spring WebFlux**: Reactive web framework
- **Spring Security OAuth2 Client**: Auth0 integration
- **Custom Redis Sessions**: Session hashes via `SessionWriter`/`SessionReader` (not Spring Session)
- **Service Common (service-web)**: Reactive HTTP logging, correlation IDs, safe logging, exception handling
- **Redis**: Session store (`session:{id}` hashes)

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `placeholder-client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `placeholder-client-secret` |
| `AUTH0_ISSUER_URI` | Auth0 tenant issuer URI | `https://placeholder.auth0.com/` |
| `IDP_AUDIENCE` | Auth0 API audience identifier | `https://api.budgetanalyzer.org` |
| `IDP_LOGOUT_RETURN_TO` | URL to redirect after Auth0 logout | `https://app.budgetanalyzer.localhost/peace` |
| `PERMISSION_SERVICE_URL` | Base URL for permission-service | `http://permission-service:8086` |
| `SPRING_DATA_REDIS_HOST` | Redis host for session storage | `localhost` |
| `SPRING_DATA_REDIS_PORT` | Redis port for session storage | `6379` |
| `SPRING_DATA_REDIS_USERNAME` | Redis ACL username | `session-gateway` |
| `SPRING_DATA_REDIS_PASSWORD` | Redis ACL password | — |
| `SPRING_DATA_REDIS_SSL_ENABLED` | Enable TLS for Redis connections | `false` |
| `SPRING_DATA_REDIS_SSL_BUNDLE` | Spring SSL bundle name for Redis trust | — |
| `INFRA_CA_CERT_PATH` | `file:` URI for the infrastructure CA certificate | — |
| `SESSION_KEY_PREFIX` | Redis key prefix for session hashes | `session:` |
| `SESSION_TTL_SECONDS` | TTL for session keys in seconds | `900` |
| `SESSION_OAUTH2_STATE_TTL_SECONDS` | TTL for OAuth2 authorization request state in Redis | `900` |
| `SESSION_COOKIE_NAME` | Public browser session cookie contract shared with ext_authz; distinct from any internal framework `SESSION` cookie | `BA_SESSION` |
| `SESSION_COOKIE_DOMAIN_OVERRIDE` | Optional parent-domain cookie override; unset means host-only cookies | — |
| `SESSION_COOKIE_SECURE` | Secure cookie flag | `true` |
| `SESSION_COOKIE_SAME_SITE` | SameSite cookie policy (`Strict`, `Lax`, `None`) | `Strict` |

### Ports

- **443**: Istio Ingress Gateway (browser entry point, SSL termination, ext_authz integration)
- **8080**: NGINX Gateway (frontend and API routing)
- **8081**: Session Gateway (behind Istio ingress, receives auth/session lifecycle requests)
- **9002**: ext_authz HTTP service (called by the Istio ingress Envoy proxy on `/api/*`)
- **8090**: ext_authz health endpoint
- **8086**: Permission Service (user roles and permissions)
- **6379**: Redis (session storage)

## Running Locally

### Prerequisites

- Java 24
- Shared local platform running from `../orchestration` (`tilt up`)
- Redis available to the service with the `session-gateway` ACL user
- Permission-service reachable at the configured `PERMISSION_SERVICE_URL` (required for login)

### Start the Service

```bash
cd ../orchestration
tilt up

# In separate terminals, expose the dependencies used by direct bootRun
kubectl port-forward -n infrastructure deployment/redis 6379:6379
kubectl port-forward deployment/permission-service 8086:8086

cd ../session-gateway
export SPRING_DATA_REDIS_PASSWORD=your_session_gateway_redis_password
export SPRING_DATA_REDIS_SSL_ENABLED=true
export SPRING_DATA_REDIS_SSL_BUNDLE=infra-ca
export INFRA_CA_CERT_PATH="file:$(cd ../orchestration && pwd)/nginx/certs/infra/infra-ca.pem"
export PERMISSION_SERVICE_URL=http://localhost:8086

./gradlew bootRun
```

`SPRING_DATA_REDIS_USERNAME` defaults to `session-gateway`. If you are reusing
values from `../orchestration/.env`, map `REDIS_SESSION_GATEWAY_PASSWORD` to
`SPRING_DATA_REDIS_PASSWORD`. The CA path must point at the host-side file
created by `../orchestration/scripts/bootstrap/setup-infra-tls.sh`. Full browser behavior still runs through
`https://app.budgetanalyzer.localhost` in the shared dev environment.

### Health Check

```bash
curl http://localhost:8081/actuator/health
```

## Security Features

### Session Cookies
- **HttpOnly**: Prevents XSS attacks
- **Secure**: HTTPS only (production)
- **SameSite=Strict**: CSRF protection
- **Public cookie contract**: `BA_SESSION` by default
- **Framework cookie distinction**: A Spring-managed `SESSION` cookie may appear as an internal implementation detail during framework flows, but Session Gateway and ext_authz do not treat it as the browser auth contract
- **Host-only by default**: No `Domain` attribute unless `SESSION_COOKIE_DOMAIN_OVERRIDE` is set
- **Domain override is an escape hatch**: Use it only when ingress/header behavior requires a parent-domain cookie
- **Timeout**: 15 minutes

### Token Protection
- IDP tokens are consumed at login time only; nothing from Auth0 is stored after the session is created
- Browser only sees opaque session cookie; all sensitive data lives in Redis
- Session hash deleted on logout, cookie cleared

### Session Heartbeat
- **Sliding window**: Frontend calls `GET /auth/v1/session` periodically (~2 min) to extend session TTL
- **Activity-gated**: Session Gateway extends unconditionally on every heartbeat call. The frontend is responsible for tracking user activity (mouse, keyboard, tab focus) and only calling while the user is active. Idle users get no heartbeat and the session expires naturally via Redis key TTL
- **Local-only validation**: Heartbeat reads and writes Redis only — Auth0 is not contacted
- **Stale-cookie cleanup**: If the browser presents a cookie for a missing or expired Redis session, heartbeat returns 401 and clears the cookie
- **Operational defaults**: 15-minute session TTL, 2-minute frontend heartbeat cadence

### ext_authz Session Validation
- The ext_authz HTTP service reads session hashes (`session:{id}`) directly from Redis — the same hashes Session Gateway writes
- On valid session: injects `X-User-Id`, `X-Roles`, `X-Permissions` headers into proxied requests
- On invalid/missing session: returns 401 to the ingress proxy, request rejected before reaching backend
- No cryptographic verification needed — Redis is trusted internal infrastructure
- Session IDs are opaque UUIDs — no sensitive data encoded in the cookie value

### Internal Session Revocation
- Session Gateway maintains `user_sessions:{userId}` Redis sets so permission-service can locate every active session for a user without scanning `session:*`
- `DELETE /internal/v1/sessions/users/{userId}` revokes all indexed sessions for that user and returns `204 No Content` whether the user had sessions or not
- The route is intentionally narrow in application security: only that exact path is unauthenticated, with network-level controls expected to restrict callers

### Return URL Support
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

### Browser Error Strategy

Session Gateway never serves Spring Boot white-label HTML for uncommitted browser document requests:

- **Callback IdP/auth failures** redirect to `/login?error=auth_failed`
- **Callback non-auth failures** redirect to `/oops`
- **All other browser navigation failures** redirect to `/oops` via a global `ErrorWebExceptionHandler`
- **API and machine requests** always receive JSON error responses, never redirects

Browser navigation is classified using `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, and `Accept: text/html`
signals, with explicit API path exclusion to protect JSON contracts.

Session contract and cookie behavior are documented in [docs/session-configuration.md](docs/session-configuration.md).
Recommended Auth0 dashboard values are documented in [docs/auth0-settings.md](docs/auth0-settings.md).

## Development

### Build

```bash
./gradlew build
```

### Run Tests

```bash
./gradlew test
```

### Code Formatting

```bash
./gradlew clean spotlessApply
```

## References

- [Recommended Auth0 Settings](docs/auth0-settings.md)
- [Security Architecture](https://github.com/budgetanalyzer/orchestration/blob/main/docs/architecture/security-architecture.md)

## Related Repositories

- **Orchestration**: https://github.com/budgetanalyzer/orchestration
- **Service Common**: https://github.com/budgetanalyzer/service-common
- **Permission Service**: https://github.com/budgetanalyzer/permission-service
- **Transaction Service**: https://github.com/budgetanalyzer/transaction-service
- **Currency Service**: https://github.com/budgetanalyzer/currency-service
- **Web Frontend**: https://github.com/budgetanalyzer/budget-analyzer-web
