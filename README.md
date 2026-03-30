# Session Gateway (BFF)

> "Archetype: service. Role: BFF for browser authentication; manages OAuth2 flows and session cookies."
>
> — [AGENTS.md](AGENTS.md#tree-position)

[![Build](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml)

Backend-for-Frontend (BFF) service that manages OAuth2 authentication flows, protects tokens from browser exposure, and writes session data as Redis hashes that the ext_authz HTTP service reads directly for per-request authorization at the Istio ingress.

## Overview

The Session Gateway implements the BFF pattern to provide secure authentication for the Budget Analyzer application:

- Manages OAuth2 flows with Auth0
- Fetches user roles and permissions from the permission-service on login
- Writes session data (userId, roles, permissions, refresh token, expiry) as Redis hashes (`session:{id}`)
- The ext_authz HTTP service reads these same hashes for ingress authorization — no separate schema or dual-write
- Issues HttpOnly session cookies to frontend
- Owns the OAuth2 and session lifecycle endpoints: `/oauth2/**`, `/auth/**`, `/login/oauth2/**`, `/logout`, `/user`
- Provides token exchange endpoint for native PKCE/M2M clients (`POST /auth/token/exchange`)

Bare `/login` is a frontend route served through NGINX. It starts the real OAuth2 flow through `/oauth2/authorization/idp`.

Browser login depends on Auth0 refresh tokens. The configured OAuth2 scope set includes
`offline_access`, and the Auth0 application must allow refresh tokens with rotation enabled.

## Architecture

```text
Browser → Istio Ingress (:443)
  ├─ /oauth2/*, /auth/*, /login/oauth2/*, /logout, /user
  │      → Session Gateway (:8081) ← OAuth2 → Auth0
  │           ├─ Permission Service (:8086) [email/displayName]
  │           └─ Redis (:6379) [session:*]
  ├─ /login, /* → NGINX (:8080) → budget-analyzer-web
  └─ /api/* → ext-authz HTTP service (:9002) → NGINX (:8080) → Backend Services

Native Client → POST /auth/token/exchange (IDP token → opaque session token)
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
| `IDP_AUDIENCE` | Auth0 API audience identifier | — |
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
| `SESSION_TTL_SECONDS` | TTL for session keys in seconds | `1800` |

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
created by `../orchestration/scripts/dev/setup-infra-tls.sh`. Full browser behavior still runs through
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
- **Timeout**: 30 minutes

### Token Protection
- Auth0 refresh tokens stored server-side in Redis session hashes — never exposed to browser
- Browser only sees opaque session cookie; all sensitive data lives in Redis
- Session hash deleted on logout, cookie cleared

### ext_authz Session Validation
- The ext_authz HTTP service reads session hashes (`session:{id}`) directly from Redis — the same hashes Session Gateway writes
- On valid session: injects `X-User-Id`, `X-Roles`, `X-Permissions` headers into proxied requests
- On invalid/missing session: returns 401 to the ingress proxy, request rejected before reaching backend
- No cryptographic verification needed — Redis is trusted internal infrastructure
- Session IDs are opaque UUIDs — no sensitive data encoded in the cookie value

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

- [Authentication Implementation Plan](../orchestration/docs/architecture/authentication-implementation-plan.md)
- [Security Architecture](../orchestration/docs/architecture/security-architecture.md)
