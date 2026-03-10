# Session Gateway (BFF)

> "Archetype: service. Role: BFF for browser authentication; manages OAuth2 flows, session cookies, and ext_authz session dual-writes."
>
> — [AGENTS.md](AGENTS.md#tree-position)

[![Build](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml)

Backend-for-Frontend (BFF) service that manages OAuth2 authentication flows, protects tokens from browser exposure, and dual-writes session data to the ext_authz Redis schema for Envoy-based per-request authorization.

## Overview

The Session Gateway implements the BFF pattern to provide secure authentication for the Budget Analyzer application:

- Manages OAuth2 flows with Auth0
- Fetches user roles and permissions from the permission-service on login
- Dual-writes session data (userId, roles, permissions) to ext_authz Redis schema for Envoy ext_authz validation
- Stores Auth0 tokens, user identity, and permissions in Redis — never exposed to browser
- Issues HttpOnly session cookies to frontend
- Proxies authenticated requests to the NGINX API Gateway
- Implements proactive token refresh with permission re-fetch and ext_authz session update
- Provides token exchange endpoint for native PKCE/M2M clients (`POST /auth/token/exchange`)

## Architecture

```
Browser → Envoy (:443) → Session Gateway (:8081) ← OAuth2 → Auth0
              │                           ↓ Session Data
              ├─ Permissions ──→ Permission Service (:8086) [email/name]
              │                           ↓ userId, roles, permissions
              ├─ Dual-write: Spring Session + ext_authz Redis hash
              │                           ↓ Stored in Redis (:6379)
              ↓ Proxy request
         Envoy Gateway ── ext_authz ──→ ext_authz gRPC service (:9001)
              │                           ↓ lookup extauthz:session:{id}
              │                           ↓ inject X-User-Id, X-Roles, X-Permissions
              ↓ headers injected → proxy to backend
         NGINX (:8080) → Backend Services ── read claims from headers

Native Client → POST /auth/token/exchange (IDP token → opaque session token)
```

## Technology Stack

- **Spring Cloud Gateway**: Reactive gateway for routing and filtering
- **Spring Security OAuth2 Client**: Auth0 integration
- **Spring Session**: Redis-backed session storage
- **Service Common (service-web)**: Reactive HTTP logging, correlation IDs, safe logging, exception handling
- **Redis**: Session store (Spring Session + ext_authz session schema)

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `placeholder-client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `placeholder-client-secret` |
| `AUTH0_ISSUER_URI` | Auth0 tenant issuer URI | `https://placeholder.auth0.com/` |
| `IDP_AUDIENCE` | Auth0 API audience identifier | — |
| `IDP_LOGOUT_RETURN_TO` | URL to redirect after Auth0 logout | `http://localhost:8080` |
| `PERMISSION_SERVICE_URL` | Base URL for permission-service | `http://permission-service:8086` |
| `EXTAUTHZ_SESSION_KEY_PREFIX` | Redis key prefix for ext_authz sessions | `extauthz:session:` |
| `EXTAUTHZ_SESSION_TTL_SECONDS` | TTL for ext_authz session keys (must match Spring Session timeout) | `1800` |

### Ports

- **8081**: Session Gateway (behind Envoy, receives proxied browser requests)
- **9001**: ext_authz gRPC service (Envoy external authorization)
- **8090**: ext_authz health endpoint
- **8086**: Permission Service (user roles and permissions)
- **6379**: Redis (session storage + ext_authz session schema)

## Running Locally

### Prerequisites

- Java 24
- Redis running on localhost:6379
- NGINX gateway running on localhost:8080
- Permission-service running on localhost:8086 (required for login)

### Start the Service

```bash
./gradlew bootRun
```

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
- Auth0 tokens stored server-side in Redis — never exposed to browser
- Session data dual-written to ext_authz Redis hash — browser only sees opaque session cookie
- All session data cleared on logout (both Spring Session and ext_authz session)
- Automatic Auth0 token refresh before expiration, with permission re-fetch and ext_authz session update

### ext_authz Session Validation
- Envoy ext_authz gRPC service validates sessions by reading directly from Redis
- On valid session: injects `X-User-Id`, `X-Roles`, `X-Permissions` headers into proxied requests
- On invalid/missing session: returns 401 to Envoy, request rejected before reaching backend
- No cryptographic verification needed — Redis is trusted internal infrastructure
- Session IDs are opaque — no sensitive data encoded in the token itself

### Return URL Support
- **Automatic saved requests**: Users return to originally requested page after login
- **Explicit parameter**: `/oauth2/authorization/auth0?returnUrl=/settings`
- **Security validation**: All redirects validated to prevent open redirect attacks
- **Priority order**: Explicit returnUrl → Saved request → Default `/`

After authentication, users are redirected based on priority:
1. Explicit `?returnUrl=` parameter if provided
2. Original requested URL if redirected to login from a protected resource
3. Default `/` homepage

All returnUrl values are validated by `RedirectUrlValidator` to ensure same-origin only, preventing open redirect vulnerabilities.

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
