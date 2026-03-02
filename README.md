# Session Gateway (BFF)

> "Archetype: service. Role: BFF for browser authentication; manages OAuth2 flows, session cookies, and internal JWT minting."
>
> — [AGENTS.md](AGENTS.md#tree-position)

[![Build](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml)

Backend-for-Frontend (BFF) service that manages OAuth2 authentication flows, protects tokens from browser exposure, and mints internal JWTs for downstream service authorization.

## Overview

The Session Gateway implements the BFF pattern to provide secure authentication for the Budget Analyzer application:

- Manages OAuth2 flows with Auth0 (abstracted behind NGINX)
- Fetches user roles and permissions from the permission-service on login
- Mints RSA-signed internal JWTs with identity, roles, and permissions claims
- Stores Auth0 tokens, permissions, and cached internal JWTs in Redis — never exposed to browser
- Issues HttpOnly session cookies to frontend
- Proxies API requests to NGINX gateway with internal JWT injection
- Implements proactive token refresh with permission re-fetch and JWT re-mint
- Exposes JWKS endpoint for backend JWT signature verification

## Architecture

```
Browser → Session Gateway (8081) → NGINX (8080) → Backend Services
          ├─ OAuth2 flows (Auth0)              ↑ verify via JWKS
          ├─ Permission fetch (permission-service:8082)
          ├─ Internal JWT minting (RS256)
          ├─ Session management (Redis)
          └─ Internal JWT relay
```

## Technology Stack

- **Spring Cloud Gateway**: Reactive gateway for routing and filtering
- **Spring Security OAuth2 Client**: Auth0 integration
- **Nimbus JOSE+JWT**: RSA key management, JWT signing, JWKS
- **Spring Session**: Redis-backed session storage
- **Service Common (service-web)**: Reactive HTTP logging, correlation IDs, safe logging, exception handling
- **Redis**: Session store (shared with other services)

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `placeholder-client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `placeholder-client-secret` |
| `AUTH0_ISSUER_URI` | Auth0 tenant issuer URI | `https://placeholder.auth0.com/` |
| `IDP_AUDIENCE` | Auth0 API audience identifier | — |
| `IDP_LOGOUT_RETURN_TO` | URL to redirect after Auth0 logout | `http://localhost:8080` |
| `JWT_SIGNING_PRIVATE_KEY_PEM` | PKCS#8 PEM RSA private key for JWT signing (ephemeral key if absent) | — |
| `PERMISSION_SERVICE_URL` | Base URL for permission-service | `http://permission-service:8082` |

### Ports

- **8081**: Session Gateway (public-facing for frontend, serves JWKS)
- **8082**: Permission Service (user roles and permissions)
- **6379**: Redis (session storage)

## Running Locally

### Prerequisites

- Java 24
- Redis running on localhost:6379
- NGINX gateway running on localhost:8080
- Permission-service running on localhost:8082 (required for login)

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
- Internal JWTs minted by Session Gateway and cached in Redis
- Neither Auth0 tokens nor internal JWTs are sent to the browser
- Automatic Auth0 token refresh before expiration, with permission re-fetch and JWT re-mint

### Internal JWT
- Signed with RS256 (RSA 2048-bit)
- Claims: `iss` (session-gateway), `sub` (internal userId), `idp_sub` (Auth0 subject), `roles`, `permissions`
- JWKS endpoint: `GET /.well-known/jwks.json` (unauthenticated, public key only)
- Two key modes: PEM-configured (production) or ephemeral (development, regenerated on restart)
- TTL: 30 minutes, re-minted 5 minutes before expiry

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
