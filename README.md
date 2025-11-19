# Session Gateway (BFF)

Backend-for-Frontend (BFF) service that manages OAuth2 authentication flows and protects tokens from browser exposure.

## Overview

The Session Gateway implements the BFF pattern to provide secure authentication for the Budget Analyzer application:

- Manages OAuth2 flows with Auth0 (abstracted behind NGINX)
- Stores JWTs in Redis (server-side) - never exposed to browser
- Issues HttpOnly session cookies to frontend
- Proxies API requests to NGINX gateway with JWT injection
- Implements proactive token refresh

## Architecture

```
Browser → Session Gateway (8081) → NGINX (8080) → Backend Services
          ├─ OAuth2 flows
          ├─ Session management
          └─ Token relay
```

## Technology Stack

- **Spring Cloud Gateway**: Reactive gateway for routing and filtering
- **Spring Security OAuth2 Client**: Auth0 integration
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

### Ports

- **8081**: Session Gateway (public-facing for frontend)
- **6379**: Redis (session storage)

## Running Locally

### Prerequisites

- Java 24
- Redis running on localhost:6379
- NGINX gateway running on localhost:8080

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
- JWTs stored server-side in Redis
- Never exposed to browser JavaScript
- Automatic refresh before expiration

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
