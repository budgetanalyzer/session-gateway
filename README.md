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

## Implementation Status

### Phase 1: Infrastructure Setup ✅
- [x] Basic Spring Cloud Gateway setup
- [x] Redis session management
- [x] Basic routing to NGINX
- [x] Health check endpoint

### Phase 2: OAuth2 Integration (Pending)
- [ ] Configure Auth0 OAuth2 client (Task 2.1)
- [ ] Implement session management (Task 2.2)
- [ ] Add TokenRelay filter (Task 2.3)
- [ ] Implement proactive token refresh (Task 2.4)
- [ ] Create logout endpoint (Task 2.5)

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
