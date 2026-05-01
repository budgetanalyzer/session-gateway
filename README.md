# Session Gateway

> "Archetype: service. Role: Session-based edge authorization; manages OAuth2 flows, session cookies, and IDP grant validation."
>
> — [AGENTS.md](AGENTS.md#tree-position)

[![Build](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml/badge.svg)](https://github.com/budgetanalyzer/session-gateway/actions/workflows/build.yml)

Session-based edge authorization service that manages OAuth2 authentication flows for browser clients and writes session data as Redis hashes that the ext_authz HTTP service reads directly for per-request authorization at the Istio ingress.

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

## What It Does

- Manages OAuth2 authorization-code flows with Auth0 for browser clients
- Fetches user roles and permissions from permission-service on login
- Writes session data (userId, roles, permissions, expiry) as Redis hashes (`session:{id}`)
- Issues HttpOnly session cookies; extends TTL via heartbeat (`GET /auth/v1/session`)
- Exposes internal session revocation for permission-service (`DELETE /internal/v1/sessions/users/{userId}`)
- ext_authz reads the same Redis hashes for ingress authorization — no separate schema

Bare `/login` is a frontend route served through NGINX. The real OAuth2 flow starts at `/oauth2/authorization/idp`.

## Tech Stack

Spring WebFlux, Spring Security OAuth2 Client, custom Redis sessions via `SessionWriter`/`SessionReader`, [service-common](https://github.com/budgetanalyzer/service-common) (reactive HTTP logging, correlation IDs, exception handling).

## Quick Start

```bash
./gradlew build          # build
./gradlew test           # test
./gradlew bootRun        # run (requires Redis + permission-service)
```

Full local setup: [docs/local-development.md](docs/local-development.md)

## Documentation

| Document | Contents |
|----------|----------|
| [Configuration](docs/configuration.md) | Environment variables, ports |
| [Security](docs/security.md) | Session cookies, token protection, heartbeat, ext_authz, revocation, return URLs, browser error strategy |
| [Session Configuration](docs/session-configuration.md) | Shared session contract, cookie behavior, internal revocation, OAuth2 state TTL |
| [Auth0 Settings](docs/auth0-settings.md) | Recommended Auth0 dashboard values |
| [Security Architecture](https://github.com/budgetanalyzer/orchestration/blob/main/docs/architecture/security-architecture.md) | Platform-wide security design |

## Related Repositories

- **Orchestration**: https://github.com/budgetanalyzer/orchestration
- **Service Common**: https://github.com/budgetanalyzer/service-common
- **Permission Service**: https://github.com/budgetanalyzer/permission-service
- **Transaction Service**: https://github.com/budgetanalyzer/transaction-service
- **Currency Service**: https://github.com/budgetanalyzer/currency-service
- **Web Frontend**: https://github.com/budgetanalyzer/budget-analyzer-web
