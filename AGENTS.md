# Budget Analyzer - Session Gateway

## Honest Discourse

Do not over-validate ideas. The user wants honest pushback, not agreement.

- If something seems wrong, say so directly
- Distinguish "novel" from "obvious in retrospect"
- Push back on vague claims — ask for concrete constraints
- Don't say "great question" or "that's a really interesting point"
- Skip the preamble and caveats — just answer

## Code Exploration

NEVER use Agent/subagent tools for code exploration. Use Grep, Glob, and Read directly.

## Tree Position

**Archetype**: service
**Scope**: budgetanalyzer ecosystem
**Role**: BFF for browser authentication; manages OAuth2 flows, session cookies, and ext_authz session dual-writes

### Relationships
- **Consumes**: service-common (patterns)
- **Coordinated by**: orchestration
- **Peers with**: Discover via `ls /workspace/*-service`
- **Observed by**: architecture-conversations

### Permissions
- **Read**: `../service-common/`, `../orchestration/docs/`
- **Write**: This repository only

### Discovery
```bash
# My peers
ls -d /workspace/*-service
# My platform
ls ../service-common/
```

## Project Overview

Session Gateway implements the Backend-for-Frontend (BFF) pattern to provide secure authentication for browser-based clients in the Budget Analyzer application.

**Purpose**: Protects sensitive tokens from browser exposure by managing OAuth2 flows server-side, issuing HTTP-only session cookies, and dual-writing session data to the ext_authz Redis schema for Envoy-based authorization. Acts as the security entry point for all browser traffic.

**Key Responsibilities**:
- Manages OAuth2/OIDC authentication flows with Auth0
- Fetches user roles and permissions from the permission-service on login
- Dual-writes session data (userId, roles, permissions) to ext_authz Redis schema for Envoy ext_authz validation
- Stores Auth0 tokens, user identity, and permissions in Redis (never exposed to browser)
- Issues HTTP-only, Secure, SameSite session cookies to browsers
- Proxies authenticated requests to the NGINX API Gateway
- Implements proactive token refresh with permission re-fetch and ext_authz session update
- Provides token exchange endpoint for native PKCE/M2M clients (`POST /auth/token/exchange`)

## Coding Standards

**Before writing or modifying any Java code, read [code-quality-standards.md](../service-common/docs/code-quality-standards.md).** Do not skip this step. The most common violations: missing `var`, wildcard imports, abbreviated variable names, Javadoc without trailing periods.

## Spring Boot Patterns

**This service follows standard Budget Analyzer Spring Boot conventions.**

**When to consult service-common documentation:**
- **Implementing new features** → Read [service-common/AGENTS.md](../service-common/AGENTS.md) for architecture patterns
- **Handling errors** → Read [error-handling.md](../service-common/docs/error-handling.md) for exception hierarchy
- **Writing tests** → Read [testing-patterns.md](../service-common/docs/testing-patterns.md) for JUnit 5 + TestContainers conventions
- **Code quality issues** → Read [code-quality-standards.md](../service-common/docs/code-quality-standards.md) for Spotless, Checkstyle, var usage

**Quick reference:**
- Naming: `*Controller`, `*Service`, `*ServiceImpl`, `*Repository`
- DTOs: `*Request`, `*Response` — NEVER `*Dto`/`*DTO`
- Exceptions: `BusinessException` for business rules, `InvalidRequestException` for bad input
- Logging: SLF4J with structured logging (never log sensitive data)
- Imports: Use `jakarta.persistence.*` — NEVER `org.hibernate.*`

## Architecture Principles

- **Defense-in-Depth Security**: Second layer in multi-tier security architecture (Envoy → ext_authz → Services)
- **ext_authz-Based Authorization**: Envoy ext_authz gRPC service validates sessions directly from Redis, injecting X-User-Id/X-Roles/X-Permissions headers into proxied requests
- **Token Protection**: Auth0 tokens stored server-side only (XSS/CSRF protection); session data dual-written to ext_authz Redis schema (never exposed to browser)
- **Session-Based Auth**: Browser clients use cookies; native clients use opaque bearer tokens from token exchange
- **Behind NGINX**: All browser traffic enters through NGINX (port 443) which proxies to Session Gateway (port 8081)
- **Stateful Sessions**: Redis provides distributed session storage (identity, roles, permissions) plus ext_authz session schema
- **Multi-Client Support**: Browser clients use OAuth2 login + cookies; native PKCE/M2M clients use `POST /auth/token/exchange`

## Service Architecture

**Pattern**: Backend-for-Frontend (BFF) + OAuth2 Client

**Architecture Flow**:
```
Browser → NGINX (:443)
              ↓ Proxy to Session Gateway
         Session Gateway (:8081) ← OAuth2 → Auth0
              │                           ↓ Session Data
              ├─ Permissions ──→ Permission Service (:8082) [email/name]
              │                           ↓ userId, roles, permissions
              ├─ Dual-write: Spring Session + ext_authz Redis hash
              │                           ↓ Stored in Redis (:6379)
              ↓ Proxy request
         Envoy Gateway ── ext_authz ──→ ext_authz gRPC service
              │                           ↓ lookup extauthz:session:{id}
              │                           ↓ inject X-User-Id, X-Roles, X-Permissions
              ↓ headers injected → proxy to backend
         Backend Services (:8083+) ── read claims from headers

Native Client → POST /auth/token/exchange (IDP token → opaque session token)
```

**Discovery**:
```bash
# View Spring Cloud Gateway routes
cat src/main/resources/application.yml | grep -A 10 "spring.cloud.gateway"

# Find all filter implementations
find src -name "*Filter*.java"

# Check OAuth2 configuration
grep -r "oauth2" src/main/resources/
```

**Port Summary**:
- **443**: NGINX Gateway (browser entry point, SSL termination)
- **8081**: Session Gateway (behind NGINX, receives proxied requests)
- **8082**: Permission Service (user roles and permissions)
- **6379**: Redis (session storage + ext_authz session schema)

## Technology Stack

**Principle**: Spring Cloud reactive stack with OAuth2 and distributed sessions.

**Discovery**:
```bash
# View all dependencies
./gradlew dependencies

# Check Spring Boot version
cat gradle/libs.versions.toml

# List key dependencies
grep "implementation" build.gradle.kts
```

**Stack Components**:
- **Gateway**: Spring Cloud Gateway (reactive, WebFlux-based)
- **Security**: Spring Security OAuth2 Client
- **Sessions**: Spring Session Data Redis
- **Service Common (service-web)**: Reactive HTTP logging, correlation IDs, safe logging, exception handling
- **Permission Client**: WebClient for reactive HTTP calls to permission-service
- **Build**: Gradle with Kotlin DSL
- **Cache**: Redis (AOF persistence)
- **Identity Provider**: Auth0 (OAuth2/OIDC)

**Service-Common Integration**:
- Auto-configured reactive utilities from `org.budgetanalyzer:service-web:0.0.1-SNAPSHOT`
- Provides: HTTP request/response logging, distributed tracing correlation IDs, safe logging with sensitive data masking, global exception handling
- OAuth2ResourceServerSecurityConfig explicitly excluded (Session Gateway is OAuth2 Client, not Resource Server)
- DataSource/JPA auto-configuration excluded (no database required)

## Key Components

**Discovery**:
```bash
# List all Java source files by type
find src/main/java -name "*.java" | sort

# Find configuration classes
grep -r "class.*Config" src/main/java

# Find controllers
grep -r "@RestController\|@Controller" src/main/java

# Find custom filters
find src -name "*Filter*.java" -o -name "*FilterFactory.java"
```

**Component Types**:

**Configuration** (src/main/java/.../config/):
- SecurityConfig: OAuth2 login, authorization, entry points, return URL handling, permission fetching on login success, ext_authz dual-write
- SessionConfig: Redis session management, Clock bean
- OAuth2ClientConfig: OAuth2 client and repository configuration

**Controllers** (src/main/java/.../api/):
- UserController: Returns current authenticated user info
- LogoutController: Session invalidation, ext_authz session deletion, and Auth0 logout
- TokenExchangeController: Exchanges IDP access tokens for opaque session bearer tokens (native clients)

**Security** (src/main/java/.../security/):
- RedirectUrlValidator: Validates redirect URLs to prevent open redirect attacks
- RedisServerRequestCache: Custom ServerRequestCache implementation for saving/retrieving original request URIs

**Filters** (src/main/java/.../filter/):
- TokenRefreshGatewayFilterFactory: Proactive OAuth2 token refresh before expiry, with permission re-fetch and ext_authz session update

**Services** (src/main/java/.../service/):
- PermissionServiceClient: Reactive WebClient that fetches user roles and permissions from the permission-service; passes email/displayName as query params (no bearer auth — network isolation)

**Session** (src/main/java/.../session/):
- SessionAttributes: Constants for session attribute keys (USER_ID, ROLES, PERMISSIONS)
- ExtAuthzSessionWriter: Dual-writes session data to ext_authz Redis hash (`extauthz:session:{id}`) for Envoy ext_authz validation

**Service-Common Utilities** (auto-configured from service-web):
- ReactiveHttpLoggingFilter: HTTP request/response logging (replaces RequestLoggingWebFilter)
- ReactiveCorrelationIdFilter: Adds correlation IDs for distributed tracing
- ReactiveApiExceptionHandler: Global exception handling for WebFlux
- SafeLogger (org.budgetanalyzer.core.logging): Safe logging with sensitive data masking

## API Endpoints

**Discovery**:
```bash
# Find all endpoint mappings
grep -r "@GetMapping\|@PostMapping\|@RequestMapping" src/main/java

# Check configured routes
cat src/main/resources/application.yml | grep -A 5 "routes:"
```

**Authentication Flow Endpoints**:
- `GET /oauth2/authorization/auth0` - Initiates OAuth2 login (auto-configured)
  - Optional `?returnUrl=` parameter: Specifies where to redirect after successful authentication
  - Example: `/oauth2/authorization/auth0?returnUrl=/dashboard`
  - Security: All returnUrl values validated by RedirectUrlValidator (same-origin only)
- `GET /login/oauth2/code/auth0` - OAuth2 callback (receives code from Auth0)
- `POST /logout` - Invalidates session, clears cookies, redirects to Auth0 logout

**Return URL Flow**:
After successful authentication, the redirect priority is:
1. **Explicit returnUrl parameter**: If `?returnUrl=/path` was provided to `/oauth2/authorization/auth0`
2. **Saved request**: If user was redirected to login from a protected resource (automatic via RedisServerRequestCache)
3. **Default**: Redirects to `/` if no returnUrl or saved request exists

**Return URL Security**:
- All redirect URLs validated by `RedirectUrlValidator` (src/main/java/.../security/RedirectUrlValidator.java:27)
- Only same-origin URLs allowed (prevents open redirect attacks)
- Rejects: external URLs, protocol-relative URLs, `javascript:`, `data:`, and other malicious schemes
- Invalid URLs safely default to `/` redirect

**Token Exchange Endpoint**:
- `POST /auth/token/exchange` - Exchanges an IDP access token for an opaque session bearer token (unauthenticated)
  - Request: `{ "accessToken": "<IDP access token>" }`
  - Response: `{ "token": "<session-id>", "expiresIn": 1800, "tokenType": "Bearer" }`
  - Validates token via IDP userinfo endpoint, fetches permissions, creates session, writes ext_authz session

**User Endpoints**:
- `GET /user` - Returns current authenticated user information

**Proxy Routes**:
- `GET /api/**` - Proxies API requests to NGINX Gateway
- `GET /**` - Proxies frontend requests to NGINX (serves React app)

## Configuration

**Discovery**:
```bash
# List all configuration files
find . -maxdepth 3 -name "*.yml" -o -name "*.properties" -o -name ".env"

# View Spring configuration
cat src/main/resources/application.yml

# Check environment variables
grep "SPRING_SECURITY_OAUTH2" .env
```

**Configuration Categories**:

**OAuth2 Client** (Auth0):
- Client ID, secret, issuer URI
- Scopes: openid, profile, email
- Redirect URI for callback

**ext_authz Session**:
- `extauthz.session.key-prefix` (`EXTAUTHZ_SESSION_KEY_PREFIX`): Redis key prefix for ext_authz sessions (default: `extauthz:session:`)
- `extauthz.session.ttl-seconds` (`EXTAUTHZ_SESSION_TTL_SECONDS`): TTL for ext_authz session keys in seconds (default: `1800`, must match Spring Session timeout)

**Permission Service**:
- `permission-service.base-url` (`PERMISSION_SERVICE_URL`): Base URL for the permission-service (default: `http://permission-service:8086`)
- Endpoint called: `GET /internal/v1/users/{idpSub}/permissions?email={email}&displayName={displayName}`
- No bearer auth — relies on network isolation (mTLS planned for Phase 2)

**Session Management**:
- Redis connection (host, port)
- Session timeout (30 minutes default)
- Cookie settings (HttpOnly, Secure, SameSite)
- Session stores: userId, roles, permissions

**Gateway Routing**:
- Routes to NGINX Gateway (`https://api.budgetanalyzer.localhost`, port 443)
- Filter chains (token relay, refresh)
- Path predicates

**Logging**:
- OAuth2 client debug logging
- Gateway filter logging
- Session management logging

**HTTP Logging** (from service-common):
- `budgetanalyzer.service.http-logging.enabled`: Enable/disable HTTP logging
- `budgetanalyzer.service.http-logging.log-level`: Log level (DEBUG, INFO, etc.)
- `budgetanalyzer.service.http-logging.include-request-body`: Log request bodies
- `budgetanalyzer.service.http-logging.include-response-body`: Log response bodies
- `budgetanalyzer.service.http-logging.include-request-headers`: Log request headers
- `budgetanalyzer.service.http-logging.include-response-headers`: Log response headers
- `budgetanalyzer.service.http-logging.include-query-params`: Log query parameters
- `budgetanalyzer.service.http-logging.include-client-ip`: Log client IP addresses
- `budgetanalyzer.service.http-logging.max-body-size`: Maximum body size to log (bytes)
- `budgetanalyzer.service.http-logging.exclude-patterns`: List of path patterns to exclude (e.g., `/actuator/**`)
- `budgetanalyzer.service.http-logging.log-errors-only`: Only log requests that result in errors

Example configuration (application.yml lines 97-113):
```yaml
budgetanalyzer:
  service:
    http-logging:
      enabled: true
      log-level: DEBUG
      include-request-body: true
      include-response-body: true
      max-body-size: 10000
      exclude-patterns:
        - /actuator/**
```

## Development Workflow

### Prerequisites
- JDK 17+
- Docker and Docker Compose (for Redis and NGINX)
- Auth0 account with configured application
- NGINX Gateway running on port 443 (handles SSL termination)

### Build and Test

**Format code:**
```bash
./gradlew clean spotlessApply
```

**Build and test:**
```bash
./gradlew clean build
```

The build includes:
- Spotless code formatting checks
- Checkstyle rule enforcement
- All unit and integration tests
- JAR file creation

**Run locally:**
```bash
./gradlew bootRun
```

### Running with Docker Compose

From the orchestration repository:
```bash
# Start all services including session-gateway
docker compose up -d session-gateway

# View logs
docker compose logs -f session-gateway

# Restart after code changes
docker compose restart session-gateway

# Stop
docker compose down
```

### Troubleshooting

**Quick Commands**:
```bash
# Check if Redis is accessible
docker exec -it redis-cache redis-cli PING

# View session data in Redis
docker exec -it redis-cache redis-cli KEYS "spring:session:*"

# Check application health
curl http://localhost:8081/actuator/health

# View application logs
docker logs session-gateway

# Test OAuth2 flow
curl -v http://localhost:8081/oauth2/authorization/auth0
```

**Common Issues**:

**Redirect Loop at Auth0**:
- Check Auth0 callback URL matches configuration
- Verify session cookie is being set (check browser dev tools)
- Review OAuth2 client logs for error details

**Session Not Persisting**:
- Verify Redis connection in application.yml
- Check Redis container is running: `docker ps | grep redis`
- Inspect Redis session keys: `docker exec redis-cache redis-cli KEYS "*"`

**ext_authz Session Not Created**:
- Check that permission-service is running and reachable at `permission-service.base-url`
- Verify session contains `INTERNAL_USER_ID`, `INTERNAL_ROLES`, `INTERNAL_PERMISSIONS` (populated on login)
- Verify ext_authz session exists in Redis: `redis-cli HGETALL "extauthz:session:{session-id}"`
- If login succeeded but ext_authz session missing, check logs for `ExtAuthzSessionWriter` errors (errors are swallowed)
- Verify `extauthz.session.key-prefix` and `extauthz.session.ttl-seconds` match ext_authz service expectations
- Enable debug logging: `logging.level.org.budgetanalyzer.sessiongateway=DEBUG`

**Token Exchange Not Working**:
- Verify the IDP userinfo endpoint is reachable from Session Gateway
- Check that the IDP access token is valid (test with `curl -H "Authorization: Bearer <token>" <issuer-uri>/userinfo`)
- Verify permission-service is running for the permission fetch step

**502 Bad Gateway**:
- Ensure NGINX Gateway is running on port 443
- Check gateway route configuration in application.yml
- Verify network connectivity: `curl https://api.budgetanalyzer.localhost/health`

## Integration Points

**Upstream (Receives From)**:
- NGINX Gateway on port 8081 (proxied from https://app.budgetanalyzer.localhost)
- React frontend making authenticated API calls (via NGINX)

**Downstream (Sends To)**:
- **Auth0**: OAuth2 authorization, token exchange, logout
- **Permission Service** (port 8082): Fetches user roles and permissions on login and token refresh (no bearer auth — network isolation)
- **Redis**: Session storage (Auth0 tokens, userId, roles, permissions) + ext_authz session dual-write (`extauthz:session:{id}`)
- **NGINX Gateway** (port 443): Proxies requests to https://api.budgetanalyzer.localhost

**Data Flow**:
1. Browser → NGINX (https://app.budgetanalyzer.localhost)
2. NGINX → Session Gateway (session cookie in request)
3. Session Gateway → Redis (lookup session: identity, roles, permissions)
4. Session Gateway → Permission Service (on login or token refresh: fetch userId, roles, permissions; passes email/displayName)
5. Session Gateway dual-writes: Spring Session + ext_authz Redis hash (`extauthz:session:{id}`)
6. Session Gateway → NGINX (proxy request to api.budgetanalyzer.localhost)
7. Envoy → ext_authz gRPC service (lookup `extauthz:session:{id}` in Redis, inject X-User-Id/X-Roles/X-Permissions headers)
8. Envoy → Backend Service (headers injected, request proxied)
9. Backend services read claims from request headers (X-User-Id, X-Roles, X-Permissions)
10. Response flows back through the chain

**Architecture Documentation**:
For detailed architecture diagrams and security design:
- [../orchestration/docs/architecture/authentication-implementation-plan.md](../orchestration/docs/architecture/authentication-implementation-plan.md)
- [../orchestration/docs/architecture/security-architecture.md](../orchestration/docs/architecture/security-architecture.md)

## Security Considerations

**Token Protection**:
- Auth0 access tokens stored server-side in Redis (never exposed to browser)
- Session data dual-written to ext_authz Redis hash — browser only sees opaque session cookie
- All session data cleared on logout (both Spring Session and ext_authz session)

**ext_authz Session Security**:
- Ext_authz sessions stored as Redis hashes under `extauthz:session:{id}` with TTL matching Spring Session timeout (30 min)
- Fields: `user_id`, `roles` (comma-joined), `permissions` (comma-joined), `created_at`, `expires_at` (unix timestamps)
- Envoy ext_authz gRPC service validates sessions by reading directly from Redis — no cryptographic verification needed (Redis is trusted internal infrastructure)
- Session IDs are opaque — no sensitive data encoded in the token itself
- Dual-write errors are logged and swallowed to avoid breaking the primary authentication flow

**Session Cookies**:
- HttpOnly: Not accessible via JavaScript
- Secure: HTTPS only in production
- SameSite: CSRF protection
- Short TTL: 30 minutes default

**OAuth2 Best Practices**:
- PKCE enabled for authorization code flow
- State parameter for CSRF protection
- Redirect URI validation
- Token refresh before expiry (proactive)

**No CORS Needed**:
BFF pattern eliminates CORS complexity - browser makes same-origin requests to Session Gateway, which proxies to backends server-side.

## Repository Structure

**Discovery**:
```bash
# View structure
tree -L 3 -I 'build|.gradle'

# List source packages
find src/main/java -type d

# Find test files
find src/test -name "*.java"
```

**Key Directories**:
- [src/main/java/org/budgetanalyzer/sessiongateway/](src/main/java/org/budgetanalyzer/sessiongateway/) - Application source
  - [config/](src/main/java/org/budgetanalyzer/sessiongateway/config/) - Spring configuration classes (OAuth2, security, session)
  - [api/](src/main/java/org/budgetanalyzer/sessiongateway/api/) - REST controllers (user, logout, token exchange)
  - [filter/](src/main/java/org/budgetanalyzer/sessiongateway/filter/) - Custom Gateway filters (token refresh)
  - [security/](src/main/java/org/budgetanalyzer/sessiongateway/security/) - Security utilities (redirect validation, request cache)
  - [service/](src/main/java/org/budgetanalyzer/sessiongateway/service/) - Business services (permission client)
  - [session/](src/main/java/org/budgetanalyzer/sessiongateway/session/) - Session management (ext_authz dual-write, session constants)
- [src/main/resources/](src/main/resources/) - Configuration files (application.yml)
- [src/test/](src/test/) - Test classes
- [gradle/](gradle/) - Gradle wrapper and version catalog
- [config/checkstyle/](config/checkstyle/) - Code style configuration

## Related Services

Session Gateway is part of the Budget Analyzer microservices ecosystem:

**Direct Dependencies**:
- **NGINX Gateway**: Downstream proxy target (API routing)
- **ext_authz gRPC Service**: Envoy ext_authz target — validates sessions from Redis, injects claims headers
- **Permission Service**: Provides user roles and permissions (called on login and token refresh, no bearer auth)
- **Redis**: Session persistence (Spring Session + ext_authz session schema)
- **Auth0**: Identity provider

**Indirect (via Envoy/NGINX)**:
- **Transaction Service**: Business logic for transactions
- **Currency Service**: Currency conversion
- **Budget Analyzer Web**: React frontend (served through NGINX)

**Repository Links**:
- Orchestration: https://github.com/budgetanalyzer/orchestration
- Session Gateway: https://github.com/budgetanalyzer/session-gateway

## Best Practices

1. **Secure Token Storage**: Never expose Auth0 tokens to the browser — Auth0 tokens stored in Redis, session data dual-written to ext_authz Redis schema
2. **Proactive Refresh**: Refresh Auth0 tokens before expiry, re-fetch permissions from permission-service, and update ext_authz session
3. **Comprehensive Logging**: Enable OAuth2 debug logging for troubleshooting
4. **Session Timeout**: Balance security (short timeout) vs UX (longer timeout)
5. **Graceful Logout**: Clear Spring Session, ext_authz session, and Auth0 session on logout
6. **Health Checks**: Monitor Redis connectivity and Auth0 availability
7. **Environment Parity**: Use same Auth0 tenant structure for dev/staging/prod
8. **Return URL Validation**: All returnUrl redirects automatically validated by RedirectUrlValidator - no additional validation needed
9. **Safe Logging**: Use `SafeLogger.toJson()` from service-common when logging objects that may contain sensitive data
10. **HTTP Logging**: Configure `budgetanalyzer.service.http-logging.*` appropriately - disable or reduce verbosity in production
11. **ext_authz TTL Alignment**: `extauthz.session.ttl-seconds` must match Spring Session timeout to prevent stale sessions
12. **Permission-Service Dependency**: Login fails if permission-service is unreachable (permissions are required); token refresh degrades gracefully (existing permissions retained on failure)
13. **Dual-Write Resilience**: ext_authz write failures are logged and swallowed — primary session flow is never broken by ext_authz errors

## NOTES FOR AI AGENTS

**CRITICAL - Prerequisites First**: Before implementing any plan or feature:
1. Check for prerequisites in documentation (e.g., "Prerequisites: service-common Enhancement")
2. If prerequisites are NOT satisfied, STOP immediately and inform the user
3. Do NOT attempt to hack around missing prerequisites - this leads to broken implementations that must be deleted
4. Complete prerequisites first, then return to the original task

### SSL/TLS Certificate Constraints

**NEVER run SSL write operations** - Claude runs in a container with its own mkcert CA, but the user's browser trusts their host's mkcert CA. These are different CAs, so certificates generated in Claude's sandbox will cause browser SSL warnings.

**Forbidden operations** (must be run by user on host):
- `mkcert` (any certificate generation)
- `openssl genrsa`, `openssl req -new`, `openssl x509 -req` (key/cert generation)
- Any script that generates certificates (e.g., `setup-k8s-tls.sh`, `setup-local-https.sh`)

**Allowed operations** (read-only):
- `openssl x509 -text -noout` (inspect certificates)
- `openssl verify` (verify certificate chains)
- `kubectl get secret -o yaml` (view secrets)
- Certificate file reads for debugging

When SSL issues occur, guide the user to run certificate scripts on their host machine.

### Critical Rules

**Always run build commands in sequence:**
```bash
./gradlew clean spotlessApply
./gradlew clean build
```

**Fix Checkstyle warnings** - Treat warnings as errors requiring immediate resolution

### Service-Specific Reminders

When working on this service:
- This is a security-critical component - always consider threat models
- BFF pattern means no CORS configuration needed (same-origin from browser perspective)
- Session Gateway serves browser clients (OAuth2 + cookies) and native clients (token exchange + bearer tokens)
- All browser traffic flows through NGINX (port 443) to Session Gateway (port 8081)
- ext_authz validates sessions directly from Redis — no JWT infrastructure needed
- Permission-service must be reachable for login to succeed (permissions fetched in OAuth2 success handler)
- Permission-service calls use no bearer auth — relies on network isolation (mTLS planned)
- ext_authz session dual-write errors are swallowed — never break the primary session flow
- `extauthz.session.ttl-seconds` must match Spring Session timeout (`@EnableRedisWebSession(maxInactiveIntervalInSeconds)`)
- Changes to OAuth2 configuration require Auth0 console updates
- Redis is critical dependency - session loss means user re-authentication
- Token refresh happens automatically via custom filter before expiry (includes permission re-fetch and ext_authz session update)
- Spring Cloud Gateway uses reactive WebFlux - avoid blocking operations
- Test OAuth2 flows end-to-end - unit tests don't catch integration issues
- Follow the hybrid architecture: NGINX (SSL termination) → Session Gateway (BFF) → Envoy (ext_authz) → Services

