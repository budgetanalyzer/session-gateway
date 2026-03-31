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

## Documentation Discipline

Always keep documentation up to date after any configuration or code change.

Update the nearest affected documentation in the same work:
- `AGENTS.md` when instructions, guardrails, discovery commands, or repository-specific workflow changes
- `README.md` when setup, usage, or repository purpose changes
- `docs/` when architecture, configuration, APIs, behaviors, or operational workflows change

Do not leave documentation updates as follow-up work.

## Tree Position

**Archetype**: service
**Scope**: budgetanalyzer ecosystem
**Role**: Session-based edge authorization; manages OAuth2 flows, session cookies, and IDP grant validation

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

Session Gateway provides session-based edge authorization for browser-based clients in the Budget Analyzer application.

**Purpose**: Protects sensitive tokens from browser exposure by managing OAuth2 flows server-side and issuing HTTP-only session cookies. Writes session data as Redis hashes that the ext_authz HTTP service reads directly for per-request authorization at the Istio ingress. Validates IDP grants via a frontend heartbeat to detect revocation and enforce sliding session windows. Owns the OAuth2 and session lifecycle endpoints, while the frontend owns bare `/login`.

**Key Responsibilities**:
- Manages OAuth2/OIDC authentication flows with Auth0 (including `offline_access` for refresh tokens)
- Fetches user roles and permissions from the permission-service on login
- Writes session data (userId, roles, permissions, refresh token, expiry) as Redis hashes (`session:{id}`)
- The ext_authz HTTP service reads these same hashes for ingress authorization — no separate schema
- Issues HTTP-only, Secure, SameSite session cookies to browsers
- Provides session heartbeat (`GET /auth/session`) — extends session TTL, refreshes IDP tokens near expiry, detects IDP grant revocation
- Owns `/oauth2/**`, `/auth/**`, `/login/oauth2/**`, `/logout`, and `/user`
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

- **Defense-in-Depth Security**: Session-based edge authorization in the hybrid architecture (Istio ingress → Session Gateway or NGINX, with ext_authz enforcing `/api/*`)
- **ext_authz-Based Authorization**: The Istio ingress Envoy proxy calls the ext_authz HTTP service, which reads session hashes directly from Redis and injects X-User-Id/X-Roles/X-Permissions headers into API requests
- **Token Protection**: Auth0 refresh tokens stored server-side in Redis session hashes (XSS/CSRF protection); browser only sees opaque session cookie
- **Session-Based Auth**: Browser clients use cookies; native clients use opaque bearer tokens from token exchange
- **Behind Istio Ingress**: Browser auth and OAuth2 protocol endpoints reach Session Gateway through Istio ingress; bare `/login` is frontend-owned and served through NGINX
- **Stateful Sessions**: Redis hashes (`session:{id}`) provide distributed session storage — identity, roles, permissions, refresh token, expiry — read by both Session Gateway and the ext_authz service
- **Multi-Client Support**: Browser clients use OAuth2 login + cookies; native PKCE/M2M clients use `POST /auth/token/exchange`
- **Sliding Sessions with IDP Grant Validation**: Frontend heartbeat (`GET /auth/session`) resets session TTL and refreshes IDP tokens near expiry — if the IDP revokes the grant, the session is terminated

## Service Architecture

**Pattern**: Session-Based Edge Authorization + OAuth2 Client

**Architecture Flow**:
```text
Browser → Istio Ingress (:443)
  ├─ /oauth2/*, /auth/*, /login/oauth2/*, /logout, /user
  │      → Session Gateway (:8081) ← OAuth2 → Auth0
  │           ├─ Permission Service (:8086) [email/displayName]
  │           └─ Redis (:6379) [session:*]
  ├─ /login, /* → NGINX (:8080) → budget-analyzer-web
  └─ /api/* → ext_authz HTTP service (:9002) → NGINX (:8080) → Backend Services

Native Client → POST /auth/token/exchange (IDP token → opaque session token)
```

**Discovery**:
```bash
# Find all Java source files
find src/main/java -name "*.java" | sort

# Find configuration classes
grep -r "class.*Config" src/main/java

# Check OAuth2 configuration
grep -r "oauth2" src/main/resources/
```

**Port Summary**:
- **443**: Istio Ingress Gateway (browser entry point, SSL termination, ext_authz integration)
- **8080**: NGINX Gateway (frontend and API routing)
- **8081**: Session Gateway (behind Istio ingress, receives auth/session lifecycle requests)
- **9002**: ext_authz HTTP service (called by the ingress Envoy proxy on `/api/*`)
- **8090**: ext_authz health endpoint
- **8086**: Permission Service (user roles and permissions)
- **6379**: Redis (session storage)

## Technology Stack

**Principle**: Spring WebFlux reactive stack with OAuth2 and custom Redis session management.

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
- **Web**: Spring WebFlux (reactive)
- **Security**: Spring Security OAuth2 Client
- **Sessions**: Custom Redis hash sessions via `SessionWriter`/`SessionReader` (not Spring Session)
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
- SecurityConfig: OAuth2 login, authorization, entry points, return URL handling, permission fetching on login success, session creation
- SessionConfig: Clock bean
- OAuth2ClientConfig: OAuth2 client, authorization request repository, and authorized client repository configuration
- WebClientConfig: WebClient bean for external HTTP calls

**Controllers** (src/main/java/.../api/):
- UserController: Returns current authenticated user info
- LogoutController: Session deletion, cookie clearing, and Auth0 logout
- TokenExchangeController: Exchanges IDP access tokens for opaque session bearer tokens (native clients)
- SessionController: Session heartbeat — extends TTL, refreshes IDP tokens near expiry, detects grant revocation

**Security** (src/main/java/.../security/):
- RedirectUrlValidator: Validates redirect URLs to prevent open redirect attacks
- RedisAuthorizationRequestRepository: Stores OAuth2 authorization requests in Redis (keyed by state parameter), carries return URL through the OAuth2 round-trip
- RedisSessionSecurityContextRepository: Resolves session cookie → Redis hash → SecurityContext for authenticated requests
- ExchangeServerOAuth2AuthorizedClientRepository: Stores/loads OAuth2 authorized clients per-exchange (not in WebSession)
- SessionPrincipal: Authentication principal holding session data

**Services** (src/main/java/.../service/):
- PermissionServiceClient: Reactive WebClient that fetches user roles and permissions from the permission-service; passes email/displayName as query params (no bearer auth — platform network isolation and mesh policy enforcement)
- IdpTokenRefreshClient: Refreshes IDP access tokens via the OAuth2 token endpoint using `refresh_token` grant; detects grant revocation on `invalid_grant` error

**Session** (src/main/java/.../session/):
- SessionWriter: Creates, updates, and deletes session Redis hashes (`session:{id}`)
- SessionReader: Reads and deserializes session hashes from Redis
- SessionData: Record holding deserialized session fields
- SessionHashFields: Constants for Redis hash field names (user_id, roles, permissions, refresh_token, etc.)
- SessionCookieHelper: Manages session cookies (set, clear, read)

**Service-Common Utilities** (auto-configured from service-web):
- ReactiveHttpLoggingFilter: HTTP request/response logging (replaces RequestLoggingWebFilter)
- ReactiveCorrelationIdFilter: Adds correlation IDs for distributed tracing
- ReactiveApiExceptionHandler: Global exception handling for WebFlux
- SafeLogger (org.budgetanalyzer.core.logging): Opt-in safe logging utilities — `SafeLogger.toJson()` for `@Sensitive` masking, `SafeLogger.mask()` for string masking, `SafeLogger.truncateId()` for truncating identifiers (session IDs, OAuth2 state)

## API Endpoints

**Discovery**:
```bash
# Find all endpoint mappings
grep -r "@GetMapping\|@PostMapping\|@RequestMapping" src/main/java

# Check configured routes
cat src/main/resources/application.yml | grep -A 5 "routes:"
```

**Authentication Flow Endpoints**:
- `GET /oauth2/authorization/idp` - Initiates OAuth2 login (auto-configured)
  - Optional `?returnUrl=` parameter: Specifies where to redirect after successful authentication
  - Example: `/oauth2/authorization/idp?returnUrl=/dashboard`
  - Security: All returnUrl values validated by RedirectUrlValidator (same-origin only)
- `GET /login/oauth2/code/idp` - OAuth2 callback (receives code from Auth0)
- `POST /logout` - Invalidates session, clears cookies, redirects to Auth0 logout
- Bare `/login` is not a Session Gateway endpoint. It is a frontend route that initiates `GET /oauth2/authorization/idp`.

**Return URL Flow**:
After successful authentication, the redirect priority is:
1. **Explicit returnUrl parameter**: If `?returnUrl=/path` was provided to `/oauth2/authorization/idp` (carried through OAuth2 round-trip via `RedisAuthorizationRequestRepository`)
2. **Default**: Redirects to `/` if no returnUrl was provided

**Return URL Security**:
- All redirect URLs validated by `RedirectUrlValidator` (src/main/java/.../security/RedirectUrlValidator.java:27)
- Only same-origin URLs allowed (prevents open redirect attacks)
- Rejects: external URLs, protocol-relative URLs, `javascript:`, `data:`, and other malicious schemes
- Invalid URLs safely default to `/` redirect

**Session Heartbeat Endpoint**:
- `GET /auth/session` - Session heartbeat: validates session, extends TTL, refreshes IDP token if near expiry
  - Reads session from Redis via cookie
  - If IDP token is within `session.refresh-threshold-seconds` (default 10 min) of expiry: refreshes via Auth0's token endpoint
  - If refresh succeeds: updates session hash with new tokens and resets TTL
  - If IDP grant revoked (`invalid_grant`): deletes session, clears cookie, returns 401
  - If session is healthy: resets `expires_at` + Redis key TTL (sliding window)
  - Response: `{ "authenticated": true, "userId": "...", "roles": [...], "expiresAt": <epoch>, "tokenRefreshed": false }`
  - **Error behavior when IDP is unreachable or returns a transient error:**
    - Returns **502 Bad Gateway**
    - **Session is preserved** — not deleted, cookie not cleared
    - Rationale: a transient IDP outage should not destroy an established session. The frontend retries on the next heartbeat interval, and the session only expires if TTL naturally lapses while the IDP remains down
    - This contrasts with grant revocation (`invalid_grant`), which is a deliberate IDP decision — session is destroyed immediately with 401
  - 401 if no valid session, token expired with no refresh token, or IDP grant revoked

**Token Exchange Endpoint**:
- `POST /auth/token/exchange` - Exchanges an IDP access token for an opaque session bearer token (unauthenticated)
  - Request: `{ "accessToken": "<IDP access token>" }`
  - Response: `{ "token": "<session-id>", "expiresIn": 1800, "tokenType": "Bearer" }`
  - Validates token via IDP userinfo endpoint, fetches permissions, creates session hash in Redis
  - **Error behavior when IDP is unreachable**: returns **503 Service Unavailable** (no session exists yet, nothing to clean up)

**User Endpoints**:
- `GET /user` - Returns current authenticated user information

**Note**: Session Gateway does not proxy downstream routes. It only handles auth/session lifecycle endpoints. The Istio ingress routes `/api/*` through ext_authz → NGINX, and `/*` through NGINX directly.

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
- Scopes: openid, profile, email, offline_access
- Redirect URI for callback
- `offline_access` scope enables Auth0 refresh tokens for IDP grant validation (Auth0 must allow refresh tokens with rotation enabled)

**Session**:
- `session.key-prefix` (`SESSION_KEY_PREFIX`): Redis key prefix for session hashes (default: `session:`)
- `session.ttl-seconds` (`SESSION_TTL_SECONDS`): TTL for session keys in seconds (default: `1800`)
- `session.refresh-threshold-seconds` (`SESSION_REFRESH_THRESHOLD_SECONDS`): Seconds before IDP token expiry to trigger refresh during heartbeat (default: `600`)
- `session.oauth2-state-ttl-seconds` (`SESSION_OAUTH2_STATE_TTL_SECONDS`): TTL for OAuth2 authorization request state in Redis (default: `900` / 15 min). Must be long enough for MFA enrollment, SSO handoffs, or slow IDP interactions
- `session.cookie.name` (`SESSION_COOKIE_NAME`): Cookie name (default: `SESSION`)
- `session.cookie.domain-override`: Cookie domain (default: `budgetanalyzer.localhost`)
- `session.cookie.secure`: HTTPS-only cookies (default: `true`)
- `session.cookie.same-site`: SameSite attribute (default: `Strict`; accepts `Strict`, `Lax`, or `None`, case-insensitively)

**Permission Service**:
- `permission-service.base-url` (`PERMISSION_SERVICE_URL`): Base URL for the permission-service (default: `http://permission-service:8086`)
- Endpoint called: `GET /internal/v1/users/{idpSub}/permissions?email={email}&displayName={displayName}`
- No bearer auth — relies on platform network isolation and mesh policy enforcement

**Redis Connection**:
- Redis connection (host, port, username, password)
- TLS configuration via Spring SSL bundles

**Logging**:
- OAuth2 client debug logging
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
        - /login/oauth2/code/**
```

## Development Workflow

### Prerequisites
- JDK 24
- Shared local platform from `../orchestration` (`tilt up`)
- Auth0 account with configured application
- Redis and permission-service reachable from the active environment

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

### Running with the Shared Dev Environment

From the orchestration repository:
```bash
cd ../orchestration
tilt up
```

For focused debugging, run Session Gateway locally only after the shared platform is up and the required Redis and permission-service dependencies are reachable.

### Troubleshooting

**Quick Commands**:
```bash
REDIS_OPS_USERNAME=$(kubectl get secret redis-bootstrap-credentials -n infrastructure -o jsonpath='{.data.ops-username}' | base64 -d)
REDIS_OPS_PASSWORD=$(kubectl get secret redis-bootstrap-credentials -n infrastructure -o jsonpath='{.data.ops-password}' | base64 -d)

# Check if Redis is accessible
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning PING

# View session data in Redis
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning KEYS "session:*"

# Check application health
curl http://localhost:8081/actuator/health

# View application logs
kubectl logs deployment/session-gateway

# Test OAuth2 flow
curl -v http://localhost:8081/oauth2/authorization/idp
```

**Common Issues**:

**Redirect Loop at Auth0**:
- Check Auth0 callback URL matches configuration
- Verify session cookie is being set (check browser dev tools)
- Review OAuth2 client logs for error details

**Session Not Persisting**:
- Verify Redis connection in application.yml
- Check Redis deployment is running: `kubectl get pods -n infrastructure | grep redis`
- Inspect Redis session keys with the `redis-ops` credentials shown above

**Session Not Created After Login**:
- Check that permission-service is running and reachable at `permission-service.base-url`
- Verify session hash exists in Redis: `redis-cli HGETALL "session:{session-id}"`
- Verify `session.key-prefix` matches the ext_authz service's expected prefix
- Enable debug logging: `logging.level.org.budgetanalyzer.sessiongateway=DEBUG`

**Heartbeat Returns 401**:
- Verify session cookie is present and session hash exists in Redis
- Check if IDP grant was revoked: look for "IDP grant revoked" in logs
- Verify `session.refresh-threshold-seconds` is less than `session.ttl-seconds`
- If tokens expired with no refresh token (token exchange sessions), this is expected — native clients re-exchange

**Heartbeat Returns 502**:
- IDP token refresh failed due to transient error (Auth0 unreachable, rate-limited, or 5xx)
- Session is intentionally preserved — frontend will retry on next heartbeat interval
- Check Auth0 connectivity from Session Gateway
- Review logs for `IdpTokenRefreshException`

**Token Exchange Not Working**:
- Verify the IDP userinfo endpoint is reachable from Session Gateway
- Check that the IDP access token is valid (test with `curl -H "Authorization: Bearer <token>" <issuer-uri>/userinfo`)
- Verify permission-service is running for the permission fetch step

**502 Bad Gateway**:
- Ensure the Istio ingress and NGINX gateway are healthy in the shared platform
- Verify network connectivity: `curl https://api.budgetanalyzer.localhost/health`

## Integration Points

**Upstream (Receives From)**:
- Istio ingress gateway routing `/oauth2/**`, `/auth/**`, `/login/oauth2/**`, `/logout`, and `/user`
- Browser login page `/login`, which is frontend-owned and initiates `/oauth2/authorization/idp`

**Downstream (Sends To)**:
- **Auth0**: OAuth2 authorization, token exchange, token refresh (IDP grant validation), logout
- **Permission Service** (port 8086): Fetches user roles and permissions on login (no bearer auth — platform network isolation)
- **Redis**: Session storage as hashes (`session:{id}`) — read by both Session Gateway and the ext_authz HTTP service

**Data Flow**:
1. Browser loads `/login` through Istio ingress → NGINX → frontend
2. Frontend initiates `GET /oauth2/authorization/idp`
3. Istio ingress routes the OAuth2 request to Session Gateway
4. Session Gateway completes OAuth2 with Auth0 and fetches permissions from permission-service
5. Session Gateway writes a session hash to Redis (`session:{id}`) and sets the session cookie
6. Frontend periodically calls `GET /auth/session` (heartbeat) — extends session TTL, refreshes IDP tokens, detects revocation
7. Browser later calls `/api/*`
8. Istio ingress Envoy calls the ext_authz HTTP service, which reads the session hash from Redis and injects X-User-Id/X-Roles/X-Permissions
9. NGINX forwards the validated API request to the backend service
10. Backend services read claims from request headers

**Architecture Documentation**:
For detailed architecture diagrams and security design:
- [../orchestration/docs/architecture/authentication-implementation-plan.md](../orchestration/docs/architecture/authentication-implementation-plan.md)
- [../orchestration/docs/architecture/security-architecture.md](../orchestration/docs/architecture/security-architecture.md)

## Security Considerations

**Token Protection**:
- Auth0 refresh tokens stored server-side in Redis session hashes (never exposed to browser)
- Browser only sees opaque session cookie; all sensitive data lives in Redis
- Session hash deleted on logout

**Session Hash Security**:
- Sessions stored as Redis hashes under `session:{id}` with configurable TTL (default 30 min)
- Fields: `user_id`, `idp_sub`, `email`, `display_name`, `picture`, `roles` (comma-joined), `permissions` (comma-joined), `refresh_token`, `token_expires_at`, `created_at`, `expires_at` (unix timestamps)
- The ext_authz HTTP service reads these same hashes directly from Redis — no cryptographic verification needed (Redis is trusted internal infrastructure)
- Session IDs are opaque UUIDs — no sensitive data encoded in the cookie value itself

**Session Cookies**:
- HttpOnly: Not accessible via JavaScript
- Secure: HTTPS only in production
- SameSite: CSRF protection
- Short TTL: 30 minutes default

**OAuth2 Best Practices**:
- PKCE enabled for authorization code flow
- State parameter for CSRF protection
- Redirect URI validation

**IDP Grant Validation**:
- Frontend heartbeat (`GET /auth/session`) triggers IDP token refresh when near expiry
- If Auth0 has revoked the grant (user disabled, consent withdrawn), refresh fails → session terminated → 401
- Safety margin: 5-min heartbeat interval with 10-min refresh threshold ensures revocation detection within ~15 min

**No CORS Needed**:
Same-origin architecture eliminates CORS complexity. Browser traffic stays on the same origin (`app.budgetanalyzer.localhost`), with `/login` served by the frontend and auth protocol endpoints handled by Session Gateway behind the same ingress.

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
  - [config/](src/main/java/org/budgetanalyzer/sessiongateway/config/) - Spring configuration classes (OAuth2, security, session, WebClient)
  - [api/](src/main/java/org/budgetanalyzer/sessiongateway/api/) - REST controllers (user, logout, token exchange, session heartbeat)
  - [security/](src/main/java/org/budgetanalyzer/sessiongateway/security/) - Security utilities (redirect validation, Redis-backed auth request/context repos, session principal)
  - [service/](src/main/java/org/budgetanalyzer/sessiongateway/service/) - Business services (permission client, IDP token refresh)
  - [session/](src/main/java/org/budgetanalyzer/sessiongateway/session/) - Session management (Redis hash writer/reader, cookie helper, session data model)
- [src/main/resources/](src/main/resources/) - Configuration files (application.yml)
- [src/test/](src/test/) - Test classes
- [gradle/](gradle/) - Gradle wrapper and version catalog
- [config/checkstyle/](config/checkstyle/) - Code style configuration

## Related Services

Session Gateway is part of the Budget Analyzer microservices ecosystem:

**Direct Dependencies**:
- **NGINX Gateway**: Frontend/API gateway and downstream route target when requests reach Session Gateway directly
- **ext_authz HTTP Service**: Istio ingress authorization target — validates sessions from Redis and injects claims headers
- **Permission Service**: Provides user roles and permissions (called on login and token refresh, no bearer auth)
- **Redis**: Session persistence (hashes under `session:{id}`)
- **Auth0**: Identity provider

**Indirect (via Istio ingress and NGINX)**:
- **Transaction Service**: Business logic for transactions
- **Currency Service**: Currency conversion
- **Budget Analyzer Web**: React frontend (served through NGINX)

**Repository Links**:
- Orchestration: https://github.com/budgetanalyzer/orchestration
- Session Gateway: https://github.com/budgetanalyzer/session-gateway

## Best Practices

1. **Secure Token Storage**: Never expose Auth0 tokens to the browser — refresh tokens stored in Redis session hashes, browser only sees opaque session cookie
2. **Comprehensive Logging**: Enable OAuth2 debug logging for troubleshooting
3. **Session Timeout**: Balance security (short timeout) vs UX (longer timeout). Frontend heartbeat provides sliding window — session only dies if browser stops calling `GET /auth/session`
4. **Graceful Logout**: Delete session hash from Redis, clear cookie, and redirect to Auth0 logout
5. **Health Checks**: Monitor Redis connectivity and Auth0 availability
6. **Environment Parity**: Use same Auth0 tenant structure for dev/staging/prod
7. **Return URL Validation**: All returnUrl redirects automatically validated by RedirectUrlValidator - no additional validation needed
8. **Safe Logging**: SafeLogger is **opt-in** — use `SafeLogger.toJson(obj)` for objects with `@Sensitive` fields, `SafeLogger.mask(value)` for sensitive strings, `SafeLogger.truncateId(sessionId)` for session IDs and OAuth2 state values. Never log raw session IDs, OAuth2 code/state, or identity tokens.
9. **HTTP Logging**: Configure `budgetanalyzer.service.http-logging.*` appropriately - disable or reduce verbosity in production. OAuth2 callback path (`/login/oauth2/code/**`) is excluded from HTTP logging (defense-in-depth).
10. **Session Key Prefix Alignment**: `session.key-prefix` must match the ext_authz service's expected prefix so it can find session hashes
11. **Permission-Service Dependency**: Login fails if permission-service is unreachable (permissions are required)
12. **Heartbeat Interval**: Frontend should call `GET /auth/session` every ~5 min. With 30-min TTL and 10-min refresh threshold, this provides a 6x safety margin for session liveness and timely IDP grant revocation detection
13. **Token Exchange Sessions**: Sessions created via `POST /auth/token/exchange` have no refresh token — heartbeat extends TTL but cannot refresh IDP tokens. Native clients handle their own token lifecycle

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

**NO GIT WRITE OPERATIONS**: Never run git commands (commit, push, checkout, reset, etc.) without explicit user request. The user controls git workflow entirely. You may suggest what to commit, but don't do it.

**Always run build commands in sequence:**
```bash
./gradlew clean spotlessApply
./gradlew clean build
```

**Fix Checkstyle warnings** - Treat warnings as errors requiring immediate resolution

### Service-Specific Reminders

When working on this service:
- This is a security-critical component - always consider threat models
- Same-origin architecture means no CORS configuration needed (browser perspective)
- Session Gateway serves browser clients (OAuth2 + cookies) and native clients (token exchange + bearer tokens)
- Auth and OAuth2 protocol endpoints flow through Istio ingress to Session Gateway; bare `/login` is frontend-owned through NGINX
- ext_authz reads session hashes directly from Redis — no JWT infrastructure needed, no separate ext_authz schema
- Permission-service must be reachable for login to succeed (permissions fetched in OAuth2 success handler)
- Permission-service calls use no bearer auth — relies on platform network isolation and mesh policy enforcement
- Sessions are custom Redis hashes (`session:{id}`) — NOT Spring Session
- `session.key-prefix` must match the ext_authz service's expected prefix
- Changes to OAuth2 configuration require Auth0 console updates
- Redis is critical dependency - session loss means user re-authentication
- Spring WebFlux reactive stack - avoid blocking operations
- Test OAuth2 flows end-to-end - unit tests don't catch integration issues
- Frontend heartbeat (`GET /auth/session`) is the only mechanism for sliding session TTL and IDP grant validation — API activity through ext_authz does NOT extend sessions
- `offline_access` scope is required for IDP token refresh — Auth0 must allow refresh tokens with rotation enabled
- Follow the hybrid architecture: Istio ingress (edge auth/routing) → Session Gateway for auth endpoints, and Istio ingress → ext_authz → NGINX for `/api/*`
