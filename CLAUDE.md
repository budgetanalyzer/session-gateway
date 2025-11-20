# Budget Analyzer - Session Gateway

## Project Overview

Session Gateway implements the Backend-for-Frontend (BFF) pattern to provide secure authentication for browser-based clients in the Budget Analyzer application.

**Purpose**: Protects sensitive JWT tokens from browser exposure by managing OAuth2 flows server-side and issuing HTTP-only session cookies. Acts as the security entry point for all browser traffic.

**Key Responsibilities**:
- Manages OAuth2/OIDC authentication flows with Auth0
- Stores JWT access tokens securely in Redis (never exposed to browser)
- Issues HTTP-only, Secure, SameSite session cookies to browsers
- Proxies authenticated requests to the NGINX API Gateway with JWT injection
- Implements proactive token refresh for seamless session continuity

## Architecture Principles

- **Defense-in-Depth Security**: Second layer in multi-tier security architecture (NGINX → Session Gateway → Services)
- **Token Protection**: JWTs stored server-side only (XSS/CSRF protection)
- **Session-Based Auth**: Browser clients use cookies, not tokens
- **Behind NGINX**: All browser traffic enters through NGINX (port 443) which proxies to Session Gateway (port 8081)
- **Stateful Sessions**: Redis provides distributed session storage
- **Browser-Only**: Machine-to-machine clients bypass this service

## Service Architecture

**Pattern**: Backend-for-Frontend (BFF) + OAuth2 Client

**Architecture Flow**:
```
Browser → NGINX (:443)
              ↓ Proxy to Session Gateway
         Session Gateway (:8081) ← OAuth2 → Auth0
              ↓ JWT + Proxy              ↓ Session Data
         NGINX Gateway (:443)           Redis (:6379)
              ↓ JWT Validation
         Backend Services (:8082+)
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
- **6379**: Redis (session storage)

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
- SecurityConfig: OAuth2 login, authorization, entry points, return URL handling
- SessionConfig: Redis session management
- OAuth2ClientConfig: OAuth2 client and repository configuration
- *FilterConfig: Gateway filter registration

**Controllers** (src/main/java/.../controller/):
- UserController: Returns current authenticated user info
- LogoutController: Session invalidation and Auth0 logout

**Security** (src/main/java/.../security/):
- RedirectUrlValidator: Validates redirect URLs to prevent open redirect attacks
- RedisServerRequestCache: Custom ServerRequestCache implementation for saving/retrieving original request URIs

**Filters** (src/main/java/.../filter/):
- TokenRefreshGatewayFilterFactory: Proactive token refresh before expiry
- OAuth2TokenRelayGatewayFilter: Injects JWT into proxied requests

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

**User Endpoints**:
- `GET /user` - Returns current authenticated user information

**Proxy Routes**:
- `GET /api/**` - Proxies API requests to NGINX Gateway (JWT injected)
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

**Session Management**:
- Redis connection (host, port)
- Session timeout (30 minutes default)
- Cookie settings (HttpOnly, Secure, SameSite)

**Gateway Routing**:
- Routes to NGINX Gateway (port 8080)
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

**Token Not Added to Proxied Requests**:
- Verify OAuth2TokenRelayGatewayFilter is registered
- Check authorized client repository has token for session
- Enable debug logging: `logging.level.org.springframework.security=DEBUG`

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
- **Redis**: Session storage and retrieval (stores JWTs, user info)
- **NGINX Gateway** (port 443): Proxies all requests with JWT injection to https://api.budgetanalyzer.localhost

**Data Flow**:
1. Browser → NGINX (https://app.budgetanalyzer.localhost)
2. NGINX → Session Gateway (session cookie in request)
3. Session Gateway → Redis (lookup JWT by session ID)
4. Session Gateway → NGINX (proxy with Authorization: Bearer JWT to api.budgetanalyzer.localhost)
5. NGINX → Token Validation Service → Backend Services
6. Response flows back through the chain

**Architecture Documentation**:
For detailed architecture diagrams and security design:
- [../orchestration/docs/architecture/authentication-implementation-plan.md](../orchestration/docs/architecture/authentication-implementation-plan.md)
- [../orchestration/docs/architecture/security-architecture.md](../orchestration/docs/architecture/security-architecture.md)

## Security Considerations

**Token Protection**:
- JWTs never sent to browser (XSS protection)
- Stored in Redis with session association
- Cleared on logout or session expiry

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
  - [config/](src/main/java/org/budgetanalyzer/sessiongateway/config/) - Spring configuration classes
  - [controller/](src/main/java/org/budgetanalyzer/sessiongateway/controller/) - REST controllers
  - [filter/](src/main/java/org/budgetanalyzer/sessiongateway/filter/) - Custom Gateway filters
- [src/main/resources/](src/main/resources/) - Configuration files (application.yml)
- [src/test/](src/test/) - Test classes
- [gradle/](gradle/) - Gradle wrapper and version catalog
- [config/checkstyle/](config/checkstyle/) - Code style configuration

## Related Services

Session Gateway is part of the Budget Analyzer microservices ecosystem:

**Direct Dependencies**:
- **NGINX Gateway**: Downstream proxy target (API routing, JWT validation)
- **Redis**: Session persistence
- **Auth0**: Identity provider

**Indirect (via NGINX)**:
- **Transaction Service**: Business logic for transactions
- **Currency Service**: Currency conversion
- **Token Validation Service**: JWT validation and user info
- **Budget Analyzer Web**: React frontend (served through NGINX)

**Repository Links**:
- Orchestration: https://github.com/budgetanalyzer/orchestration
- Session Gateway: https://github.com/budgetanalyzer/session-gateway

## Best Practices

1. **Secure Token Storage**: Never expose JWTs to browser - always store in Redis
2. **Proactive Refresh**: Refresh tokens before expiry for seamless UX
3. **Comprehensive Logging**: Enable OAuth2 debug logging for troubleshooting
4. **Session Timeout**: Balance security (short timeout) vs UX (longer timeout)
5. **Graceful Logout**: Clear both session and Auth0 session on logout
6. **Health Checks**: Monitor Redis connectivity and Auth0 availability
7. **Environment Parity**: Use same Auth0 tenant structure for dev/staging/prod
8. **Return URL Validation**: All returnUrl redirects automatically validated by RedirectUrlValidator - no additional validation needed
9. **Safe Logging**: Use `SafeLogger.toJson()` from service-common when logging objects that may contain sensitive data
10. **HTTP Logging**: Configure `budgetanalyzer.service.http-logging.*` appropriately - disable or reduce verbosity in production

## Notes for Claude Code

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
- Session Gateway is browser-specific - M2M clients should use NGINX Gateway directly
- All browser traffic flows through NGINX (port 443) to Session Gateway (port 8081)
- Changes to OAuth2 configuration require Auth0 console updates
- Redis is critical dependency - session loss means user re-authentication
- Token refresh happens automatically via custom filter before expiry
- Spring Cloud Gateway uses reactive WebFlux - avoid blocking operations
- Test OAuth2 flows end-to-end - unit tests don't catch integration issues
- Follow the hybrid architecture: NGINX (SSL termination) → Session Gateway (BFF) → NGINX (API Gateway) → Services
