# Configuration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `placeholder-client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `placeholder-client-secret` |
| `AUTH0_ISSUER_URI` | Auth0 tenant issuer URI | `https://placeholder.auth0.com/` |
| `IDP_REDIRECT_URI` | OAuth callback URI; set an exact external URL to avoid deriving it from request headers | `{baseUrl}/login/oauth2/code/{registrationId}` |
| `IDP_LOGOUT_RETURN_TO` | URL to redirect after Auth0 logout | `https://app.budgetanalyzer.localhost/peace` |
| `PERMISSION_SERVICE_URL` | Base URL for permission-service | `http://permission-service:8086` |
| `PERMISSION_SERVICE_LOGIN_TIMEOUT` | Maximum duration for the login user-sync call; on expiry the callback redirects to `/oops` without creating a session | `5s` |
| `PERMISSION_SERVICE_AUTHORIZATION_REFRESH_TIMEOUT` | Maximum duration for the heartbeat authorization lookup | `2s` |
| `SPRING_DATA_REDIS_HOST` | Redis host for session storage | `localhost` |
| `SPRING_DATA_REDIS_PORT` | Redis port for session storage | `6379` |
| `SPRING_DATA_REDIS_USERNAME` | Redis ACL username | `session-gateway` |
| `SPRING_DATA_REDIS_PASSWORD` | Redis ACL password | — |
| `SPRING_DATA_REDIS_SSL_ENABLED` | Enable TLS for Redis connections | `false` |
| `SPRING_DATA_REDIS_SSL_BUNDLE` | Spring SSL bundle name for Redis trust | — |
| `INFRA_CA_CERT_PATH` | `file:` URI for the infrastructure CA certificate | — |
| `SESSION_KEY_PREFIX` | Redis key prefix for session hashes | `session:` |
| `SESSION_TTL_SECONDS` | TTL for session keys in seconds | `900` |
| `SESSION_MAX_LIFETIME_SECONDS` | Absolute session lifetime in seconds from `created_at`; heartbeats never extend a session past it. Must be at least `SESSION_TTL_SECONDS` | `28800` |
| `SESSION_OAUTH2_STATE_TTL_SECONDS` | TTL for OAuth2 authorization request state in Redis (seconds) | `600` |
| `SESSION_COOKIE_NAME` | Public browser session cookie contract shared with ext_authz; distinct from any internal framework `SESSION` cookie. A `__Host-` name requires `SESSION_COOKIE_SECURE=true` | `__Host-BA_SESSION` |
| `SESSION_COOKIE_SECURE` | Secure cookie flag | `true` |
| `SESSION_COOKIE_SAME_SITE` | SameSite cookie policy (`Strict`, `Lax`, `None`) | `Strict` |

## Logging

Application logging defaults to `INFO` for `org.budgetanalyzer`. HTTP metadata logging remains
enabled at `DEBUG`, but request and response body capture use the safe service-common defaults and
are disabled.

The opt-in `debug-logging` Spring profile raises application logging to `TRACE` and enables HTTP
request and response body capture. Use it only for local debugging with synthetic data; never use
it with real identity, session, or financial data.

```bash
SPRING_PROFILES_ACTIVE=debug-logging ./gradlew bootRun
```

Structured session lifecycle audit events are emitted at `INFO` on the dedicated
`budgetanalyzer.audit` logger. They contain internal user identifiers, operation names, outcomes,
and correlation IDs, but never session tokens, session digests, OAuth values, or profile data.

## Health Probes

Actuator liveness and readiness probes are enabled in every environment. Liveness contains only
Spring's `livenessState` indicator. Readiness contains `readinessState` and `redis`, because Redis
is required to authenticate and manage browser sessions. Permission-service is intentionally not
part of readiness: it is a downstream dependency, and its outage must not remove the entire auth
lane from service.

- `/actuator/health/liveness` reports whether the process should be restarted.
- `/actuator/health/readiness` reports unavailable when Redis cannot be reached.

## JSON Serialization

Session Gateway configures Jackson with `spring.jackson.default-property-inclusion: non_null`.
All JSON response types omit properties whose values are null. This keeps optional response fields
absent unless they have values and prevents a present JSON null from violating a non-null OpenAPI
property schema.

## Ports

| Port | Service | Purpose |
|------|---------|---------|
| 443 | Istio Ingress Gateway | Browser entry point, SSL termination, ext_authz integration |
| 8080 | NGINX Gateway | Frontend and API routing |
| 8081 | Session Gateway | Auth/session lifecycle requests (behind Istio ingress) |
| 9002 | ext_authz HTTP service | Called by Istio ingress Envoy proxy on `/api/*` |
| 8090 | ext_authz health endpoint | Health checks |
| 8086 | Permission Service | User roles and permissions |
| 6379 | Redis | Session storage |
