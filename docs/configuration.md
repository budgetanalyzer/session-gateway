# Configuration

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AUTH0_CLIENT_ID` | Auth0 application client ID | `placeholder-client-id` |
| `AUTH0_CLIENT_SECRET` | Auth0 application client secret | `placeholder-client-secret` |
| `AUTH0_ISSUER_URI` | Auth0 tenant issuer URI | `https://placeholder.auth0.com/` |
| `IDP_AUDIENCE` | Auth0 API audience identifier | `https://api.budgetanalyzer.org` |
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
| `SESSION_TTL_SECONDS` | TTL for session keys in seconds | `900` |
| `SESSION_OAUTH2_STATE_TTL_SECONDS` | TTL for OAuth2 authorization request state in Redis | `900` |
| `SESSION_COOKIE_NAME` | Public browser session cookie contract shared with ext_authz; distinct from any internal framework `SESSION` cookie | `BA_SESSION` |
| `SESSION_COOKIE_DOMAIN_OVERRIDE` | Optional parent-domain cookie override; unset means host-only cookies | — |
| `SESSION_COOKIE_SECURE` | Secure cookie flag | `true` |
| `SESSION_COOKIE_SAME_SITE` | SameSite cookie policy (`Strict`, `Lax`, `None`) | `Strict` |

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
