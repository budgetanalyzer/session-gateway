# Session Architecture Rethink — Implementation Plan

## Context

Session Gateway currently uses Spring Cloud Gateway + Spring Session with a dual-write to a separate ext_authz Redis hash. This creates five problems documented in `conversations/001-extauthz-ttl-drift-and-session-architecture-rethink.md`:

1. **TTL drift** — Spring Session (sliding) and ext_authz hash (fixed) diverge
2. **Dead token refresh** — `TokenRefreshGatewayFilterFactory` is wired to no route
3. **Hard logout at 30 min** — nothing touches Session Gateway after login, so nothing resets any TTL
4. **Session outlives IDP revocation** — no mechanism to check if Auth0 revoked the user
5. **Root cause: two Redis keys for one logical session**

The fix: strip Session Gateway down to a plain WebFlux app with one Redis hash per session, no Spring Session, no Spring Cloud Gateway. Add a frontend heartbeat for session liveness and IDP grant validation.

### Decisions

1. Drop "BFF" label — this is a session-based edge authorization architecture
2. Single Redis hash `session:{id}` — no Spring Session, no dual-write
3. Add `offline_access` scope — Auth0 issues refresh tokens for IDP grant validation
4. Frontend heartbeat `GET /auth/session` — triggers token refresh, extends session
5. ext_authz stays read-only — Session Gateway is the sole session writer

---

## Phase 1: Strip and Build Session Core

**Goal**: Remove dead code, Gateway, and Spring Session. Build the new session infrastructure. Service compiles but doesn't function end-to-end yet.

### 1a. Delete dead/obsolete files

| File | Reason |
|------|--------|
| `src/main/java/.../filter/TokenRefreshGatewayFilterFactory.java` | Dead code |
| `src/main/java/.../config/OAuth2ClientManagerConfig.java` | Gateway token refresh support |
| `src/main/java/.../config/OAuth2AuthorizedClientRepositoryConfig.java` | WebSession-based OAuth2 client storage |
| `src/main/java/.../config/DynamicDomainCookieWebSessionIdResolver.java` | Spring Session cookie resolver |
| `src/main/java/.../config/OAuth2LoginDebugger.java` | Debug logging for OAuth2 flow |
| `src/main/java/.../config/EnvironmentDebugger.java` | Startup debug logging |
| `src/main/java/.../security/RedisServerRequestCache.java` | Spring Session-based request cache |
| `src/main/java/.../session/ExtAuthzSessionWriter.java` | Dual-write (replaced by unified writer) |
| `src/main/java/.../session/SessionAttributes.java` | Spring Session attribute constants |
| `src/test/.../filter/TokenRefreshGatewayFilterFactoryTest.java` | Tests for dead code |
| `src/test/.../security/RedisServerRequestCacheTest.java` | Tests for deleted class |
| `src/test/.../session/ExtAuthzSessionWriterTest.java` | Tests for deleted class |

### 1b. Remove dependencies from `build.gradle.kts`

- Remove `spring-cloud-starter-gateway-server-webflux`
- Remove `spring-session-data-redis`
- Remove `spring-cloud-dependencies` BOM
- Add `spring-boot-starter-webflux` (was transitively provided by gateway)
- Keep: `spring-boot-starter-oauth2-client`, `spring-boot-starter-data-redis`, `service-web`, `springdoc-openapi`, `spring-boot-starter-actuator`

### 1c. Strip `application.yml`

- Remove entire `spring.cloud.gateway` section (routes, httpclient wiretap)
- Remove `spring.session` section (store-type, timeout, redis flush-mode/namespace)
- Update `extauthz.session.key-prefix` default to `session:` (or rename config property)
- Keep: server config, OAuth2 config, Redis config, logging, permission-service, actuator, cookie config, IDP config

### 1d. Strip `SessionConfig.java`

- Remove `@EnableRedisWebSession`
- Remove `springSessionDefaultRedisSerializer` bean (Jackson serializer)
- Remove `sessionLoggingFilter` bean
- Remove `webSessionIdResolver` bean
- Keep `clock` bean
- This class becomes minimal (just Clock + new Redis config)

### 1e. Update `SessionGatewayApplication.java`

- Remove Gateway-related auto-configuration exclusions if any exist
- The app currently excludes DataSource and JPA — keep those

### 1f. Create session infrastructure

**New file: `src/main/java/.../session/SessionHashFields.java`**
Constants for Redis hash field names:
```
user_id, idp_sub, email, display_name, picture,
roles, permissions, refresh_token, token_expires_at,
created_at, expires_at
```

**New file: `src/main/java/.../session/SessionData.java`**
Record holding deserialized session data (userId, idpSub, email, displayName, picture, roles, permissions, refreshToken, tokenExpiresAt, createdAt, expiresAt).

**New file: `src/main/java/.../session/SessionWriter.java`**
- `ReactiveRedisTemplate<String, String>` with `StringRedisSerializer`
- `createSession(...)` — generates UUID session ID, writes hash fields via `HMSET`, sets `EXPIRE`, returns session ID
- `updateSessionExpiry(sessionId, ttlSeconds)` — updates `expires_at` field + Redis key TTL (for heartbeat)
- `updateTokenAndExpiry(sessionId, refreshToken, tokenExpiresAt, ttlSeconds)` — updates refresh token + expiry fields + TTL (for successful refresh)
- `deleteSession(sessionId)` — deletes the key
- Configurable via `session.key-prefix` (default `session:`) and `session.ttl-seconds` (default `1800`)

**New file: `src/main/java/.../session/SessionReader.java`**
- `readSession(sessionId)` — `HGETALL`, returns `Mono<SessionData>`, checks `expires_at`
- Returns `Mono.empty()` if not found or expired

**New file: `src/main/java/.../session/SessionCookieHelper.java`**
- `setSessionCookie(exchange, sessionId)` — writes `Set-Cookie: SESSION={id}; HttpOnly; Secure; SameSite=Lax; Path=/; Domain={configured domain}`
- `clearSessionCookie(exchange)` — writes `Set-Cookie` with `Max-Age=0`
- `readSessionId(exchange)` — extracts session ID from `Cookie` header
- Domain from `session.cookie.domain-override` config (preserving Envoy workaround)

### 1g. Add new config properties to `application.yml`

```yaml
session:
  key-prefix: ${SESSION_KEY_PREFIX:session:}
  ttl-seconds: ${SESSION_TTL_SECONDS:1800}
  cookie:
    domain-override: budgetanalyzer.localhost
    name: SESSION
    secure: true
    same-site: lax
```

### 1h. Tests for Phase 1

- `SessionWriterTest.java` — integration test with TestContainers Redis: create, read, delete, expiry
- `SessionReaderTest.java` — integration test: read existing, read missing, read expired
- `SessionCookieHelperTest.java` — unit test: set, clear, read cookie
- Verify: `./gradlew clean spotlessApply && ./gradlew clean build`

---

## Phase 2: OAuth2 Login Flow

**Goal**: Reimplement the OAuth2 login flow writing to the single session hash. Login works end-to-end.

### 2a. OAuth2 authorization request storage

**New file: `src/main/java/.../security/RedisAuthorizationRequestRepository.java`**
Implements `ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>`:
- `saveAuthorizationRequest(request, exchange)` — serialize to JSON, write to `oauth2:state:{state}` Redis key with 10-min TTL. Also store `returnUrl` from query param if present.
- `loadAuthorizationRequest(exchange)` — extract `state` param from callback, read from Redis
- `removeAuthorizationRequest(exchange)` — delete the Redis key after callback
- Uses same `ReactiveRedisTemplate` as session infrastructure

### 2b. Rewrite `SecurityConfig.java`

Major rewrite. Key changes:
- `oauth2Login()` with custom `authorizationRequestRepository` (the Redis one from 2a)
- Custom `authenticationSuccessHandler` that:
  1. Extracts IDP profile from `OAuth2AuthenticationToken` (sub, name, email, picture)
  2. Extracts access token + refresh token from `OAuth2AuthorizedClient`
  3. Calls `permissionServiceClient.fetchPermissions(idpSub, email, displayName)`
  4. Calls `sessionWriter.createSession(...)` with all fields
  5. Calls `sessionCookieHelper.setSessionCookie(exchange, sessionId)`
  6. Determines redirect URL (from authorization request's `additionalParameters` or default `/`)
  7. Redirects
- Authentication entry point: API paths -> 401, browser paths -> redirect to `/oauth2/authorization/idp` (same as current)
- Remove Gateway-specific filter chains, force-session-creation filter

### 2c. Update `OAuth2ClientConfig.java`

- Keep audience customizer
- Modify returnUrl capture to store in authorization request `additionalParameters` (instead of WebSession)
- Remove logging wrapper if it depends on Gateway internals

### 2d. Add `offline_access` scope

In `application.yml`, add to OAuth2 scopes:
```yaml
scope:
  - openid
  - profile
  - email
  - offline_access
```

**Note**: Auth0 application settings may need `offline_access` allowed + refresh token rotation configured. This is an Auth0 console change — document it but don't automate it.

### 2e. Custom `ServerSecurityContextRepository`

**New file: `src/main/java/.../security/RedisSessionSecurityContextRepository.java`**
- `load(exchange)` — reads SESSION cookie via `sessionCookieHelper`, reads hash via `sessionReader`, creates a simple `Authentication` token from session data
- `save(exchange, context)` — no-op (session hash is written by success handler)
- This bridges Spring Security's expectations with our Redis-only session

### 2f. Tests for Phase 2

- Update `AbstractIntegrationTest.java` — adjust WireMock stubs for new flow
- Integration test for full OAuth2 login flow (authorize -> callback -> session hash created -> cookie set -> redirect)
- Verify login works with: `./gradlew clean build`

---

## Phase 3: Remaining Endpoints

**Goal**: Update logout, user info, and token exchange to use the single session hash.

### 3a. Rewrite `LogoutController.java`

- Read session ID from cookie (via `sessionCookieHelper`)
- Delete session hash (via `sessionWriter.deleteSession`)
- Clear session cookie (via `sessionCookieHelper.clearSessionCookie`)
- Redirect to IDP logout (same URL template logic)
- Remove: `ServerOAuth2AuthorizedClientRepository` dependency, Spring Session invalidation

### 3b. Rewrite `UserController.java`

- Read session ID from cookie
- Read session data from hash (via `sessionReader`)
- Build `UserInfoResponse` from session data fields (idpSub, displayName, email, picture, roles)
- Remove: `Authentication` parameter, `WebSession` parameter, `OAuth2AuthenticationToken` casting
- 401 if no session

### 3c. Rewrite `TokenExchangeController.java`

- Validate IDP token via userinfo (same as current)
- Fetch permissions (same as current)
- Extract IDP profile from userinfo response (sub, name, email, picture)
- Create session hash via `sessionWriter.createSession(...)` with access token expiry from userinfo or a default
- Note: token exchange doesn't get a refresh token (the caller has their own IDP token). Store null/empty for `refresh_token`.
- Return opaque session ID as bearer token (same response contract)
- Remove: `ReactiveSessionRepository` dependency, Spring Session creation

### 3d. Tests for Phase 3

- Update `LogoutControllerTest.java`
- Update `UserControllerTest.java`
- Update `TokenExchangeControllerTest.java`
- `RedirectUrlValidatorTest.java` — keep as-is (no changes to validator)
- Update `SessionGatewayApplicationTests.java` — smoke test with new config

---

## Phase 4: Heartbeat Endpoint

**Goal**: New `GET /auth/session` endpoint that validates the IDP grant and extends session TTL.

### 4a. IDP token refresh client

**New file: `src/main/java/.../service/IdpTokenRefreshClient.java`**
- Direct WebClient POST to Auth0's `/oauth/token` endpoint
- Grant type: `refresh_token`
- Sends: client_id, client_secret, refresh_token, grant_type
- Returns: new access_token, new refresh_token (if rotated), expires_in
- On 4xx: IDP revoked the grant -> return error signal
- Config: reads client-id, client-secret, token endpoint from OAuth2 client registration properties

### 4b. Heartbeat controller

**New file: `src/main/java/.../api/SessionController.java`**

`GET /auth/session`:
1. Read session ID from cookie
2. Read session hash via `sessionReader`
3. If no session: return 401
4. Check `token_expires_at` — if within refresh threshold (e.g., 10 min):
   a. Call `idpTokenRefreshClient.refresh(refreshToken)`
   b. If refresh succeeds: update hash (new refresh_token, new token_expires_at, reset expires_at + TTL)
   c. If refresh fails (401): delete session hash, clear cookie, return 401
5. If not near token expiry: just reset `expires_at` + Redis TTL (sliding window)
6. Return 200 with session metadata

**Response contract** (`SessionStatusResponse.java`):
```json
{
  "authenticated": true,
  "userId": "user123",
  "roles": ["ADMIN", "USER"],
  "expiresAt": 1711720800,
  "expiresInSeconds": 1740,
  "tokenRefreshed": false
}
```

### 4c. Add `/auth/session` to security permit rules

Since we handle auth ourselves via cookie + Redis, this endpoint should be `permitAll` at the Spring Security level and handle its own 401 logic internally.

### 4d. Configuration

```yaml
session:
  refresh-threshold-seconds: ${SESSION_REFRESH_THRESHOLD_SECONDS:600}  # 10 min
```

### 4e. Tests for Phase 4

- `SessionControllerTest.java` — valid session, expired session, near-expiry triggers refresh, refresh failure -> 401
- `IdpTokenRefreshClientTest.java` — successful refresh, failed refresh (WireMock)

### 4f. Verification

Full session lifecycle test:
1. OAuth2 login -> session hash created, cookie set
2. `GET /user` -> returns user info from hash
3. `GET /auth/session` -> 200, session extended
4. `GET /auth/session` with near-expiry token -> refresh triggered
5. `GET /logout` -> hash deleted, cookie cleared, IDP logout redirect
6. `GET /auth/session` -> 401

---

## Phase 5: Infrastructure (orchestration repo)

**Goal**: Update ext_authz config and Redis ACLs to match new key prefix.

### 5a. Redis ACL update

**File: `orchestration/kubernetes/infrastructure/redis/start-redis.sh`**

Current:
```
user session-gateway ... ~spring:session:* ~extauthz:session:* ...
user ext-authz ... ~extauthz:session:* +hgetall +ping ...
```

New:
```
user session-gateway ... ~session:* ~oauth2:state:* ...
user ext-authz ... ~session:* +hgetall +ping ...
```

- `session-gateway` gets `~session:*` (session hashes) and `~oauth2:state:*` (OAuth2 authorization requests)
- `ext-authz` gets `~session:*` (read-only, same commands)
- Remove `~spring:session:*` and `~extauthz:session:*` from both

### 5b. ext_authz deployment config

**File: `orchestration/kubernetes/services/ext-authz/deployment.yaml`**

Add env var:
```yaml
- name: SESSION_KEY_PREFIX
  value: "session:"
```

No Go code changes needed.

### 5c. Istio routing

Verify `/auth/**` is already routed to Session Gateway — it is. No changes needed for `GET /auth/session`.

### 5d. Verification

After deploying:
```bash
# Flush Redis (safe — not live)
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning FLUSHALL

# Login, then verify session hash exists under new prefix
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning KEYS "session:*"

# Verify no stale spring:session:* or extauthz:session:* keys
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning KEYS "*session*"
```

---

## Phase 6: Documentation (all repos)

**Goal**: Replace "BFF" terminology with "session-based edge authorization", remove dual-write/Spring Session references, update architecture descriptions everywhere.

### Strategy

Scan all repos for: `BFF`, `dual-write`, `dual write`, `Spring Session`, `extauthz:session:`, `spring:session:`. Update each file in context — not blind find-replace.

### 6a. Organization README

**File: `/workspace/.github/profile/README.md`**
- "Backend For Frontend Oauth2 Security" -> "session-based edge authorization with OAuth2"
- "Server-side session management (BFF pattern)" -> "Server-side session management (opaque sessions in Redis)"
- "Session Dual-Write" -> "Session Write"
- "OAuth2 BFF, session management, Redis dual-write" -> "OAuth2 authentication service, session management"
- Mermaid diagram: update "Session Dual-Write" label

### 6b. Orchestration — architecture docs

**Rename files:**
- `bff-security-benefits.md` -> `session-security-benefits.md`
- `bff-api-gateway-pattern.md` -> `session-edge-authorization-pattern.md`

**Update content in:**
- `security-architecture.md` — replace "BFF" references, remove Spring Session references, update session schema
- `system-overview.md` — update Session Gateway description
- `m2m-client-authorization.md` — update auth flow references
- `port-reference.md` — update Session Gateway description
- `deployment-architecture-gcp.md` — replace BFF references
- `deployment-architecture-gcp-demo-mode.md` — update Redis session config

**Update:**
- `orchestration/AGENTS.md` — update service descriptions, remove BFF references
- `orchestration/README.md` — update service descriptions

### 6c. Session Gateway docs

**Update:**
- `session-gateway/AGENTS.md` — major rewrite: remove BFF references, update architecture, update components, update session schema, remove dual-write references, add heartbeat endpoint, update security considerations
- `session-gateway/README.md` — update to match new architecture

### 6d. Budget Analyzer Web docs

**Update:**
- `budget-analyzer-web/docs/authentication.md` — remove "BFF", update "dual-write" to single hash, remove "Spring Session" references, update login/logout flow, add heartbeat docs
- `budget-analyzer-web/AGENTS.md` — update Session Gateway references
- `budget-analyzer-web/README.md` — update if it references BFF

### 6e. Other service docs

Scan and update references in:
- `transaction-service/AGENTS.md`, `README.md`
- `currency-service/AGENTS.md`, `README.md`
- `permission-service/AGENTS.md`, `README.md`
- `service-common/AGENTS.md`, `README.md`

### 6f. Architecture conversations

**Update visuals:**
- `architecture-conversations/visuals/request-flow-bff-gateway.md` (and v2) — rename/update
- `architecture-conversations/visuals/ecosystem-overview.md` (and v2) — update labels

**Do NOT rewrite conversation files** (001, 014, etc.) — they are historical records.

### 6g. Orchestration operational docs

Update references in:
- `docs/development/getting-started.md`
- `docs/development/local-environment.md`
- `docs/runbooks/tilt-debugging.md`
- `docs/plans/security-hardening-v2.md` — update Redis ACL references
- `SECURITY.md`

### 6h. Update conversation 001

**File: `conversations/001-extauthz-ttl-drift-and-session-architecture-rethink.md`**
- Update status from "Open discussion, no code changes made" to "Implemented" with date and link to this plan

---

## Phase 7: Frontend Heartbeat (budget-analyzer-web)

**Goal**: Add session heartbeat and inactivity warning to the React frontend.

This phase is in a separate repo and can be planned in detail there. High-level:

### 7a. Session heartbeat hook

- `useSessionHeartbeat()` — detects user activity (mouse, keyboard, click), calls `GET /auth/session` every ~5 min while active
- On 401 response: redirect to login
- On network error: retry once, then warn

### 7b. Inactivity warning

- After N minutes of no activity, show modal: "Your session will expire soon. Click Continue to stay signed in."
- "Continue" triggers immediate heartbeat
- Timeout: session expires on Redis TTL

### 7c. Wire into app

- Add heartbeat hook to app shell (runs on all authenticated pages)
- Add inactivity modal component

---

## Key Design Decisions

### Session hash schema
```
session:{uuid}
  user_id          -> "internal-user-id"
  idp_sub          -> "auth0|abc123"
  email            -> "user@example.com"
  display_name     -> "Jane Doe"
  picture          -> "https://..."
  roles            -> "ADMIN,USER"
  permissions      -> "transactions:read,transactions:write"
  refresh_token    -> "v1.MjQ3NjM4..."
  token_expires_at -> "1711720800"
  created_at       -> "1711713600"
  expires_at       -> "1711715400"
```

ext_authz reads: `user_id`, `roles`, `permissions`, `expires_at` (ignores other fields).

### ext_authz sees refresh_token in HGETALL

ext_authz uses `HGETALL` which returns all fields, including `refresh_token`. This is acceptable — the refresh token is only useful with Auth0's client secret (which ext_authz doesn't have), and both services are internal infrastructure behind network isolation. Optional future hardening: change ext_authz to `HMGET` for specific fields.

### Session lifetime mechanics

- **Heartbeat** (`GET /auth/session`): resets `expires_at` + Redis key TTL (sliding window)
- **API activity** (through ext_authz): does NOT extend session (ext_authz is read-only)
- **Session dies when**: Redis key expires (TTL) OR `expires_at` passes (checked by ext_authz)
- **Safety margin**: 5-min heartbeat interval, 30-min session TTL = 6x margin

### Token refresh trigger

- Heartbeat checks `token_expires_at`
- If within `session.refresh-threshold-seconds` (default 10 min): attempt refresh
- Refresh success: update tokens + extend session
- Refresh failure (IDP revoked): delete session -> 401 -> frontend redirects to login

### returnUrl without Spring Session

Stored in OAuth2 authorization request's `additionalParameters`, serialized to Redis with the authorization request. Survives the IDP round-trip via the `state` parameter. Retrieved in the success handler.

---

## Verification (end-to-end after all phases)

```bash
# Build
cd /workspace/session-gateway
./gradlew clean spotlessApply && ./gradlew clean build

# Deploy (from orchestration)
cd /workspace/orchestration && tilt up

# Flush Redis
REDIS_OPS_USERNAME=$(kubectl get secret redis-bootstrap-credentials -n infrastructure -o jsonpath='{.data.ops-username}' | base64 -d)
REDIS_OPS_PASSWORD=$(kubectl get secret redis-bootstrap-credentials -n infrastructure -o jsonpath='{.data.ops-password}' | base64 -d)
kubectl exec -n infrastructure deployment/redis -- redis-cli --user "$REDIS_OPS_USERNAME" --pass "$REDIS_OPS_PASSWORD" --no-auth-warning FLUSHALL

# Test login flow
# 1. Navigate to https://app.budgetanalyzer.localhost/login
# 2. Complete Auth0 login
# 3. Verify SESSION cookie in browser
# 4. Verify Redis: KEYS "session:*" shows one key
# 5. Verify Redis: HGETALL "session:{id}" shows all fields including refresh_token

# Test heartbeat
# curl -b "SESSION={id}" https://app.budgetanalyzer.localhost/auth/session
# -> 200 with session metadata

# Test API (ext_authz validation)
# curl -b "SESSION={id}" https://app.budgetanalyzer.localhost/api/transactions
# -> should succeed (ext_authz reads session:* prefix)

# Test logout
# Navigate to /logout -> clears hash, clears cookie, redirects to Auth0 logout

# Test no stale keys
# KEYS "*" should show no spring:session:* or extauthz:session:* keys
```

---

## Implementation Order

| Phase | Scope | Repo |
|-------|-------|------|
| 1 | Strip + session core | session-gateway |
| 2 | OAuth2 login flow | session-gateway |
| 3 | Logout + User + TokenExchange | session-gateway |
| 4 | Heartbeat endpoint | session-gateway |
| 5 | Redis ACLs + ext_authz config | orchestration |
| 6 | Documentation (all repos) | all |
| 7 | Frontend heartbeat | budget-analyzer-web |

Phases 1-4 are sequential (each builds on the previous). Phase 5 can be done in parallel with 3-4. Phase 6 can start after Phase 4. Phase 7 is independent and can be deferred.
