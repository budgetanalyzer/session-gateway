# 001 - ext_authz TTL Drift and Session Architecture Rethink

**Date:** 2026-03-29
**Status:** Open discussion, no code changes made
**Scope:** Session Gateway architecture, ext_authz session TTL drift, token refresh, BFF justification

---

## Context

Started from reviewing `docs/bug-extauthz-session-ttl-drift.md` and escalated to questioning the overall Session Gateway architecture.

## Key Files Examined

- `src/main/java/.../session/ExtAuthzSessionWriter.java` — dual-writes `extauthz:session:{id}` with fixed 1800s TTL
- `src/main/java/.../config/SessionConfig.java` — `@EnableRedisWebSession(maxInactiveIntervalInSeconds = 1800)` (sliding)
- `src/main/java/.../filter/TokenRefreshGatewayFilterFactory.java` — dead code, not applied to any route
- `src/main/resources/application.yml` — gateway routes, comment confirms TokenRefresh not compatible with Gateway Server
- `orchestration/ext-authz/session.go` — Go ext_authz reads `extauthz:session:{id}`, checks `expires_at` field + Redis TTL
- `orchestration/ext-authz/http_server.go` — read-only session lookup, header injection
- `orchestration/docs/architecture/security-architecture.md` — full architecture doc
- `orchestration/docs/architecture/bff-security-benefits.md` — BFF justification doc

---

## Problem 1: ext_authz TTL Drift (the bug doc)

Two independent TTL mechanisms manage one logical session:
- **Spring Session**: sliding-window TTL (resets on every `WebSession` access)
- **ext_authz key**: fixed TTL from write time

Any request through Session Gateway resets the Spring Session TTL. Nothing resets the ext_authz TTL except token refresh (which is dead code). If the IDP token lifetime exceeds 30 minutes, the ext_authz key dies first.

Additional detail: `session.go:112-119` checks `expires_at` as an application-level field *in addition* to Redis TTL. So any fix that bumps the Redis key TTL also needs to update the `expires_at` hash field.

### Options Analyzed for TTL Drift

**Option A: Sliding TTL in ext_authz (Go service)**
- ext_authz bumps TTL + `expires_at` on every successful `HGETALL`
- Pros: ext_authz sees every API request; `EXPIRE` + `HSET` is O(1)
- Cons: turns ext_authz from read-only to reader+writer; requires changes to orchestration repo
- Verdict: solid for active-use case

**Option B: Refresh ext_authz TTL from Session Gateway**
- Add a filter that bumps ext_authz TTL whenever a request passes through Session Gateway
- Pros: addresses the exact drift cause (Spring Session resets, ext_authz doesn't); keeps all write logic in one service
- Cons: same write amplification as A; only covers Session Gateway request path
- Verdict: most targeted fix for the drift bug specifically

**Option C: Derive ext_authz TTL from access token expiry**
- Set ext_authz key TTL to `token.expiresAt - now` instead of fixed 1800s
- Cons: doesn't fix the problem, just shifts the window; couples session lifetime to IDP config; if token is long-lived, ext_authz outlives Spring Session (security issue in reverse direction)
- Verdict: weak, papers over the symptom

**Option D: ext_authz checks Spring Session existence**
- Remove `expires_at` check, have ext_authz also check `spring:session:sessions:{id}` exists
- Cons: couples ext_authz to Spring Session key schema; adds second Redis read; orphaned keys
- Verdict: fragile, wouldn't do this

**Option E: Session-destroy listener + longer ext_authz TTL**
- Set ext_authz TTL longer (2x), add `SessionDestroyedEvent` listener to clean up
- Cons: ext_authz outlives session (security concern); Spring WebFlux session destroy events are unreliable (depends on Redis keyspace notifications)
- Verdict: appealing in theory, fragile in practice

**Option F: Combine A + B**
- Covers both request paths
- Cons: two places managing same TTL; probably overkill

Initial recommendation was **Option B** as cleanest fix for the specific bug.

---

## Problem 2: Token Refresh is Dead Code

`TokenRefreshGatewayFilterFactory` is a `@Component` extending `AbstractGatewayFilterFactory` but is **not configured on any route** in `application.yml`. Comment at line 84-86 confirms:

```yaml
# TokenRelay and TokenRefresh filters are not compatible with Spring Cloud Gateway Server
```

The security architecture doc (`security-architecture.md:286-298`) describes a token refresh flow that never happens. `bff-security-benefits.md` lists "Automatic Token Refresh Without Browser Involvement" as a primary benefit. That benefit doesn't exist.

---

## Problem 3: Active Users Get Hard-Logged-Out at 30 Minutes

In the Istio deployment, the post-login flow is:

```
API use: Browser -> Istio -> ext_authz (Redis) -> NGINX -> backend
```

**Nothing touches Session Gateway after login.** So:
- Token refresh never fires (dead code + nothing triggers it)
- Spring Session TTL never resets (no requests hit Session Gateway)
- ext_authz TTL never resets (fixed from creation)

An active user gets hard-logged-out after 30 minutes regardless of activity. The TTL drift in the bug doc is a sub-case that only manifests if something (like `/user` polling) keeps the Spring Session alive.

---

## Problem 4: Session Lifetime Decoupled from Token Lifetime

Because the Auth0 access token is never used for API authorization (ext_authz reads from Redis, backends read from headers), the token lifetime is irrelevant. This means:

- **Session can outlive the token**: Auth0 could revoke the user and the Redis session keeps working
- **Token can outlive the session**: Refresh token (8h-30d) sits in Redis unused

The session lifetime is governed entirely by Redis key TTL, not token lifetime. This is architecturally wrong — the IDP grant should be the source of truth for "is this user still authorized."

---

## Problem 5: Root Cause — Two Sessions for One Logical Session

The dual-write exists because the Go ext_authz service can't deserialize Spring Session's `GenericJackson2JsonRedisSerializer` output (Jackson type info wrapping).

### Could we embed ext_authz fields in the Spring Session hash?

Spring Session stores: `spring:session:sessions:{id}` with Jackson-serialized fields. We could write additional plain-string fields into the same hash:

```
extauthz:user_id      -> "user123"        (raw string)
extauthz:roles        -> "admin,user"     (raw string)
extauthz:permissions  -> "read,write"     (raw string)
```

Go service reads from `spring:session:sessions:{id}`, only looks at `extauthz:*` fields. Spring Session's sliding TTL manages the key's lifetime. One key, one TTL, no drift.

This works because Spring Session's `ReactiveRedisSessionRepository` does `HMSET` for its own fields and `EXPIRE` for TTL — it doesn't delete unknown fields.

**But the broader problem remains:** API activity doesn't touch Session Gateway, so Spring Session's sliding TTL never resets either. The unified key still expires after 30 minutes of pure API use.

---

## The Big Question: What Is Session Gateway Actually Achieving?

In the Istio production deployment, Session Gateway does exactly five things:

1. **OAuth2 flow** — authorization code + PKCE with Auth0
2. **Permission fetch** — calls permission-service on login
3. **Session creation** — writes Redis hash + sets cookie
4. **Logout** — clears Redis, redirects to Auth0 logout
5. **Token exchange** — `POST /auth/token/exchange` for native/M2M clients

Things it does on paper but not in practice:
- Token refresh (dead code)
- API routing (Istio does this)
- Frontend routing (Istio does this)
- Session sliding (nothing touches it mid-session)

**The BFF pattern is defensible** (token protection, instant revocation, IDP abstraction). **The implementation carries way more complexity than the pattern requires.**

---

## Proposed Direction: Strip Session Gateway Down

The minimum viable BFF:

1. A plain Spring Boot WebFlux app (not Gateway — no routing needed)
2. A few endpoints: OAuth2 callback, logout, user info, token exchange
3. On login success: call permission-service, write **one** Redis hash (the ext_authz hash), set cookie
4. On logout: delete hash, redirect to Auth0 logout
5. ext_authz bumps `EXPIRE` on every successful read (sliding window from API activity)
6. **No Spring Session at all** — just raw `ReactiveRedisTemplate` ops

This eliminates:
- Dual-session / TTL drift problem (one hash, one TTL)
- Spring Session's Jackson serialization complexity
- Dead gateway routes and filter factories
- Spring Cloud Gateway dependency entirely
- Dead token refresh filter
- Spring Session <-> ext_authz coupling

For token-expiry-driven sessions: store `expires_at` in the hash and have Go check it, or set Redis TTL to `min(slidingWindow, tokenExpiresAt - now)` when writing.

---

## Decisions Needed

1. **Do we commit to the simplified architecture?** Drop Spring Session + Spring Cloud Gateway, use raw Redis ops + plain WebFlux.
2. **Should ext_authz bump TTL on read?** One `EXPIRE` per authenticated API request (O(1), sub-ms). This is the mechanism that makes sliding windows work when Session Gateway is out of the hot path.
3. **Should session lifetime be coupled to token lifetime?** Store `expires_at` from the access token, enforce in ext_authz, or just use a fixed sliding window?
4. **What to do with token refresh?** If we keep Auth0 tokens, do we need refresh at all? The token is only used at login time. If we want ongoing validation that the Auth0 grant is still good, we'd need to periodically check (but that's a different mechanism than token refresh).

---

---

## Session 2: Token Refresh, BFF Identity Crisis, and Session Heartbeat

**Date:** 2026-03-29
**Status:** Design converged, no code changes made

### Starting Question

If we drop the gateway and use the MVP BFF, how does token refresh work?

### The Trigger Problem

Token refresh needs a trigger — something that says "check this token and refresh if near expiry." In a textbook BFF, the trigger is the proxy path: every API call flows through the BFF, which checks the token before forwarding.

In this architecture, the post-login hot path is:

```
Browser → Istio → ext_authz (Redis) → NGINX → Backend
```

Session Gateway is never in the loop after login. There's no request to hang a refresh check on.

### How Token Refresh Normally Works (SPA + JWT baseline)

Standard SPA pattern without BFF:

```
1. Login: Browser → IDP → gets access_token (short, 15-60 min) + refresh_token
2. API call: Browser → API server → validates JWT signature + exp claim
3. Token near expiry: Browser JS detects exp approaching
4. Refresh: Browser → IDP token endpoint → new access_token
5. Continue: Browser uses new access_token for API calls
```

Key mechanics:
- Access tokens are short-lived (15 min to 1 hour), self-validating (signature + claims)
- Refresh tokens are long-lived (hours to days), opaque, only sent to IDP
- **The browser drives refresh** — SPA HTTP client watches for 401s or proactively checks `exp`
- Revocation propagates at token expiry — revoked user's existing tokens work until they expire, next refresh fails

Revocation latency = access token lifetime. That's the fundamental tradeoff.

**Why BFF breaks this**: BFF took token management away from the browser (for good security reasons), but that also removed the natural refresh trigger. The browser can't read `exp` (no token), can't call the IDP token endpoint (no refresh token).

### "Is This Still a BFF?"

Short answer: no. The architecture broke BFF intentionally.

**A BFF does three things:**
1. Holds credentials on behalf of the browser (token storage)
2. Mediates between browser and backend (proxies API calls)
3. Manages credential lifecycle (refresh, revocation, logout)

Session Gateway does #1 and #3 (at login/logout), but not #2. ext_authz is not a BFF — it's a policy enforcement point (reads Redis hash, injects headers). Nothing in the architecture does #2.

**This is a session-based edge authorization architecture**, not BFF:
- **Session Gateway**: Authentication service. Handles OAuth2 flows, creates sessions, manages logout. Touched at login and logout.
- **ext_authz**: Session enforcement at the edge. Validates sessions, injects claims headers. Touched on every API call.
- **Redis**: Session store. Single source of truth for session state.

This split is architecturally sound: backends don't consume JWTs (they consume `X-User-Id`/`X-Roles`/`X-Permissions` headers from ext_authz), so there's nothing for a hot-path proxy to attach. Putting Session Gateway in every API call would add latency, a scaling bottleneck, and it would just read the same Redis hash that ext_authz reads.

**The architecture is clean. The label "BFF" is what's wrong.** Calling it BFF sets expectations (hot-path proxy, token relay, token refresh) that don't match the design and shouldn't.

### Refresh Tokens Are Not Tied to JWTs

Concepts that are often conflated but are orthogonal:

- **Token format** (JWT vs opaque): how the token is structured
- **Token type** (access, refresh, ID): what the token is for
- **Grant type** (authorization code, client credentials, refresh): how you obtain tokens

Refresh tokens work with any access token format. Auth0 issues them when you request `offline_access` scope. Current config only requests `openid, profile, email` — no refresh tokens are being issued.

**The key insight**: refresh tokens aren't just for getting fresh access tokens. **A refresh grant failing is how you learn the IDP revoked the user.** The refresh token is a liveness check on the IDP grant. That's why it matters even though we never use the access token for API authorization.

### Single Redis Hash Includes the Refresh Token

In the simplified architecture (one Redis hash, no Spring Session), the refresh token goes in the same session hash:

```
session:{id}
  user_id          → "user123"
  roles            → "admin,user"
  permissions      → "read,write"
  refresh_token    → "v1.MjQ3NjM4..."
  token_expires_at → "1711720800"
  created_at       → "1711713600"
```

- Browser holds `{id}` as an opaque cookie (same as any session cookie system)
- ext_authz reads the hash but only uses `user_id`, `roles`, `permissions`, expiry fields — ignores `refresh_token`
- Session Gateway reads `refresh_token` when it needs to validate the IDP grant
- The refresh token is just another field in a server-side session store, visible only to Session Gateway

### Session Heartbeat: The Trigger Mechanism

**Requirement**: Session cannot outlive IDP revocation. This is a portfolio piece demonstrating security architecture, not an MVP cutting corners.

**Solution**: Frontend session heartbeat — the same pattern used by banking apps.

SPAs broke the natural session-activity signal. In server-rendered apps, every user action is an HTTP request through the session layer. In an SPA with edge auth, the user can be active for 30 minutes with every request bypassing Session Gateway entirely. The heartbeat restores that signal.

**Two frontend timers:**

1. **Session keep-alive**: While the user is active (mouse, clicks, keystrokes), periodically call `GET /auth/session` (every ~5 min, only during activity). This is the refresh trigger.
2. **Inactivity warning**: If no user activity for N minutes, show "Your session will expire" modal. Click "Continue" fires the keep-alive. Ignore it and the session dies on Redis TTL.

**Flow:**

```
User active in SPA
  → Frontend detects activity (mouse, clicks, keyboard)
  → Every ~5 min: GET /auth/session → Istio → Session Gateway
  → Session Gateway:
      1. Read session:{id} from Redis
      2. Check refresh_token against Auth0 (if near token_expires_at)
      3. If refresh succeeds → update token_expires_at, reset TTL
      4. If refresh fails → delete session → return 401
      5. Return 200 with session metadata (time remaining, etc.)
  → Frontend receives response
      - 200: session alive, reset inactivity timer
      - 401: IDP revoked, redirect to login

User inactive
  → Frontend shows "session expiring" modal
  → User clicks "Continue" → fires GET /auth/session (same flow)
  → User ignores → session dies on Redis TTL
```

**Properties:**
- IDP grant validation on a regular cadence (every 5-10 min, or at token expiry boundary)
- Sliding session window driven by actual user activity
- Revocation propagation bounded by heartbeat interval
- Clean logout UX with inactivity warning
- Session Gateway stays out of the API hot path — handles login, logout, and session heartbeat only

### Revised Architecture Summary

```
Session Gateway responsibilities (3 endpoints, all session lifecycle):
  1. Login:     OAuth2 flow → create session:{id} hash → set cookie
  2. Logout:    Delete session:{id} → redirect to Auth0 logout
  3. Heartbeat: Validate IDP grant → refresh token → update session TTL

ext_authz responsibilities (every API request):
  1. Read session:{id} from Redis
  2. Validate not expired
  3. Inject X-User-Id, X-Roles, X-Permissions headers
  4. Bump TTL (sliding window from API activity)

Frontend responsibilities:
  1. Activity detection → periodic heartbeat to Session Gateway
  2. Inactivity warning → "session expiring" modal
  3. 401 handling → redirect to login
```

### Decisions Made

1. **Drop BFF label.** This is a session-based edge authorization architecture. The label was causing confusion and setting wrong expectations.
2. **Single Redis hash.** One `session:{id}` key with all fields (user_id, roles, permissions, refresh_token, expiry). No Spring Session, no dual-write, no TTL drift.
3. **Add `offline_access` scope.** Auth0 issues refresh tokens. Stored in the session hash, used by Session Gateway for IDP grant validation.
4. **Frontend heartbeat triggers refresh.** `GET /auth/session` endpoint on Session Gateway. Called every ~5 min during user activity. Validates IDP grant, refreshes token, updates session TTL.
5. **ext_authz bumps TTL on read.** Sliding window from API activity. Independent of heartbeat (both contribute to session liveness).

### Open Items for Implementation

- Define exact `GET /auth/session` response contract (what metadata does the frontend need?)
- Decide heartbeat interval vs access token lifetime tradeoff
- Define ext_authz TTL bump ceiling (should it cap at `token_expires_at`?)
- Determine if ext_authz should signal "near expiry" via response header (optimization — frontend could trigger early heartbeat)
- Update architecture docs: replace "BFF" terminology with "session-based edge authorization"
- Plan implementation order: ext_authz TTL bump → single Redis hash → heartbeat endpoint → frontend timers

### No Code Changes Made

This was a design discussion session. No files were modified.
