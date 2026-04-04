# Plan: Refresh Token Removal and TokenExchangeController Deletion

Date: 2026-04-04

Status: Not started

Related documents:

- [`local-session-revocation-and-refresh-token-removal.md`](local-session-revocation-and-refresh-token-removal.md)

## Context

The parent plan (`local-session-revocation-and-refresh-token-removal.md`) combines session
revocation with refresh token removal. The session-revocation flow is being planned separately.
This plan extracts the refresh token and token exchange removal work into a focused, independently
trackable unit.

This covers Phases 3, 4, and 5 of the parent plan plus the relevant parts of Phase 6.

### Dependency

Phase 2 (heartbeat simplification) and Phase 3 (refresh token acquisition removal) require local
session revocation to exist first. Without it, removing Auth0 refresh-based heartbeat validation
loses the only mechanism for terminating active sessions. Phase 1 (TokenExchangeController removal)
has no such dependency and can proceed immediately.

---

## Phase 1: Remove TokenExchangeController

No dependencies. This is dead code removal — the endpoint creates Redis-backed bearer sessions
that no client uses.

### Files to delete

| File | What it is |
|------|------------|
| `src/main/java/org/budgetanalyzer/sessiongateway/api/TokenExchangeController.java` | Controller: `POST /auth/token/exchange` |
| `src/main/java/org/budgetanalyzer/sessiongateway/api/request/TokenExchangeRequest.java` | Request DTO |
| `src/main/java/org/budgetanalyzer/sessiongateway/api/response/TokenExchangeResponse.java` | Response DTO |
| `src/test/java/org/budgetanalyzer/sessiongateway/api/TokenExchangeControllerTest.java` | 9 test cases |

### Files to edit

| File | Change |
|------|--------|
| `SecurityConfig.java:90` | Remove `"/auth/token/exchange"` from the `.permitAll()` path matchers list |

### Documentation

- Remove token exchange references from `docs/auth0-settings.md` and `README.md` if present
- Update any doc that presents Session Gateway as handling non-browser token flows

---

## Phase 2: Remove Refresh Token from Heartbeat

**Depends on:** local session revocation existing (Phase 2 of parent plan).

This simplifies `GET /auth/session` so browser-session validity depends only on local Redis session
state. No more Auth0 calls during heartbeat.

### Files to delete

| File | What it is |
|------|------------|
| `src/main/java/org/budgetanalyzer/sessiongateway/service/IdpTokenRefreshClient.java` | Refresh-token grant client (193 lines) |
| `src/test/java/org/budgetanalyzer/sessiongateway/service/IdpTokenRefreshClientTest.java` | 4 test cases |

### Files to edit

**`SessionController.java`** — the bulk of the change:
- Remove `idpTokenRefreshClient` field and constructor parameter (~line 49, 72)
- Remove `refreshThresholdSeconds` field and constructor injection (~line 51, 76)
- Simplify `processHeartbeat` (lines 123-144): remove token-expiry check, remove `needsRefresh`
  branch — always call `extendSession`
- Delete `refreshAndExtend` method entirely (lines 146-200)
- Remove `tokenRefreshed` parameter from `buildResponse` (lines 218-227)

**`SessionStatusResponse.java`** — remove `tokenRefreshed` field (line 25) and its `@param` doc
(line 14). The record becomes:
```java
public record SessionStatusResponse(
    boolean active,
    String userId,
    List<String> roles,
    long expiresAt) {}
```

**`SessionProperties.java`** — remove `refreshThresholdSeconds` field (line 18) and its validation
(lines 29-35).

**`application.yml:69`** — remove `refresh-threshold-seconds` line.

**`src/test/resources/application.yml:29`** — remove test `refresh-threshold-seconds` line.

**`SessionPropertiesTest.java`** — remove `refreshThresholdSeconds` validation tests (~lines 43,
77-82). Update the happy-path construction to not pass the removed field.

### Test changes

- Remove or update any test that asserts `tokenRefreshed` in heartbeat response
- Remove tests that verify Auth0 refresh calls during heartbeat
- Add test: active browser session with valid Redis TTL returns 200 regardless of token expiry
- Add test: Auth0 outage does not affect heartbeat response

---

## Phase 3: Remove Refresh Token Acquisition and Storage

**Depends on:** Phase 2 of this plan (heartbeat no longer reads refresh token fields).

### Files to edit

**`application.yml:57`** — remove `offline_access` from OAuth2 scope list.

**`src/test/resources/application.yml:19`** — remove `offline_access` from test scope list.

**`SessionHashFields.java`** — delete `REFRESH_TOKEN` constant (line 28) and `TOKEN_EXPIRES_AT`
constant (line 31).

**`SessionWriter.java`**:
- `createSession` method (line 71-109): remove `refreshToken` and `tokenExpiresAt` parameters.
  Remove the two `Map.entry` calls for those fields (lines 95, 97-98).
- Delete `updateTokenAndExpiry` method entirely (lines ~150-165) — no longer called by anything
  after Phase 2.

**`SessionReader.java`**:
- Remove reading of `refresh_token` field (line 63) and `token_expires_at` field (line 76).
- Update `SessionData` record to remove `refreshToken` and `tokenExpiresAt` fields.

**`SecurityConfig.java`**:
- `handleAuthenticationSuccess` (lines 160-174): remove `refreshTokenValue(authorizedClient)` and
  `tokenExpiresAt(authorizedClient)` arguments from `createSession` call.
- Delete `refreshTokenValue` helper method (lines 209-216).
- Delete `tokenExpiresAt` helper method (lines 218-225).

**`BrowserErrorRedirectIntegrationTest.java`** — update if it references refresh token behavior
(~line 160-170).

---

## Phase 4: Documentation

Update in the same implementation work, not after.

| File | Change |
|------|--------|
| `README.md` | Remove claims about refresh-token heartbeat validation |
| `AGENTS.md` | Reflect browser-only contract |
| `docs/session-configuration.md` | Remove `SESSION_REFRESH_THRESHOLD_SECONDS` |
| `docs/auth0-settings.md` | Remove browser refresh-token requirements; Auth0 is login-time only |
| Parent plan | Mark Phases 3, 4, 5 as extracted to this plan |

---

## Verification

```bash
./gradlew clean build
```

- `POST /auth/token/exchange` returns 404
- Browser login succeeds without `offline_access` scope
- Browser heartbeat returns 200 for valid Redis session regardless of token expiry
- Browser heartbeat does not make any Auth0 calls
- No code references `refresh_token`, `token_expires_at`, `refreshThreshold`, or
  `TokenExchangeController`
- `grep -r "offline_access" src/` returns nothing
