# Session-Gateway: User Session Revocation

Status: Steps 1-9 implemented on 2026-04-04.

Follow-up: `docs/plans/fix-targeted-session-revocation-races.md` supersedes the earlier
non-atomic revocation design and the "refresh TTL only" heartbeat design in this document.

## Context

Permission-service needs to deactivate users and immediately kill all their active browser sessions.
Today, session-gateway has no way to find "all sessions for user X" — each session is an independent
`session:{uuid}` hash in Redis, discoverable only by cookie. The cross-service plan
(`architecture-conversations/docs/plans/cross-service-user-revocation.md`) assigns session-gateway
two responsibilities:

1. Maintain a **user-session index** in Redis so all sessions for a user can be located without
   scanning `session:*` keys.
2. Expose **`DELETE /internal/v1/sessions/users/{userId}`** so permission-service can revoke all
   sessions during user deactivation.

---

## Design Decisions

### deleteSession and SREM
**Read userId from hash before deleting, then SREM.** This avoids changing the `deleteSession`
signature (which would ripple into `LogoutController`). A single `HGET user_id` costs one extra
Redis round-trip on a logout path that already does DEL + cookie clear + IDP redirect. If the hash
is already expired, HGET returns nil and we skip the SREM — stale set entries are harmless by
design.

### User session index key prefix
**Hardcoded constant** `USER_SESSIONS_KEY_PREFIX = "user_sessions:"` in `SessionHashFields`. The
primary key prefix is configurable for test isolation, but the index key is a cross-service contract
with permission-service. Making it configurable creates a coordination problem for no benefit. Tests
isolate via unique userIds and `@BeforeEach` Redis cleanup.

### Internal endpoint security
**Permit only the exact path `/internal/v1/sessions/users/*`** in `SecurityConfig`, not a blanket
`/internal/v1/**`. This ensures each future internal route requires an explicit security config
change — no route becomes mesh-trusted by accident. Network-level controls (Calico policy) restrict
who can reach session-gateway in production, but the app-level exception should be equally narrow.

### Controller placement
**New class `InternalSessionController`** in the `api` package. Every existing controller is
browser-facing (cookies, redirects). The internal endpoint is service-to-service (no cookies, JSON,
different error semantics). Separate class makes the security boundary visible in code structure.

### Response format
**204 No Content in all cases** (sessions existed, no sessions, stale entries). DELETE is idempotent
— "ensure no sessions exist for this user" is satisfied whether we deleted 5 or 0. No response body.
Bodyless responses avoid turning the endpoint into a user-existence oracle.

### Audit logging
**Log every revocation request at INFO level** in `InternalSessionController`, including `userId`
and the count of sessions deleted. This is a security-relevant operation initiated by another
service — it must be auditable. Log before the Redis work begins (request received) and after
(outcome), so partial failures are visible.

### User-session index maintenance on heartbeat
**Superseded on 2026-04-04 by
`docs/plans/fix-targeted-session-revocation-races.md`.** Refreshing only the set TTL is not
enough. If the `user_sessions:{userId}` entry is missing, heartbeat and token refresh must also
`SADD` the current session ID back into the set while they refresh TTLs. Otherwise a live session
can remain invisible to targeted revocation indefinitely.

Both call sites already have the userId:
- `SessionController.extendSession()` (line 202) has `sessionData.userId()`
- `SessionController.refreshAndExtend()` (line 146) has `sessionData.userId()`

The Lua script (`CONDITIONAL_UPDATE_SCRIPT`) uses `KEYS[2]` for the user sessions set and, when
`KEYS[1]` exists, both re-indexes the current session with `SADD` and refreshes the TTL on both
keys. The same change applies to `updateTokenAndExpiry`, which uses the same script.

### Lua scripts as external files
**Move Lua scripts from inline Java strings to `.lua` files in `src/main/resources/redis/`.** The
existing `CONDITIONAL_UPDATE_SCRIPT` is already being modified for the index TTL work, so this is
the natural time to extract it. Benefits: IDE syntax highlighting and linting for Lua, scripts
readable on their own, no change to runtime behavior (Spring caches the SHA1 and uses `EVALSHA`
after the first call).

### Atomicity of deleteAllSessionsForUser
**Superseded on 2026-04-04 by
`docs/plans/fix-targeted-session-revocation-races.md`.** The earlier `SMEMBERS -> batch UNLINK`
design is incorrect because a concurrent session create can survive revocation and lose its index
entry. `deleteAllSessionsForUser(...)` now needs a Redis Lua script that reads the indexed session
IDs, derives the `session:{id}` keys inside the script, and deletes those hashes plus the
`user_sessions:{userId}` key in one execution.

---

## Implementation Steps

### Step 1: Extract Lua script to external file and extend it for index repair

**File:** `src/main/resources/redis/conditional-update.lua` **(new)**

Extract the existing `CONDITIONAL_UPDATE_SCRIPT` from `SessionWriter.java` and extend it so the
heartbeat/token-refresh update path re-adds the active session ID into the user index while it
refreshes both TTLs:

```lua
-- Conditionally updates hash fields and TTL only if the key exists.
-- KEYS[1]: session hash key
-- KEYS[2]: user sessions index key
-- ARGV[1]: session ID
-- ARGV[2..N-1]: field/value pairs to HSET
-- ARGV[N]: TTL in seconds (always the last argument)
-- Returns 1 if updated, 0 if session does not exist.
if redis.call('exists', KEYS[1]) == 1 then
  for i = 2, #ARGV - 1, 2 do
    redis.call('hset', KEYS[1], ARGV[i], ARGV[i + 1])
  end
  local ttl = tonumber(ARGV[#ARGV])
  redis.call('expire', KEYS[1], ttl)
  redis.call('sadd', KEYS[2], ARGV[1])
  redis.call('expire', KEYS[2], ttl)
  return 1
end
return 0
```

**File:** `src/main/java/.../session/SessionWriter.java`

Replace the inline `RedisScript.of(""" ... """, Long.class)` with:

```java
private static final RedisScript<Long> CONDITIONAL_UPDATE_SCRIPT =
    RedisScript.of(new ClassPathResource("redis/conditional-update.lua"), Long.class);
```

### Step 2: Add user-session index key prefix constant

**File:** `src/main/java/.../session/SessionHashFields.java`

Add:
```java
/** Key prefix for the per-user session index SET. */
public static final String USER_SESSIONS_KEY_PREFIX = "user_sessions:";
```

### Step 3: Make `SessionWriter.createSession()` atomic

**Files:**
- `src/main/resources/redis/create-session.lua` **(new)**
- `src/main/java/.../session/SessionWriter.java`

Replace the multi-command Java write path with one Redis script execution that performs:
- `HSET session:{id} ...fields`
- `EXPIRE session:{id} ttlSeconds`
- `SADD user_sessions:{userId} sessionId`
- `EXPIRE user_sessions:{userId} ttlSeconds` (refresh TTL on every session creation)

This removes the race where revocation can snapshot the user index before a new session is added to
it.

### Step 4: Update `updateSessionExpiry` and `updateTokenAndExpiry` signatures

**File:** `src/main/java/.../session/SessionWriter.java`

Add `userId` to both methods so they can pass the user index key, and pass `sessionId` into the Lua
script so the update path can repair missing membership:

- `updateSessionExpiry(String sessionId, String userId, long ttlSeconds)`
- `updateTokenAndExpiry(String sessionId, String userId, String refreshToken, Instant tokenExpiresAt, long ttlSeconds)`

Both pass `List.of(sessionKey, userSessionsKey)` as KEYS to the script. The Lua script (updated in
Step 1) both re-adds `sessionId` to `KEYS[2]` and refreshes TTL on both keys in the same
conditional execution.

**File:** `src/main/java/.../api/SessionController.java`

Update call sites (both already have `sessionData`):
- `extendSession()` (line 204): pass `sessionData.userId()`
- `refreshAndExtend()` (line 162): pass `sessionData.userId()`

### Step 5: Modify `SessionWriter.deleteSession()` to clean up the index

**File:** `src/main/java/.../session/SessionWriter.java` (lines 174–179)

Change from a bare `DEL` to:
1. `HGET session:{id} user_id` — get the userId before deleting
2. `UNLINK session:{id}` — delete the session hash
3. If userId was found: `SREM user_sessions:{userId} sessionId`

If the hash is already gone (expired), `HGET` returns empty → skip SREM → return false. Signature
and return type unchanged: `Mono<Boolean> deleteSession(String sessionId)`.

### Step 6: Add `deleteAllSessionsForUser()` to `SessionWriter`

**File:** `src/main/java/.../session/SessionWriter.java`

New method:
```java
public Mono<Long> deleteAllSessionsForUser(String userId)
```

Logic:
1. Execute `delete-user-sessions.lua` with `KEYS[1]=user_sessions:{userId}`
2. Inside the script, `SMEMBERS` the indexed session IDs
3. Derive each `session:{id}` key inside Lua and `DEL` those hashes plus the index key itself in
   one execution
4. Return the deleted key count for logging and tests

If the set does not exist, the script deletes nothing and returns `0`.

### Step 7: Create `InternalSessionController`

**File:** `src/main/java/.../api/InternalSessionController.java` **(new)**

```java
@RestController
@RequestMapping("/internal/v1")
public class InternalSessionController {

    private static final Logger log = LoggerFactory.getLogger(InternalSessionController.class);

    private final SessionWriter sessionWriter;

    public InternalSessionController(SessionWriter sessionWriter) { ... }

    @DeleteMapping("/sessions/users/{userId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> deleteUserSessions(@PathVariable String userId) {
        log.info("Session revocation requested for userId={}", userId);
        return sessionWriter.deleteAllSessionsForUser(userId)
            .doOnSuccess(count ->
                log.info("Session revocation completed for userId={}, deletedKeys={}", userId, count))
            .then();
    }
}
```

### Step 8: Update `SecurityConfig` to permit the revocation endpoint

**File:** `src/main/java/.../config/SecurityConfig.java` (line ~87)

Add only the specific revocation path to the `permitAll` block — not a blanket `/internal/v1/**`:

```java
.pathMatchers("/internal/v1/sessions/users/*").permitAll()
```

Each future internal route must be explicitly permitted. This keeps the app-level exception as
narrow as the network-level Calico policy.

### Step 9: Tests

**File:** `src/test/.../session/SessionWriterIntegrationTest.java` — add to existing class:

| Test | What it verifies |
|------|-----------------|
| `createSession_addsToUserSessionIndex` | SMEMBERS contains returned sessionId; set has TTL |
| `createSession_multipleSessionsSameUser_allInIndex` | 3 sessions → 3 entries in set |
| `updateSessionExpiry_refreshesUserSessionIndexTtl` | After heartbeat, set TTL is refreshed to ttlSeconds |
| `updateSessionExpiry_reindexesSessionWhenUserIndexEntryIsMissing` | Heartbeat repair path re-adds the missing session ID before refreshing TTL |
| `updateTokenAndExpiry_refreshesUserSessionIndexTtl` | After token refresh, set TTL is refreshed |
| `updateTokenAndExpiry_reindexesSessionWhenUserIndexEntryIsMissing` | Token refresh repair path re-adds the missing session ID before refreshing TTL |
| `deleteSession_removesFromUserSessionIndex` | After deleting s1, set contains only s2 |
| `deleteSession_sessionAlreadyExpired_skipsIndexCleanup` | Returns false; stale set entry remains (harmless) |
| `deleteAllSessionsForUser_deletesAllSessionsAndIndex` | All hashes gone, set key gone |
| `deleteAllSessionsForUser_staleEntryInIndex_succeeds` | One expired hash, one live → no error, live hash deleted |
| `deleteAllSessionsForUser_noSessions_succeeds` | Returns 0, no error |
| `deleteAllSessionsForUser_raceWithCreateSession_neverLeavesSurvivingSessionUnindexed` | Concurrent create + revoke never leaves a surviving hash without matching set membership |

**File:** `src/test/.../api/InternalSessionControllerIntegrationTest.java` **(new)** — extends `AbstractIntegrationTest`:

| Test | What it verifies |
|------|-----------------|
| `deleteUserSessions_revokesAllActiveSessions` | 3 sessions → DELETE returns 204, all hashes + set gone |
| `deleteUserSessions_noSessions_returns204` | Idempotent: 204 even with no sessions |
| `deleteUserSessions_withStaleExpiredSession_returns204` | Mixed live/expired → 204, live hash deleted |
| `deleteUserSessions_heartbeatRaceDoesNotRecreateSession` | After revocation, `updateSessionExpiry` is a no-op (Lua conditional check) |
| `getSessionStatus_reindexesSessionSoInternalRevocationCanDeleteIt` | Heartbeat repairs a missing index entry and the internal DELETE endpoint then removes the session |
| `deleteUserSessions_endpointAccessibleWithoutAuth` | No cookie/token → 204, not 401 |

Update `deleteTestKeys()` in `SessionWriterIntegrationTest` to also clean up `user_sessions:*` keys.

---

## Files Changed

| File | Change |
|------|--------|
| `src/main/resources/redis/conditional-update.lua` | **New file** — extracted + extended Lua script |
| `src/main/resources/redis/create-session.lua` | **New file** — atomic session-create + indexing script |
| `src/main/resources/redis/delete-user-sessions.lua` | **New file** — atomic user-session revocation script |
| `src/main/.../session/SessionHashFields.java` | Add `USER_SESSIONS_KEY_PREFIX` constant |
| `src/main/.../session/SessionWriter.java` | Replace inline Lua with `ClassPathResource`, modify `createSession`, modify `deleteSession`, update signatures for `updateSessionExpiry`/`updateTokenAndExpiry`, add `deleteAllSessionsForUser` |
| `src/main/.../api/SessionController.java` | Pass `sessionData.userId()` to `updateSessionExpiry` and `updateTokenAndExpiry` |
| `src/main/.../config/SecurityConfig.java` | Add `/internal/v1/sessions/users/*` to `permitAll` |
| `src/main/.../api/InternalSessionController.java` | **New file** — DELETE endpoint |
| `src/test/.../session/SessionWriterIntegrationTest.java` | Add re-indexing and concurrent create-vs-revoke regression coverage, update cleanup |
| `src/test/.../api/InternalSessionControllerIntegrationTest.java` | **New file** — internal revocation endpoint integration tests |
| `src/test/.../api/SessionControllerIntegrationTest.java` | Add heartbeat re-indexing path that proves internal targeted revocation can see the repaired session |

---

## Verification

```bash
# Run all tests
./gradlew test

# Run just the affected test classes
./gradlew test --tests "*SessionWriterIntegrationTest" --tests "*InternalSessionControllerIntegrationTest"
```

After tests pass, manually verify with a running instance:
```bash
# Create sessions (via normal login flow), then:
curl -X DELETE http://localhost:8081/internal/v1/sessions/users/{userId} -v
# Expect: 204 No Content
# Verify in Redis: SMEMBERS user_sessions:{userId} → (empty), session hashes gone
```
