# Fix Targeted Session Revocation Races

Status: Steps 1-9 implemented on 2026-04-04.

## Problem Statement

The current targeted revocation implementation has two correctness gaps:

1. `deleteAllSessionsForUser(...)` is not atomic with concurrent `createSession(...)`.
   It currently does `SMEMBERS user_sessions:{userId}` in one step and `UNLINK` in a later step.
   A session created in between can survive revocation and lose its index entry.
2. Heartbeat and token refresh do not repair missing `user_sessions:{userId}` entries.
   They refresh the set TTL, but they never `SADD` the current session ID back into the set.
   Any session whose index entry is missing remains invisible to targeted revocation.

This is a code-level flaw, not inherently a live-system migration issue. In a clean rollout with
empty Redis, the "pre-existing sessions" example does not apply. The self-healing gap still does.

## Goals

- Make per-user revocation atomic with concurrent session creation.
- Make heartbeat and token refresh re-index the active session if its index entry is missing.
- Preserve existing API behavior and session semantics outside these correctness fixes.
- Keep the Redis contract explicit and testable.

## Non-Goals

- No one-off Redis backfill is included in this plan.
- No change to the revocation HTTP contract (`DELETE /internal/v1/sessions/users/{userId}`).
- No change to ext_authz session lookup behavior.

## Design Changes

### 1. Make session creation atomic

Replace the current multi-command `createSession(...)` flow with a Redis Lua script that performs
all of the following in one execution:

- `HSET session:{id} ...fields`
- `EXPIRE session:{id} ttl`
- `SADD user_sessions:{userId} sessionId`
- `EXPIRE user_sessions:{userId} ttl`

This removes the window where revocation can snapshot the user set before a new session is indexed.

### 2. Make heartbeat/token refresh re-index the current session

Extend the existing conditional update script so it does more than refresh TTLs.
When `session:{id}` exists, the script must:

- apply the requested hash updates
- `EXPIRE session:{id} ttl`
- `SADD user_sessions:{userId} sessionId`
- `EXPIRE user_sessions:{userId} ttl`

That makes `updateSessionExpiry(...)` and `updateTokenAndExpiry(...)` self-healing for missing
index entries.

### 3. Make user revocation atomic

Replace the current `SMEMBERS -> Java builds key list -> UNLINK` sequence in
`deleteAllSessionsForUser(...)` with a Redis Lua script that:

- reads all members from `user_sessions:{userId}`
- derives the corresponding `session:{id}` keys inside the script
- deletes the session hashes and the `user_sessions:{userId}` key in the same execution

This removes the race where a concurrent session create can survive and become unindexed.

## Implementation Steps

### Step 1: Add an atomic session-create script

Create `src/main/resources/redis/create-session.lua`.

Inputs:
- `KEYS[1]`: session hash key
- `KEYS[2]`: user session index key
- `ARGV[1]`: session ID
- `ARGV[2]`: TTL seconds
- `ARGV[3..N]`: alternating hash field/value pairs

Behavior:
- `HSET` all session fields into `KEYS[1]`
- `EXPIRE KEYS[1]`
- `SADD KEYS[2] ARGV[1]`
- `EXPIRE KEYS[2]`
- return success marker

### Step 2: Extend the conditional update script to re-index

Update `src/main/resources/redis/conditional-update.lua`.

Current behavior:
- conditionally updates the hash
- refreshes key TTLs

Required new behavior:
- accept the current `sessionId` as an argument
- `SADD` that session ID into `KEYS[2]` when `KEYS[1]` exists
- continue to `EXPIRE` both keys

This must remain conditional on the session hash existing. The update path must never recreate a
deleted session hash.

### Step 3: Add an atomic user-revocation script

Create `src/main/resources/redis/delete-user-sessions.lua`.

Inputs:
- `KEYS[1]`: user session index key
- `ARGV[1]`: session key prefix

Behavior:
- `SMEMBERS KEYS[1]`
- derive each session hash key using the configured prefix
- delete every indexed session hash plus `KEYS[1]` itself in one script execution
- return the number of deleted keys for logging/tests

Implementation note:
- check whether the deployed Redis version allows `UNLINK` inside Lua
- if not, use `DEL` inside the script
- correctness matters more than async deletion here

### Step 4: Refactor `SessionWriter` to use scripts

Update `src/main/java/org/budgetanalyzer/sessiongateway/session/SessionWriter.java`.

Changes:
- register the new `create-session.lua` script
- register the new `delete-user-sessions.lua` script
- change `createSession(...)` to a single script execution
- change `updateSessionExpiry(...)` to pass `sessionId`, `sessionKey`, `userSessionsKey`, field
  updates, and TTL to the updated conditional script
- change `updateTokenAndExpiry(...)` the same way
- change `deleteAllSessionsForUser(...)` to a single script execution

Do not keep the current `SMEMBERS -> UNLINK` implementation around as a fallback. That is the bug.

### Step 5: Keep `deleteSession(...)` behavior unless a separate bug is found

`deleteSession(...)` is not the source of the two review findings.

It can remain as:
- `HGET user_id`
- `UNLINK session:{id}`
- `SREM user_sessions:{userId} sessionId`

If further cleanup is needed later, do it as separate work. Do not mix extra behavioral changes
into this fix.

### Step 6: Add integration coverage for re-indexing

Extend `src/test/java/org/budgetanalyzer/sessiongateway/session/SessionWriterIntegrationTest.java`
with cases that prove missing index entries are repaired:

- `updateSessionExpiryReindexesSessionWhenUserIndexEntryIsMissing`
- `updateTokenAndExpiryReindexesSessionWhenUserIndexEntryIsMissing`
- existing TTL assertions should continue to pass after re-indexing

Suggested setup for both tests:
- create a session
- manually remove the session ID from `user_sessions:{userId}`
- call the update method
- assert the update succeeded
- assert the session ID is back in the set

### Step 7: Add integration coverage for revocation/create races

Add a regression test in
`src/test/java/org/budgetanalyzer/sessiongateway/session/SessionWriterIntegrationTest.java`
that exercises concurrent `createSession(...)` and `deleteAllSessionsForUser(...)`.

The exact scheduling is non-deterministic, so the test should use a repeat loop rather than assume
a single interleaving. The invariant to assert after each attempt is:

- there is never a surviving `session:{id}` hash for the target user without a matching
  `user_sessions:{userId}` membership entry

Valid end states:
- the new session was deleted by revocation
- the new session survived and is still indexed

Invalid end state:
- the new session survived but the user index key is missing or does not contain that session ID

### Step 8: Keep controller tests and add one re-indexing path if useful

`src/test/java/org/budgetanalyzer/sessiongateway/api/InternalSessionControllerIntegrationTest.java`
already covers the basic endpoint behavior.

Keep those tests and, if it adds signal, add one scenario that:
- creates a session
- manually removes its set membership
- calls heartbeat/update path to re-index it
- then calls `DELETE /internal/v1/sessions/users/{userId}`
- asserts the session is deleted

The race fix itself belongs at the `SessionWriter` level, not the controller layer.

### Step 9: Update documentation to remove the stale design assumption

Update the existing plan document
`docs/plans/user-session-revocation.md`.

That document currently records this design choice:
- revocation atomicity uses sequential operations, not Lua

That decision is now known to be wrong. The document should be updated to either:
- explicitly mark that section as superseded, or
- replace it with the new atomic-script design

Also update any nearby documentation that describes heartbeat/index maintenance so it states:
- heartbeat and token refresh re-index the active session, not just refresh TTL

## Acceptance Criteria

- Concurrent `createSession(...)` and `deleteAllSessionsForUser(...)` cannot leave a surviving
  unindexed session.
- `updateSessionExpiry(...)` re-adds the current session ID to `user_sessions:{userId}` when the
  session hash still exists.
- `updateTokenAndExpiry(...)` re-adds the current session ID to `user_sessions:{userId}` when the
  session hash still exists.
- No update path recreates a deleted session hash.
- Existing revocation endpoint semantics remain `204 No Content`.
- `./gradlew test` passes.
- Prefer `./gradlew clean build` as final verification if time permits.

## Rollout Note

For this repository's stated non-live scenario, no migration step is required.

If this design is ever deployed against an environment that already contains active session hashes
without corresponding `user_sessions:{userId}` membership, heartbeat/token refresh will repair
those sessions only after they next hit the update path. Immediate coverage for all already-active
sessions would require a separate backfill job or operational cleanup.
