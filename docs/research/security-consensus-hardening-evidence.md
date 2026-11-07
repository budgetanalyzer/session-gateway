# Security Consensus Hardening Evidence

## Plan 02.1, Phase 1: OAuth Callback Browser Binding

Validated on 2026-11-07 in the Session Gateway workspace for worker run
`20261107T082308Z-phase-1-76f722b7-bd8d-4166-ac5e-24957f2fbbf8`.
Scope: `RedisAuthorizationRequestRepository`, its integration coverage and existing OAuth callback
fixtures, and [the security contract](../security.md#oauth-callback-browser-binding).

### Implemented contract

- `__Host-BA_OAUTH_BINDING` is a reusable, independent 256-bit random browser-session cookie:
  Secure, HttpOnly, Path=/, SameSite=Lax, no Domain or persistent expiry. Valid bindings are exactly
  64 lowercase hex characters; missing, malformed or ambiguous cookie input is not accepted on
  callback. Login start generates a binding when no valid cookie is supplied.
- Authorization redirects use `response_type=code` without `response_mode`; the callback is a
  top-level GET with query parameters. Tests assert the generated authorization parameters.
- Redis stores only SHA-256 of the binding in `browser_binding_hash`. Creation rejects an existing
  state key and atomically writes the hash and TTL. Its inline Lua uses only `TYPE`, `HSET`, and
  `EXPIRE`, already permitted by plan 01's Session Gateway allowlist; `EVALSHA`/`EVAL` are also
  already permitted. No ACL changes are needed.
- Constant-time comparison precedes deletion. Only `DEL == 1` returns the authorization request
  and exposes callback attributes. A zero result or Redis error fails closed before token exchange
  or session issuance. Missing/wrong bindings leave state intact. Denial callbacks use the same
  consume path. The cookie survives all callbacks.
- The authorization resolver supplies a fresh random state at each start. State values must never
  be reused or recreated after expiry/consumption; this invariant and immutable live records make
  validate-then-delete sufficient. No callback Lua or compatibility format was introduced.

### Validation results

Final documented command sequence:

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Both succeeded. The build completed in 46 seconds, with **189 tests, 0 failures, 0 errors,
0 skipped**. Spotless, Checkstyle (no violations), compilation, JAR assembly and JaCoCo gates
passed. JaCoCo reported **916/970 lines (94.43%)** and **194/258 branches (75.19%)**, above the
repository gates of 90% and 65% respectively. Reports are generated under `build/reports/` and
`build/test-results/test/`.

| Evidence | Result |
| --- | --- |
| `SecurityConfigIntegrationTest` (13 cases) | Real HTTP login succeeds with binding; wrong/missing browser cookie cannot call the token endpoint or issue a session; the owner can subsequently finish the same transaction; replay is rejected. |
| Same HTTP suite, denial callback | Missing/wrong binding preserves state and exposes no stored return URL; correct binding consumes state once and retains the existing failure redirect context; denial/replay causes no token exchange or session cookie. |
| Same HTTP suite, pending tabs | Tabs sharing a cookie both complete with real session hashes; starts without a cookie produce distinct bindings, the losing callback is rejected, and a fresh retry succeeds. |
| `RedisAuthorizationRequestRepositoryIntegrationTest` (19 cases) | Hash-only storage, finite TTL, malformed/duplicate/missing/wrong binding rejection, record preservation, replay/expiry, immutable state, cookie reuse, and null-save consumption behavior pass against Testcontainers Redis. |
| Competing callbacks | A registration lookup barrier ensures both callbacks read and validate the same real Redis record before either deletes it; exactly one returns a request and sets attributes. |
| Expiry between read and delete | The lookup hook expires the real Redis key after binding validation but before deletion; no request or callback attributes are returned. |
| Redis deletion error | A dedicated Testcontainers ACL user can load state but lacks `DEL`; consumption raises a Redis error without attributes or record loss. The temporary user is deleted afterward. |
| Existing diagnostics/domain-override suites (4 + 1 cases) | Fixtures now carry the binding cookie; downstream failure diagnostics and the public-session domain override behavior still pass. |

The first-start race tests deliberately send both starts without a cookie, representing requests
sent before either response's cookie is stored. They then use one retained binding for callbacks.
This covers the accepted race outcome; browser cookie storage and cross-site delivery still need
phase 3's live proof.

During development, validation caught and resolved test-client method ordering, two style
violations, expiry-fixture semantics (`expire(Duration.ZERO)` does not force expiry in the Spring
API), and ACL cleanup response decoding. The final run has no failed checks. JVM class-sharing
and Redis reconnect messages appeared during test shutdown without test failures.

### Handoff and limitations

- Phase 2's API-test login helpers must carry `__Host-BA_OAUTH_BINDING` from initiation to callback.
  Existing-cookie parallel tabs must reuse it. No other repository was modified in this phase.
- Phase 3 must prove behavior through the live stack, including actual browser cookie attributes
  and cross-site GET delivery. No Tilt, cluster mutation, or live Auth0 access was used here.
- An existing local pending OAuth record without a binding hash fails closed. Start a fresh login
  and allow old state to expire; no migration or reset is required. Cookie loss requires a fresh
  login too. The accepted simultaneous-first-start race can reject one tab.
- Retaining one cookie does not bound pending Redis records; existing TTL and platform rate/capacity
  controls remain necessary. The binding is not an application-session credential.
- `returnUrl` handling and application CSRF policy remain outside this phase.
- No git write operations or runner-owned state/outcome changes were made.

Source context: [plan 02.1](../../../orchestration/docs/plans/security-hardening-02.1-oauth-callback-binding.md),
[contested decision 4](../../../orchestration/docs/research/security-review-contested-issues-2026-11-02.md#4-oauth-correlation-cookie-and-atomic-consume),
R1 finding 1, R2's cookie requirements and R4's callback test list, together with
[RFC 9700 section 2.1.1](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1).
This evidence is ready for plan 05 phase 3's cross-repository collection.
