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


## Plan 02.2, Phase 1: Bound OAuth Login Input

Implemented on 2026-11-07 for worker run
`20261107T090611Z-phase-1-4733a849-9c7b-4f78-87e4-cc09c0817cd5`.
Scope: Session Gateway only; no later phases or sibling-repository changes.

### Contract and decisions

- The authorization resolver admits only safe `returnUrl` values of at most 2048 Java string
  characters. Unsafe, empty, or oversized input is dropped while OAuth login continues. Valid
  destinations retain query parameters, fragments, and valid percent encoding.
- The Redis repository reads `return_url` exclusively from validated authorization-request
  additional parameters. Both the authorization URI and raw request-query fallbacks are removed.
  Validation belongs at login initiation; callback redirect validation remains defense in depth.
- `RedirectUrlValidator` rejects backslashes, control characters, whitespace (including Unicode
  spaces and BOM), malformed URI syntax, schemes, and authorities. Existing restrictions on a
  single leading slash and embedded `://` remain. This covers the current frontend's unsafe
  origin/backslash cases and adds the plan's stricter character and URI parsing rules.
- OAuth-state lifetime defaults to 600 seconds, separate from the 900-second session lifetime.
  The existing main-configuration default test and test configuration now agree.
- `IDP_REDIRECT_URI` accepts a fixed callback URL. Unset, it retains
  `{baseUrl}/login/oauth2/code/{registrationId}`; fixing the URI requires deployment configuration.
  No ingress/header policy was changed.
- Updated [session configuration](../session-configuration.md#bounded-login-return-url),
  [environment variables](../configuration.md), [security behavior](../security.md#return-url-support),
  and the existing OAuth-state default in `AGENTS.md`.

### Validation results

Final documented sequence:

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Both passed; the final build took 51 seconds. **218 tests passed, 0 failures, 0 errors,
0 skipped**. Spotless, compilation, JAR assembly, and JaCoCo gates passed; both Checkstyle reports
contain zero violations. Coverage is **926/977 lines (94.78%)** and **210/272 branches (77.21%)**,
above the repository's 90% line and 65% branch gates. `git diff --check` passed.
Reports are under `build/reports/` and `build/test-results/test/`.

The first build identified the old 900-second expectation in `SessionPropertiesTest`; updating
that assertion to the planned 600-second default resolved the sole failure. A subsequent passing
build was repeated after enabling forwarded-header processing in the fixed-URI test. Final output
includes JVM class-sharing warnings and Redis reconnect/Netty listener errors during test-context
shutdown; these did not fail any test or gate. No tests were skipped or weakened.

### Handoff and limitations

The real-bean resolver/repository tests use Testcontainers Redis. They check valid URLs,
2048/2049-character boundaries, invalid inputs, preserved nonce/PKCE/browser-binding fields, and
finite state TTL at or below 600 seconds. A repository regression separately proves neither raw
URI fallback can restore an unchecked return URL. The fixed-URI HTTP test enables the application's
`framework` forwarded-header strategy and verifies the configured URI in both the IdP redirect
and Redis despite forged forwarded headers. Existing browser-binding and callback suites remain
part of the full build.

No live Auth0, Tilt, or cluster access was used. Existing pending state retains its old contents
and TTL; new logins use the new validation and default. No schema migration or reset is required.
The per-record cap and shorter TTL do not bound the number of anonymous records: rate limits and
Redis memory settings remain plan 04 phase 1 work. Frontend and deployment configuration belong
to later phases of plan 02.2. No git writes or runner-owned state/outcome edits were performed.

Context: [plan 02.2](../../../orchestration/docs/plans/security-hardening-02.2-oauth-login-input.md),
R2's login-start cap and finding H, R3's `noeviction` caveat, and the current frontend
`loginRedirect.ts`. This section is available for plan 05 phase 3's evidence collection.
