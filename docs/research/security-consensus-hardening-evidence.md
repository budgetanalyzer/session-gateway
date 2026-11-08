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

## Plan 02.5, Phase 1: Hashed Session Keys

Implemented on 2026-11-07 for worker run
`20261107T120425Z-phase-1-95a286fb-5da2-4365-b6d2-17032d4b7d63`.
Scope: Session Gateway only; ext-authz (phase 2) and orchestration consumers are later phases.

### Contract and decisions

- `SessionTokenDigest.sha256Hex(token)` is the single helper: the lowercase hex SHA-256 of the
  cookie token's UTF-8 bytes. `SessionWriter` and `SessionReader` build every `session:` key from
  it. `create-session.lua` and `conditional-update.lua` receive the digest as `ARGV[1]`, so
  `user_sessions:{userId}` members are digests. `deleteSession` removes the digest member.
  `delete-user-sessions.lua` is unchanged because it builds keys from those members.
- `createSession` returns the raw random UUID token for the cookie only; no Redis command carries
  it. Plain SHA-256 without salt or HMAC, as planned, because the tokens are random UUIDs.
- Logs use `SessionTokenDigest.logId(token)`, the first eight digest characters. This covers
  `SessionWriter`, `SessionReader`, and also `SessionController`, `UserController`, and
  `LogoutController`, which previously logged `SafeLogger.truncateId` of the raw token. Leaving
  them would have kept raw-token prefixes in logs, contrary to the phase goal.
- There is no raw-key fallback or migration. Raw-key sessions become unreachable at cutover.
- Golden vector for phase 2: token `3f2504e0-4f89-41d3-9a0c-0305e82c3301` →
  digest `16362f566387b3cf5a6e92fb0a986c76ca20eb3a0c12cbdfbd0b29501e0c18df` →
  key `session:16362f566387b3cf5a6e92fb0a986c76ca20eb3a0c12cbdfbd0b29501e0c18df`. The digest was
  computed independently with `sha256sum` and `openssl dgst -sha256` before being pinned in tests.
- Documented in [Hashed Session Keys](../session-configuration.md#hashed-session-keys),
  [security](../security.md#hashed-session-keys), `AGENTS.md`, and `README.md`.

### Validation results

Final documented sequence:

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Both passed; the build took 58 seconds. **237 tests passed, 0 failures, 0 errors, 0 skipped**.
Spotless, compilation, JAR assembly, and JaCoCo gates passed, and both Checkstyle reports contain
zero violations. Coverage is **953/1006 lines (94.73%)** and **221/282 branches (78.37%)**, above
the 90% line and 65% branch gates. Redis reconnect/Netty listener stack traces appeared during
test-context shutdown, as in earlier phases; no test result references them.

| Evidence | Result |
| --- | --- |
| `SessionTokenDigestTest` (5 cases) | Golden digest and default-prefix key match; output is 64 lowercase hex characters; `logId` returns `16362f56…` and handles a missing token. |
| `SessionReaderIntegrationTest` golden case | A hash written at the literal golden key is read using the raw golden token. A hash named by a raw token is not found. |
| `SessionWriterIntegrationTest` raw-token case | After create and heartbeat refresh, no Redis key, `user_sessions:*` member, or session field value contains the raw token. The index holds exactly the digest, and `deleteSession` removes both. |
| `LogoutControllerIntegrationTest` | The digest-keyed hash and index member exist before `/logout` and are gone after it. |
| `InternalSessionControllerIntegrationTest` | The index holds the three digests before bulk revocation. Revocation deletes their hashes and index and leaves the other user's digest-keyed session. |
| Existing heartbeat, login, security-context, and user suites | Pass with keys and members derived through the digest. |

### Handoff and limitations

- Phase 2 must derive ext-authz keys with the same function and pin the same golden vector.
  Until ext-authz, the orchestration seeders, and the verifiers switch, the local stack cannot read
  new sessions; do not rely on a running stack before the plan's Live phase.
- After deploying, run `./scripts/ops/flush-redis.sh` from orchestration; existing sessions are
  unreachable.
- Hashing removes the bearer value, not enumeration. Principals that can list keys still see
  session counts and user-index names (contested decision 2).
- `RedisAuthorizationRequestRepository` still has its own private SHA-256 for
  `browser_binding_hash`. It is not a session key and was left unchanged.
- No Tilt, cluster, or live Auth0 access was used. No git writes or runner-owned state/outcome
  edits were made.

Context: [plan 02.5](../../../orchestration/docs/plans/security-hardening-02.5-hashed-session-keys.md),
[contested decision 2](../../../orchestration/docs/research/security-review-contested-issues-2026-11-02.md#2-redis-enumeration-after-hashing),
R2 finding A, R3's three fixes for finding A, and R4's Redis finding. This section is available
for plan 05 phase 3's evidence collection.

## Plan 02.6, Phase 1: `__Host-` Session Cookie

Validated on 2026-11-07 in the Session Gateway workspace for worker run
`20261107T144205Z-phase-1-c1079767-86d0-4c72-bc01-0a96898669d8`.
Scope: `application.yml`, `SessionProperties`, `SessionCookieHelper`, the startup contract logger,
tests, and [the cookie contract](../session-configuration.md#cookie-behavior).

### Implemented contract

- `SESSION_COOKIE_NAME` defaults to `__Host-BA_SESSION`.
- D4 applied by removal: `session.cookie.domain-override` / `SESSION_COOKIE_DOMAIN_OVERRIDE` and
  `CookieProperties.domainOverride` no longer exist, so no `Domain` attribute can be emitted. The
  former override integration suite was deleted. A leftover `SESSION_COOKIE_DOMAIN_OVERRIDE`
  environment variable is ignored by binding.
- Startup fails when `session.cookie.name` starts with `__Host-` (case-insensitive, as browsers
  match the prefix) and `session.cookie.secure=false`.
- The startup log line is now `Public session cookie contract configured: name={name}`.

### Actual `Set-Cookie` output

Captured from the Reactor Netty HTTP responses in the integration suites (the encoding differs from
`ResponseCookie.toString()`, so the integration tests assert the raw header):

```text
# login callback (SecurityConfigIntegrationTest)
__Host-BA_SESSION=<uuid>; Path=/; Secure; HTTPOnly; SameSite=Strict
# logout clear (LogoutControllerIntegrationTest)
__Host-BA_SESSION=; Max-Age=0; Expires=<now>; Path=/; Secure; HTTPOnly; SameSite=Strict
```

Both carry `Secure` and `Path=/` with no `Domain`, satisfying the `__Host-` prefix rules for
setting and clearing. Heartbeat clears use the same `SessionCookieHelper` path and are covered by
the existing `SessionControllerIntegrationTest` attribute assertions.

### Validation results

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Both succeeded: **236 tests, 0 failures, 0 errors, 0 skipped**; Spotless and Checkstyle passed.
JaCoCo reported **945/998 lines (94.69%)** and **217/278 branches (78.06%)**. The first build run
failed two new raw-header assertions written against `ResponseCookie.toString()` ordering
(`HttpOnly`, `Path` before `Max-Age`); they were corrected to the real wire format above.

### Handoff and limitations

- ext-authz, API tests and orchestration must switch to `__Host-BA_SESSION` in the same merge unit;
  until then the local stack is inconsistent. Existing local `BA_SESSION` cookies are simply ignored,
  so users log in again; no migration is needed.
- `kubernetes/production` pins older session-gateway images without this change (plan 05, Phase 3).
- Browser acceptance of the cookie through the live ingress is not proven here.

## Plan 02.7, Phase 1: POST Heartbeat And Logout

Validated on 2026-11-07 in the Session Gateway workspace for worker run
`20261107T160007Z-phase-1-d62968bd-68a9-46d9-ae83-19c3e50b67a3`.

### Implemented contract

- The heartbeat is now `POST /auth/v1/session`; `GET` and `HEAD` return `405 Method Not Allowed`
  without reaching the mutating controller path.
- Logout is now a form-compatible `POST /logout`. It deletes the Redis session, clears the public
  cookie, and returns `303 See Other` with the server-constructed identity provider logout URL.
- Spring Security's built-in POST logout filter is disabled so the application-owned controller
  retains the Redis, cookie, and identity-provider behavior.
- `GET` and `HEAD` logout requests return `405 Method Not Allowed` and leave the Redis session
  intact. The generated OpenAPI contract publishes only the POST operations and the logout 303.
- Session Gateway adds no CSRF token or Fetch Metadata contract. The exact-Origin control remains
  the ingress responsibility in plan 02.8.

### Validation results

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Both succeeded on the first run; the build took 58 seconds. **240 tests passed, 0 failures, 0
errors, 0 skipped**. Spotless, Checkstyle, JAR assembly, and JaCoCo gates passed. Coverage is
**946/999 lines (94.69%)** and **217/278 branches (78.06%)**.

`SessionControllerIntegrationTest` covers POST success and GET/HEAD rejection.
`LogoutControllerIntegrationTest` covers POST invalidation, the exact 303 target, GET/HEAD
rejection without invalidation, and the OpenAPI method/status contract.

### Handoff and limitations

- The frontend, API tests, and orchestration callers still use the old methods until later phases
  in this synchronized merge unit update them. The local stack is intentionally inconsistent until
  those phases complete.
- No live stack, cluster mutation, or Auth0 access was used; live behavior belongs to plan phase 4.
- No local state reset is required for this HTTP method change.

Context: [plan 02.7](../../../orchestration/docs/plans/security-hardening-02.7-post-heartbeat-logout.md)
and [contested decision 1](../../../orchestration/docs/research/security-review-contested-issues-2026-11-02.md#1-primary-csrf-control).

## Security Hardening 03, Phase 9: Safe Logging, Readiness And Session Audit Events

Validated on 2026-11-07 in the Session Gateway workspace for worker run
`20261107T212028Z-phase-9-f2a88620-0d6e-4e14-8a19-799c70c15ddb`.

### Implemented contract

- Base application logging is `INFO` for `org.budgetanalyzer`; HTTP request and response body
  capture now use the disabled service-common defaults. The Kubernetes profile no longer carries
  the obsolete request-body override or timeout-investigation comment.
- The opt-in `debug-logging` profile enables application `TRACE` and HTTP body capture for local
  synthetic-data diagnosis only.
- Readiness contains `readinessState` and Redis. Liveness remains dependency-free, and
  permission-service is deliberately excluded from readiness.
- Login success, login failure, logout, and bulk revocation emit structured events through the
  shared `AuditLogger`. Events use internal user IDs where an authenticated identity is
  available; bulk revocation records the target user as the resource. No event contains a session
  token or digest.
- Correction: this phase did not audit callback failures completed by the dedicated callback
  `WebExceptionHandler`s or logout session-read failures, and logout failures recorded a
  hard-coded `500`. The review remediation below closes those paths.

### Validation results

- `./gradlew clean spotlessApply` and `./gradlew clean build`: passed (Spotless, Checkstyle,
  all tests, JaCoCo verification).
- `SessionGatewayApplicationIntegrationTest` loads the main `application.yml` with the
  `kubernetes` profile and asserts `org.budgetanalyzer` is `INFO` and both HTTP body flags are
  off; it also asserts readiness reports `readinessState` and `redis`, and liveness has no Redis
  component.
- `DebugLoggingProfileIntegrationTest` asserts the opt-in profile enables `TRACE` and both body
  flags.
- `SecurityConfigIntegrationTest`, `LogoutControllerIntegrationTest`, and
  `InternalSessionControllerIntegrationTest` capture `budgetanalyzer.audit` and assert exactly one
  event per login success, login failure, logout, and bulk revocation, with the expected actor,
  operation, and outcome, and without the session token or its digest.

### Handoff and limitations

- The existing trusted-client-address gap remains out of scope and is recorded by Phase 4.
- Permission-service failures continue to affect individual login or heartbeat operations without
  taking the Session Gateway pod out of readiness.

## Security Hardening 03 Review Remediation, Phase 1: Session Lifecycle Audit Completion

Validated on 2026-11-08 in the Session Gateway workspace for worker run
`20261108T081228Z-phase-1-76b3ef89-d592-47cb-88ca-2af70415df7c`; the logout commit-point and
config-override follow-ups were validated in worker run
`20261108T085210Z-phase-1-7c343686-101b-43ab-b128-81d83cd76365`.

### Implemented contract

- `SessionLifecycleAuditLogger` is the single Session Gateway-local emitter around `AuditLogger`.
  Login and logout events record the completed response's status and the response correlation ID.
- Terminal-path owners: `SecurityConfig` owns login success, OAuth2 authentication failures
  (including userinfo transport failures, which Spring Security wraps as authentication failures),
  and post-authentication permission-service or session-write failures.
  `OAuth2CallbackTransportFailureWebExceptionHandler` owns token-endpoint and JWKS transport
  failures. `OAuth2CallbackUnexpectedFailureWebExceptionHandler` owns other callback exceptions
  that escape the security chain. `LogoutController` and `InternalSessionController` own logout
  and bulk revocation.
- Logout operations are `LOGOUT_SUCCESS` and `LOGOUT_FAILURE`. A session-read failure (for example
  a malformed Redis hash) or Redis deletion failure now returns `302` to `/oops` without clearing
  the cookie or redirecting to the identity provider, then emits one `LOGOUT_FAILURE` with outcome
  `302`. The actor is the resolved internal user ID, or `anonymous` when the read failed. The
  OpenAPI contract documents the `302`.
- Logout failure recovery covers only the session read and the deletion step. Session deletion is
  the commit point, so nothing after it reports `LOGOUT_FAILURE` or redirects to `/oops` with a
  cookie-clearing header. `LogoutController` builds the identity provider logout `URI` once in its
  constructor, so a malformed `idp.logout.url-template` fails startup. A failed final response
  write is neither redirected nor audited.
- Bulk revocation keeps its existing behavior: `204` on success; on Redis failure,
  service-common's JSON `500`, with one event recording `500`.

### Validation results

- Focused run of `SecurityConfigIntegrationTest`, `OAuth2CallbackDiagnosticsIntegrationTest`,
  `LogoutControllerIntegrationTest`, `InternalSessionControllerIntegrationTest`, and
  `SessionGatewayApplicationIntegrationTest`: 42 tests passed, 0 failures.
- `./gradlew clean spotlessApply` then `./gradlew clean build`: passed. **246 tests, 0
  failures, 0 errors, 0 skipped**; Spotless, Checkstyle (0 findings), and JaCoCo gates passed.
  Coverage: **1009/1059 lines (95.28%)**, **221/280 branches (78.93%)**.
- `git diff --check`: clean.
- Follow-up run `20261108T085210Z-phase-1-7c343686-101b-43ab-b128-81d83cd76365`: the focused run
  above plus the new `LogoutControllerTest` (malformed `idp.logout.url-template` throws
  `IllegalArgumentException` at construction) passed with 43 tests, 0 failures. The logout
  deletion-failure case was renamed to
  `logoutRedirectsToOopsWithoutClearingCookieWhenRedisDeletionFails`. `./gradlew clean
  spotlessApply` then `./gradlew clean build`: passed. **247 tests, 0 failures, 0 errors, 0
  skipped**; Checkstyle 0 findings. Coverage: **1010/1060 lines (95.28%)**, **221/280 branches
  (78.93%)**. `git diff --check`: clean.
- The shared `AbstractIntegrationTest` audit capture asserts exactly one event per request, with
  operation, actor, outcome, and the response `X-Correlation-ID`, plus absence of session tokens,
  digests, OAuth code and state, and profile values where present. Covered paths: login success;
  token-endpoint `500`; token and JWKS connection resets; token, JWKS, and userinfo response
  timeouts (the test asserts the transport handler logs for token and JWKS but not for userinfo);
  permission-service transport failure, login timeout, and session-write failure; a wrong-type
  `oauth2:state:{state}` record handled by the unexpected-failure handler; authenticated and
  cookie-less logout success; logout with a hash missing `expires_at`; logout with a wrong-type
  user index; and bulk-revocation success and wrong-type-index failure.

### Handoff and limitations

- `SessionGatewayApplicationIntegrationTest` still uses
  `spring.config.additional-location=file:./src/main/resources/`. Removing it made
  `readinessIncludesRedisWhileLivenessRemainsDependencyFree` and
  `kubernetesProfileUsesSafeLoggingDefaults` fail: `src/test/resources/application.yml` shadows
  the main `application.yml` on the test classpath, so the readiness group and base logging levels
  are not loaded. Only `application-kubernetes.yml` is picked up from main resources. Resolved:
  the remediation plan keeps the override, and a one-line comment at the override now explains the
  shadowing. The readiness, base logging, and `kubernetes` profile assertions remain.
- No test injects a post-deletion failure, because the only remaining one is the final response
  write, which is deliberately neither redirected nor audited.
