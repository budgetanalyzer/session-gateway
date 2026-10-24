# Coding and Testing Guideline Remediation

Resolve the three findings from the `spring-boot-4-upgrade` branch review: replace volatile
component inventories in `AGENTS.md` with discovery-based guidance, replace reflection-based
framework wiring assertions with observable OAuth2 and JWT behavior, and bring
`SecurityConfig` field names into compliance with the full type-based naming convention.

Preserve runtime behavior and public contracts. Keep application-owned Spring beans real, use
WireMock for IdP HTTP behavior and Testcontainers for Redis-backed integration behavior, and do
not weaken, disable, or delete behavioral coverage. Do not add suppressions or run git write
operations. Apply the repository-relative instructions in `AGENTS.md` and the shared standards in
`../service-common/docs/code-quality-standards.md` and
`../service-common/docs/testing-patterns.md` throughout the plan.

## Phase 1: Replace volatile AGENTS.md component inventories

### Workspace

.

### Goal

Make the repository guidance comply with the workspace AGENTS.md checkstyle by directing agents
to discover current classes and consult the documents that own behavior, instead of maintaining a
class-by-class component inventory.

### Scope

- `AGENTS.md`, especially the `Key Components` section and its `Component Types` lists added to or
  expanded by the current branch.
- Existing discovery commands and links to `docs/security.md`, `docs/session-configuration.md`,
  and other local owner documents needed to preserve useful guidance.

### Non-goals

- Do not change application code, tests, runtime configuration, or behavior.
- Do not rewrite all of `AGENTS.md` or remove unique security, workflow, write-boundary, or
  validation rules.
- Do not duplicate detailed component behavior in another document merely to shorten
  `AGENTS.md`.
- Do not edit the orchestration-owned AGENTS.md checkstyle.

### Required context

- `../orchestration/docs/agents-md-checkstyle.md`. Apply its preservation rule, AG001 pattern
  guidance, AG002 source-of-truth rule, AG003 discovery requirement, AG005 inventory rule, and
  AG016 consultation-trigger rule.
- The existing `AGENTS.md` discovery blocks around `Key Components`, `API Endpoints`, and
  `Repository Structure`.
- `docs/security.md` for security and browser error behavior.
- `docs/session-configuration.md` for session and dedicated IdP callback transport behavior.
- `README.md` for the stable service overview.

### Execution steps

1. Read the complete AGENTS.md checkstyle before editing `AGENTS.md`.
2. Replace the class-by-class `Component Types` inventories with a concise package-level
   orientation, discovery commands using `find` or `rg`, and consultation triggers to the local
   owner documents. Preserve high-value rules such as the browser-only OAuth2 model, Redis session
   ownership, callback error strategy, and service-common integration.
3. Ensure the discovery commands reveal configuration classes, controllers, filters, services,
   and session components from source rather than naming a maintained set of current classes.
4. Retain any unique instruction that is not owned elsewhere. If a detailed behavior already has
   an owner document, leave a short stable rule and a trigger explaining when to read that
   document.
5. Review the branch diff for other newly added class inventories in `AGENTS.md`; convert any such
   additions to the same discovery-and-owner-document pattern without expanding this into a full
   file rewrite.

### Implementation notes

- Stable package responsibilities are suitable orientation; exhaustive class names are not.
- Use repository-relative plain paths or relative Markdown links. Do not add GitHub-web links or
  machine-specific absolute paths.
- Keep the existing direct operating guardrails intact even when related details move behind an
  owner-document pointer.

### Validation

- Read the edited section against the checklist in
  `../orchestration/docs/agents-md-checkstyle.md`.
- Run the new or retained discovery commands and confirm that they return the current source
  structure.
- Run `rg -n "Component Types|SecurityConfig:|SessionWriter:|InternalSessionController:|OAuth2ClientConfig:" AGENTS.md`
  and confirm no maintained component inventory remains in the remediated section.
- Run `git diff --check -- AGENTS.md`.
- Inspect `git diff -- AGENTS.md` and confirm unique security and workflow guardrails were
  preserved.

### Completion criteria

- `AGENTS.md` discovers current components from source and points to the documents that own their
  behavior.
- The current branch no longer adds or expands a class-by-class component inventory.
- No unique repository instruction, security constraint, or validation gate is lost.
- Only documentation changes are present from this phase.

## Phase 2: Replace reflection-based framework assertions with behavior tests

### Workspace

.

### Goal

Verify the dedicated IdP transport and ID-token validation through observable HTTP and decoder
behavior without reading private Spring Security fields.

### Scope

- `src/test/java/org/budgetanalyzer/sessiongateway/config/OAuth2ClientConfigIntegrationTest.java`.
- `src/test/java/org/budgetanalyzer/sessiongateway/config/OAuth2CallbackDiagnosticsIntegrationTest.java`.
- `src/test/java/org/budgetanalyzer/sessiongateway/config/IdpReactiveJwtDecoderFactoryTest.java`,
  including renaming it to `IdpReactiveJwtDecoderFactoryIntegrationTest.java` if it starts a real
  WireMock HTTP server.
- Existing test helpers in the same package when a small focused helper extraction removes
  duplication without changing shared test behavior.

### Non-goals

- Do not mock or spy application-owned beans.
- Do not assert private field names, private validator collections, or Spring Security's internal
  object graph.
- Do not weaken or remove the successful end-to-end OAuth2 callback coverage in
  `SecurityConfigIntegrationTest`.
- Do not change production behavior merely to expose internals to tests.
- Do not add `@SuppressWarnings`, `@Disabled`, fixed sleeps, or implementation-only test hooks.

### Required context

- `../service-common/docs/testing-patterns.md`, especially `Test Behavior, Not Implementation`,
  `Keep Application-Owned Spring Beans Real`, `External HTTP (WireMock)`, and the Spring Boot
  upgrade strategy.
- `../service-common/docs/code-quality-standards.md` for AssertJ, naming, formatting, and the
  suppression policy.
- `src/main/java/org/budgetanalyzer/sessiongateway/config/OAuth2ClientConfig.java`.
- `src/main/java/org/budgetanalyzer/sessiongateway/config/IdpReactiveJwtDecoderFactory.java`.
- `src/test/java/org/budgetanalyzer/sessiongateway/config/SecurityConfigIntegrationTest.java`,
  which already proves the complete successful authorization-code callback, JWKS retrieval,
  userinfo retrieval, permission lookup, and session creation path.
- `src/test/java/org/budgetanalyzer/sessiongateway/config/OAuth2CallbackDiagnosticsIntegrationTest.java`,
  which already proves the configured dedicated response timeout and connection-pool behavior at
  the token endpoint.

### Execution steps

1. Remove `oauth2CallbackBeansUseDedicatedIdpWebClient` and the related injected bean fields and
   `ReflectionTestUtils` import from `OAuth2ClientConfigIntegrationTest`. Keep the assertions that
   use the public `ConnectionProvider` API to verify configured pool settings.
2. Audit `OAuth2CallbackDiagnosticsIntegrationTest` against all three outbound callback stages:
   authorization-code token exchange, JWKS retrieval, and userinfo retrieval. Keep the existing
   token timeout and pool-pressure tests, and add focused delayed-response cases for any stage not
   yet proven to honor the dedicated client's configured timeout.
3. For each added callback diagnostic test, drive the real browser authorization and callback
   endpoints with `WebTestClient`, use WireMock for the IdP boundary, and assert the controlled
   redirect/error classification and sanitized diagnostics. Assert stable observable outcomes and
   request paths; do not inspect bean fields or Spring internals.
4. Rewrite the decoder-factory validator test to exercise `ReactiveJwtDecoder.decode` against a
   real WireMock JWKS endpoint with signed tokens. Cover a valid token plus invalid temporal and
   OIDC claims needed to prove the default timestamp and ID-token validators remain active. Assert
   errors through Reactor/AssertJ behavior rather than extracting the private validator chain.
5. Keep the public missing-JWK-URI error contract test. Retain the per-registration reuse test only
   if decoder reuse is treated as an intentional class contract; otherwise replace it with an
   observable repeated-decode case or remove it when equivalent integration coverage proves the
   relevant behavior.
6. Remove all `ReflectionTestUtils` imports and all suppressions made unnecessary by deleting
   unchecked private-field casts. Keep the test data deterministic and isolate WireMock lifecycle
   per test class.

### Implementation notes

- The dedicated transport claim is observable because the diagnostic test context sets timeouts
  and pool limits that differ from normal defaults. Delayed WireMock responses should trigger
  those bounds through the real callback path.
- A happy-path callback alone proves interoperability but not that every outbound stage uses the
  dedicated transport. Focused timeout cases provide that evidence without coupling tests to bean
  internals.
- Test JWTs should use generated RSA keys, the registration's issuer and client ID, controlled
  timestamps, and a WireMock-served public JWK set. Reuse existing signing helpers where that keeps
  the test readable.
- Prefer `StepVerifier` for reactive decode results and AssertJ for value/error details.

### Validation

- Run `rg -n "ReflectionTestUtils|getField\\(" src/test/java` and confirm it returns no matches.
- Run `rg -n "@SuppressWarnings|@Disabled|Thread\\.sleep" src/test/java/org/budgetanalyzer/sessiongateway/config`
  and confirm this remediation adds none and removes the decoder-test suppressions.
- Run the focused tests with `./gradlew test --tests '*OAuth2ClientConfigIntegrationTest' --tests '*OAuth2CallbackDiagnosticsIntegrationTest' --tests '*IdpReactiveJwtDecoderFactory*'`.
- Run `./gradlew test --tests '*SecurityConfigIntegrationTest'` to confirm the existing complete
  callback flow still passes.
- Inspect the focused test report and confirm no test is skipped.

### Completion criteria

- No test reads private Spring or application fields to prove OAuth2 client wiring or validator
  composition.
- Observable tests cover dedicated transport behavior for token exchange, JWKS, and userinfo and
  preserve the successful end-to-end callback path.
- JWT decoder tests prove accepted and rejected token behavior through the public decoder API.
- Focused tests pass with no disabled tests or new suppressions.

## Phase 3: Enforce type-based field names and complete repository validation

### Workspace

.

### Goal

Bring `SecurityConfig` class-level dependency names into compliance with the full type-based naming
rule, confirm the branch-touched production code has no equivalent naming violations, and validate
the combined remediation with the repository's required build sequence.

### Scope

- `src/main/java/org/budgetanalyzer/sessiongateway/config/SecurityConfig.java`.
- Branch-touched production Java files returned by
  `git diff --name-only main...HEAD -- src/main/java`
  for a focused class-field naming audit.
- Documentation only if the naming or test cleanup makes an existing statement inaccurate.

### Non-goals

- Do not rename public APIs, Spring bean method names, configuration properties, JSON fields,
  endpoint paths, or external protocol terms.
- Do not perform a repository-wide cosmetic rename unrelated to the three review findings.
- Do not alter security rules, OAuth2 behavior, serialization, or session behavior.
- Do not suppress compiler or Checkstyle warnings.

### Required context

- `../service-common/docs/code-quality-standards.md`, sections `Variable Declarations and Naming`
  and `Class-Level Fields`.
- The critical variable-naming rule in `../service-common/AGENTS.md`.
- `src/main/java/org/budgetanalyzer/sessiongateway/config/SecurityConfig.java` and its integration
  coverage in `src/test/java/org/budgetanalyzer/sessiongateway/config/SecurityConfigIntegrationTest.java`.
- The required validation sequence in this repository's `AGENTS.md`.

### Execution steps

1. Rename these `SecurityConfig` fields and matching constructor parameters/usages to preserve the
   complete declared type in lower camel case:
   - `authorizationRequestResolver` to `serverOAuth2AuthorizationRequestResolver`;
   - `authorizationRequestRepository` to `serverAuthorizationRequestRepository`;
   - `authorizedClientRepository` to `serverOAuth2AuthorizedClientRepository`.
2. Leave already compliant fields such as `serverSecurityContextRepository`,
   `permissionServiceClient`, `sessionWriter`, `sessionCookieHelper`,
   `oauth2CallbackRedirectResolver`, and `jsonMapper` unchanged.
3. Inspect every class-level field in production Java files touched by the branch. Fix an
   equivalent abbreviated or generic field name only when the full declared class/interface type
   provides an unambiguous compliant name and the rename is private and behavior-neutral.
4. Review the combined diff for stale test imports, dead helpers, accidental public API changes,
   documentation drift, wildcard imports, forbidden DTO suffixes, and new suppressions.
5. Run the required formatting and complete build sequence. Fix any formatting, Checkstyle,
   Javadoc, test, or coverage failure caused by the remediation; do not weaken tests or thresholds.
6. Inspect the build output and Gradle problems report. Resolve repository-source compiler or
   Checkstyle warnings introduced or exposed by this work. If the pre-existing unchecked warning
   in `IdpReactiveJwtDecoderFactory` remains, identify its exact compiler location with
   `-Xlint:unchecked` and fix it without a suppression when the fix is in scope and behavior-neutral;
   otherwise record it explicitly rather than claiming a warning-free build.

### Implementation notes

- This is a private identifier cleanup. Constructor injection and Spring bean resolution depend on
  types and qualifiers, so no application behavior should change.
- Standard conventions such as `log` for SLF4J loggers and names for scalar configuration values
  are not class-dependency abbreviation violations.
- Preserve the test and coverage architecture established in Phase 2.

### Validation

- Run `rg -n "authorizationRequestResolver|authorizationRequestRepository|authorizedClientRepository" src/main/java/org/budgetanalyzer/sessiongateway/config/SecurityConfig.java`
  and confirm the abbreviated names are absent.
- Run `git diff --check`, then inspect both `git diff --stat main...HEAD` and the uncommitted
  `git diff` for accidental scope expansion.
- Run the required sequence exactly:

  ```bash
  ./gradlew clean spotlessApply
  ./gradlew clean build
  ```

- Confirm Checkstyle and Spotless pass, all tests execute with zero failures and zero unexpected
  skips, and JaCoCo remains above the configured 90% line and 65% branch thresholds.
- Run `rg -n "ReflectionTestUtils|getField\\(" src/test/java` again and confirm no private-field
  inspection was reintroduced.
- Run `rg -n "@Disabled|@MockBean|@MockitoBean|@SpyBean|@MockitoSpyBean" src/test/java` and confirm
  the remediation introduced none.

### Completion criteria

- `SecurityConfig` dependency fields use full type-based names and all constructor assignments and
  usages compile.
- No equivalent naming violation remains in branch-touched production Java files.
- The documentation and behavior tests from Phases 1 and 2 remain intact.
- The full required build passes with coverage gates satisfied and no remediation-caused warnings.
- The final diff contains only the plan and changes needed to resolve the three review findings.
