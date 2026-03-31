# Session Cookie Contract Alignment And Build Hardening

## Context

The current branch proved two things:

1. Using `SESSION` as the public browser session contract is too generic. It collides with Spring
   WebFlux and Spring Session defaults, which can also emit a `SESSION` cookie.
2. `session-gateway` does not currently meet the repository build standard. `./gradlew clean build`
   fails because:
   - heartbeat clear-cookie tests observe `SameSite=Lax` instead of the intended `Strict`
   - `SessionPropertiesTest` asserts the wrong exception layer

The fix is to stop using `SESSION` as the app-level contract and move to an explicit platform
cookie name that both `session-gateway` and `ext_authz` understand.

Target contract:

- public browser session cookie: `BA_SESSION` by default
- Redis session key prefix: keep `session:`
- ext_authz continues to read the unified Redis hash written by `session-gateway`

The cluster has never been released, so there is no migration — just a clean cut from `SESSION` to
`BA_SESSION` everywhere.

## Goals

1. Remove the public-cookie collision with framework defaults.
2. Restore `session-gateway` to a passing `./gradlew clean build`.
3. Make the cookie contract explicit and documented across repos.

## Non-Goals

- No change to the unified Redis session hash schema in this plan.
- No change to the `session:` Redis key prefix in this plan.
- No change to frontend login routing in this plan.

## Decision

Adopt an explicit app cookie name and treat framework cookies as internal implementation detail.

This plan uses:

- public cookie name: `BA_SESSION`

The exact name can be changed before implementation, but it must not be `SESSION`.

## Session-Gateway Changes

### 1. Separate the public cookie from framework defaults

- Change the default public cookie name in `SessionProperties` and `application.yml` from
  `SESSION` to `BA_SESSION`
- Audit all code paths that read or clear the public cookie so they use `SessionCookieHelper`
  exclusively
- Ensure no code path hardcodes `SESSION`

### 2. Isolate or eliminate internal framework WebSession cookies

- Determine whether Spring Security OAuth2 still creates a WebSession internally during the OAuth2
  round-trip
- Do not allow framework defaults to own the `SESSION` name
- Add a focused integration assertion that the public session lifecycle does not depend on a
  framework cookie name

Implementation note:

- If the OAuth2 flow can run with no framework cookie at all, prefer that
- Current verification in this repository shows the OAuth2 callback emits only `BA_SESSION`

### 3. Fix the current failing build

- Fix heartbeat tests so they validate the intended public cookie behavior after the rename
- Fix `SessionPropertiesTest` to assert the root cause message rather than the outer Spring Boot
  wrapper exception
- Re-run `./gradlew clean build` until the repo is green

### 4. Add regression coverage for the cookie contract

- Add integration coverage for OAuth2 callback setting `BA_SESSION`
- Add integration coverage for heartbeat stale-cookie clearing with `BA_SESSION`
- Add integration coverage for logout clearing `BA_SESSION`
- Add a regression test that a framework cookie, if present, does not reuse the public cookie name
- Keep the existing cookie-domain override coverage and adapt it to `BA_SESSION`

Implemented in this repository on 2026-03-31:

- `SecurityConfigIntegrationTest` verifies the OAuth2 callback emits only `BA_SESSION`
- `SessionControllerTest` verifies stale-cookie clearing uses `BA_SESSION` and ignores a stray
  request `SESSION` cookie
- `LogoutControllerIntegrationTest` verifies logout clears `BA_SESSION`, deletes the Redis hash,
  and keeps a stray framework `SESSION` cookie on its own distinct name
- `SecurityConfigCookieDomainOverrideIntegrationTest` keeps domain-override coverage on
  `BA_SESSION`

### 5. Update local configuration and documentation

- Update `README.md` environment variable documentation for the new default cookie name
- Update `docs/session-configuration.md` to document:
  - default public cookie name (`BA_SESSION`)
  - distinction between public cookie contract and any internal framework cookie
- Update any architecture plan or design doc that still presents `SESSION` as the long-term
  contract

Implemented in this repository on 2026-03-31:

- `src/main/resources/application.yml` wires `SESSION_COOKIE_DOMAIN_OVERRIDE` in the main runtime
  defaults alongside `SESSION_COOKIE_NAME=BA_SESSION`
- `README.md` documents `BA_SESSION` as the public cookie contract shared with ext_authz, not a
  generic framework `SESSION` cookie
- `docs/session-configuration.md` documents the public-versus-framework cookie distinction and the
  host-only default for `SESSION_COOKIE_DOMAIN_OVERRIDE`
- `AGENTS.md` no longer documents `SESSION` as the cookie default

### 6. Optional hardening

- Consider rejecting blank or unsupported cookie names more explicitly in startup validation docs
- Add a startup log line that states the configured public cookie name and whether a domain
  override is enabled
- Add an integration assertion that only the intended public cookie is consumed by `/user` and
  `/auth/session`

Implemented in this repository on 2026-03-31:

- `SessionCookieContractStartupLogger` logs the configured public cookie name and whether a domain
  override is enabled after startup completes
- `SessionCookieContractStartupLoggerTest` covers the startup log output for both host-only and
  domain-override configurations
- `UserControllerIntegrationTest` verifies `/user` rejects a lone framework `SESSION` cookie even
  when it carries a valid Redis session ID
- `SessionControllerTest` verifies `/auth/session` clears only the stale public `BA_SESSION` and
  does not fall back to a valid framework `SESSION` cookie
- `docs/session-configuration.md` now states the current validation boundary explicitly: blank
  cookie names and invalid SameSite values fail startup, but there is no cookie-name allowlist

## Orchestration Changes

### 1. Update ext_authz cookie lookup

- Replace any hardcoded `SESSION` lookup with `BA_SESSION`
- Keep the cookie name configurable via `SESSION_COOKIE_NAME`
- Ensure the deployment path actually uses that setting instead of relying on an implicit code default

### 2. Update deployment configuration

- Add `SESSION_COOKIE_NAME=BA_SESSION` to the checked-in ext_authz deployment manifests as part of the orchestration change
- Add or update any related environment-variable wiring / Helm values / manifests for the session cookie name
- Ensure all environments use `BA_SESSION` unless deliberately overridden
- Keep Redis key prefix aligned with `session-gateway`

### 3. Add ext_authz test coverage

- Add unit or integration coverage for:
  - request with `BA_SESSION` cookie
  - missing or unknown cookie name
- Verify ext_authz does not depend on a cookie named `SESSION`

### 4. Update orchestration documentation

- Document the cookie-name contract as a cross-repo setting
- Document that orchestration sets the ext_authz deployment `SESSION_COOKIE_NAME` explicitly rather than depending on the compiled default
- Remove `SESSION` as the documented default

## Verification Checklist

### Session-Gateway

- `./gradlew clean spotlessApply`
- `./gradlew clean build`
- OAuth2 login callback sets `BA_SESSION`
- `/auth/session` accepts `BA_SESSION` and clears stale `BA_SESSION` correctly
- `/logout` clears `BA_SESSION` correctly
- no production code path depends on a public cookie named `SESSION`

### Orchestration

- ext_authz accepts `BA_SESSION`
- ext_authz does not reference `SESSION` as a cookie name
- checked-in ext_authz deployment manifests set `SESSION_COOKIE_NAME=BA_SESSION`
- `/api/*` authorization works end-to-end through ingress with `BA_SESSION`

## Exit Criteria

- `session-gateway` passes `./gradlew clean build`
- `session-gateway` emits `BA_SESSION`, not `SESSION`
- ext_authz reads `BA_SESSION`
- orchestration deploys ext_authz with `SESSION_COOKIE_NAME=BA_SESSION`
- docs in both repos describe the same cookie contract
