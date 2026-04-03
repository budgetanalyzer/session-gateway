# OAuth2 Callback Regressions

Date: 2026-04-02

Status: Open

This document records two correctness bugs introduced by the 2026-04-02 browser OAuth2 callback
hardening work.

## 1. Custom OIDC decoder weakens ID token validation

Severity: P2

Status: Fixed (2026-04-02)

Affected code:

- `src/main/java/org/budgetanalyzer/sessiongateway/config/IdpReactiveJwtDecoderFactory.java`

Problem:

`IdpReactiveJwtDecoderFactory` replaces Spring Security's default ID token validator chain with a
bare `OidcIdTokenValidator`:

- `NimbusReactiveJwtDecoder#setJwtValidator(new OidcIdTokenValidator(clientRegistration))`

That is not equivalent to the framework default. Spring's
`ReactiveOidcIdTokenDecoderFactory` keeps the OIDC validator and the default JWT validators
together. Replacing the validator outright drops default checks that Spring previously enforced.

Impact:

- an ID token with a future `nbf` claim can now be accepted when Spring would previously reject it
- any other condition enforced by Spring's default validator chain can also be skipped
- the dedicated JWKS client change therefore introduces a real authentication validation regression

Fix applied:

- wrapped `OidcIdTokenValidator` with `JwtValidators.createDefaultWithValidators(...)` to preserve
  Spring's default validator chain (`JwtTimestampValidator`, `X509CertificateThumbprintValidator`)
  alongside the OIDC-specific validation
- added unit test `IdpReactiveJwtDecoderFactoryTest` verifying the validator chain composition

## 2. Callback transport redirect handler is scoped too broadly

Severity: P2

Affected code:

- `src/main/java/org/budgetanalyzer/sessiongateway/security/OAuth2CallbackTransportFailureWebExceptionHandler.java`

Problem:

`OAuth2CallbackTransportFailureWebExceptionHandler` redirects any transport-classified exception on
`/login/oauth2/code/**` to `/login?error=auth_failed`. The current check only confirms:

- the response is not committed
- the request path starts with `/login/oauth2/code/`
- `OAuth2CallbackFailureClassifier` sees a transport-shaped exception somewhere in the cause chain

That scope is too broad. It does not prove the failure came from the dedicated IdP/OIDC callback
client.

Impact:

- a `WebClientRequestException` from `PermissionServiceClient.fetchPermissions(...)` can be
  rewritten as a login callback failure
- a transport-shaped failure while creating the Redis-backed session during login success handling
  can also be rewritten as `/login?error=auth_failed`
- unrelated downstream outages are therefore masked as authentication failures, which can trigger
  pointless re-login loops and hide the real operational fault

Required fix direction:

- limit the redirect behavior to failures raised by the dedicated IdP callback client path
- let unrelated downstream or session-creation failures fall through to normal error handling
- fix plan recorded in `docs/plans/callback-error-routing-separation.md`
