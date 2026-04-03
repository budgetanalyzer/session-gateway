# Plan: OAuth2 Callback Reliability via Dedicated IdP Connection Pooling

Date: 2026-04-01

Status: Phases 1, 2, and 3 implemented on 2026-04-02

This file keeps its historical path for link stability, but the refresh-token contract is no longer
part of its scope.

Related documents:

- `docs/plans/auth0-session-revocation-tradeoffs.md` for the browser-session policy decision
- `docs/plans/local-session-revocation-and-refresh-token-removal.md` for refresh-token removal and
  local session revocation work

## Scope

This plan is only about hardening the browser OAuth2 callback path.

It does not cover:

- browser refresh-token policy
- heartbeat-driven IdP grant validation
- local revoke-all-session design
- broader auth-session contract changes

## Problem Statement

The Auth0 white-label callback failure is a transport-reliability problem in the browser login
path.

The important diagnosis has not changed:

- the failure is not explained by logout handling
- the failure is not explained by missing OAuth state
- the failure is not explained by a bad `/peace` redirect flow

The weak point is the outbound IdP/OIDC HTTP path used during the OAuth2 callback, especially the
authorization-code token exchange and the immediate follow-up identity fetches. Relying on the
default unmanaged reactive client path leaves connection reuse, acquisition, and timeout behavior
too implicit for a latency-sensitive login callback.

## Goals

1. Put Auth0 and OIDC callback traffic on a dedicated `ConnectionProvider` / `HttpClient` /
   `WebClient` path with explicit pooling behavior.
2. Make connection-level callback failures land in the controlled login failure flow instead of a
   generic 500 or white-label page.
3. Preserve `returnUrl` on callback failure when the OAuth state can still be reconstructed.
4. Add safe diagnostics that distinguish connection acquisition, connect timeout, response timeout,
   and upstream error cases without leaking tokens, codes, or raw state values.

## Non-Goals

- Do not use this plan to reintroduce browser refresh-token requirements.
- Do not tie callback hardening to the separate browser-session revocation decision.
- Do not broaden this into a full redesign of all outbound HTTP clients in the service.
- Do not change the external login flow shape if connection-pool isolation is sufficient.

## Implementation Plan

## Phase 1: Dedicated IdP Client Path

Implementation status:

- implemented in Session Gateway on 2026-04-02
- dedicated connection pool, HttpClient, WebClient, and callback bean wiring are now explicit in
  code
- remaining work in this plan is Phase 2 controlled failure routing and Phase 3 diagnostics and
  verification

### Work

- Add a dedicated Auth0/OIDC `ConnectionProvider` with explicit pool configuration instead of using
  the default shared Reactor Netty client state.
- Add a dedicated IdP `HttpClient` that sets explicit transport behavior for:
  - connection acquisition timeout
  - connect timeout
  - response timeout
  - any small set of channel options or handlers needed to avoid hanging callback exchanges
- Expose a dedicated IdP `WebClient` built on that client.
- Keep this configuration narrowly scoped to Auth0/OIDC traffic rather than making it the generic
  application default.

### Minimum Wiring

The dedicated client must cover the browser callback critical path:

- authorization-code token exchange used by `oauth2Login`
- OIDC userinfo or equivalent identity fetch performed during browser login success handling

If the current code path makes other Auth0 calls share the same failure mode, they can use the
same dedicated client, but callback hardening is the primary target.

### Exit Criteria

- Browser callback traffic no longer uses the default unmanaged IdP client path.
- Pool sizing and timeout behavior are explicit in code and easy to reason about during incidents.

## Phase 2: Controlled Failure Routing

Implementation status:

- implemented in Session Gateway on 2026-04-02
- callback-path transport failures now redirect to `/login?error=auth_failed` instead of falling
  through to the framework error page
- `returnUrl` is preserved on controlled failure redirects when the OAuth2 state was reconstructed
  successfully

### Work

- Catch connection-pool exhaustion, connect failures, read/response timeouts, and similar transport
  exceptions on the callback path.
- Map those failures to the existing controlled login failure route instead of letting them surface
  as a framework-level 500 page.
- Preserve `returnUrl` on failure when the OAuth state was recovered successfully.
- Fall back to `/login?error=auth_failed` when `returnUrl` cannot be reconstructed safely.

### Exit Criteria

- A transport failure during callback redirects to `/login?error=auth_failed` instead of producing
  a white-label error page.
- `returnUrl` survives the failure path whenever the reconstructed state makes that safe.

## Phase 3: Diagnostics And Verification

Implementation status:

- implemented in Session Gateway on 2026-04-02
- dedicated callback diagnostics now classify pool-acquire, connect, response-timeout, and
  upstream 4xx/5xx failures without logging raw OAuth codes, tokens, cookies, or raw state values
- integration coverage now proves the browser callback path honors the dedicated timeout and pool
  settings instead of falling back to a white-label 500 page

### Work

- Add safe logging around the IdP callback client path with enough detail to separate:
  - pool-acquire timeout
  - TCP connect failure
  - upstream response timeout
  - upstream 4xx or 5xx response
- Do not log raw authorization codes, tokens, cookies, or raw OAuth state values.
- Add tests that prove the callback path uses the dedicated client configuration and failure
  mapping.

### Tests

- callback token-exchange transport failure redirects to `/login?error=auth_failed`
- callback failure preserves `returnUrl` when OAuth state lookup succeeds
- callback failure does not leak raw OAuth state, code, or token values in logs
- dedicated IdP client bean is used by the browser callback path
- repeated callback attempts under constrained connection-pool conditions fail in the controlled
  path rather than via a white-label 500

### Manual Verification

- reproduce the original callback failure scenario against the hardened client path
- verify repeated browser logins no longer hit the generic callback error page under the original
  reproduction conditions
- inspect logs to confirm failure classification is specific but sanitized

Manual verification completed in automated form for the dedicated timeout and constrained-pool
scenarios via integration tests. Reproducing the original environment-specific white-label failure
against a live Auth0 path is still an operational smoke test, not something this repository can
prove offline.

## Design Constraints

- Keep the fix focused. The point is to harden the callback transport path, not to smuggle in a
  second session-policy discussion.
- Avoid hidden defaults. If connection pooling is central to the fix, pool behavior must be
  explicit in code.
- Do not solve pool isolation by disabling reuse entirely unless there is hard evidence that reuse
  itself is the defect. That is the blunt fallback, not the default design.

## Expected Outcome

After this plan lands, browser OAuth2 callbacks should be resilient to the transport failure mode
behind the Auth0 white-label page. The callback path should either complete successfully or fail
through the normal login error flow with preserved deep-link context when possible.
