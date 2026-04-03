# Plan: Callback Error Routing Separation

Date: 2026-04-02

Status: Planned

Related documents:

- `docs/bugs/2026-04-02-oauth2-callback-regressions.md`
- `docs/plans/oauth2-callback-reliability-and-refresh-token-contract.md`

## Scope

This plan fixes bug #2 from the 2026-04-02 OAuth2 callback hardening work.

It is only about browser callback failure routing and user-facing error separation.

For the broader service-wide browser error strategy, see
`docs/plans/global-browser-error-routing.md`. This callback plan is a narrower slice, not the full
answer to "never show framework HTML from Session Gateway."

## Problem Statement

The current callback transport fallback is too broad.

`OAuth2CallbackTransportFailureWebExceptionHandler` now rewrites any transport-shaped exception on
`/login/oauth2/code/**` to `/login?error=auth_failed`. That avoids the Spring white-label error
page, but it also misclassifies failures that are not authentication failures.

Examples:

- the dedicated IdP callback client times out during token exchange
- `PermissionServiceClient.fetchPermissions(...)` fails after the user was already authenticated
- Redis session creation fails during login success handling

Only the first case is an authentication failure. The latter two are application failures during
callback completion.

## Decision

The callback path will use two different redirect outcomes:

- actual OAuth2 / IdP / authentication failures redirect to
  `/login?error=auth_failed[&returnUrl=...]`
- unexpected callback-completion failures redirect to `/oops`

`/oops` is a frontend-owned app error route. Session Gateway may redirect to it, but the page
itself belongs to `budget-analyzer-web`. NGINX remains transport only.

## Goals

1. Never show a framework white-label page on the browser OAuth2 callback path.
2. Keep `/login?error=auth_failed` reserved for real authentication failures.
3. Redirect non-auth callback failures to the frontend-owned generic app error page at `/oops`.
4. Keep non-callback paths on their existing error handling behavior.

## Non-Goals

- Do not redirect ordinary in-app API failures to `/oops`.
- Do not turn NGINX into the owner of application error UX.
- Do not blanket-catch `Throwable`.
- Do not redesign all application-wide error handling as part of this bug fix.

## Target Behavior

### Redirect To Login

Redirect to `/login?error=auth_failed` only when the callback failed because authentication itself
did not complete successfully.

This includes:

- authorization-code token exchange failure
- IdP/OIDC userinfo failure that Spring treats as authentication failure
- JWKS / ID token validation failure
- dedicated IdP callback-client transport failure

### Redirect To Oops

Redirect to `/oops` when authentication already succeeded or was far enough along that the failure
is now an application-completion problem rather than an authentication problem.

This includes:

- permission-service failure during login success handling
- Redis session creation failure
- other unexpected callback-path exceptions after the auth step

### Keep Existing Handling Elsewhere

Do not use `/oops` for:

- normal API 4xx/5xx responses rendered inline in the SPA
- existing `/auth/session` or `/auth/token/exchange` API errors
- non-callback server exceptions outside `/login/oauth2/code/**`

## Implementation Plan

## Phase 1: Restrict Login Redirects To Dedicated IdP Failures

### Work

- Add an explicit callback-client failure marker for errors raised by the dedicated IdP callback
  client path.
- Ensure the marker covers the dedicated callback transport path only:
  - authorization-code token exchange
  - OIDC userinfo fetch during browser login
  - JWKS retrieval for ID token validation
- Update `OAuth2CallbackTransportFailureWebExceptionHandler` so it redirects to `/login` only when:
  - the request is on `/login/oauth2/code/**`
  - the response is not committed
  - the exception chain includes the dedicated IdP callback marker

### Rationale

Path matching plus transport-shape classification is not enough. The service must know the failure
came from the dedicated IdP callback client, not from permission-service, Redis, or unrelated
callback-completion work.

## Phase 2: Add A Generic Callback Fallback Redirect

### Work

- Add a second callback-only exception handler for unexpected `Exception`s on
  `/login/oauth2/code/**`.
- This handler must be lower-priority than the dedicated authentication-failure path, but still run
  before the framework falls back to the default error page.
- Redirect those failures to `/oops`.
- Log the failure with sanitized context.

### Guardrails

- Catch `Exception`, not `Throwable`.
- Scope the handler to the callback path only.
- Do not rewrite non-callback failures to `/oops`.

## Phase 3: Frontend-Owned Oops Route

### Work

- Add a frontend route at `/oops` in `budget-analyzer-web`.
- Make it a generic fatal app error page, not a login-specific retry page.
- Keep the page frontend-owned even though Session Gateway may redirect to it.

### Rationale

This route is part of the application UX. NGINX should deliver it, not define it.

### Rollout Constraint

The frontend `/oops` route must ship before or with the Session Gateway redirect change. Redirecting
to `/oops` before the frontend serves that route creates a broken user path.

## Phase 4: Tests And Documentation

### Tests

- dedicated IdP callback transport failure redirects to `/login?error=auth_failed`
- callback failure preserves `returnUrl` on the login redirect when the OAuth state is available
- permission-service callback failure redirects to `/oops`
- session creation failure during callback redirects to `/oops`
- non-callback exceptions do not get rewritten to `/oops`
- no raw OAuth code, tokens, cookies, or raw state values appear in logs

### Documentation

When the code lands, update:

- `AGENTS.md`
- `README.md`
- any callback-behavior docs that describe browser login failure routing

## Exit Criteria

- browser callback failures never surface the framework white-label page
- real authentication failures still land on `/login?error=auth_failed`
- non-auth callback failures land on `/oops`
- the implementation no longer depends on broad transport-shape matching alone
