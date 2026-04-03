# Plan: Global Browser Error Routing

Date: 2026-04-02

Status: Implemented

Related documents:

- `docs/plans/callback-error-routing-separation.md`
- `docs/plans/oauth2-callback-reliability-and-refresh-token-contract.md`

## Scope

This plan extends the existing callback-only hardening into a service-wide browser error strategy.

It is about removing framework-rendered HTML error pages from Session Gateway for browser document
requests and replacing them with controlled redirects to the frontend-owned `/oops` route.

## Problem Statement

The current implementation does not satisfy the stronger requirement "never show a white-label page
from this app."

What exists today:

- callback-path failures on `/login/oauth2/code/**` are already intercepted by dedicated
  `WebExceptionHandler` beans
- dedicated IdP transport/authentication failures redirect to `/login?error=auth_failed`
- other callback-completion failures redirect to `/oops`

What does not exist today:

- a global browser error fallback for non-callback failures
- an explicit replacement for Spring Boot's reactive default error page behavior

Why this gap is real:

- Istio routes only auth-lifecycle paths to session-gateway (`/oauth2/**`, `/login/oauth2/**`,
  `/auth/**`, `/logout`, `/user`). Browser-facing static asset paths (`/`, `/index.html`,
  `/assets/**`, `/@vite/**`) are routed to NGINX by the catch-all app-httproute and never reach
  this service. The residual `permitAll` rules for those paths have been removed from
  `SecurityConfig`.
- The browser navigations that *do* reach session-gateway are: `/oauth2/authorization/idp` (start
  OAuth2 flow), `/login/oauth2/code/idp` (callback), and `/logout`. Failures on these paths are
  the real scope of this plan.
- `service-web` contributes `ReactiveApiExceptionHandler`, but that is `@RestControllerAdvice`
  focused on API-style responses, not a replacement for Boot's reactive error fallback
- Spring Boot 3.5.7 still auto-configures `DefaultErrorWebExceptionHandler` for WebFlux at order
  `-1`, and that handler has a dedicated `acceptsTextHtml()` branch plus whitelabel rendering when
  enabled

As a result, non-callback exceptions on auth-lifecycle browser navigations that escape normal
controller advice can still fall through to framework HTML error rendering.

## Decision

Session Gateway will own a global browser-navigation error strategy:

- callback-specific failures keep their existing special handling
- all other uncommitted browser document requests that reach the global WebFlux error fallback will
  redirect to `/oops`
- API and machine-consumed routes keep structured non-HTML error responses

`/oops` remains frontend-owned. Session Gateway only redirects to it.

## Goals

1. Never serve Spring framework HTML error UI for uncommitted browser document requests.
2. Preserve `/login?error=auth_failed` for real OAuth2/IdP authentication failures on the callback
   path.
3. Preserve JSON error contracts for API and machine-consumed endpoints.
4. Keep the redirect target on the same origin at frontend route `/oops`.

## Non-Goals

- Do not claim redirects are possible after the response is committed.
- Do not claim redirects are possible after a broken TCP connection or upstream proxy failure.
- Do not convert API failures into HTML redirects.
- Do not move application error-page ownership into NGINX.
- Do not broaden `/login?error=auth_failed` into a generic operational-failure bucket.

## Required Clarification

The literal statement "never show a white-label page anywhere" is too absolute to be technically
defensible. Once bytes are committed, or the connection dies before a redirect can be sent, the app
cannot recover the browser experience.

The practical contract should be:

- no Spring Boot white-label HTML for uncommitted browser document requests handled by Session
  Gateway

That is the strongest guarantee the service can actually enforce.

## Target Behavior

### Callback Path

Keep the existing split on `/login/oauth2/code/**`:

- dedicated IdP/authentication failures redirect to `/login?error=auth_failed[&returnUrl=...]`
- non-auth callback-completion failures redirect to `/oops`

### Non-Callback Browser Document Requests

For browser navigations outside the callback path:

- if an exception escapes to the global WebFlux error fallback before the response is committed,
  redirect to `/oops`
- do not render framework HTML error pages

Examples:

- unexpected failure during `/oauth2/authorization/idp`
- unexpected failure during `/logout`
- browser navigation to a Session Gateway-served HTML path that fails before completion
- framework-level 404/500 handling on browser-facing paths that would otherwise render Boot HTML

### API And Machine Requests

For API-style routes, keep non-HTML responses:

- `/auth/session`
- `/auth/token/exchange`
- `/user`
- `/api/**`
- OpenAPI and other developer endpoints unless explicitly reclassified

These routes must not start returning `/oops` redirects just because a browser-like `Accept` header
appears.

## Implementation Plan

## Phase 1: Define Browser Document Request Classification

### Work

- Introduce an explicit request classifier for "browser document navigation" rather than relying on
  `Accept: text/html` alone.
- Use a combination of signals:
  - `GET` or `HEAD`
  - browser navigation headers when present (`Sec-Fetch-Mode: navigate`,
    `Sec-Fetch-Dest: document`)
  - explicit exclusion of API/machine endpoints
- Treat callback requests separately so the existing callback handlers stay authoritative.

### Rationale

`Accept` alone is too broad. SPA fetches, developer tools, and some programmatic clients can send
browser-like accept headers. The classifier has to protect the JSON contract first.

## Phase 2: Replace Boot's Reactive HTML Error Fallback

### Work

- Add a custom reactive `ErrorWebExceptionHandler` bean so Boot's
  `DefaultErrorWebExceptionHandler` is no longer the active global fallback in this application.
- Implement the custom handler by extending the reactive error infrastructure, not by scattering
  broad `try/catch` logic across controllers.
- Behavior:
  - browser document requests redirect to `/oops`
  - non-browser requests return a sanitized JSON error response
- Keep logging structured and sanitized.

### Rationale

This is the right interception point for the gap that still exists. The problem is not normal
controller exceptions that `ReactiveApiExceptionHandler` already handles; it is the framework-level
fallback path that still knows how to render HTML.

## Phase 3: Preserve Callback-Specific Priority

### Work

- Keep `OAuth2CallbackTransportFailureWebExceptionHandler` first for dedicated IdP/auth failures.
- Keep `OAuth2CallbackUnexpectedFailureWebExceptionHandler` immediately after it for generic
  callback-completion failures.
- Ensure the new global error fallback does not rewrite those cases into a different outcome.

### Rationale

The callback path already has business-specific semantics. The global handler is a safety net for
everything else, not a replacement for that routing.

## Phase 4: Add Defense-In-Depth Configuration

### Work

- Explicitly set `server.error.whitelabel.enabled=false` once the custom fallback is in place.
- Keep `/error` reachable internally so the reactive error pipeline still works.
- Document that disabling whitelabel alone is not the fix; it is only a secondary guardrail.

### Rationale

If the custom handler is accidentally removed later, the property reduces the chance of silently
reintroducing the Boot HTML page. On its own, though, it does not provide the `/oops` behavior you
want.

## Phase 5: Tests

### Integration Tests

- non-callback browser HTML request failure redirects to `/oops`
- callback dedicated IdP transport failure still redirects to
  `/login?error=auth_failed[&returnUrl=...]`
- callback completion failure still redirects to `/oops`
- API failure on `/auth/session` stays non-redirecting and non-HTML
- API failure on `/auth/token/exchange` stays JSON
- browser-facing 404 fallback does not render Boot HTML
- no raw OAuth code, tokens, cookies, or raw state values appear in logs

### Test Design Notes

- include at least one failure that bypasses normal controller advice, otherwise the test does not
  exercise the global fallback being added
- assert `Location: /oops` and absence of `text/html` error body generation from Boot

## Phase 6: Rollout Coordination

### Work

- Confirm `budget-analyzer-web` already serves `/oops` on the same origin in every environment
  before rollout.
- Verify ingress routing still sends the redirected `/oops` request to NGINX/frontend rather than
  back into Session Gateway.
- Roll out the frontend route before or with the backend change.

### Rationale

Redirecting to a route that is not universally available just replaces one broken browser path with
another.

## Exit Criteria

- Session Gateway no longer serves Spring Boot white-label HTML for uncommitted browser document
  requests
- callback auth failures still land on `/login?error=auth_failed`
- callback non-auth failures still land on `/oops`
- API routes still return non-HTML error responses
- the behavior is covered by integration tests, not just unit tests
