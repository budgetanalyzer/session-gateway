# Fix: Error contract and test gaps via service-common ErrorWebExceptionHandler

## Context

Code review found two bugs in the global error handler:
1. **High**: Non-browser JSON responses hardcode `type=INTERNAL_ERROR` regardless of actual HTTP status, breaking the shared API error contract
2. **Medium**: Tests don't cover plan exit criteria (browser 404 fallback, JSON contract assertions) and violate shared testing guidance by asserting on `$.message`

Root cause: `GlobalBrowserErrorWebExceptionHandler` duplicates JSON error rendering instead of leveraging service-common's error contract. The fix is to move filter-level JSON error rendering into service-common and simplify session-gateway's handler to only do browser redirects.

## Prerequisite: service-common changes

The following changes must land in service-common **before** starting the session-gateway work. See the plan in `service-common/docs/plans/reactive-error-web-exception-handler.md`.

### Summary of service-common work

**1. Add `resolveException()` default method on `ApiExceptionHandler`**

Extract the exception→response dispatch into a single reusable method:

```java
// on ApiExceptionHandler
record ResolvedError(HttpStatusCode status, ApiErrorResponse response) {}

default ResolvedError resolveException(Throwable throwable) {
    return switch (throwable) {
        case ResourceNotFoundException e    -> new ResolvedError(NOT_FOUND, buildNotFoundError(e));
        case InvalidRequestException e      -> new ResolvedError(BAD_REQUEST, buildInvalidRequestError(e));
        case BusinessException e            -> new ResolvedError(UNPROCESSABLE_ENTITY, buildBusinessError(e));
        case WebExchangeBindException e     -> new ResolvedError(BAD_REQUEST, buildValidationError(extractFieldErrors(e)));
        case ServiceUnavailableException e  -> new ResolvedError(SERVICE_UNAVAILABLE, buildServiceUnavailableError(e));
        case ClientException e              -> new ResolvedError(SERVICE_UNAVAILABLE, buildServiceUnavailableError(e));
        case AccessDeniedException e        -> new ResolvedError(FORBIDDEN, buildPermissionDeniedError());
        case AuthorizationDeniedException e -> new ResolvedError(FORBIDDEN, buildPermissionDeniedError());
        case AuthenticationException e      -> new ResolvedError(UNAUTHORIZED, buildUnauthorizedError());
        case ResponseStatusException e      -> resolveResponseStatus(e);
        default                             -> new ResolvedError(INTERNAL_SERVER_ERROR, buildInternalError((Exception) throwable));
    };
}
```

This calls the existing `build*Error()` default methods — no duplication.

**2. Slim down `ReactiveApiExceptionHandler` `@ExceptionHandler` methods**

Each method becomes: log + `return Mono.just(resolveException(e).toResponseEntity())`. The dispatch logic moves out of the individual `@ExceptionHandler` methods and into `resolveException()`.

**3. Add `ReactiveErrorWebExceptionHandler`**

New class in `service-web`, registered via `ServiceWebAutoConfiguration` alongside `ReactiveApiExceptionHandler`:

- Implements `ErrorWebExceptionHandler`, `ApiExceptionHandler`, `Ordered`
- Order `-1` (replaces Boot's `DefaultErrorWebExceptionHandler`)
- Registered with `@ConditionalOnMissingBean(ErrorWebExceptionHandler.class)` so services can override
- Injects `ObjectMapper` for serialization
- `handle()` calls `resolveException(throwable)`, serializes the `ApiErrorResponse`, writes to the response

This gives every reactive service proper `ApiErrorResponse` JSON for filter-level exceptions automatically.

## Session-gateway changes (this repo)

All steps below depend on the service-common prerequisite being complete and the updated `service-common` dependency being available.

### Step 1: Replace `GlobalBrowserErrorWebExceptionHandler` with `BrowserErrorRedirectHandler`

The handler no longer renders JSON. It only redirects browser routes and passes everything else through to service-common's `ReactiveErrorWebExceptionHandler`.

**Rename** `GlobalBrowserErrorWebExceptionHandler` → `BrowserErrorRedirectHandler`.

New implementation (~20 lines of logic):

```java
@Component
public class BrowserErrorRedirectHandler implements WebExceptionHandler, Ordered {

    private static final Set<String> API_PATH_PREFIXES =
        Set.of("/auth/", "/api/", "/v3/api-docs", "/swagger-ui", "/actuator/");

    private static final Set<String> API_EXACT_PATHS = Set.of("/user");

    @Override
    public int getOrder() { return -2; }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
        if (exchange.getResponse().isCommitted()) {
            return Mono.error(throwable);
        }
        var path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (isApiPath(path)) {
            return Mono.error(throwable); // fall through to common JSON handler
        }
        log.error("Browser route error: exceptionType={} path={}, redirecting to /oops",
            throwable.getClass().getSimpleName(), path);
        exchange.getResponse().setStatusCode(HttpStatus.FOUND);
        exchange.getResponse().getHeaders().setLocation(URI.create("/oops"));
        return exchange.getResponse().setComplete();
    }
}
```

Key changes from current implementation:
- Implements `WebExceptionHandler` (not `ErrorWebExceptionHandler`) so it doesn't suppress service-common's handler via `@ConditionalOnMissingBean`
- Order `-2` (runs before service-common's `-1`)
- No `jsonError()` method, no `JSON_ERROR_BODY`, no `ObjectMapper`
- Path-based routing replaces header sniffing — aligns with `SecurityConfig.authenticationEntryPoint()` which already defines the same API vs browser split
- Non-API paths always redirect; API paths always fall through for JSON rendering

**Why path-based instead of header sniffing**: `SecurityConfig` (line 128-137) already defines which paths are API (`/api/**`, `/user`) vs browser (everything else) via `authenticationEntryPoint()`. `BrowserNavigationRequestClassifier` reimplements this same split using `Sec-Fetch-Mode`/`Sec-Fetch-Dest`/`Accept` headers — a second source of truth that must be kept in sync. Path-based classification eliminates the redundancy.

### Step 2: Delete `BrowserNavigationRequestClassifier`

Remove:
- `src/main/java/org/budgetanalyzer/sessiongateway/security/BrowserNavigationRequestClassifier.java`
- `src/test/java/org/budgetanalyzer/sessiongateway/security/BrowserNavigationRequestClassifierTest.java`

The path-based check is trivial enough to live directly in the handler.

### Step 3: Update integration tests

**File**: `src/test/java/org/budgetanalyzer/sessiongateway/config/GlobalBrowserErrorRoutingIntegrationTest.java`

**3a: Rename test class** to `BrowserErrorRedirectIntegrationTest` to match the renamed handler.

**3b: Remove `$.message` assertion** (testing-patterns.md violation).
In `nonBrowserFilterFailureReturnsJson` (current line 101-102), remove:
```java
.jsonPath("$.message").isEqualTo("An unexpected error occurred")
```

**3c: Add browser 404 test** (plan exit criteria gap).
Add test `browserNavigationToNonExistentPathRedirectsToOops` — hits a genuinely non-existent path (e.g., `/this/path/does/not/exist`) with no special headers, asserts redirect to `/oops`. With path-based classification, no browser headers are needed — the path alone determines routing.

**3d: Strengthen API endpoint tests**.
Tests `apiSessionEndpointStaysJsonOnFailure` (current line 106) and `apiTokenExchangeEndpointStaysJsonOnFailure` (current line 118) currently only assert `Content-Type` doesn't contain `text/html`. Strengthen to:
- Assert `Content-Type` IS `application/json`
- Assert `$.type` exists

**3e: Add status-specific type mapping test**.
Extend the test `WebFilter` to accept an optional `?status=N` query parameter, throwing `ResponseStatusException(N)` when present. Add test `nonBrowserResponseStatusExceptionReturnsMatchingType` — hits `/test/simulate-filter-error?status=404` without browser headers, asserts `$.type` equals `NOT_FOUND` and HTTP status is 404. This validates that service-common's `ReactiveErrorWebExceptionHandler` is correctly wired and producing the right contract.

**3f: Update log-capture setup** to reference `BrowserErrorRedirectHandler` instead of `GlobalBrowserErrorWebExceptionHandler`.

### Step 4: Update handler Javadoc references

The callback handlers reference the global handler in their Javadoc:
- `OAuth2CallbackTransportFailureWebExceptionHandler`
- `OAuth2CallbackUnexpectedFailureWebExceptionHandler`

Update any references from `GlobalBrowserErrorWebExceptionHandler` to `BrowserErrorRedirectHandler`.

## WebExceptionHandler chain (for reference)

After this change, the session-gateway exception handler chain is:

| Order | Handler | Scope |
|-------|---------|-------|
| `-4` | `OAuth2CallbackTransportFailureWebExceptionHandler` | Callback transport errors → redirect to login |
| `-3` | `OAuth2CallbackUnexpectedFailureWebExceptionHandler` | Callback unexpected errors → redirect to /oops |
| `-2` | `BrowserErrorRedirectHandler` (this repo) | Non-API paths → redirect to /oops |
| `-1` | `ReactiveErrorWebExceptionHandler` (service-common) | Everything else → `ApiErrorResponse` JSON |
| _controller level_ | `ReactiveApiExceptionHandler` (service-common) | Controller exceptions → `ApiErrorResponse` JSON |

Each handler returns `Mono.error(throwable)` for exceptions it doesn't own, letting the next handler in the chain pick them up. This is the same pattern the callback handlers already use.

## Verification

```bash
./gradlew test --tests '*BrowserErrorRedirectIntegrationTest'
```
