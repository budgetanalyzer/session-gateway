# Return URL Support Implementation Plan

**Date:** 2025-11-19
**Status:** Planned (Not Implemented)

## Problem Statement

Session Gateway currently does not support return URLs in the OAuth2 authorization flow. After successful authentication, users are always redirected to the root path `/` regardless of:
- The originally requested URL before login redirect
- An explicit `returnUrl` query parameter

**Current Behavior:**
```
User visits: /dashboard
→ Redirected to Auth0 login
→ After auth success: Lands on / (NOT /dashboard)
```

**Desired Behavior:**
```
User visits: /dashboard
→ Redirected to Auth0 login
→ After auth success: Returns to /dashboard

OR

User clicks: /oauth2/authorization/auth0?returnUrl=/settings
→ Auth0 login
→ After auth success: Lands on /settings
```

## Research Summary

### Current Project Versions
- **Spring Boot:** 3.5.7 (latest stable)
- **Spring Cloud:** 2025.0.0 ("Northfields")
- **Spring Cloud Gateway:** 4.3.0
- **Spring Security:** 6.5.6
- **Java:** 24

### Spring Security WebFlux Saved Request Issue

**Key Finding:** The fundamental saved request issue in Spring Security WebFlux OAuth2Login is **NOT fixed** in any current or upcoming stable releases.

**GitHub Issue #8967** (opened August 2020, still OPEN):
- **Problem:** `SPRING_SECURITY_SAVED_REQUEST` is blank when using WebFlux OAuth2
- **Root Cause:** Issue in `RedirectServerAuthenticationSuccessHandler` with `WebSessionServerRequestCache`
- **Status:** Assigned to milestone 5.5.0, but no PR merged
- **Impact:** Affects Spring Security 6.5.x and likely 7.0.0

**Upgrade Analysis:**
- ❌ **Spring Security 6.5.7** (latest 6.x): Issue not fixed
- ❌ **Spring Cloud Gateway 5.0.0-RC1**: No evidence of OAuth2 fixes, Release Candidate not production-ready
- ❌ **Spring Security 7.0.0**: Requires incompatible Spring Boot 4.0 (currently RC1), no confirmed fixes

**Conclusion:** Custom implementation required - upstream fix unlikely in near term.

## Implementation Approach

### Architecture Overview

The solution implements a custom `ServerRequestCache` that properly saves and restores request URIs across the OAuth2 authentication flow, integrated with Redis session storage.

**Flow Diagram:**
```
┌─────────────────────────────────────────────────────────────────┐
│ 1. User requests protected resource: /dashboard                 │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 2. SecurityConfig detects unauthenticated request               │
│    → CustomServerRequestCache.saveRequest()                     │
│    → Saves "/dashboard" to Redis session                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 3. Redirect to /oauth2/authorization/auth0                      │
│    (or user explicitly visits with ?returnUrl=/settings)        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 4. OAuth2ClientConfig captures explicit returnUrl parameter     │
│    → Saves to session attribute "CUSTOM_RETURN_URL"             │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 5. Auth0 OAuth2 flow completes                                  │
│    → Callback to /login/oauth2/code/auth0                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ 6. OAuth2 Success Handler executes                              │
│    → Check for explicit "CUSTOM_RETURN_URL" in session          │
│    → Else, use CustomServerRequestCache.getRedirectUri()        │
│    → Validate URL (same-origin only)                            │
│    → Redirect to saved URL or default "/"                       │
└─────────────────────────────────────────────────────────────────┘
```

### Components to Implement

#### 1. Custom ServerRequestCache Implementation

**File:** `src/main/java/org/budgetanalyzer/sessiongateway/security/RedisServerRequestCache.java`

**Purpose:**
- Save original request URI to Redis session before OAuth2 redirect
- Retrieve saved URI after successful authentication
- Handle query parameters and path preservation

**Key Methods:**
```java
public class RedisServerRequestCache implements ServerRequestCache {
    private static final String SAVED_REQUEST_KEY = "SPRING_SECURITY_SAVED_REQUEST";

    @Override
    public Mono<Void> saveRequest(ServerWebExchange exchange) {
        // Save full request URI to session
        // Store path + query parameters
    }

    @Override
    public Mono<URI> getRedirectUri(ServerWebExchange exchange) {
        // Retrieve saved URI from session
        // Return Mono.empty() if none saved
    }

    @Override
    public Mono<ServerHttpRequest> removeMatchingRequest(ServerWebExchange exchange) {
        // Clear saved request from session
    }
}
```

**Integration:**
- Works with existing Redis session configuration
- Uses Spring Session's WebSession for storage
- Clears saved request after retrieval to prevent stale redirects

#### 2. SecurityConfig Updates

**File:** `src/main/java/org/budgetanalyzer/sessiongateway/config/SecurityConfig.java`

**Changes Required:**

**a) Add ServerRequestCache Bean:**
```java
@Bean
public ServerRequestCache serverRequestCache() {
    return new RedisServerRequestCache();
}
```

**b) Register in Security Filter Chain:**
```java
.requestCache(requestCache -> requestCache
    .requestCache(serverRequestCache()))
```

**c) Update OAuth2 Success Handler:**

**Current (line 195-308):**
```java
private ServerAuthenticationSuccessHandler createOAuth2SuccessHandler() {
    return (webFilterExchange, authentication) -> {
        // Hardcoded redirect to "/"
        return new RedirectServerAuthenticationSuccessHandler("/")
            .onAuthenticationSuccess(webFilterExchange, authentication);
    };
}
```

**Proposed:**
```java
private ServerAuthenticationSuccessHandler createOAuth2SuccessHandler(
    ServerRequestCache requestCache) {
    return (webFilterExchange, authentication) -> {
        ServerWebExchange exchange = webFilterExchange.getExchange();

        // Priority 1: Check for explicit returnUrl in session
        return exchange.getSession()
            .flatMap(session -> {
                String explicitReturnUrl = session.getAttribute("CUSTOM_RETURN_URL");
                if (explicitReturnUrl != null) {
                    session.getAttributes().remove("CUSTOM_RETURN_URL");
                    return validateAndRedirect(explicitReturnUrl, webFilterExchange, authentication);
                }

                // Priority 2: Check ServerRequestCache for saved request
                return requestCache.getRedirectUri(exchange)
                    .flatMap(uri -> validateAndRedirect(uri.toString(), webFilterExchange, authentication))
                    .switchIfEmpty(Mono.defer(() ->
                        // Priority 3: Default to "/"
                        new RedirectServerAuthenticationSuccessHandler("/")
                            .onAuthenticationSuccess(webFilterExchange, authentication)
                    ));
            });
    };
}

private Mono<Void> validateAndRedirect(
    String redirectUrl,
    WebFilterExchange webFilterExchange,
    Authentication authentication) {

    // Validate URL is same-origin
    if (isValidRedirectUrl(redirectUrl)) {
        return new RedirectServerAuthenticationSuccessHandler(redirectUrl)
            .onAuthenticationSuccess(webFilterExchange, authentication);
    }

    // Invalid URL - redirect to safe default
    return new RedirectServerAuthenticationSuccessHandler("/")
        .onAuthenticationSuccess(webFilterExchange, authentication);
}
```

#### 3. OAuth2ClientConfig Updates

**File:** `src/main/java/org/budgetanalyzer/sessiongateway/config/OAuth2ClientConfig.java`

**Purpose:** Capture explicit `?returnUrl=` query parameter before OAuth2 redirect

**Implementation:**

Add authorization request customizer:
```java
@Bean
public OAuth2AuthorizationRequestCustomizer authorizationRequestCustomizer() {
    return (context) -> {
        ServerWebExchange exchange = context.getExchange();
        String returnUrl = exchange.getRequest().getQueryParams().getFirst("returnUrl");

        if (returnUrl != null && !returnUrl.isEmpty()) {
            // Store in session for retrieval after OAuth2 callback
            exchange.getSession().subscribe(session ->
                session.getAttributes().put("CUSTOM_RETURN_URL", returnUrl)
            );
        }
    };
}
```

Register in `ReactiveOAuth2AuthorizedClientManager` configuration.

#### 4. URL Validation Utility

**File:** `src/main/java/org/budgetanalyzer/sessiongateway/security/RedirectUrlValidator.java`

**Purpose:** Prevent open redirect vulnerabilities

**Security Rules:**
```java
public class RedirectUrlValidator {

    public static boolean isValidRedirectUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        // Must be relative path (starts with /)
        if (!url.startsWith("/")) {
            return false;
        }

        // Reject protocol-relative URLs (//example.com)
        if (url.startsWith("//")) {
            return false;
        }

        // Reject URLs with protocol (http://, https://, javascript:, etc.)
        if (url.contains("://") || url.startsWith("javascript:") || url.startsWith("data:")) {
            return false;
        }

        // Allow only same-origin paths
        return true;
    }
}
```

**Validation Strategy:**
- ✅ Allow: `/dashboard`, `/settings?tab=profile`
- ❌ Reject: `https://evil.com`, `//evil.com`, `javascript:alert(1)`

### Implementation Steps

1. **Create RedisServerRequestCache**
   - Implement `ServerRequestCache` interface
   - Use WebSession for Redis-backed storage
   - Handle save/retrieve/remove operations

2. **Create RedirectUrlValidator**
   - Implement validation logic
   - Add unit tests for edge cases

3. **Update SecurityConfig**
   - Add `serverRequestCache()` bean
   - Update `createOAuth2SuccessHandler()` method signature
   - Implement URL retrieval priority logic
   - Integrate validation

4. **Update OAuth2ClientConfig**
   - Add authorization request customizer
   - Capture `returnUrl` query parameter
   - Store in session

5. **Testing**
   - Unit tests for RedisServerRequestCache
   - Unit tests for RedirectUrlValidator
   - Integration tests for OAuth2 flow:
     - Test automatic saved request
     - Test explicit returnUrl parameter
     - Test security validation (reject external URLs)
     - Test Redis session persistence

6. **Code Quality**
   - Run `./gradlew clean spotlessApply`
   - Run `./gradlew clean build`
   - Fix any Checkstyle violations

## Testing Strategy

### Unit Tests

**RedisServerRequestCacheTest:**
```java
- testSaveRequest_savesUriToSession()
- testGetRedirectUri_retrievesSavedUri()
- testGetRedirectUri_returnsEmptyWhenNoSavedRequest()
- testRemoveMatchingRequest_clearsSession()
- testSaveRequest_preservesQueryParameters()
```

**RedirectUrlValidatorTest:**
```java
- testValidateUrl_allowsRelativePaths()
- testValidateUrl_rejectsAbsoluteUrls()
- testValidateUrl_rejectsProtocolRelativeUrls()
- testValidateUrl_rejectsJavascriptUrls()
- testValidateUrl_rejectsDataUrls()
- testValidateUrl_allowsQueryParameters()
```

### Integration Tests

**OAuth2ReturnUrlIntegrationTest:**
```java
@AutoConfigureWebTestClient
@SpringBootTest(webEnvironment = RANDOM_PORT)
class OAuth2ReturnUrlIntegrationTest {

    @Test
    void testProtectedResourceRedirect_savesOriginalUrl() {
        // Access /dashboard without auth
        // Verify redirect to OAuth2 authorization
        // Verify saved request in Redis session
    }

    @Test
    void testExplicitReturnUrl_redirectsAfterAuth() {
        // Call /oauth2/authorization/auth0?returnUrl=/settings
        // Complete OAuth2 flow (mock)
        // Verify redirect to /settings
    }

    @Test
    void testInvalidReturnUrl_redirectsToDefault() {
        // Call with returnUrl=https://evil.com
        // Complete OAuth2 flow
        // Verify redirect to / (safe default)
    }
}
```

### Manual Testing Checklist

- [ ] Visit `/dashboard` without auth → redirected to Auth0 → after login returns to `/dashboard`
- [ ] Visit `/api/transactions` without auth → after login returns to `/api/transactions`
- [ ] Click explicit link with `?returnUrl=/settings` → after login lands on `/settings`
- [ ] Try malicious URL `?returnUrl=https://evil.com` → after login lands on `/` (rejected)
- [ ] Test with query parameters: `/search?q=test` → preserves query string
- [ ] Test session expiry: saved request cleared after successful redirect
- [ ] Verify Redis session contains saved request before auth
- [ ] Verify Redis session clears saved request after auth

## Security Considerations

### Threat Model

**Open Redirect Vulnerability (PREVENTED):**
- Attacker crafts: `/oauth2/authorization/auth0?returnUrl=https://evil.com/phishing`
- Without validation: User redirected to attacker site after auth
- **Mitigation:** URL validation rejects absolute URLs and protocol-relative URLs

**Session Fixation (MITIGATED):**
- Spring Security creates new session after authentication
- Redis session storage with proper expiry
- Session cookies with HttpOnly, Secure, SameSite flags

**XSS via URL Parameters (PREVENTED):**
- Return URLs validated before storage
- URLs are redirected to (302/307), not rendered in HTML
- No DOM manipulation with user-supplied URLs

**CSRF (ALREADY MITIGATED):**
- OAuth2 state parameter provides CSRF protection
- Session cookies with SameSite=Lax

### Validation Rules

1. **Must be relative path:** Starts with `/`
2. **No protocol-relative URLs:** Reject `//example.com`
3. **No absolute URLs:** Reject `http://`, `https://`
4. **No JavaScript/Data URLs:** Reject `javascript:`, `data:`
5. **Same-origin only:** All redirects to same domain

### Logging

Add security audit logging:
```java
log.info("Saved return URL for session: {}", sanitizedUrl);
log.warn("Rejected invalid return URL: {}", sanitizedUrl);
log.info("Redirecting authenticated user to: {}", sanitizedUrl);
```

## Edge Cases

1. **Multiple login tabs:** Each session maintains separate saved request
2. **Session expiry during OAuth2 flow:** Saved request lost → redirect to `/`
3. **Direct visit to `/oauth2/authorization/auth0`:** No saved request → redirect to `/`
4. **Refresh token flow:** Should not affect saved request (already authenticated)
5. **Logout then login:** Previous saved request cleared
6. **Deep links with query params:** Preserve full query string in saved request

## Rollback Plan

If issues arise post-deployment:

1. **Immediate:** Revert SecurityConfig to hardcoded "/" redirect
2. **Session cleanup:** Saved requests in Redis will expire naturally (30min TTL)
3. **Monitoring:** Watch for redirect loop errors or Auth0 callback failures

## Success Criteria

- ✅ User accessing protected resource returns to that resource after login
- ✅ Explicit `returnUrl` parameter works correctly
- ✅ Invalid/malicious URLs rejected safely
- ✅ All unit and integration tests pass
- ✅ No Checkstyle violations
- ✅ Redis session storage works correctly
- ✅ No impact on existing OAuth2 flows
- ✅ Security audit logging in place

## Future Enhancements

1. **Whitelist specific allowed paths** (if more restrictive control needed)
2. **Support for multiple Auth0 tenants** with different redirect rules
3. **Admin UI to view/debug saved requests** in Redis
4. **Metrics/telemetry** for return URL usage patterns
5. **Timeout for saved requests** (auto-clear after N minutes)

## References

- Spring Security Issue #8967: https://github.com/spring-projects/spring-security/issues/8967
- Spring Security Issue #6341: https://github.com/spring-projects/spring-security/issues/6341
- Spring Security WebFlux Docs: https://docs.spring.io/spring-security/reference/reactive/oauth2/login/index.html
- OWASP Open Redirect: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html

## Notes

- This is a **custom implementation** due to lack of upstream fix in Spring Security WebFlux
- The approach integrates cleanly with existing Redis session management
- URL validation is critical for security - do not skip or weaken validation
- Test thoroughly with real Auth0 tenant before production deployment
