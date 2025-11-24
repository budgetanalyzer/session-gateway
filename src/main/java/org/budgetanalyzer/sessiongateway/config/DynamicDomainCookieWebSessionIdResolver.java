package org.budgetanalyzer.sessiongateway.config;

import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.session.CookieWebSessionIdResolver;

/**
 * Custom WebSessionIdResolver that sets the cookie domain dynamically based on the request's host.
 *
 * <p>This resolver extracts the root domain from the request URI (which respects X-Forwarded-Host
 * when ForwardedHeaderTransformer is active) and sets it as the cookie domain. This ensures the
 * session cookie is shared across subdomains (e.g., app.budgetanalyzer.localhost and
 * api.budgetanalyzer.localhost).
 *
 * <p>Examples of domain extraction:
 *
 * <ul>
 *   <li>app.budgetanalyzer.localhost → budgetanalyzer.localhost
 *   <li>api.budgetanalyzer.localhost → budgetanalyzer.localhost
 *   <li>app.budgetanalyzer.com → budgetanalyzer.com
 *   <li>localhost → null (no domain set)
 * </ul>
 *
 * <h2>KNOWN ISSUE: Envoy Gateway Host Header Rewriting</h2>
 *
 * <p><strong>Expected behavior:</strong> Envoy Gateway should preserve the original Host header
 * (app.budgetanalyzer.localhost) when proxying to session-gateway, OR set X-Forwarded-Host to
 * preserve the original hostname. This would allow dynamic domain extraction to work correctly.
 *
 * <p><strong>Actual behavior:</strong> Envoy Gateway rewrites the Host header to the internal pod
 * IP address (e.g., 10.244.0.18:8081) and does NOT set X-Forwarded-Host. This causes the dynamic
 * domain extraction to fail because:
 *
 * <ul>
 *   <li>IP addresses cannot be used as cookie domains
 *   <li>The extracted domain becomes null instead of "budgetanalyzer.localhost"
 *   <li>Cookies are scoped to the pod IP, not the actual hostname
 * </ul>
 *
 * <p><strong>Current workaround:</strong> A configurable domain override is used via {@code
 * session.cookie.domain-override}. The dynamic extraction logic continues to run for debugging
 * purposes, but the final cookie domain is taken from the configuration.
 *
 * <p><strong>Debugging output:</strong> All dynamic resolution logic and logging is preserved to
 * help diagnose when/if Envoy Gateway behavior is fixed. Check logs for comparison between
 * dynamically extracted domain and configured override.
 *
 * <p>See {@code kubernetes/gateway/app-httproute.yaml} for Envoy Gateway routing configuration.
 */
public class DynamicDomainCookieWebSessionIdResolver extends CookieWebSessionIdResolver {

  private static final Logger log =
      LoggerFactory.getLogger(DynamicDomainCookieWebSessionIdResolver.class);

  /**
   * Configurable cookie domain override.
   *
   * <p>This value is used as the final cookie domain, bypassing dynamic extraction which currently
   * fails due to Envoy Gateway rewriting the Host header to pod IP addresses.
   *
   * <p>Set to the root domain (e.g., "budgetanalyzer.localhost") to share cookies across
   * subdomains. Set to empty string to disable override and use dynamic extraction.
   */
  @Value("${session.cookie.domain-override:}")
  private String domainOverride;

  @Override
  public List<String> resolveSessionIds(ServerWebExchange exchange) {
    var cookieMap = exchange.getRequest().getCookies();
    var cookies = cookieMap.get(getCookieName());
    if (cookies == null) {
      return List.of();
    }
    return cookies.stream().map(HttpCookie::getValue).toList();
  }

  @Override
  public void setSessionId(ServerWebExchange exchange, String id) {
    Assert.notNull(id, "'id' is required");

    log.debug("=== setSessionId called ===");
    log.debug("Session ID (first 8 chars): {}", id.substring(0, Math.min(8, id.length())));

    var cookie = buildSessionCookie(exchange, id, getCookieMaxAge());
    exchange.getResponse().getCookies().set(getCookieName(), cookie);

    log.debug("Cookie set in response: {}", cookie);
  }

  @Override
  public void expireSession(ServerWebExchange exchange) {
    var cookie = buildSessionCookie(exchange, "", Duration.ZERO);
    exchange.getResponse().getCookies().set(getCookieName(), cookie);
  }

  private ResponseCookie buildSessionCookie(
      ServerWebExchange exchange, String value, Duration maxAge) {
    var uriHost = exchange.getRequest().getURI().getHost();
    var forwardedHost = exchange.getRequest().getHeaders().getFirst("X-Forwarded-Host");
    var hostHeader = exchange.getRequest().getHeaders().getFirst("Host");

    log.debug("=== buildSessionCookie - Host Resolution ===");
    log.debug("URI host (from exchange): {}", uriHost);
    log.debug("X-Forwarded-Host header: {}", forwardedHost);
    log.debug("Host header: {}", hostHeader);
    log.debug("Full URI: {}", exchange.getRequest().getURI());

    // Use X-Forwarded-Host if available, otherwise Host header, finally URI host
    var host = forwardedHost != null ? forwardedHost : hostHeader != null ? hostHeader : uriHost;
    log.debug("Using host for domain extraction: {}", host);

    var extractedDomain = extractDomain(host);
    log.debug("Extracted domain: {}", extractedDomain);

    // Determine final domain: use override if configured, otherwise use extracted
    String finalDomain;
    if (domainOverride != null && !domainOverride.isEmpty()) {
      finalDomain = domainOverride;
      if (extractedDomain == null) {
        log.warn(
            "=== DOMAIN MISMATCH === Extracted domain is NULL, using override: {}", domainOverride);
      } else if (!extractedDomain.equals(domainOverride)) {
        log.warn(
            "=== DOMAIN MISMATCH === Extracted: {}, Override: {} - using override",
            extractedDomain,
            domainOverride);
      } else {
        log.debug(
            "=== DOMAIN MATCH === Extracted and override both: {} - Envoy may be fixed!",
            extractedDomain);
      }
    } else {
      finalDomain = extractedDomain;
      log.debug("No domain override configured, using extracted domain: {}", extractedDomain);
    }

    log.debug("Final cookie domain: {}", finalDomain);

    var builder =
        ResponseCookie.from(getCookieName(), value)
            .path("/")
            .maxAge(maxAge)
            .httpOnly(true)
            .secure(true)
            .sameSite("None");

    if (finalDomain != null) {
      builder.domain(finalDomain);
    }

    var cookie = builder.build();
    log.debug(
        "Built cookie: name={}, domain={}, path={}, secure={}, httpOnly={}, sameSite={}",
        cookie.getName(),
        cookie.getDomain(),
        cookie.getPath(),
        cookie.isSecure(),
        cookie.isHttpOnly(),
        cookie.getSameSite());

    return cookie;
  }

  /**
   * Extract root domain from host.
   *
   * <p>For subdomains like "app.budgetanalyzer.localhost", returns "budgetanalyzer.localhost". For
   * plain "localhost", returns null (no domain needed).
   *
   * @param host the host from the request URI
   * @return the root domain, or null if no domain should be set
   */
  private String extractDomain(String host) {
    if (host == null || "localhost".equals(host)) {
      log.debug("extractDomain: host is null or localhost, returning null");
      return null;
    }

    // Strip port if present (e.g., "app.example.com:8081" -> "app.example.com")
    var hostWithoutPort = host.contains(":") ? host.substring(0, host.indexOf(':')) : host;
    log.debug("extractDomain: host={}, hostWithoutPort={}", host, hostWithoutPort);

    // Check if this is an IP address (all parts are numeric)
    var parts = hostWithoutPort.split("\\.");
    if (isIpAddress(parts)) {
      log.debug("extractDomain: detected IP address, returning null (no domain for IPs)");
      return null;
    }

    log.debug("extractDomain: parts count={}", parts.length);

    if (parts.length >= 2) {
      var domain = parts[parts.length - 2] + "." + parts[parts.length - 1];
      log.debug("extractDomain: extracted domain={}", domain);
      return domain;
    }

    log.debug("extractDomain: not enough parts, returning null");
    return null;
  }

  /**
   * Check if the host parts represent an IP address.
   *
   * @param parts the host split by "."
   * @return true if all parts are numeric (IPv4 address)
   */
  private boolean isIpAddress(String[] parts) {
    if (parts.length != 4) {
      return false;
    }
    for (String part : parts) {
      try {
        int num = Integer.parseInt(part);
        if (num < 0 || num > 255) {
          return false;
        }
      } catch (NumberFormatException e) {
        return false;
      }
    }
    return true;
  }
}
