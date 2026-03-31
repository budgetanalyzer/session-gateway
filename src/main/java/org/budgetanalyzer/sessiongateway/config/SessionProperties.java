package org.budgetanalyzer.sessiongateway.config;

import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for Redis-backed browser and token-exchange sessions.
 *
 * <p>Defaults are defined in {@code application.yml}. This class centralizes access and validates
 * the session contract at startup.
 */
@ConfigurationProperties(prefix = "session")
public record SessionProperties(
    String keyPrefix,
    long ttlSeconds,
    long refreshThresholdSeconds,
    long oauth2StateTtlSeconds,
    CookieProperties cookie) {

  /** Creates validated session properties. */
  public SessionProperties {
    keyPrefix = requireNonBlank(keyPrefix, "session.key-prefix");
    ttlSeconds = requirePositive(ttlSeconds, "session.ttl-seconds");
    oauth2StateTtlSeconds =
        requirePositive(oauth2StateTtlSeconds, "session.oauth2-state-ttl-seconds");

    if (refreshThresholdSeconds < 0) {
      throw new IllegalArgumentException(
          "session.refresh-threshold-seconds must be zero or greater.");
    }
    if (refreshThresholdSeconds >= ttlSeconds) {
      throw new IllegalArgumentException(
          "session.refresh-threshold-seconds must be less than session.ttl-seconds.");
    }

    cookie = Objects.requireNonNull(cookie, "session.cookie must not be null.");
  }

  /** Nested cookie configuration for browser sessions. */
  public record CookieProperties(
      String name, String domainOverride, boolean secure, String sameSite) {

    /** Creates validated cookie properties. */
    public CookieProperties {
      name = requireNonBlank(name, "session.cookie.name");
      domainOverride = normalizeOptional(domainOverride);
      sameSite = canonicalizeSameSite(sameSite);
    }

    /** Returns whether the cookie should emit an explicit Domain attribute. */
    public boolean hasDomainOverride() {
      return domainOverride != null;
    }
  }

  private static String requireNonBlank(String value, String propertyName) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(propertyName + " must not be blank.");
    }

    return value;
  }

  private static long requirePositive(long value, String propertyName) {
    if (value <= 0) {
      throw new IllegalArgumentException(propertyName + " must be greater than zero.");
    }

    return value;
  }

  private static String normalizeOptional(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }

    return value;
  }

  private static String canonicalizeSameSite(String sameSite) {
    if (sameSite == null) {
      throw new IllegalArgumentException(
          "session.cookie.same-site must be one of Strict, Lax, or None.");
    }

    return switch (sameSite.trim().toLowerCase(java.util.Locale.ROOT)) {
      case "strict" -> "Strict";
      case "lax" -> "Lax";
      case "none" -> "None";
      default ->
          throw new IllegalArgumentException(
              "Unsupported session.cookie.same-site value '"
                  + sameSite
                  + "'. Expected Strict, Lax, or None.");
    };
  }
}
