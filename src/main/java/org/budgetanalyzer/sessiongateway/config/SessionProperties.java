package org.budgetanalyzer.sessiongateway.config;

import java.util.Locale;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for Redis-backed browser sessions and OAuth2 authorization request state.
 *
 * <p>Defaults are defined in {@code application.yml}. This class centralizes access and validates
 * the session contract at startup.
 */
@ConfigurationProperties(prefix = "session")
public record SessionProperties(
    String keyPrefix,
    long ttlSeconds,
    long maxLifetimeSeconds,
    long oauth2StateTtlSeconds,
    CookieProperties cookie) {

  /** Creates validated session properties. */
  public SessionProperties {
    keyPrefix = requireNonBlank(keyPrefix, "session.key-prefix");
    ttlSeconds = requirePositive(ttlSeconds, "session.ttl-seconds");
    if (maxLifetimeSeconds < ttlSeconds) {
      throw new IllegalArgumentException(
          "session.max-lifetime-seconds must be greater than or equal to session.ttl-seconds.");
    }
    oauth2StateTtlSeconds =
        requirePositive(oauth2StateTtlSeconds, "session.oauth2-state-ttl-seconds");

    cookie = Objects.requireNonNull(cookie, "session.cookie must not be null.");
  }

  /** Nested cookie configuration for browser sessions. */
  public record CookieProperties(String name, boolean secure, String sameSite) {

    private static final String HOST_COOKIE_PREFIX = "__Host-";

    /** Creates validated cookie properties. */
    public CookieProperties {
      name = requireNonBlank(name, "session.cookie.name");
      if (!secure
          && name.regionMatches(true, 0, HOST_COOKIE_PREFIX, 0, HOST_COOKIE_PREFIX.length())) {
        throw new IllegalArgumentException(
            "session.cookie.secure must be true when session.cookie.name starts with "
                + HOST_COOKIE_PREFIX
                + ".");
      }
      sameSite = canonicalizeSameSite(sameSite);
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

  private static String canonicalizeSameSite(String sameSite) {
    if (sameSite == null) {
      throw new IllegalArgumentException(
          "session.cookie.same-site must be one of Strict, Lax, or None.");
    }

    return switch (sameSite.trim().toLowerCase(Locale.ROOT)) {
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
