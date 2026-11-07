package org.budgetanalyzer.sessiongateway.config;

import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Typed configuration for permission-service calls. */
@ConfigurationProperties(prefix = "permission-service")
public record PermissionServiceProperties(
    String baseUrl, Duration loginTimeout, Duration authorizationRefreshTimeout) {

  /** Creates validated permission-service properties. */
  public PermissionServiceProperties {
    if (baseUrl == null || baseUrl.isBlank()) {
      throw new IllegalArgumentException("permission-service.base-url must not be blank.");
    }

    requirePositive(loginTimeout, "permission-service.login-timeout");
    requirePositive(
        authorizationRefreshTimeout, "permission-service.authorization-refresh-timeout");
  }

  private static void requirePositive(Duration duration, String propertyName) {
    Objects.requireNonNull(duration, propertyName + " must not be null.");
    if (duration.isZero() || duration.isNegative()) {
      throw new IllegalArgumentException(propertyName + " must be greater than zero.");
    }
  }
}
