package org.budgetanalyzer.sessiongateway.config;

import java.time.Duration;
import java.util.Objects;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Typed configuration for permission-service calls. */
@ConfigurationProperties(prefix = "permission-service")
public record PermissionServiceProperties(String baseUrl, Duration authorizationRefreshTimeout) {

  /** Creates validated permission-service properties. */
  public PermissionServiceProperties {
    if (baseUrl == null || baseUrl.isBlank()) {
      throw new IllegalArgumentException("permission-service.base-url must not be blank.");
    }

    Objects.requireNonNull(
        authorizationRefreshTimeout,
        "permission-service.authorization-refresh-timeout must not be null.");
    if (authorizationRefreshTimeout.isZero() || authorizationRefreshTimeout.isNegative()) {
      throw new IllegalArgumentException(
          "permission-service.authorization-refresh-timeout must be greater than zero.");
    }
  }
}
