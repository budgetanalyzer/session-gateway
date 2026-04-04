package org.budgetanalyzer.sessiongateway.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Typed configuration for the dedicated outbound IdP/OIDC HTTP client.
 *
 * <p>This client is scoped to the browser OAuth2 callback path so connection pooling and timeout
 * behavior stay explicit and isolated from unrelated outbound traffic.
 */
@ConfigurationProperties(prefix = "idp.http-client")
public record IdpHttpClientProperties(
    String poolName,
    int maxConnections,
    int pendingAcquireMaxCount,
    Duration pendingAcquireTimeout,
    Duration maxIdleTime,
    Duration maxLifeTime,
    Duration evictionInterval,
    Duration connectTimeout,
    Duration responseTimeout,
    Duration readTimeout,
    Duration writeTimeout) {

  /** Creates validated IdP HTTP client properties. */
  public IdpHttpClientProperties {
    poolName = requireNonBlank(poolName, "idp.http-client.pool-name");
    maxConnections = requirePositive(maxConnections, "idp.http-client.max-connections");
    pendingAcquireMaxCount =
        requirePositive(pendingAcquireMaxCount, "idp.http-client.pending-acquire-max-count");
    pendingAcquireTimeout =
        requirePositiveDuration(pendingAcquireTimeout, "idp.http-client.pending-acquire-timeout");
    maxIdleTime = requirePositiveDuration(maxIdleTime, "idp.http-client.max-idle-time");
    maxLifeTime = requirePositiveDuration(maxLifeTime, "idp.http-client.max-life-time");
    evictionInterval =
        requirePositiveDuration(evictionInterval, "idp.http-client.eviction-interval");
    connectTimeout = requirePositiveDuration(connectTimeout, "idp.http-client.connect-timeout");
    responseTimeout = requirePositiveDuration(responseTimeout, "idp.http-client.response-timeout");
    readTimeout = requirePositiveDuration(readTimeout, "idp.http-client.read-timeout");
    writeTimeout = requirePositiveDuration(writeTimeout, "idp.http-client.write-timeout");

    if (connectTimeout.toMillis() > Integer.MAX_VALUE) {
      throw new IllegalArgumentException(
          "idp.http-client.connect-timeout must be 2147483647ms or less.");
    }
  }

  private static String requireNonBlank(String value, String propertyName) {
    if (value == null || value.isBlank()) {
      throw new IllegalArgumentException(propertyName + " must not be blank.");
    }

    return value;
  }

  private static int requirePositive(int value, String propertyName) {
    if (value <= 0) {
      throw new IllegalArgumentException(propertyName + " must be greater than zero.");
    }

    return value;
  }

  private static Duration requirePositiveDuration(Duration value, String propertyName) {
    if (value == null || value.isZero() || value.isNegative()) {
      throw new IllegalArgumentException(propertyName + " must be greater than zero.");
    }

    return value;
  }
}
