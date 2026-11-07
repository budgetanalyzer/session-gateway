package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class PermissionServicePropertiesTest {

  private static final String BASE_URL = "http://permission-service:8086";

  @Test
  void shouldAcceptPositiveTimeouts() {
    var permissionServiceProperties =
        new PermissionServiceProperties(BASE_URL, Duration.ofSeconds(5), Duration.ofSeconds(2));

    assertThat(permissionServiceProperties.baseUrl()).isEqualTo(BASE_URL);
    assertThat(permissionServiceProperties.loginTimeout()).isEqualTo(Duration.ofSeconds(5));
    assertThat(permissionServiceProperties.authorizationRefreshTimeout())
        .isEqualTo(Duration.ofSeconds(2));
  }

  @Test
  void shouldRejectBlankBaseUrl() {
    assertThatThrownBy(
            () ->
                new PermissionServiceProperties(" ", Duration.ofSeconds(5), Duration.ofSeconds(2)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("base-url");
  }

  @Test
  void shouldRejectMissingLoginTimeout() {
    assertThatThrownBy(() -> new PermissionServiceProperties(BASE_URL, null, Duration.ofSeconds(2)))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("login-timeout");
  }

  @Test
  void shouldRejectNonPositiveLoginTimeout() {
    assertThatThrownBy(
            () -> new PermissionServiceProperties(BASE_URL, Duration.ZERO, Duration.ofSeconds(2)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("login-timeout must be greater than zero");
    assertThatThrownBy(
            () ->
                new PermissionServiceProperties(
                    BASE_URL, Duration.ofSeconds(-1), Duration.ofSeconds(2)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("login-timeout must be greater than zero");
  }

  @Test
  void shouldRejectMissingAuthorizationRefreshTimeout() {
    assertThatThrownBy(() -> new PermissionServiceProperties(BASE_URL, Duration.ofSeconds(5), null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("authorization-refresh-timeout");
  }

  @Test
  void shouldRejectNonPositiveAuthorizationRefreshTimeout() {
    assertThatThrownBy(
            () -> new PermissionServiceProperties(BASE_URL, Duration.ofSeconds(5), Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("authorization-refresh-timeout must be greater than zero");
    assertThatThrownBy(
            () ->
                new PermissionServiceProperties(
                    BASE_URL, Duration.ofSeconds(5), Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("authorization-refresh-timeout must be greater than zero");
  }
}
