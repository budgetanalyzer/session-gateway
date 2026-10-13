package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.Test;

class PermissionServicePropertiesTest {

  @Test
  void shouldAcceptPositiveAuthorizationRefreshTimeout() {
    var permissionServiceProperties =
        new PermissionServiceProperties("http://permission-service:8086", Duration.ofSeconds(2));

    assertThat(permissionServiceProperties.baseUrl()).isEqualTo("http://permission-service:8086");
    assertThat(permissionServiceProperties.authorizationRefreshTimeout())
        .isEqualTo(Duration.ofSeconds(2));
  }

  @Test
  void shouldRejectBlankBaseUrl() {
    assertThatThrownBy(() -> new PermissionServiceProperties(" ", Duration.ofSeconds(2)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("base-url");
  }

  @Test
  void shouldRejectMissingAuthorizationRefreshTimeout() {
    assertThatThrownBy(
            () -> new PermissionServiceProperties("http://permission-service:8086", null))
        .isInstanceOf(NullPointerException.class)
        .hasMessageContaining("authorization-refresh-timeout");
  }

  @Test
  void shouldRejectNonPositiveAuthorizationRefreshTimeout() {
    assertThatThrownBy(
            () -> new PermissionServiceProperties("http://permission-service:8086", Duration.ZERO))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("greater than zero");
    assertThatThrownBy(
            () ->
                new PermissionServiceProperties(
                    "http://permission-service:8086", Duration.ofSeconds(-1)))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("greater than zero");
  }
}
