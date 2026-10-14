package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import org.budgetanalyzer.sessiongateway.config.PermissionServiceProperties;

class PermissionServiceClientIntegrationTest {

  private WireMockServer wireMock;
  private PermissionServiceClient permissionServiceClient;

  @BeforeEach
  void setUp() {
    wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMock.start();

    var baseUrl = "http://localhost:" + wireMock.port();
    var webClient = WebClient.builder().baseUrl(baseUrl).build();
    var permissionServiceProperties =
        new PermissionServiceProperties(baseUrl, Duration.ofMillis(250));
    permissionServiceClient = new PermissionServiceClient(webClient, permissionServiceProperties);
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void shouldReturnParsedResponseWhenFetchingPermissions() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cabc123/permissions"))
            .withQueryParam("email", equalTo("user@example.com"))
            .withQueryParam("displayName", equalTo("Test User"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "user-456",
                          "roles": ["ROLE_USER", "ROLE_ADMIN"],
                          "permissions": ["transactions:read", "transactions:write"]
                        }
                        """)));

    var response =
        permissionServiceClient
            .fetchPermissions("auth0|abc123", "user@example.com", "Test User")
            .block();

    assertThat(response).isNotNull();
    assertThat(response.userId()).isEqualTo("user-456");
    assertThat(response.roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    assertThat(response.permissions()).containsExactly("transactions:read", "transactions:write");
  }

  @Test
  void shouldThrowOnClientErrorWhenFetchingPermissions() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cnotfound/permissions"))
            .willReturn(aResponse().withStatus(404)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|notfound", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void shouldThrowOnServerErrorWhenFetchingPermissions() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cerror/permissions"))
            .willReturn(aResponse().withStatus(500)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|error", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void shouldReturnCurrentAuthorizationForActiveUser() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/user-456/authorization"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "user-456",
                          "status": "ACTIVE",
                          "roles": ["USER"],
                          "permissions": ["transactions:read"]
                        }
                        """)));

    var response = permissionServiceClient.fetchAuthorization("user-456").block();

    assertThat(response).isNotNull();
    assertThat(response.status()).isEqualTo(PermissionServiceClient.AccountStatus.ACTIVE);
    assertThat(response.roles()).containsExactly("USER");
    assertThat(response.permissions()).containsExactly("transactions:read");
  }

  @Test
  void shouldReturnEmptyAuthorizationWhenUserIsMissing() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/missing-user/authorization"))
            .willReturn(aResponse().withStatus(404)));

    var authorization = permissionServiceClient.fetchAuthorization("missing-user").blockOptional();

    assertThat(authorization).isEmpty();
  }

  @Test
  void shouldRejectInvalidAuthorizationPayload() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/user-456/authorization"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "different-user",
                          "status": "ACTIVE",
                          "roles": ["USER"],
                          "permissions": []
                        }
                        """)));

    assertThatThrownBy(() -> permissionServiceClient.fetchAuthorization("user-456").block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class)
        .hasMessageContaining("invalid payload");
  }

  @Test
  void shouldTimeoutAuthorizationLookup() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/slow-user/authorization"))
            .willReturn(aResponse().withStatus(200).withFixedDelay(1000)));

    assertThatThrownBy(() -> permissionServiceClient.fetchAuthorization("slow-user").block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class)
        .hasMessageContaining("lookup failed");
  }
}
