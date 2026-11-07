package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.http.Fault;

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
        new PermissionServiceProperties(baseUrl, Duration.ofMillis(250), Duration.ofMillis(250));
    permissionServiceClient = new PermissionServiceClient(webClient, permissionServiceProperties);
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void shouldReturnParsedResponseWhenFetchingPermissions() {
    wireMock.stubFor(
        post(urlEqualTo("/internal/v1/users/sync"))
            .withHeader("Content-Type", equalTo("application/json"))
            .withRequestBody(
                equalToJson(
                    """
                    {
                      "idpSub": "auth0|abc123",
                      "email": "user@example.com",
                      "displayName": "Test User"
                    }
                    """))
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
  void shouldThrowOnDeactivatedUserWhenFetchingPermissions() {
    wireMock.stubFor(
        post(urlEqualTo("/internal/v1/users/sync"))
            .withRequestBody(matchingJsonPath("$.idpSub", equalTo("auth0|deactivated")))
            .willReturn(aResponse().withStatus(422)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|deactivated", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void shouldThrowOnServerErrorWhenFetchingPermissions() {
    wireMock.stubFor(
        post(urlEqualTo("/internal/v1/users/sync")).willReturn(aResponse().withStatus(500)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|error", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void shouldTimeoutWhenFetchingPermissions() {
    wireMock.stubFor(
        post(urlEqualTo("/internal/v1/users/sync"))
            .willReturn(aResponse().withStatus(200).withFixedDelay(1000)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|slow", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class)
        .hasMessageContaining("user sync failed")
        .hasCauseInstanceOf(TimeoutException.class);
  }

  @Test
  void shouldThrowOnTransportFailureWhenFetchingPermissions() {
    wireMock.stubFor(
        post(urlEqualTo("/internal/v1/users/sync"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|reset", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class)
        .hasMessageContaining("user sync failed");
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
