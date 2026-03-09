package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

class PermissionServiceClientTest {

  private WireMockServer wireMock;
  private PermissionServiceClient permissionServiceClient;

  @BeforeEach
  void setUp() {
    wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMock.start();

    var webClient = WebClient.builder().baseUrl("http://localhost:" + wireMock.port()).build();
    permissionServiceClient = new PermissionServiceClient(webClient);
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void fetchPermissions_returnsParsedResponse() {
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
  void fetchPermissions_throwsOnClientError() {
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
  void fetchPermissions_throwsOnServerError() {
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
}
