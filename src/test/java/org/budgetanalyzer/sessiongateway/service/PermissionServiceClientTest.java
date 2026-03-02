package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
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
  private PermissionServiceClient client;

  @BeforeEach
  void setUp() {
    wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMock.start();

    WebClient webClient =
        WebClient.builder().baseUrl("http://localhost:" + wireMock.port()).build();
    client = new PermissionServiceClient(webClient);
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void fetchPermissions_returnsParsedResponse() {
    wireMock.stubFor(
        get(urlEqualTo("/internal/v1/users/auth0%7Cabc123/permissions"))
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

    var response = client.fetchPermissions("auth0|abc123").block();

    assertThat(response).isNotNull();
    assertThat(response.userId()).isEqualTo("user-456");
    assertThat(response.roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    assertThat(response.permissions()).containsExactly("transactions:read", "transactions:write");
  }

  @Test
  void fetchPermissions_throwsOnClientError() {
    wireMock.stubFor(
        get(urlEqualTo("/internal/v1/users/auth0%7Cnotfound/permissions"))
            .willReturn(aResponse().withStatus(404)));

    assertThatThrownBy(() -> client.fetchPermissions("auth0|notfound").block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void fetchPermissions_throwsOnServerError() {
    wireMock.stubFor(
        get(urlEqualTo("/internal/v1/users/auth0%7Cerror/permissions"))
            .willReturn(aResponse().withStatus(500)));

    assertThatThrownBy(() -> client.fetchPermissions("auth0|error").block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }
}
