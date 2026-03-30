package org.budgetanalyzer.sessiongateway;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

class SessionGatewayApplicationTests extends AbstractIntegrationTest {

  @Test
  void contextLoads() {
    // Context should load successfully with mocked IDP and Redis testcontainer
  }

  @Test
  void healthEndpointIsAccessible() {
    webTestClient.get().uri("/actuator/health").exchange().expectStatus().isOk();
  }

  @Test
  void unauthenticatedApiRequest_returns401() {
    webTestClient.get().uri("/api/anything").exchange().expectStatus().isUnauthorized();
  }

  @Test
  void unauthenticatedUserRequest_redirectsToOauth2Login() {
    webTestClient
        .get()
        .uri("/user")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .valueMatches("Location", ".*/oauth2/authorization/idp.*");
  }

  @Test
  void tokenExchangeEndpointIsReachable() {
    var status =
        webTestClient
            .post()
            .uri("/auth/token/exchange")
            .header("Content-Type", "application/json")
            .bodyValue("{\"accessToken\": \"\"}")
            .exchange()
            .returnResult(Void.class)
            .getStatus();

    assertThat(status.value()).isNotEqualTo(404);
  }

  @Test
  void logoutRequiresAuthentication() {
    webTestClient
        .get()
        .uri("/logout")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .valueMatches("Location", ".*/oauth2/authorization/idp.*");
  }

  @Test
  void oauth2AuthorizationEndpointRedirectsToIdp() {
    webTestClient
        .get()
        .uri("/oauth2/authorization/idp")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .valueMatches("Location", ".*/idp/authorize.*");
  }
}
