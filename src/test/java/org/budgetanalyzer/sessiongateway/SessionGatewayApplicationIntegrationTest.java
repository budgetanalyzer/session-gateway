package org.budgetanalyzer.sessiongateway;

import org.junit.jupiter.api.Test;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

class SessionGatewayApplicationIntegrationTest extends AbstractIntegrationTest {

  @Test
  void contextLoads() {
    // Context should load successfully with mocked IDP and Redis testcontainer
  }

  @Test
  void healthEndpointIsAccessible() {
    webTestClient.get().uri("/actuator/health").exchange().expectStatus().isOk();
  }

  @Test
  void unauthenticatedUserRequest_returns401() {
    webTestClient.get().uri("/auth/v1/user").exchange().expectStatus().isUnauthorized();
  }

  @Test
  void retiredTokenExchangeEndpointReturns404() {
    webTestClient
        .post()
        .uri("/auth/token/exchange")
        .header("Content-Type", "application/json")
        .bodyValue("{\"accessToken\": \"\"}")
        .exchange()
        .expectStatus()
        .isNotFound();
  }

  @Test
  void logoutRedirectsToIdpLogoutWithoutAuthentication() {
    webTestClient
        .get()
        .uri("/logout")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .valueMatches("Location", ".*/v2/logout.*");
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
