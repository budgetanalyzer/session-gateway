package org.budgetanalyzer.sessiongateway;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

import org.budgetanalyzer.service.config.HttpLoggingProperties;
import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

@ActiveProfiles("kubernetes")
// src/test/resources/application.yml shadows the main application.yml, so load the shipped file.
@SpringBootTest(
    webEnvironment = RANDOM_PORT,
    properties = "spring.config.additional-location=file:./src/main/resources/")
class SessionGatewayApplicationIntegrationTest extends AbstractIntegrationTest {

  @Autowired private Environment environment;
  @Autowired private HttpLoggingProperties httpLoggingProperties;

  @Test
  void contextLoads() {
    // Context should load successfully with mocked IDP and Redis testcontainer
  }

  @Test
  void healthEndpointIsAccessible() {
    webTestClient.get().uri("/actuator/health").exchange().expectStatus().isOk();
  }

  @Test
  void kubernetesProfileUsesSafeLoggingDefaults() {
    assertThat(environment.getProperty("logging.level.org.budgetanalyzer")).isEqualTo("INFO");
    assertThat(httpLoggingProperties.isIncludeRequestBody()).isFalse();
    assertThat(httpLoggingProperties.isIncludeResponseBody()).isFalse();
  }

  @Test
  void readinessIncludesRedisWhileLivenessRemainsDependencyFree() {
    webTestClient
        .get()
        .uri("/actuator/health/readiness")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.components.readinessState.status")
        .isEqualTo("UP")
        .jsonPath("$.components.redis.status")
        .isEqualTo("UP");

    webTestClient
        .get()
        .uri("/actuator/health/liveness")
        .exchange()
        .expectStatus()
        .isOk()
        .expectBody()
        .jsonPath("$.status")
        .isEqualTo("UP")
        .jsonPath("$.components.redis")
        .doesNotExist();
  }

  @Test
  void shouldReturn401ForUnauthenticatedUserRequest() {
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
        .post()
        .uri("/logout")
        .exchange()
        .expectStatus()
        .isEqualTo(HttpStatus.SEE_OTHER)
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
