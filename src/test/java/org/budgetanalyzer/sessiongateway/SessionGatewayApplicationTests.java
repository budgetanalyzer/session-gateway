package org.budgetanalyzer.sessiongateway;

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
}
