package org.budgetanalyzer.sessiongateway;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(
    properties = {
      "spring.data.redis.host=localhost",
      "spring.data.redis.port=6379",
      "AUTH0_CLIENT_ID=test-client-id",
      "AUTH0_CLIENT_SECRET=test-client-secret",
      "AUTH0_ISSUER_URI=https://test.auth0.com"
    })
class SessionGatewayApplicationTests {

  @Test
  void contextLoads() {
    // This test verifies that the Spring application context loads successfully
  }
}
