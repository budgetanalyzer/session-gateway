package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

class UserControllerIntegrationTest extends AbstractIntegrationTest {

  private static final String TEST_SESSION_KEY_PREFIX = "session:test:";

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @BeforeEach
  void setUp() {
    deleteTestKeys();
  }

  @Test
  void getCurrentUser_returns401WhenOnlyFrameworkSessionCookieIsPresent() {
    var sessionId = createSession();

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    assertThat(exchangeResult.getResponseCookies().keySet()).doesNotContain("BA_SESSION");
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            "user-userinfo",
            "auth0|userinfo",
            "userinfo@example.com",
            "User Info",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"))
        .block();
  }

  private void deleteTestKeys() {
    reactiveStringRedisTemplate
        .keys(TEST_SESSION_KEY_PREFIX + "*")
        .collectList()
        .flatMap(
            keys ->
                keys.isEmpty()
                    ? reactor.core.publisher.Mono.empty()
                    : reactiveStringRedisTemplate
                        .delete(reactor.core.publisher.Flux.fromIterable(keys))
                        .then())
        .block();
  }
}
