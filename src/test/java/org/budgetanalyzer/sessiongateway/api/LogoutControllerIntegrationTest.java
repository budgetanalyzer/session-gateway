package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

class LogoutControllerIntegrationTest extends AbstractIntegrationTest {

  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:";

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @BeforeEach
  void setUp() {
    deleteTestKeys();
  }

  @Test
  void logoutClearsPublicSessionCookieDeletesRedisSessionHashAndIgnoresFrameworkSessionCookie() {
    var sessionId = createSession();

    var exchangeResult =
        webTestClient
            .get()
            .uri("/logout")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .cookie("SESSION", "framework-session-123")
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader()
            .valueMatches(HttpHeaders.LOCATION, ".*/v2/logout.*")
            .returnResult(Void.class);

    assertThat(exchangeResult.getResponseCookies().keySet())
        .contains(PUBLIC_SESSION_COOKIE_NAME, "SESSION");
    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(exchangeResult.getResponseCookies().getFirst("SESSION")).isNotNull();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            "user-logout",
            "auth0|logout",
            "logout@example.com",
            "Logout User",
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

  private Map<String, String> readHashEntries(String key) {
    return reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .blockOptional()
        .orElse(Map.of());
  }

  private void assertCleared(ResponseCookie sessionCookie) {
    assertThat(sessionCookie).isNotNull();
    assertThat(sessionCookie.getValue()).isEmpty();
    assertThat(sessionCookie.getDomain()).isNull();
    assertThat(sessionCookie.getMaxAge()).isZero();
    assertThat(sessionCookie.getPath()).isEqualTo("/");
    assertThat(sessionCookie.isHttpOnly()).isTrue();
    assertThat(sessionCookie.isSecure()).isTrue();
    assertThat(sessionCookie.getSameSite()).isEqualTo("Strict");
  }
}
