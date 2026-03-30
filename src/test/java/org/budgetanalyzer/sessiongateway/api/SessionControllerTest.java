package org.budgetanalyzer.sessiongateway.api;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.ResponseCookie;
import org.springframework.test.context.TestPropertySource;

import org.budgetanalyzer.sessiongateway.api.response.SessionStatusResponse;
import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@Import(SessionControllerTest.FixedClockTestConfiguration.class)
@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:heartbeat:",
      "session.ttl-seconds=1800",
      "session.refresh-threshold-seconds=600",
    })
class SessionControllerTest extends AbstractIntegrationTest {

  private static final Instant BASE_INSTANT = Instant.parse("2026-03-30T00:00:00Z");
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:heartbeat:";

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private MutableClock mutableClock;

  @BeforeEach
  void setUp() {
    mutableClock.setInstant(BASE_INSTANT);
    deleteTestKeys();
  }

  @Test
  void getSessionStatus_returnsSessionMetadataAndExtendsExpiryForValidSession() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);

    var response =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);
    var sessionTtl =
        reactiveStringRedisTemplate.getExpire(TEST_SESSION_KEY_PREFIX + sessionId).block();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.userId()).isEqualTo("user-123");
    assertThat(response.roles()).containsExactly("ROLE_USER");
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(1800).getEpochSecond());
    assertThat(response.expiresInSeconds()).isEqualTo(1800);
    assertThat(response.tokenRefreshed()).isFalse();
    assertThat(sessionFields)
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(1800).getEpochSecond()))
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(3600).getEpochSecond()))
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "refresh-token-123");
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(1800));
  }

  @Test
  void getSessionStatus_returns401ForExpiredSession() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(1900));

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie("SESSION", sessionId)
        .exchange()
        .expectStatus()
        .isUnauthorized();
  }

  @Test
  void getSessionStatus_refreshesNearExpiryTokenAndUpdatesSessionHash() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(500), "refresh-token-123");
    var heartbeatInstant = BASE_INSTANT.plusSeconds(100);
    mutableClock.setInstant(heartbeatInstant);
    stubRefreshTokenEndpoint(
        200,
        """
        {
          "access_token": "new-access-token",
          "refresh_token": "rotated-refresh-token",
          "token_type": "Bearer",
          "expires_in": 7200
        }
        """);

    var response =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);

    assertThat(response).isNotNull();
    assertThat(response.tokenRefreshed()).isTrue();
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(1800).getEpochSecond());
    assertThat(response.expiresInSeconds()).isEqualTo(1800);
    assertThat(sessionFields)
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "rotated-refresh-token")
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(7200).getEpochSecond()))
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(1800).getEpochSecond()));
  }

  @Test
  void getSessionStatus_returns401AndClearsSessionWhenGrantRevoked() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(500), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(100));
    stubRefreshTokenEndpoint(
        401,
        """
        {
          "error": "invalid_grant"
        }
        """);

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    var clearedSessionCookie = exchangeResult.getResponseCookies().getFirst("SESSION");

    assertThat(clearedSessionCookie).isNotNull();
    assertCleared(clearedSessionCookie);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
  }

  @Test
  void getSessionStatus_returns401WhenTokenExpiredAndNoRefreshToken() {
    var sessionId = createSession(BASE_INSTANT.minusSeconds(60), null);
    mutableClock.setInstant(BASE_INSTANT);

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie("SESSION", sessionId)
        .exchange()
        .expectStatus()
        .isUnauthorized();

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isNotEmpty();
  }

  @Test
  void getSessionStatus_extendsSessionWhenTokenNotExpiredAndNoRefreshToken() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), null);
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);

    var response =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.tokenRefreshed()).isFalse();
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(1800).getEpochSecond());
  }

  @Test
  void getSessionStatus_returns502WhenIdpRefreshFails() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(500), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(100));
    stubRefreshTokenEndpoint(500, "{\"error\": \"server_error\"}");

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie("SESSION", sessionId)
        .exchange()
        .expectStatus()
        .isEqualTo(502);

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isNotEmpty();
  }

  private String createSession(Instant tokenExpiresAt, String refreshToken) {
    return sessionWriter
        .createSession(
            "user-123",
            "auth0|heartbeat",
            "heartbeat@example.com",
            "Heartbeat User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            refreshToken,
            tokenExpiresAt)
        .block();
  }

  private void stubRefreshTokenEndpoint(int status, String body) {
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(status)
                    .withHeader("Content-Type", "application/json")
                    .withBody(body)));
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
    assertThat(sessionCookie.getValue()).isEmpty();
    assertThat(sessionCookie.getMaxAge()).isZero();
    assertThat(sessionCookie.getPath()).isEqualTo("/");
    assertThat(sessionCookie.isHttpOnly()).isTrue();
  }

  @TestConfiguration(proxyBeanMethods = false)
  static class FixedClockTestConfiguration {

    @Bean
    @Primary
    MutableClock mutableClock() {
      return new MutableClock(BASE_INSTANT, ZoneOffset.UTC);
    }
  }

  static final class MutableClock extends Clock {

    private Instant instant;
    private final ZoneId zoneId;

    private MutableClock(Instant instant, ZoneId zoneId) {
      this.instant = instant;
      this.zoneId = zoneId;
    }

    @Override
    public ZoneId getZone() {
      return zoneId;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return new MutableClock(instant, zone);
    }

    @Override
    public Instant instant() {
      return instant;
    }

    void setInstant(Instant instant) {
      this.instant = instant;
    }
  }
}
