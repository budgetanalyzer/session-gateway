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

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.api.response.SessionStatusResponse;
import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@Import(SessionControllerIntegrationTest.FixedClockTestConfiguration.class)
@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:heartbeat:",
      "session.ttl-seconds=900",
      "session.refresh-threshold-seconds=600",
    })
class SessionControllerIntegrationTest extends AbstractIntegrationTest {

  private static final Instant BASE_INSTANT = Instant.parse("2026-03-30T00:00:00Z");
  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:heartbeat:";
  private static final String TEST_USER_ID = "heartbeat-user-primary";
  private static final String USER_SESSIONS_KEY_PATTERN =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + "heartbeat-user-*";
  private static final String TEST_USER_SESSIONS_KEY =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + TEST_USER_ID;

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
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult();

    var response = exchangeResult.getResponseBody();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);
    var sessionTtl =
        reactiveStringRedisTemplate.getExpire(TEST_SESSION_KEY_PREFIX + sessionId).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(TEST_USER_SESSIONS_KEY).block();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.userId()).isEqualTo(TEST_USER_ID);
    assertThat(response.roles()).containsExactly("ROLE_USER");
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(900).getEpochSecond());
    assertThat(response.tokenRefreshed()).isFalse();
    assertThat(exchangeResult.getResponseCookies().keySet())
        .doesNotContain(PUBLIC_SESSION_COOKIE_NAME);
    assertThat(sessionFields)
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(900).getEpochSecond()))
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(3600).getEpochSecond()))
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "refresh-token-123");
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).containsExactly(sessionId);
  }

  @Test
  void getSessionStatus_returns401ForExpiredSession() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(1000));

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
  }

  @Test
  void getSessionStatus_refreshesNearExpiryTokenAndUpdatesSessionHash() {
    var heartbeatInstant = BASE_INSTANT.plusSeconds(100);
    mutableClock.setInstant(heartbeatInstant);
    var sessionId = createSession(BASE_INSTANT.plusSeconds(500), "refresh-token-123");
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();
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
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(TEST_USER_SESSIONS_KEY).block();

    assertThat(response).isNotNull();
    assertThat(response.tokenRefreshed()).isTrue();
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(900).getEpochSecond());
    assertThat(sessionFields)
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "rotated-refresh-token")
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(7200).getEpochSecond()))
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(900).getEpochSecond()));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
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
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    var clearedSessionCookie =
        exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(clearedSessionCookie).isNotNull();
    assertCleared(clearedSessionCookie);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void getSessionStatus_returns401WhenTokenExpiredAndNoRefreshToken() {
    var sessionId = createSession(BASE_INSTANT.minusSeconds(60), null);
    mutableClock.setInstant(BASE_INSTANT);

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
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
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.tokenRefreshed()).isFalse();
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(900).getEpochSecond());
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).containsExactly(sessionId);
  }

  @Test
  void getSessionStatus_ignoresFrameworkSessionCookieWhenPublicCookiePresent() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .cookie("SESSION", "framework-session-123")
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult();

    var response = exchangeResult.getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.userId()).isEqualTo(TEST_USER_ID);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId))
        .containsEntry(SessionHashFields.USER_ID, TEST_USER_ID);
  }

  @Test
  void getSessionStatus_clearsPublicCookieAndDoesNotFallbackToFrameworkSessionCookie() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(300));

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, "missing-session")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId))
        .containsEntry(SessionHashFields.USER_ID, TEST_USER_ID);
  }

  @Test
  void getSessionStatus_returns502WhenIdpRefreshFails() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(500), "refresh-token-123");
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(100));
    stubRefreshTokenEndpoint(500, "{\"error\": \"server_error\"}");

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
        .exchange()
        .expectStatus()
        .isEqualTo(502);

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isNotEmpty();
  }

  @Test
  void getSessionStatusReindexesSessionSoInternalRevocationCanDeleteIt() {
    var sessionId = createSession(BASE_INSTANT.plusSeconds(3600), "refresh-token-123");
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);

    reactiveStringRedisTemplate.opsForSet().remove(TEST_USER_SESSIONS_KEY, sessionId).block();

    webTestClient
        .get()
        .uri("/auth/session")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
        .exchange()
        .expectStatus()
        .isOk();

    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).containsExactly(sessionId);

    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", TEST_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent();

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void getSessionStatus_clearsCookieWhenSessionHashMissing() {
    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, "missing-session")
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    assertThat(exchangeResult.getResponseCookies().keySet())
        .containsExactly(PUBLIC_SESSION_COOKIE_NAME)
        .doesNotContain("SESSION");
    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
  }

  private String createSession(Instant tokenExpiresAt, String refreshToken) {
    return sessionWriter
        .createSession(
            TEST_USER_ID,
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
    Mono.when(deleteKeys(TEST_SESSION_KEY_PREFIX + "*"), deleteKeys(USER_SESSIONS_KEY_PATTERN))
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

  private List<String> readSetMembers(String key) {
    return reactiveStringRedisTemplate
        .opsForSet()
        .members(key)
        .collectSortedList()
        .blockOptional()
        .orElse(List.of());
  }

  private Mono<Void> deleteKeys(String pattern) {
    return reactiveStringRedisTemplate
        .keys(pattern)
        .collectList()
        .flatMap(
            keys ->
                keys.isEmpty()
                    ? Mono.empty()
                    : reactiveStringRedisTemplate.delete(keys.toArray(String[]::new)).then());
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
