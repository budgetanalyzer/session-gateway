package org.budgetanalyzer.sessiongateway.api;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.api.response.SessionStatusResponse;
import org.budgetanalyzer.sessiongateway.api.response.UserInfoResponse;
import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@Import(SessionControllerIntegrationTest.FixedClockTestConfiguration.class)
@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:heartbeat:",
      "session.ttl-seconds=900",
      "permission-service.authorization-refresh-timeout=1s",
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
  private static final String UNAUTHORIZED_RESPONSE_SCHEMA_PATH =
      "$.paths['/auth/v1/session'].get.responses['401'].content"
          + "['application/json'].schema['$ref']";
  private static final String SERVICE_UNAVAILABLE_RESPONSE_SCHEMA_PATH =
      "$.paths['/auth/v1/session'].get.responses['503'].content"
          + "['application/json'].schema['$ref']";

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private MutableClock mutableClock;

  @BeforeEach
  void setUp() {
    mutableClock.setInstant(BASE_INSTANT);
    deleteTestKeys();
  }

  @Test
  void shouldRefreshStaleGrantsAndReturnTheStoredExpiry() {
    final var sessionId = createSession();
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();
    stubActiveAuthorization(List.of("ADMIN"), List.of("transactions:write"));

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/v1/session")
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
    assertThat(response.userId()).isEqualTo(TEST_USER_ID);
    assertThat(response.roles()).containsExactly("ADMIN");
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(900).getEpochSecond());
    assertThat(exchangeResult.getResponseCookies().keySet())
        .doesNotContain(PUBLIC_SESSION_COOKIE_NAME);
    assertThat(sessionFields)
        .containsEntry(SessionHashFields.ROLES, "ADMIN")
        .containsEntry(SessionHashFields.PERMISSIONS, "transactions:write")
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(heartbeatInstant.plusSeconds(900).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).containsExactly(sessionId);
    wireMockServer.verify(1, getRequestedFor(urlEqualTo(authorizationPath())));

    var userInfoResponse =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(UserInfoResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(userInfoResponse).isNotNull();
    assertThat(userInfoResponse.roles()).containsExactly("ADMIN");
    assertThat(userInfoResponse.permissions()).containsExactly("transactions:write");
  }

  @Test
  void shouldReplaceStaleGrantsWithEmptyGrantsForActiveUser() {
    var sessionId = createSession();
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);
    stubActiveAuthorization(List.of(), List.of());

    var response =
        webTestClient
            .get()
            .uri("/auth/v1/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.roles()).isEmpty();
    assertThat(response.expiresAt()).isEqualTo(heartbeatInstant.plusSeconds(900).getEpochSecond());
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId))
        .containsEntry(SessionHashFields.ROLES, "")
        .containsEntry(SessionHashFields.PERMISSIONS, "")
        .containsEntry(SessionHashFields.EXPIRES_AT, String.valueOf(response.expiresAt()));
  }

  @Test
  void shouldReturnJson401WhenSessionCookieIsAbsent() {
    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(webTestClient.get().uri("/auth/v1/session"));

    assertThat(exchangeResult.getResponseCookies()).doesNotContainKey(PUBLIC_SESSION_COOKIE_NAME);
  }

  @Test
  void shouldReturnJson401WhenSessionCookieIsBlank() {
    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(
            webTestClient.get().uri("/auth/v1/session").cookie(PUBLIC_SESSION_COOKIE_NAME, ""));

    assertThat(exchangeResult.getResponseCookies()).doesNotContainKey(PUBLIC_SESSION_COOKIE_NAME);
  }

  @Test
  void shouldReturn401ForExpiredSession() {
    var sessionId = createSession();
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(1000));

    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(exchangeResult.getResponseBody())
        .asString(StandardCharsets.UTF_8)
        .doesNotContain(sessionId, "expired", "expires_at");
  }

  @Test
  void shouldDocumentJson401And503Responses() {
    var responseSpec =
        webTestClient.get().uri("/v3/api-docs").exchange().expectStatus().isOk().expectBody();

    responseSpec
        .jsonPath(UNAUTHORIZED_RESPONSE_SCHEMA_PATH)
        .isEqualTo("#/components/schemas/ApiErrorResponse")
        .jsonPath(SERVICE_UNAVAILABLE_RESPONSE_SCHEMA_PATH)
        .isEqualTo("#/components/schemas/ApiErrorResponse");
  }

  @Test
  void shouldNotCallIdpTokenEndpoint() {
    var sessionId = createSession();
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(300));
    stubActiveAuthorization(List.of("USER"), List.of("transactions:read"));

    webTestClient
        .get()
        .uri("/auth/v1/session")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
        .exchange()
        .expectStatus()
        .isOk();

    // The heartbeat returning 200 without any token-endpoint stub proves Session Gateway no
    // longer reaches Auth0 during heartbeat — WireMock would return 404 for an unstubbed call
    // and the controller would propagate the failure.
    assertThat(wireMockServer.findAll(postRequestedFor(urlEqualTo("/idp/oauth/token")))).isEmpty();
  }

  @Test
  void shouldIgnoreFrameworkSessionCookieWhenPublicCookiePresent() {
    var sessionId = createSession();
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);
    stubActiveAuthorization(List.of("USER"), List.of("transactions:read"));

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/v1/session")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
            .cookie("SESSION", "framework-session-123")
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(SessionStatusResponse.class)
            .returnResult();

    var response = exchangeResult.getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.userId()).isEqualTo(TEST_USER_ID);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId))
        .containsEntry(SessionHashFields.USER_ID, TEST_USER_ID);
  }

  @Test
  void shouldClearPublicCookieAndNotFallbackToFrameworkSessionCookie() {
    var sessionId = createSession();
    mutableClock.setInstant(BASE_INSTANT.plusSeconds(300));

    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, "missing-session")
                .cookie("SESSION", sessionId));

    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(exchangeResult.getResponseBody())
        .asString(StandardCharsets.UTF_8)
        .doesNotContain("missing-session", sessionId);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId))
        .containsEntry(SessionHashFields.USER_ID, TEST_USER_ID);
  }

  @Test
  void getSessionStatusReindexesSessionSoInternalRevocationCanDeleteIt() {
    var sessionId = createSession();
    var heartbeatInstant = BASE_INSTANT.plusSeconds(300);
    mutableClock.setInstant(heartbeatInstant);
    stubActiveAuthorization(List.of("USER"), List.of("transactions:read"));

    reactiveStringRedisTemplate.opsForSet().remove(TEST_USER_SESSIONS_KEY, sessionId).block();

    webTestClient
        .get()
        .uri("/auth/v1/session")
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
  void shouldClearCookieWhenSessionHashMissing() {
    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, "missing-session"));

    assertThat(exchangeResult.getResponseCookies().keySet())
        .containsExactly(PUBLIC_SESSION_COOKIE_NAME)
        .doesNotContain("SESSION");
    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(exchangeResult.getResponseBody())
        .asString(StandardCharsets.UTF_8)
        .doesNotContain("missing-session", "missing", "expired");
  }

  @Test
  void shouldInvalidateSessionWhenAccountIsDeactivated() {
    var sessionId = createSession();
    stubAuthorization("DEACTIVATED", List.of(), List.of(), 0);

    assertHeartbeatInvalidatesSession(sessionId);
  }

  @Test
  void shouldInvalidateSessionWhenAccountIsMissing() {
    var sessionId = createSession();
    stubAuthorizationError(404);

    assertHeartbeatInvalidatesSession(sessionId);
  }

  @Test
  void shouldInvalidateSessionWhenAccountIsDeleted() {
    var sessionId = createSession();
    stubAuthorizationError(404);

    assertHeartbeatInvalidatesSession(sessionId);
  }

  @Test
  void shouldPreserveSessionWhenAuthorizationLookupTimesOut() {
    var sessionId = createSession();
    stubAuthorization("ACTIVE", List.of("ADMIN"), List.of("transactions:write"), 1500);

    assertFailedHeartbeatPreservesSession(sessionId);
  }

  @Test
  void shouldPreserveSessionWhenAuthorizationLookupReturnsServerError() {
    var sessionId = createSession();
    stubAuthorizationError(500);

    assertFailedHeartbeatPreservesSession(sessionId);
  }

  @Test
  void shouldPreserveSessionWhenAuthorizationLookupPayloadIsInvalid() {
    var sessionId = createSession();
    wireMockServer.stubFor(
        get(urlPathEqualTo(authorizationPath()))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"userId\":\"heartbeat-user-primary\",\"status\":\"ACTIVE\"}")));

    assertFailedHeartbeatPreservesSession(sessionId);
  }

  @Test
  void repeatedFailedHeartbeatsCannotKeepShortLivedSessionAlive() {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;
    reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(1)).block();
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofSeconds(1)).block();
    stubAuthorizationError(500);

    for (var attempt = 0; attempt < 3; attempt++) {
      assertServiceUnavailableResponse(
          webTestClient
              .get()
              .uri("/auth/v1/session")
              .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));
    }

    await()
        .atMost(Duration.ofSeconds(3))
        .untilAsserted(
            () -> {
              assertThat(readHashEntries(sessionKey)).isEmpty();
              assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
            });
  }

  @Test
  void successfulHeartbeatCanRecoverAfterFailureWhileSessionRemainsValid() {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;
    reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(5)).block();
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofSeconds(5)).block();
    stubAuthorizationError(500);

    assertServiceUnavailableResponse(
        webTestClient.get().uri("/auth/v1/session").cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

    wireMockServer.resetAll();
    stubOidcDiscovery();
    stubActiveAuthorization(List.of("ADMIN"), List.of("transactions:write"));

    webTestClient
        .get()
        .uri("/auth/v1/session")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
        .exchange()
        .expectStatus()
        .isOk();

    assertThat(readHashEntries(sessionKey))
        .containsEntry(SessionHashFields.ROLES, "ADMIN")
        .containsEntry(SessionHashFields.PERMISSIONS, "transactions:write");
    assertThat(reactiveStringRedisTemplate.getExpire(sessionKey).block())
        .isGreaterThan(Duration.ofSeconds(5));
  }

  @Test
  void concurrentSessionDeletionDuringLookupDoesNotResurrectSession() throws Exception {
    var sessionId = createSession();
    stubAuthorization("ACTIVE", List.of("ADMIN"), List.of("transactions:write"), 500);

    var heartbeatFuture = heartbeatExpectingUnauthorized(sessionId);
    awaitAuthorizationRequest();
    sessionWriter.deleteAllSessionsForUser(TEST_USER_ID).block();
    heartbeatFuture.get(3, TimeUnit.SECONDS);

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void concurrentSessionExpiryDuringLookupDoesNotResurrectSession() throws Exception {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;
    reactiveStringRedisTemplate.expire(sessionKey, Duration.ofMillis(250)).block();
    reactiveStringRedisTemplate.expire(TEST_USER_SESSIONS_KEY, Duration.ofMillis(250)).block();
    stubAuthorization("ACTIVE", List.of("ADMIN"), List.of("transactions:write"), 500);

    var heartbeatFuture = heartbeatExpectingUnauthorized(sessionId);
    awaitAuthorizationRequest();
    heartbeatFuture.get(3, TimeUnit.SECONDS);

    assertThat(readHashEntries(sessionKey)).isEmpty();
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void redisMutationFailureNeverReturnsSuccessOrChangesSession() {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;
    final var originalFields = readHashEntries(sessionKey);
    stubActiveAuthorization(List.of("ADMIN"), List.of("transactions:write"));
    reactiveStringRedisTemplate.unlink(TEST_USER_SESSIONS_KEY).block();
    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .put(TEST_USER_SESSIONS_KEY, "invalid", "index")
        .block();

    var exchangeResult =
        assertServiceUnavailableResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

    assertThat(exchangeResult.getResponseBody())
        .asString(StandardCharsets.UTF_8)
        .doesNotContain(sessionId, "invalid", TEST_USER_ID);
    assertThat(readHashEntries(sessionKey)).isEqualTo(originalFields);
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            TEST_USER_ID,
            "auth0|heartbeat",
            "heartbeat@example.com",
            "Heartbeat User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"))
        .block();
  }

  private void stubActiveAuthorization(List<String> roles, List<String> permissions) {
    stubAuthorization("ACTIVE", roles, permissions, 0);
  }

  private void stubAuthorization(
      String status, List<String> roles, List<String> permissions, int delayMilliseconds) {
    wireMockServer.stubFor(
        get(urlPathEqualTo(authorizationPath()))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withFixedDelay(delayMilliseconds)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "%s",
                          "status": "%s",
                          "roles": %s,
                          "permissions": %s
                        }
                        """
                            .formatted(
                                TEST_USER_ID,
                                status,
                                toJsonArray(roles),
                                toJsonArray(permissions)))));
  }

  private void stubAuthorizationError(int status) {
    wireMockServer.stubFor(
        get(urlPathEqualTo(authorizationPath())).willReturn(aResponse().withStatus(status)));
  }

  private void assertHeartbeatInvalidatesSession(String sessionId) {
    var exchangeResult =
        assertUnauthorizedHeartbeatResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

    assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
    assertThat(exchangeResult.getResponseBody())
        .asString(StandardCharsets.UTF_8)
        .doesNotContain(sessionId, "DEACTIVATED", "deleted", "missing", TEST_USER_ID);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
    assertThat(readSetMembers(TEST_USER_SESSIONS_KEY)).isEmpty();
  }

  private void assertFailedHeartbeatPreservesSession(String sessionId) {
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;
    var originalFields = readHashEntries(sessionKey);
    var originalSessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();
    final var originalIndexTtl =
        reactiveStringRedisTemplate.getExpire(TEST_USER_SESSIONS_KEY).block();
    var startedAtNanos = System.nanoTime();

    var exchangeResult =
        assertServiceUnavailableResponse(
            webTestClient
                .get()
                .uri("/auth/v1/session")
                .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

    var elapsed = Duration.ofNanos(System.nanoTime() - startedAtNanos).plusSeconds(1);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();

    assertThat(exchangeResult.getResponseCookies()).doesNotContainKey(PUBLIC_SESSION_COOKIE_NAME);
    assertThat(readHashEntries(sessionKey)).isEqualTo(originalFields);
    assertTtlOnlyElapsed(originalSessionTtl, sessionTtl, elapsed);
    var indexTtl = reactiveStringRedisTemplate.getExpire(TEST_USER_SESSIONS_KEY).block();
    assertTtlOnlyElapsed(originalIndexTtl, indexTtl, elapsed);
  }

  private void assertTtlOnlyElapsed(Duration before, Duration after, Duration elapsed) {
    assertThat(after).isNotNull();
    assertThat(after).isLessThanOrEqualTo(before);
    assertThat(after).isGreaterThanOrEqualTo(before.minus(elapsed));
  }

  private CompletableFuture<Void> heartbeatExpectingUnauthorized(String sessionId) {
    return CompletableFuture.runAsync(
        () -> {
          var exchangeResult =
              assertUnauthorizedHeartbeatResponse(
                  webTestClient
                      .get()
                      .uri("/auth/v1/session")
                      .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId));

          assertCleared(exchangeResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME));
          assertThat(exchangeResult.getResponseBody())
              .asString(StandardCharsets.UTF_8)
              .doesNotContain(sessionId, TEST_USER_ID, "disappeared", "expired", "deleted");
        });
  }

  private void awaitAuthorizationRequest() {
    await()
        .atMost(Duration.ofSeconds(2))
        .untilAsserted(
            () -> wireMockServer.verify(1, getRequestedFor(urlEqualTo(authorizationPath()))));
  }

  private String authorizationPath() {
    return "/internal/v1/users/" + TEST_USER_ID + "/authorization";
  }

  private String toJsonArray(List<String> values) {
    return "[" + String.join(",", values.stream().map(value -> "\"" + value + "\"").toList()) + "]";
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

  private EntityExchangeResult<byte[]> assertUnauthorizedHeartbeatResponse(
      WebTestClient.RequestHeadersSpec<?> requestHeadersSpec) {
    return requestHeadersSpec
        .exchange()
        .expectStatus()
        .isUnauthorized()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("UNAUTHORIZED")
        .jsonPath("$.message")
        .isEqualTo("Authentication required")
        .jsonPath("$.code")
        .doesNotExist()
        .jsonPath("$.fieldErrors")
        .doesNotExist()
        .returnResult();
  }

  private EntityExchangeResult<byte[]> assertServiceUnavailableResponse(
      WebTestClient.RequestHeadersSpec<?> requestHeadersSpec) {
    return requestHeadersSpec
        .exchange()
        .expectStatus()
        .isEqualTo(503)
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("SERVICE_UNAVAILABLE")
        .jsonPath("$.message")
        .isEqualTo("Session refresh unavailable")
        .jsonPath("$.code")
        .doesNotExist()
        .jsonPath("$.fieldErrors")
        .doesNotExist()
        .returnResult();
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
