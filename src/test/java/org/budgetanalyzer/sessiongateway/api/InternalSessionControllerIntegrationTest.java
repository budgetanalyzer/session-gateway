package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.TestPropertySource;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:internal-revocation:",
      "session.ttl-seconds=900",
    })
class InternalSessionControllerIntegrationTest extends AbstractIntegrationTest {

  private static final String TEST_SESSION_KEY_PREFIX = "session:test:internal-revocation:";
  private static final String PRIMARY_USER_ID = "internal-revocation-user-primary";
  private static final String SECONDARY_USER_ID = "internal-revocation-user-secondary";
  private static final String MISSING_USER_ID = "internal-revocation-user-missing";
  private static final String USER_SESSIONS_KEY_PATTERN =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + "internal-revocation-user-*";
  private static final String PRIMARY_USER_SESSIONS_KEY =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + PRIMARY_USER_ID;
  private static final String SECONDARY_USER_SESSIONS_KEY =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + SECONDARY_USER_ID;

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @BeforeEach
  void setUp() {
    deleteTestKeys();
  }

  @Test
  void deleteUserSessionsRevokesAllActiveSessionsForTheRequestedUser() {
    var firstSessionId = createSession(PRIMARY_USER_ID, "auth0|internal-primary-1");
    var secondSessionId = createSession(PRIMARY_USER_ID, "auth0|internal-primary-2");
    var thirdSessionId = createSession(PRIMARY_USER_ID, "auth0|internal-primary-3");
    var unrelatedSessionId = createSession(SECONDARY_USER_ID, "auth0|internal-secondary");

    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", PRIMARY_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent()
        .expectBody()
        .isEmpty();

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + firstSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + secondSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + thirdSessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + unrelatedSessionId))
        .containsEntry(SessionHashFields.USER_ID, SECONDARY_USER_ID);
    assertThat(readSetMembers(SECONDARY_USER_SESSIONS_KEY)).containsExactly(unrelatedSessionId);
  }

  @Test
  void deleteUserSessionsReturnsNoContentWithoutAuthenticationWhenNoSessionsExist() {
    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", MISSING_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent()
        .expectBody()
        .isEmpty();
  }

  @Test
  void deleteUserSessionsReturnsNoContentWhenUserIndexContainsStaleExpiredSession() {
    var staleSessionId = createSession(PRIMARY_USER_ID, "auth0|internal-stale");
    var liveSessionId = createSession(PRIMARY_USER_ID, "auth0|internal-live");

    reactiveStringRedisTemplate.unlink(TEST_SESSION_KEY_PREFIX + staleSessionId).block();

    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", PRIMARY_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent()
        .expectBody()
        .isEmpty();

    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + staleSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + liveSessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void deleteUserSessionsPreventsHeartbeatRaceFromRecreatingDeletedSession() {
    var sessionId = createSession(PRIMARY_USER_ID, "auth0|internal-race");

    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", PRIMARY_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent();

    var updated = sessionWriter.updateSessionExpiry(sessionId, PRIMARY_USER_ID, 900).block();

    assertThat(updated).isFalse();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void deleteUserSessionsEndpointIsAccessibleWithoutAuthentication() {
    webTestClient
        .delete()
        .uri("/internal/v1/sessions/users/{userId}", PRIMARY_USER_ID)
        .exchange()
        .expectStatus()
        .isNoContent()
        .expectBody()
        .isEmpty();
  }

  private String createSession(String userId, String idpSub) {
    return sessionWriter
        .createSession(
            userId,
            idpSub,
            userId + "@example.com",
            "Internal Revocation User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"))
        .block();
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
}
