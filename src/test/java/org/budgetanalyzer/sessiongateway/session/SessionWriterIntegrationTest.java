package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.TestPropertySource;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

@Import(SessionWriterIntegrationTest.FixedClockTestConfiguration.class)
@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:writer:",
      "session.ttl-seconds=900",
    })
class SessionWriterIntegrationTest extends AbstractIntegrationTest {

  private static final Instant BASE_INSTANT = Instant.parse("2026-03-30T00:00:00Z");
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:writer:";
  private static final String PRIMARY_USER_ID = "writer-user-primary";
  private static final String SECONDARY_USER_ID = "writer-user-secondary";
  private static final String MISSING_USER_ID = "writer-user-missing";
  private static final String USER_SESSIONS_KEY_PATTERN =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + "writer-user-*";
  private static final String PRIMARY_USER_SESSIONS_KEY =
      SessionHashFields.USER_SESSIONS_KEY_PREFIX + PRIMARY_USER_ID;

  @Autowired private SessionWriter sessionWriter;
  @Autowired private SessionReader sessionReader;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private MutableClock mutableClock;

  @BeforeEach
  void setUp() {
    mutableClock.setInstant(BASE_INSTANT);
    deleteTestKeys();
  }

  @Test
  void createSessionStoresHashWithExpectedFieldsAndTtl() {
    var sessionId = createSession(PRIMARY_USER_ID);

    assertThat(sessionId).isNotBlank();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);
    var sessionTtl =
        reactiveStringRedisTemplate.getExpire(TEST_SESSION_KEY_PREFIX + sessionId).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();
    var sessionData = sessionReader.readSession(sessionId).block();

    assertThat(sessionFields)
        .containsEntry(SessionHashFields.USER_ID, PRIMARY_USER_ID)
        .containsEntry(SessionHashFields.IDP_SUB, "auth0|writer")
        .containsEntry(SessionHashFields.EMAIL, "writer@example.com")
        .containsEntry(SessionHashFields.DISPLAY_NAME, "Writer Test")
        .containsEntry(SessionHashFields.PICTURE, "https://example.com/avatar.png")
        .containsEntry(SessionHashFields.ROLES, "ROLE_USER")
        .containsEntry(SessionHashFields.PERMISSIONS, "transactions:read")
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "refresh-token-123")
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()))
        .containsEntry(SessionHashFields.CREATED_AT, String.valueOf(BASE_INSTANT.getEpochSecond()))
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()));

    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isPositive();
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));

    assertThat(sessionData).isNotNull();
    assertThat(sessionData.userId()).isEqualTo(PRIMARY_USER_ID);
    assertThat(sessionData.idpSub()).isEqualTo("auth0|writer");
    assertThat(sessionData.email()).isEqualTo("writer@example.com");
    assertThat(sessionData.displayName()).isEqualTo("Writer Test");
    assertThat(sessionData.picture()).isEqualTo("https://example.com/avatar.png");
    assertThat(sessionData.roles()).containsExactly("ROLE_USER");
    assertThat(sessionData.permissions()).containsExactly("transactions:read");
    assertThat(sessionData.refreshToken()).isEqualTo("refresh-token-123");
    assertThat(sessionData.tokenExpiresAt()).isEqualTo(BASE_INSTANT.plusSeconds(900));
    assertThat(sessionData.createdAt()).isEqualTo(BASE_INSTANT);
    assertThat(sessionData.expiresAt()).isEqualTo(BASE_INSTANT.plusSeconds(900));
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).containsExactly(sessionId);
  }

  @Test
  void createSessionMultipleSessionsSameUserAddsAllSessionsToUserIndex() {
    var firstSessionId = createSession(PRIMARY_USER_ID);
    var secondSessionId = createSession(PRIMARY_USER_ID);
    var thirdSessionId = createSession(PRIMARY_USER_ID);

    var userSessionIds = readSetMembers(PRIMARY_USER_SESSIONS_KEY);
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();

    assertThat(userSessionIds)
        .containsExactlyInAnyOrder(firstSessionId, secondSessionId, thirdSessionId);
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isPositive();
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
  }

  @Test
  void deleteSessionRemovesSessionHashAndUserIndexEntry() {
    var deletedSessionId = createSession(PRIMARY_USER_ID);
    var remainingSessionId = createSession(PRIMARY_USER_ID);

    var deleted = sessionWriter.deleteSession(deletedSessionId).block();

    assertThat(deleted).isTrue();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + deletedSessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).containsExactly(remainingSessionId);
  }

  @Test
  void deleteSessionWhenHashIsMissingReturnsFalseAndLeavesStaleUserIndexEntry() {
    var sessionId = createSession(PRIMARY_USER_ID);

    reactiveStringRedisTemplate.unlink(TEST_SESSION_KEY_PREFIX + sessionId).block();

    var deleted = sessionWriter.deleteSession(sessionId).block();

    assertThat(deleted).isFalse();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).containsExactly(sessionId);
  }

  @Test
  void updateSessionExpiryRefreshesExpiresAtFieldAndBothRedisTtls() {
    var sessionId = createSession(PRIMARY_USER_ID);
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .put(
            sessionKey, SessionHashFields.EXPIRES_AT, String.valueOf(BASE_INSTANT.getEpochSecond()))
        .then(reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(30)))
        .block();
    reactiveStringRedisTemplate.expire(PRIMARY_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();

    var updated = sessionWriter.updateSessionExpiry(sessionId, PRIMARY_USER_ID, 600).block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();

    assertThat(updated).isTrue();
    assertThat(sessionFields)
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(600).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(600));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(600));
  }

  @Test
  void updateSessionExpiryReindexesSessionWhenUserIndexEntryIsMissing() {
    var sessionId = createSession(PRIMARY_USER_ID);
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(30)).block();
    reactiveStringRedisTemplate.expire(PRIMARY_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();

    reactiveStringRedisTemplate.opsForSet().remove(PRIMARY_USER_SESSIONS_KEY, sessionId).block();

    var updated = sessionWriter.updateSessionExpiry(sessionId, PRIMARY_USER_ID, 600).block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();

    assertThat(updated).isTrue();
    assertThat(sessionFields)
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(600).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(600));
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).containsExactly(sessionId);
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(600));
  }

  @Test
  void updateSessionExpiryReturnsFalseWhenSessionDoesNotExist() {
    var updated =
        sessionWriter.updateSessionExpiry("nonexistent-session", PRIMARY_USER_ID, 600).block();

    assertThat(updated).isFalse();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + "nonexistent-session")).isEmpty();
  }

  @Test
  void updateTokenAndExpiryUpdatesTokenFieldsAndBothRedisTtls() {
    var sessionId = createSession(PRIMARY_USER_ID);
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    reactiveStringRedisTemplate.expire(PRIMARY_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();

    var updated =
        sessionWriter
            .updateTokenAndExpiry(
                sessionId,
                PRIMARY_USER_ID,
                "rotated-refresh-token",
                BASE_INSTANT.plusSeconds(1200),
                900)
            .block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();

    assertThat(updated).isTrue();
    assertThat(sessionFields)
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "rotated-refresh-token")
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(1200).getEpochSecond()))
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
  }

  @Test
  void updateTokenAndExpiryReindexesSessionWhenUserIndexEntryIsMissing() {
    var sessionId = createSession(PRIMARY_USER_ID);
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(30)).block();
    reactiveStringRedisTemplate.expire(PRIMARY_USER_SESSIONS_KEY, Duration.ofSeconds(30)).block();

    reactiveStringRedisTemplate.opsForSet().remove(PRIMARY_USER_SESSIONS_KEY, sessionId).block();

    var updated =
        sessionWriter
            .updateTokenAndExpiry(
                sessionId,
                PRIMARY_USER_ID,
                "rotated-refresh-token",
                BASE_INSTANT.plusSeconds(1200),
                900)
            .block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();
    var userSessionsTtl = reactiveStringRedisTemplate.getExpire(PRIMARY_USER_SESSIONS_KEY).block();

    assertThat(updated).isTrue();
    assertThat(sessionFields)
        .containsEntry(SessionHashFields.REFRESH_TOKEN, "rotated-refresh-token")
        .containsEntry(
            SessionHashFields.TOKEN_EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(1200).getEpochSecond()))
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).containsExactly(sessionId);
    assertThat(userSessionsTtl).isNotNull();
    assertThat(userSessionsTtl).isGreaterThan(Duration.ofSeconds(30));
    assertThat(userSessionsTtl).isLessThanOrEqualTo(Duration.ofSeconds(900));
  }

  @Test
  void updateTokenAndExpiryReturnsFalseWhenSessionDoesNotExist() {
    var updated =
        sessionWriter
            .updateTokenAndExpiry(
                "nonexistent-session", PRIMARY_USER_ID, "refresh-token", BASE_INSTANT, 600)
            .block();

    assertThat(updated).isFalse();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + "nonexistent-session")).isEmpty();
  }

  @Test
  void deleteAllSessionsForUserRemovesIndexedSessionHashesAndPreservesOtherUsers() {
    var firstSessionId = createSession(PRIMARY_USER_ID);
    var secondSessionId = createSession(PRIMARY_USER_ID);
    var thirdSessionId = createSession(PRIMARY_USER_ID);
    var unrelatedSessionId = createSession(SECONDARY_USER_ID);

    var deletedKeyCount = sessionWriter.deleteAllSessionsForUser(PRIMARY_USER_ID).block();

    assertThat(deletedKeyCount).isEqualTo(4L);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + firstSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + secondSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + thirdSessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + unrelatedSessionId))
        .containsEntry(SessionHashFields.USER_ID, SECONDARY_USER_ID);
    assertThat(readSetMembers(SessionHashFields.USER_SESSIONS_KEY_PREFIX + SECONDARY_USER_ID))
        .containsExactly(unrelatedSessionId);
  }

  @Test
  void deleteAllSessionsForUserSucceedsWhenUserIndexContainsStaleSessionEntry() {
    var staleSessionId = createSession(PRIMARY_USER_ID);
    var liveSessionId = createSession(PRIMARY_USER_ID);

    reactiveStringRedisTemplate.unlink(TEST_SESSION_KEY_PREFIX + staleSessionId).block();

    var deletedKeyCount = sessionWriter.deleteAllSessionsForUser(PRIMARY_USER_ID).block();

    assertThat(deletedKeyCount).isEqualTo(2L);
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + staleSessionId)).isEmpty();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + liveSessionId)).isEmpty();
    assertThat(readSetMembers(PRIMARY_USER_SESSIONS_KEY)).isEmpty();
  }

  @Test
  void deleteAllSessionsForUserReturnsZeroWhenIndexDoesNotExist() {
    var deletedKeyCount = sessionWriter.deleteAllSessionsForUser(MISSING_USER_ID).block();

    assertThat(deletedKeyCount).isZero();
  }

  @Test
  void deleteAllSessionsForUserRaceWithCreateSessionNeverLeavesSurvivingSessionUnindexed()
      throws Exception {
    var executorService = Executors.newFixedThreadPool(2);

    try {
      for (var attempt = 0; attempt < 100; attempt++) {
        var userId = PRIMARY_USER_ID + "-race-" + attempt;
        var existingSessionId = createSession(userId);
        var startLatch = new CountDownLatch(1);

        var createFuture =
            executorService.submit(
                () -> {
                  if (!startLatch.await(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Timed out waiting to start createSession");
                  }
                  return createSession(userId);
                });
        var deleteFuture =
            executorService.submit(
                () -> {
                  if (!startLatch.await(5, TimeUnit.SECONDS)) {
                    throw new IllegalStateException(
                        "Timed out waiting to start deleteAllSessionsForUser");
                  }
                  return sessionWriter.deleteAllSessionsForUser(userId).block();
                });

        startLatch.countDown();

        var createdSessionId = createFuture.get(5, TimeUnit.SECONDS);
        deleteFuture.get(5, TimeUnit.SECONDS);

        var createdSessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + createdSessionId);
        var userSessionIds = readSetMembers(SessionHashFields.USER_SESSIONS_KEY_PREFIX + userId);

        assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + existingSessionId))
            .withFailMessage("attempt %s: revocation left the pre-existing session behind", attempt)
            .isEmpty();

        if (createdSessionFields.isEmpty()) {
          assertThat(userSessionIds)
              .withFailMessage(
                  "attempt %s: deleted session %s remained indexed", attempt, createdSessionId)
              .isEmpty();
          continue;
        }

        assertThat(createdSessionFields)
            .withFailMessage(
                "attempt %s: surviving session %s lost its user id", attempt, createdSessionId)
            .containsEntry(SessionHashFields.USER_ID, userId);
        assertThat(userSessionIds)
            .withFailMessage(
                "attempt %s: surviving session %s lost its user index entry",
                attempt, createdSessionId)
            .containsExactly(createdSessionId);
      }
    } finally {
      executorService.shutdownNow();
    }
  }

  private String createSession(String userId) {
    return sessionWriter
        .createSession(
            userId,
            "auth0|writer",
            "writer@example.com",
            "Writer Test",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            "refresh-token-123",
            BASE_INSTANT.plusSeconds(900))
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
