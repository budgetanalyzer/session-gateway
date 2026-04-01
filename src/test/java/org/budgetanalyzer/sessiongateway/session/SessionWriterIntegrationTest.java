package org.budgetanalyzer.sessiongateway.session;

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
import org.springframework.test.context.TestPropertySource;

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
    var sessionId =
        sessionWriter
            .createSession(
                "user-123",
                "auth0|writer",
                "writer@example.com",
                "Writer Test",
                "https://example.com/avatar.png",
                List.of("ROLE_USER"),
                List.of("transactions:read"),
                "refresh-token-123",
                BASE_INSTANT.plusSeconds(900))
            .block();

    assertThat(sessionId).isNotBlank();

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId);
    var sessionTtl =
        reactiveStringRedisTemplate.getExpire(TEST_SESSION_KEY_PREFIX + sessionId).block();
    var sessionData = sessionReader.readSession(sessionId).block();

    assertThat(sessionFields)
        .containsEntry(SessionHashFields.USER_ID, "user-123")
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

    assertThat(sessionData).isNotNull();
    assertThat(sessionData.userId()).isEqualTo("user-123");
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
  }

  @Test
  void deleteSessionRemovesSessionHash() {
    var sessionId = createSession();

    var deleted = sessionWriter.deleteSession(sessionId).block();

    assertThat(deleted).isTrue();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + sessionId)).isEmpty();
  }

  @Test
  void updateSessionExpiryRefreshesExpiresAtFieldAndRedisTtl() {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .put(
            sessionKey, SessionHashFields.EXPIRES_AT, String.valueOf(BASE_INSTANT.getEpochSecond()))
        .then(reactiveStringRedisTemplate.expire(sessionKey, Duration.ofSeconds(30)))
        .block();

    var updated = sessionWriter.updateSessionExpiry(sessionId, 600).block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();

    assertThat(updated).isTrue();
    assertThat(sessionFields)
        .containsEntry(
            SessionHashFields.EXPIRES_AT,
            String.valueOf(BASE_INSTANT.plusSeconds(600).getEpochSecond()));
    assertThat(sessionTtl).isNotNull();
    assertThat(sessionTtl).isPositive();
    assertThat(sessionTtl).isLessThanOrEqualTo(Duration.ofSeconds(600));
  }

  @Test
  void updateSessionExpiryReturnsFalseWhenSessionDoesNotExist() {
    var updated = sessionWriter.updateSessionExpiry("nonexistent-session", 600).block();

    assertThat(updated).isFalse();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + "nonexistent-session")).isEmpty();
  }

  @Test
  void updateTokenAndExpiryUpdatesTokenFieldsAndSessionTtl() {
    var sessionId = createSession();
    var sessionKey = TEST_SESSION_KEY_PREFIX + sessionId;

    var updated =
        sessionWriter
            .updateTokenAndExpiry(
                sessionId, "rotated-refresh-token", BASE_INSTANT.plusSeconds(1200), 900)
            .block();
    var sessionFields = readHashEntries(sessionKey);
    var sessionTtl = reactiveStringRedisTemplate.getExpire(sessionKey).block();

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
  }

  @Test
  void updateTokenAndExpiryReturnsFalseWhenSessionDoesNotExist() {
    var updated =
        sessionWriter
            .updateTokenAndExpiry("nonexistent-session", "refresh-token", BASE_INSTANT, 600)
            .block();

    assertThat(updated).isFalse();
    assertThat(readHashEntries(TEST_SESSION_KEY_PREFIX + "nonexistent-session")).isEmpty();
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            "user-123",
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
