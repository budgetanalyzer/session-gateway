package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
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

import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

@Import(SessionReaderIntegrationTest.FixedClockTestConfiguration.class)
@TestPropertySource(
    properties = {
      "session.key-prefix=session:test:reader:",
      "session.ttl-seconds=900",
    })
class SessionReaderIntegrationTest extends AbstractIntegrationTest {

  private static final Instant BASE_INSTANT = Instant.parse("2026-03-30T00:00:00Z");
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:reader:";

  @Autowired private SessionReader sessionReader;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private MutableClock mutableClock;

  @BeforeEach
  void setUp() {
    mutableClock.setInstant(BASE_INSTANT);
    deleteTestKeys();
  }

  @Test
  void readSessionReturnsExistingSessionHash() {
    writeSessionHash(
        "session-123",
        Map.ofEntries(
            Map.entry(SessionHashFields.USER_ID, "user-123"),
            Map.entry(SessionHashFields.IDP_SUB, "auth0|reader"),
            Map.entry(SessionHashFields.EMAIL, "reader@example.com"),
            Map.entry(SessionHashFields.DISPLAY_NAME, "Reader Test"),
            Map.entry(SessionHashFields.PICTURE, ""),
            Map.entry(SessionHashFields.ROLES, "ROLE_USER,ROLE_ADMIN"),
            Map.entry(SessionHashFields.PERMISSIONS, "transactions:read,transactions:write"),
            Map.entry(SessionHashFields.CREATED_AT, String.valueOf(BASE_INSTANT.getEpochSecond())),
            Map.entry(
                SessionHashFields.EXPIRES_AT,
                String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()))),
        Duration.ofMinutes(5));

    var sessionData = sessionReader.readSession("session-123").block();

    assertThat(sessionData).isNotNull();
    assertThat(sessionData.userId()).isEqualTo("user-123");
    assertThat(sessionData.idpSub()).isEqualTo("auth0|reader");
    assertThat(sessionData.email()).isEqualTo("reader@example.com");
    assertThat(sessionData.displayName()).isEqualTo("Reader Test");
    assertThat(sessionData.picture()).isEmpty();
    assertThat(sessionData.roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    assertThat(sessionData.permissions())
        .containsExactly("transactions:read", "transactions:write");
    assertThat(sessionData.createdAt()).isEqualTo(BASE_INSTANT);
    assertThat(sessionData.expiresAt()).isEqualTo(BASE_INSTANT.plusSeconds(900));
  }

  @Test
  void readSessionResolvesGoldenVectorKeyFromRawToken() {
    var goldenSessionKey =
        TEST_SESSION_KEY_PREFIX
            + "16362f566387b3cf5a6e92fb0a986c76ca20eb3a0c12cbdfbd0b29501e0c18df";
    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .putAll(
            goldenSessionKey,
            Map.ofEntries(
                Map.entry(SessionHashFields.USER_ID, "user-golden"),
                Map.entry(
                    SessionHashFields.CREATED_AT, String.valueOf(BASE_INSTANT.getEpochSecond())),
                Map.entry(
                    SessionHashFields.EXPIRES_AT,
                    String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()))))
        .then(reactiveStringRedisTemplate.expire(goldenSessionKey, Duration.ofMinutes(5)))
        .block();

    var sessionData = sessionReader.readSession("3f2504e0-4f89-41d3-9a0c-0305e82c3301").block();

    assertThat(sessionData).isNotNull();
    assertThat(sessionData.userId()).isEqualTo("user-golden");
  }

  @Test
  void readSessionDoesNotResolveKeyNamedByRawToken() {
    writeRawTokenKeyedHash("raw-token-session");

    StepVerifier.create(sessionReader.readSession("raw-token-session")).verifyComplete();
  }

  @Test
  void readSessionReturnsEmptyWhenSessionMissing() {
    StepVerifier.create(sessionReader.readSession("missing-session")).verifyComplete();
  }

  @Test
  void readSessionReturnsEmptyWhenSessionExpired() {
    writeSessionHash(
        "expired-session",
        Map.ofEntries(
            Map.entry(SessionHashFields.USER_ID, "user-123"),
            Map.entry(SessionHashFields.IDP_SUB, "auth0|expired"),
            Map.entry(SessionHashFields.EMAIL, "expired@example.com"),
            Map.entry(SessionHashFields.DISPLAY_NAME, "Expired User"),
            Map.entry(SessionHashFields.PICTURE, ""),
            Map.entry(SessionHashFields.ROLES, "ROLE_USER"),
            Map.entry(SessionHashFields.PERMISSIONS, "transactions:read"),
            Map.entry(
                SessionHashFields.CREATED_AT,
                String.valueOf(BASE_INSTANT.minusSeconds(900).getEpochSecond())),
            Map.entry(
                SessionHashFields.EXPIRES_AT,
                String.valueOf(BASE_INSTANT.minusSeconds(1).getEpochSecond()))),
        Duration.ofMinutes(5));

    StepVerifier.create(sessionReader.readSession("expired-session")).verifyComplete();
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

  private void writeSessionHash(String sessionId, Map<String, String> sessionFields, Duration ttl) {
    var key = TEST_SESSION_KEY_PREFIX + SessionTokenDigest.sha256Hex(sessionId);

    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .putAll(key, sessionFields)
        .then(reactiveStringRedisTemplate.expire(key, ttl))
        .block();
  }

  private void writeRawTokenKeyedHash(String sessionToken) {
    var rawTokenKey = TEST_SESSION_KEY_PREFIX + sessionToken;

    reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .putAll(
            rawTokenKey,
            Map.ofEntries(
                Map.entry(SessionHashFields.USER_ID, "user-raw"),
                Map.entry(
                    SessionHashFields.CREATED_AT, String.valueOf(BASE_INSTANT.getEpochSecond())),
                Map.entry(
                    SessionHashFields.EXPIRES_AT,
                    String.valueOf(BASE_INSTANT.plusSeconds(900).getEpochSecond()))))
        .then(reactiveStringRedisTemplate.expire(rawTokenKey, Duration.ofMinutes(5)))
        .block();
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
