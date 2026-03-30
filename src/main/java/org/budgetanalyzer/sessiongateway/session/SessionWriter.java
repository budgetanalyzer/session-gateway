package org.budgetanalyzer.sessiongateway.session;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.core.logging.SafeLogger;

/** Writes and manages session data in Redis as a single hash per session. */
@Component
public class SessionWriter {

  private static final Logger log = LoggerFactory.getLogger(SessionWriter.class);

  private final ReactiveStringRedisTemplate redisTemplate;
  private final Clock clock;
  private final String keyPrefix;
  private final long ttlSeconds;

  public SessionWriter(
      ReactiveStringRedisTemplate redisTemplate,
      Clock clock,
      @Value("${session.key-prefix:session:}") String keyPrefix,
      @Value("${session.ttl-seconds:1800}") long ttlSeconds) {
    this.redisTemplate = redisTemplate;
    this.clock = clock;
    this.keyPrefix = keyPrefix;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Creates a new session hash in Redis.
   *
   * <p>Generates a UUID session ID, writes all fields via HMSET, and sets the key TTL.
   *
   * @param userId internal user ID from the permission service
   * @param idpSub IDP subject identifier
   * @param email user's email address
   * @param displayName user's display name
   * @param picture user's profile picture URL (nullable)
   * @param roles user roles
   * @param permissions user permissions
   * @param refreshToken IDP refresh token (nullable for token exchange sessions)
   * @param tokenExpiresAt when the IDP access token expires
   * @return the generated session ID
   */
  public Mono<String> createSession(
      String userId,
      String idpSub,
      String email,
      String displayName,
      String picture,
      List<String> roles,
      List<String> permissions,
      String refreshToken,
      Instant tokenExpiresAt) {
    var sessionId = UUID.randomUUID().toString();
    var key = keyPrefix + sessionId;
    var now = clock.instant();
    var expiresAt = now.plusSeconds(ttlSeconds);

    var fields =
        Map.ofEntries(
            Map.entry(SessionHashFields.USER_ID, userId),
            Map.entry(SessionHashFields.IDP_SUB, idpSub),
            Map.entry(SessionHashFields.EMAIL, email),
            Map.entry(SessionHashFields.DISPLAY_NAME, displayName),
            Map.entry(SessionHashFields.PICTURE, picture != null ? picture : ""),
            Map.entry(SessionHashFields.ROLES, String.join(",", roles)),
            Map.entry(SessionHashFields.PERMISSIONS, String.join(",", permissions)),
            Map.entry(SessionHashFields.REFRESH_TOKEN, refreshToken != null ? refreshToken : ""),
            Map.entry(
                SessionHashFields.TOKEN_EXPIRES_AT,
                String.valueOf(tokenExpiresAt.getEpochSecond())),
            Map.entry(SessionHashFields.CREATED_AT, String.valueOf(now.getEpochSecond())),
            Map.entry(SessionHashFields.EXPIRES_AT, String.valueOf(expiresAt.getEpochSecond())));

    log.debug("Creating session {} for userId={}", SafeLogger.truncateId(sessionId), userId);

    return redisTemplate
        .<String, String>opsForHash()
        .putAll(key, fields)
        .then(redisTemplate.expire(key, Duration.ofSeconds(ttlSeconds)))
        .thenReturn(sessionId);
  }

  /**
   * Updates the session expiry for heartbeat-driven sliding window.
   *
   * <p>Resets the {@code expires_at} hash field and the Redis key TTL.
   *
   * @param sessionId the session ID
   * @param ttlSeconds the new TTL in seconds
   * @return true if the key TTL was set
   */
  public Mono<Boolean> updateSessionExpiry(String sessionId, long ttlSeconds) {
    var key = keyPrefix + sessionId;
    var expiresAt = String.valueOf(clock.instant().plusSeconds(ttlSeconds).getEpochSecond());

    return redisTemplate
        .<String, String>opsForHash()
        .put(key, SessionHashFields.EXPIRES_AT, expiresAt)
        .then(redisTemplate.expire(key, Duration.ofSeconds(ttlSeconds)));
  }

  /**
   * Updates the refresh token, token expiry, and session expiry after a successful IDP refresh.
   *
   * @param sessionId the session ID
   * @param refreshToken the new IDP refresh token
   * @param tokenExpiresAt when the new IDP access token expires
   * @param ttlSeconds the new session TTL in seconds
   * @return true if the key TTL was set
   */
  public Mono<Boolean> updateTokenAndExpiry(
      String sessionId, String refreshToken, Instant tokenExpiresAt, long ttlSeconds) {
    var key = keyPrefix + sessionId;
    var expiresAt = String.valueOf(clock.instant().plusSeconds(ttlSeconds).getEpochSecond());

    var fields =
        Map.of(
            SessionHashFields.REFRESH_TOKEN, refreshToken,
            SessionHashFields.TOKEN_EXPIRES_AT, String.valueOf(tokenExpiresAt.getEpochSecond()),
            SessionHashFields.EXPIRES_AT, expiresAt);

    return redisTemplate
        .<String, String>opsForHash()
        .putAll(key, fields)
        .then(redisTemplate.expire(key, Duration.ofSeconds(ttlSeconds)));
  }

  /**
   * Deletes a session hash from Redis.
   *
   * @param sessionId the session ID
   * @return true if the key was deleted
   */
  public Mono<Boolean> deleteSession(String sessionId) {
    var key = keyPrefix + sessionId;
    log.debug("Deleting session {}", SafeLogger.truncateId(sessionId));

    return redisTemplate.delete(key).map(count -> count > 0);
  }
}
