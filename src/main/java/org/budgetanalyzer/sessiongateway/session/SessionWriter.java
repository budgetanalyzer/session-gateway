package org.budgetanalyzer.sessiongateway.session;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.core.logging.SafeLogger;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;

/** Writes and manages session data in Redis as a single hash per session. */
@Component
public class SessionWriter {

  private static final Logger log = LoggerFactory.getLogger(SessionWriter.class);

  /** Updates hash fields and TTL only if the key already exists. Returns 1 if updated, 0 if not. */
  private static final RedisScript<Long> CONDITIONAL_UPDATE_SCRIPT =
      RedisScript.of(new ClassPathResource("redis/conditional-update.lua"), Long.class);

  /** Creates a session hash and its user session index entry atomically. */
  private static final RedisScript<Long> CREATE_SESSION_SCRIPT =
      RedisScript.of(new ClassPathResource("redis/create-session.lua"), Long.class);

  /** Deletes every indexed session for a user atomically. */
  private static final RedisScript<Long> DELETE_USER_SESSIONS_SCRIPT =
      RedisScript.of(new ClassPathResource("redis/delete-user-sessions.lua"), Long.class);

  private final ReactiveStringRedisTemplate redisTemplate;
  private final Clock clock;
  private final String keyPrefix;
  private final long ttlSeconds;

  public SessionWriter(
      ReactiveStringRedisTemplate redisTemplate, Clock clock, SessionProperties sessionProperties) {
    this.redisTemplate = redisTemplate;
    this.clock = clock;
    this.keyPrefix = sessionProperties.keyPrefix();
    this.ttlSeconds = sessionProperties.ttlSeconds();
  }

  /**
   * Creates a new session hash in Redis.
   *
   * <p>Generates a UUID session ID, writes all fields, and indexes the session for targeted
   * revocation in one Redis script execution.
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
    var sessionKey = sessionKey(sessionId);
    var userSessionsKey = userSessionsKey(userId);
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
        .execute(
            CREATE_SESSION_SCRIPT,
            List.of(sessionKey, userSessionsKey),
            createSessionArguments(sessionId, fields))
        .single()
        .thenReturn(sessionId);
  }

  /**
   * Updates the session expiry for heartbeat-driven sliding window.
   *
   * <p>Atomically checks that the session hash exists before writing. Returns false if the session
   * was deleted or expired between the caller's read and this write.
   *
   * @param sessionId the session ID
   * @param userId the internal user ID for refreshing the session index TTL
   * @param ttlSeconds the new TTL in seconds
   * @return true if updated, false if the session no longer exists
   */
  public Mono<Boolean> updateSessionExpiry(String sessionId, String userId, long ttlSeconds) {
    var sessionKey = sessionKey(sessionId);
    var userSessionsKey = userSessionsKey(userId);
    var expiresAt = String.valueOf(clock.instant().plusSeconds(ttlSeconds).getEpochSecond());

    return redisTemplate
        .execute(
            CONDITIONAL_UPDATE_SCRIPT,
            List.of(sessionKey, userSessionsKey),
            conditionalUpdateArguments(
                sessionId, ttlSeconds, SessionHashFields.EXPIRES_AT, expiresAt))
        .single()
        .map(result -> result == 1L);
  }

  /**
   * Updates the refresh token, token expiry, and session expiry after a successful IDP refresh.
   *
   * <p>Atomically checks that the session hash exists before writing. Returns false if the session
   * was deleted or expired between the caller's read and this write, preventing creation of partial
   * session hashes that lack identity fields.
   *
   * @param sessionId the session ID
   * @param userId the internal user ID for refreshing the session index TTL
   * @param refreshToken the new IDP refresh token
   * @param tokenExpiresAt when the new IDP access token expires
   * @param ttlSeconds the new session TTL in seconds
   * @return true if updated, false if the session no longer exists
   */
  public Mono<Boolean> updateTokenAndExpiry(
      String sessionId,
      String userId,
      String refreshToken,
      Instant tokenExpiresAt,
      long ttlSeconds) {
    var sessionKey = sessionKey(sessionId);
    var userSessionsKey = userSessionsKey(userId);
    var expiresAt = String.valueOf(clock.instant().plusSeconds(ttlSeconds).getEpochSecond());

    return redisTemplate
        .execute(
            CONDITIONAL_UPDATE_SCRIPT,
            List.of(sessionKey, userSessionsKey),
            conditionalUpdateArguments(
                sessionId,
                ttlSeconds,
                SessionHashFields.REFRESH_TOKEN,
                refreshToken,
                SessionHashFields.TOKEN_EXPIRES_AT,
                String.valueOf(tokenExpiresAt.getEpochSecond()),
                SessionHashFields.EXPIRES_AT,
                expiresAt))
        .single()
        .map(result -> result == 1L);
  }

  /**
   * Deletes a session hash from Redis.
   *
   * @param sessionId the session ID
   * @return true if the key was deleted
   */
  public Mono<Boolean> deleteSession(String sessionId) {
    var sessionKey = sessionKey(sessionId);
    log.debug("Deleting session {}", SafeLogger.truncateId(sessionId));

    return redisTemplate
        .<String, String>opsForHash()
        .get(sessionKey, SessionHashFields.USER_ID)
        .flatMap(
            userId ->
                redisTemplate
                    .unlink(sessionKey)
                    .flatMap(
                        deletedKeyCount ->
                            redisTemplate
                                .opsForSet()
                                .remove(userSessionsKey(userId), sessionId)
                                .thenReturn(deletedKeyCount > 0)))
        .defaultIfEmpty(false);
  }

  /**
   * Deletes every session currently indexed for the given user.
   *
   * @param userId the internal user ID whose sessions should be removed
   * @return the number of Redis keys deleted
   */
  public Mono<Long> deleteAllSessionsForUser(String userId) {
    var userSessionsKey = userSessionsKey(userId);

    return redisTemplate
        .execute(DELETE_USER_SESSIONS_SCRIPT, List.of(userSessionsKey), List.of(keyPrefix))
        .single();
  }

  private String sessionKey(String sessionId) {
    return keyPrefix + sessionId;
  }

  private List<String> createSessionArguments(String sessionId, Map<String, String> fields) {
    var scriptArguments = new ArrayList<String>();
    scriptArguments.add(sessionId);
    scriptArguments.add(String.valueOf(ttlSeconds));
    fields.forEach(
        (field, value) -> {
          scriptArguments.add(field);
          scriptArguments.add(value);
        });
    return List.copyOf(scriptArguments);
  }

  private List<String> conditionalUpdateArguments(
      String sessionId, long ttlSeconds, String... fieldValuePairs) {
    var scriptArguments = new ArrayList<String>();
    scriptArguments.add(sessionId);
    scriptArguments.addAll(List.of(fieldValuePairs));
    scriptArguments.add(String.valueOf(ttlSeconds));
    return List.copyOf(scriptArguments);
  }

  private String userSessionsKey(String userId) {
    return SessionHashFields.USER_SESSIONS_KEY_PREFIX + userId;
  }
}
