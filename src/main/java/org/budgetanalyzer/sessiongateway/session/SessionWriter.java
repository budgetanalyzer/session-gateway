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

  /** Updates authorization and TTL only if the session exists. Returns 1 if updated, 0 if not. */
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
   * <p>Generates a random UUID session token, writes all fields under the token's SHA-256 digest,
   * and indexes the digest for targeted revocation in one Redis script execution. The raw token is
   * returned for the cookie and never stored.
   *
   * @param userId internal user ID from the permission service
   * @param idpSub IDP subject identifier
   * @param email user's email address
   * @param displayName user's display name
   * @param picture user's profile picture URL (nullable)
   * @param roles user roles
   * @param permissions user permissions
   * @return the generated raw session token for the cookie
   */
  public Mono<String> createSession(
      String userId,
      String idpSub,
      String email,
      String displayName,
      String picture,
      List<String> roles,
      List<String> permissions) {
    var sessionToken = UUID.randomUUID().toString();
    var sessionDigest = SessionTokenDigest.sha256Hex(sessionToken);
    var sessionKey = keyPrefix + sessionDigest;
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
            Map.entry(SessionHashFields.CREATED_AT, String.valueOf(now.getEpochSecond())),
            Map.entry(SessionHashFields.EXPIRES_AT, String.valueOf(expiresAt.getEpochSecond())));

    log.debug("Creating session {} for userId={}", SafeLogger.truncateId(sessionDigest), userId);

    return redisTemplate
        .execute(
            CREATE_SESSION_SCRIPT,
            List.of(sessionKey, userSessionsKey),
            createSessionArguments(sessionDigest, fields))
        .single()
        .thenReturn(sessionToken);
  }

  /**
   * Refreshes authorization and expiry for the heartbeat-driven sliding window.
   *
   * <p>Atomically checks that the session hash exists before writing. Returns an empty publisher if
   * the session was deleted or expired between the caller's read and this write. The user session
   * index TTL is only ever extended, so a shorter TTL near the absolute lifetime cap cannot expire
   * the index before another of the user's sessions.
   *
   * @param sessionToken the raw session token from the cookie
   * @param userId the internal user ID for refreshing the session index TTL
   * @param roles the current roles from permission-service
   * @param permissions the current permissions from permission-service
   * @param expiresAt the new session expiry
   * @param ttlSeconds the new session TTL in seconds, matching {@code expiresAt}
   * @return the expiry written to Redis, or empty if the session no longer exists
   */
  public Mono<Instant> refreshSessionAuthorization(
      String sessionToken,
      String userId,
      List<String> roles,
      List<String> permissions,
      Instant expiresAt,
      long ttlSeconds) {
    var sessionDigest = SessionTokenDigest.sha256Hex(sessionToken);
    var sessionKey = keyPrefix + sessionDigest;
    var userSessionsKey = userSessionsKey(userId);

    return redisTemplate
        .execute(
            CONDITIONAL_UPDATE_SCRIPT,
            List.of(sessionKey, userSessionsKey),
            conditionalUpdateArguments(
                sessionDigest,
                ttlSeconds,
                SessionHashFields.ROLES,
                String.join(",", roles),
                SessionHashFields.PERMISSIONS,
                String.join(",", permissions),
                SessionHashFields.EXPIRES_AT,
                String.valueOf(expiresAt.getEpochSecond())))
        .single()
        .filter(result -> result == 1L)
        .map(result -> expiresAt);
  }

  /**
   * Deletes a session hash and its user index entry from Redis.
   *
   * @param sessionToken the raw session token from the cookie
   * @return true if the key was deleted
   */
  public Mono<Boolean> deleteSession(String sessionToken) {
    var sessionDigest = SessionTokenDigest.sha256Hex(sessionToken);
    var sessionKey = keyPrefix + sessionDigest;
    log.debug("Deleting session {}", SafeLogger.truncateId(sessionDigest));

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
                                .remove(userSessionsKey(userId), sessionDigest)
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

  private List<String> createSessionArguments(String sessionDigest, Map<String, String> fields) {
    var scriptArguments = new ArrayList<String>();
    scriptArguments.add(sessionDigest);
    scriptArguments.add(String.valueOf(ttlSeconds));
    fields.forEach(
        (field, value) -> {
          scriptArguments.add(field);
          scriptArguments.add(value);
        });
    return List.copyOf(scriptArguments);
  }

  private List<String> conditionalUpdateArguments(
      String sessionDigest, long ttlSeconds, String... fieldValuePairs) {
    var scriptArguments = new ArrayList<String>();
    scriptArguments.add(sessionDigest);
    scriptArguments.addAll(List.of(fieldValuePairs));
    scriptArguments.add(String.valueOf(ttlSeconds));
    return List.copyOf(scriptArguments);
  }

  private String userSessionsKey(String userId) {
    return SessionHashFields.USER_SESSIONS_KEY_PREFIX + userId;
  }
}
