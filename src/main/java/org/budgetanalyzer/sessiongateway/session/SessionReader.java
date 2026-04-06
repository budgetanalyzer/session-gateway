package org.budgetanalyzer.sessiongateway.session;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.core.logging.SafeLogger;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;

/** Reads session data from Redis hashes. */
@Component
public class SessionReader {

  private static final Logger log = LoggerFactory.getLogger(SessionReader.class);

  private final ReactiveStringRedisTemplate redisTemplate;
  private final Clock clock;
  private final String keyPrefix;

  public SessionReader(
      ReactiveStringRedisTemplate redisTemplate, Clock clock, SessionProperties sessionProperties) {
    this.redisTemplate = redisTemplate;
    this.clock = clock;
    this.keyPrefix = sessionProperties.keyPrefix();
  }

  /**
   * Reads a session from Redis by session ID.
   *
   * <p>Returns {@code Mono.empty()} if the session does not exist or has expired.
   *
   * @param sessionId the session ID
   * @return the session data, or empty if not found or expired
   */
  public Mono<SessionData> readSession(String sessionId) {
    var key = keyPrefix + sessionId;

    return redisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .filter(fields -> !fields.isEmpty())
        .flatMap(
            fields -> {
              var expiresAt =
                  Instant.ofEpochSecond(Long.parseLong(fields.get(SessionHashFields.EXPIRES_AT)));

              if (clock.instant().isAfter(expiresAt)) {
                log.debug("Session {} has expired", SafeLogger.truncateId(sessionId));
                return Mono.empty();
              }

              var roles = fields.getOrDefault(SessionHashFields.ROLES, "");
              var permissions = fields.getOrDefault(SessionHashFields.PERMISSIONS, "");

              return Mono.just(
                  new SessionData(
                      fields.get(SessionHashFields.USER_ID),
                      fields.get(SessionHashFields.IDP_SUB),
                      fields.get(SessionHashFields.EMAIL),
                      fields.get(SessionHashFields.DISPLAY_NAME),
                      fields.getOrDefault(SessionHashFields.PICTURE, ""),
                      roles.isEmpty() ? List.of() : List.of(roles.split(",")),
                      permissions.isEmpty() ? List.of() : List.of(permissions.split(",")),
                      Instant.ofEpochSecond(
                          Long.parseLong(fields.get(SessionHashFields.CREATED_AT))),
                      expiresAt));
            });
  }
}
