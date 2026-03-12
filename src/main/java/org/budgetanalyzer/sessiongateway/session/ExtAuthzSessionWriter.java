package org.budgetanalyzer.sessiongateway.session;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.connection.ReactiveRedisConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Service;

import reactor.core.publisher.Mono;

/**
 * Dual-writes session data to the ext_authz Redis schema.
 *
 * <p>Writes session data as a Redis hash under {@code extauthz:session:{id}} for the Envoy
 * ext_authz gRPC service to validate requests directly from Redis.
 */
@Service
public class ExtAuthzSessionWriter {

  private static final Logger log = LoggerFactory.getLogger(ExtAuthzSessionWriter.class);

  private final ReactiveRedisTemplate<String, String> reactiveRedisTemplate;
  private final String keyPrefix;
  private final long ttlSeconds;

  /**
   * Creates a new ExtAuthzSessionWriter.
   *
   * @param reactiveRedisConnectionFactory the Redis connection factory
   * @param keyPrefix the Redis key prefix for ext_authz sessions
   * @param ttlSeconds the TTL in seconds for ext_authz session keys
   */
  public ExtAuthzSessionWriter(
      ReactiveRedisConnectionFactory reactiveRedisConnectionFactory,
      @Value("${extauthz.session.key-prefix:extauthz:session:}") String keyPrefix,
      @Value("${extauthz.session.ttl-seconds:1800}") long ttlSeconds) {
    var serializationContext =
        RedisSerializationContext.<String, String>newSerializationContext(
                new StringRedisSerializer())
            .build();
    this.reactiveRedisTemplate =
        new ReactiveRedisTemplate<>(reactiveRedisConnectionFactory, serializationContext);
    this.keyPrefix = keyPrefix;
    this.ttlSeconds = ttlSeconds;
  }

  /**
   * Writes session data to the ext_authz Redis hash.
   *
   * <p>Creates a hash with fields: user_id, roles, permissions, created_at, expires_at. Errors are
   * logged and swallowed to avoid breaking the primary session flow.
   *
   * @param sessionId the Spring session ID
   * @param userId the internal user ID
   * @param roles the user's roles
   * @param permissions the user's permissions
   * @return a Mono that completes when the write is done
   */
  public Mono<Void> writeSession(
      String sessionId, String userId, List<String> roles, List<String> permissions) {
    var key = keyPrefix + sessionId;
    var now = Instant.now();
    var expiresAt = now.plusSeconds(ttlSeconds);
    var hashOps = reactiveRedisTemplate.opsForHash();

    var fields =
        Map.of(
            "user_id", userId,
            "roles", String.join(",", roles),
            "permissions", String.join(",", permissions),
            "created_at", String.valueOf(now.getEpochSecond()),
            "expires_at", String.valueOf(expiresAt.getEpochSecond()));

    return hashOps
        .putAll(key, fields)
        .then(reactiveRedisTemplate.expire(key, Duration.ofSeconds(ttlSeconds)))
        .then()
        .doOnSuccess(v -> log.debug("Wrote ext_authz session for sessionId={}", sessionId))
        .onErrorResume(
            error -> {
              log.warn("Failed to write ext_authz session for sessionId={}", sessionId, error);
              return Mono.empty();
            });
  }

  /**
   * Deletes the ext_authz session from Redis.
   *
   * <p>Errors are logged and swallowed to avoid breaking the logout flow.
   *
   * @param sessionId the Spring session ID
   * @return a Mono that completes when the deletion is done
   */
  public Mono<Void> deleteSession(String sessionId) {
    var key = keyPrefix + sessionId;

    return reactiveRedisTemplate
        .delete(key)
        .then()
        .doOnSuccess(v -> log.debug("Deleted ext_authz session for sessionId={}", sessionId))
        .onErrorResume(
            error -> {
              log.warn("Failed to delete ext_authz session for sessionId={}", sessionId, error);
              return Mono.empty();
            });
  }
}
