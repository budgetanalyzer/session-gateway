package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

@Testcontainers
class ExtAuthzSessionWriterTest {

  @Container
  static GenericContainer<?> redisContainer =
      new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
          .withExposedPorts(6379)
          .withReuse(true);

  private static final String KEY_PREFIX = "extauthz:session:test:";
  private static final long TTL_SECONDS = 1800;

  private ExtAuthzSessionWriter extAuthzSessionWriter;
  private ReactiveRedisTemplate<String, String> reactiveRedisTemplate;

  @BeforeEach
  void setUp() {
    var connectionFactory =
        new LettuceConnectionFactory(redisContainer.getHost(), redisContainer.getFirstMappedPort());
    connectionFactory.afterPropertiesSet();

    var serializationContext =
        RedisSerializationContext.<String, String>newSerializationContext(
                new StringRedisSerializer())
            .build();
    reactiveRedisTemplate = new ReactiveRedisTemplate<>(connectionFactory, serializationContext);

    extAuthzSessionWriter = new ExtAuthzSessionWriter(connectionFactory, KEY_PREFIX, TTL_SECONDS);
  }

  @Test
  void writeSession_createsHashWithCorrectFields() {
    extAuthzSessionWriter
        .writeSession(
            "session-1",
            "user-123",
            List.of("ROLE_USER", "ROLE_ADMIN"),
            List.of("transactions:read", "transactions:write"))
        .block();

    var key = KEY_PREFIX + "session-1";
    var hashOps = reactiveRedisTemplate.opsForHash();

    assertThat(hashOps.get(key, "user_id").block()).isEqualTo("user-123");
    assertThat(hashOps.get(key, "roles").block()).isEqualTo("ROLE_USER,ROLE_ADMIN");
    assertThat(hashOps.get(key, "permissions").block())
        .isEqualTo("transactions:read,transactions:write");
    assertThat(hashOps.get(key, "created_at").block()).isNotNull();
    assertThat(hashOps.get(key, "expires_at").block()).isNotNull();
  }

  @Test
  void writeSession_setsTtl() {
    extAuthzSessionWriter
        .writeSession("session-ttl", "user-123", List.of("ROLE_USER"), List.of("read"))
        .block();

    var key = KEY_PREFIX + "session-ttl";
    var ttl = reactiveRedisTemplate.getExpire(key).block();

    assertThat(ttl).isNotNull();
    assertThat(ttl).isGreaterThan(Duration.ZERO);
    assertThat(ttl).isLessThanOrEqualTo(Duration.ofSeconds(TTL_SECONDS));
  }

  @Test
  void writeSession_commaJoinsRolesAndPermissions() {
    extAuthzSessionWriter
        .writeSession(
            "session-join", "user-1", List.of("A", "B", "C"), List.of("x:read", "y:write"))
        .block();

    var key = KEY_PREFIX + "session-join";
    var hashOps = reactiveRedisTemplate.opsForHash();

    assertThat(hashOps.get(key, "roles").block()).isEqualTo("A,B,C");
    assertThat(hashOps.get(key, "permissions").block()).isEqualTo("x:read,y:write");
  }

  @Test
  void deleteSession_removesKey() {
    extAuthzSessionWriter
        .writeSession("session-del", "user-1", List.of("ROLE_USER"), List.of("read"))
        .block();

    var key = KEY_PREFIX + "session-del";
    assertThat(reactiveRedisTemplate.hasKey(key).block()).isTrue();

    extAuthzSessionWriter.deleteSession("session-del").block();

    assertThat(reactiveRedisTemplate.hasKey(key).block()).isFalse();
  }

  @Test
  void writeSession_handlesEmptyLists() {
    extAuthzSessionWriter.writeSession("session-empty", "user-1", List.of(), List.of()).block();

    var key = KEY_PREFIX + "session-empty";
    var hashOps = reactiveRedisTemplate.opsForHash();

    assertThat(hashOps.get(key, "roles").block()).isEqualTo("");
    assertThat(hashOps.get(key, "permissions").block()).isEqualTo("");
  }
}
