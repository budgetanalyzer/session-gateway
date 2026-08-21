package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.test.context.TestPropertySource;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@TestPropertySource(properties = "session.key-prefix=session:test:security-context:")
class RedisSessionSecurityContextRepositoryIntegrationTest extends AbstractIntegrationTest {

  private static final String TEST_USER_ID = "security-context-user";

  @Autowired private RedisSessionSecurityContextRepository redisSessionSecurityContextRepository;

  @Autowired private SessionWriter sessionWriter;
  @Autowired private SessionProperties sessionProperties;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @BeforeEach
  void deleteTestSessions() {
    Mono.when(
            deleteKeys(sessionProperties.keyPrefix() + "*"),
            deleteKeys(SessionHashFields.USER_SESSIONS_KEY_PREFIX + TEST_USER_ID))
        .block();
  }

  @Test
  void loadReturnsEmptyWhenSessionCookieMissing() {
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/auth/v1/user").build());

    StepVerifier.create(redisSessionSecurityContextRepository.load(mockServerWebExchange))
        .verifyComplete();
  }

  @Test
  void loadReturnsEmptyWhenSessionMissingFromRedis() {
    var mockServerWebExchange = exchangeWithSessionCookie("missing-session");

    StepVerifier.create(redisSessionSecurityContextRepository.load(mockServerWebExchange))
        .verifyComplete();
  }

  @Test
  void loadRebuildsAuthenticatedSecurityContextFromSessionHash() {
    var sessionId = createSession();
    var mockServerWebExchange = exchangeWithSessionCookie(sessionId);

    var securityContext = redisSessionSecurityContextRepository.load(mockServerWebExchange).block();

    assertThat(securityContext).isInstanceOf(SecurityContextImpl.class);
    assertThat(securityContext.getAuthentication())
        .isInstanceOf(UsernamePasswordAuthenticationToken.class);
    assertThat(securityContext.getAuthentication().isAuthenticated()).isTrue();
    assertThat(securityContext.getAuthentication().getAuthorities())
        .extracting("authority")
        .containsExactlyInAnyOrder("ROLE_USER", "transactions:read");
    assertThat(securityContext.getAuthentication().getCredentials()).isEqualTo(sessionId);

    var sessionPrincipal = (SessionPrincipal) securityContext.getAuthentication().getPrincipal();
    assertThat(sessionPrincipal.getName()).isEqualTo("auth0|security-context");
    assertThat(sessionPrincipal.userId()).isEqualTo(TEST_USER_ID);
    assertThat(sessionPrincipal.email()).isEqualTo("security-context@example.com");
    assertThat(sessionPrincipal.displayName()).isEqualTo("Security Context User");
    assertThat(sessionPrincipal.picture()).isEqualTo("https://example.com/avatar.png");
    assertThat(sessionPrincipal.roles()).containsExactly("ROLE_USER");
    assertThat(sessionPrincipal.permissions()).containsExactly("transactions:read");
  }

  @Test
  void saveLeavesExistingRedisSessionUnchanged() {
    var sessionId = createSession();
    var sessionKey = sessionProperties.keyPrefix() + sessionId;
    var mockServerWebExchange = exchangeWithSessionCookie(sessionId);
    var originalSessionFields = readHashEntries(sessionKey);
    var replacementSecurityContext =
        new SecurityContextImpl(
            UsernamePasswordAuthenticationToken.authenticated(
                "replacement-principal", "replacement-credentials", List.of()));

    StepVerifier.create(
            redisSessionSecurityContextRepository.save(
                mockServerWebExchange, replacementSecurityContext))
        .verifyComplete();

    assertThat(readHashEntries(sessionKey)).isEqualTo(originalSessionFields);
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            TEST_USER_ID,
            "auth0|security-context",
            "security-context@example.com",
            "Security Context User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"))
        .block();
  }

  private MockServerWebExchange exchangeWithSessionCookie(String sessionId) {
    return MockServerWebExchange.from(
        MockServerHttpRequest.get("/auth/v1/user")
            .cookie(new HttpCookie(sessionProperties.cookie().name(), sessionId))
            .build());
  }

  private Map<String, String> readHashEntries(String key) {
    return reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .blockOptional()
        .orElse(Map.of());
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
