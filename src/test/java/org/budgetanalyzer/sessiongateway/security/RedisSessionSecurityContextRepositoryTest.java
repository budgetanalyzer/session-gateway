package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextImpl;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;

@ExtendWith(MockitoExtension.class)
class RedisSessionSecurityContextRepositoryTest {

  @Mock private SessionCookieHelper sessionCookieHelper;
  @Mock private SessionReader sessionReader;

  @Test
  void loadReturnsEmptyWhenSessionCookieMissing() {
    var redisSessionSecurityContextRepository =
        new RedisSessionSecurityContextRepository(sessionCookieHelper, sessionReader);
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());

    when(sessionCookieHelper.readSessionId(mockServerWebExchange)).thenReturn(null);

    StepVerifier.create(redisSessionSecurityContextRepository.load(mockServerWebExchange))
        .verifyComplete();

    verifyNoInteractions(sessionReader);
  }

  @Test
  void loadReturnsEmptyWhenSessionMissingFromRedis() {
    var redisSessionSecurityContextRepository =
        new RedisSessionSecurityContextRepository(sessionCookieHelper, sessionReader);
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());

    when(sessionCookieHelper.readSessionId(mockServerWebExchange)).thenReturn("session-123");
    when(sessionReader.readSession("session-123")).thenReturn(Mono.empty());

    StepVerifier.create(redisSessionSecurityContextRepository.load(mockServerWebExchange))
        .verifyComplete();
  }

  @Test
  void loadRebuildsAuthenticatedSecurityContextFromSessionHash() {
    var redisSessionSecurityContextRepository =
        new RedisSessionSecurityContextRepository(sessionCookieHelper, sessionReader);
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());
    var sessionData =
        new SessionData(
            "user-123",
            "auth0|abc123",
            "jane@example.com",
            "Jane Doe",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            "refresh-token",
            Instant.parse("2026-03-30T00:10:00Z"),
            Instant.parse("2026-03-30T00:00:00Z"),
            Instant.parse("2026-03-30T00:15:00Z"));

    when(sessionCookieHelper.readSessionId(mockServerWebExchange)).thenReturn("session-123");
    when(sessionReader.readSession("session-123")).thenReturn(Mono.just(sessionData));

    var securityContext = redisSessionSecurityContextRepository.load(mockServerWebExchange).block();

    assertThat(securityContext).isInstanceOf(SecurityContextImpl.class);
    assertThat(securityContext.getAuthentication())
        .isInstanceOf(UsernamePasswordAuthenticationToken.class);
    assertThat(securityContext.getAuthentication().isAuthenticated()).isTrue();
    assertThat(securityContext.getAuthentication().getAuthorities())
        .extracting("authority")
        .containsExactlyInAnyOrder("ROLE_USER", "transactions:read");
    assertThat(securityContext.getAuthentication().getCredentials()).isEqualTo("session-123");

    var sessionPrincipal = (SessionPrincipal) securityContext.getAuthentication().getPrincipal();
    assertThat(sessionPrincipal.getName()).isEqualTo("auth0|abc123");
    assertThat(sessionPrincipal.userId()).isEqualTo("user-123");
    assertThat(sessionPrincipal.email()).isEqualTo("jane@example.com");
    assertThat(sessionPrincipal.displayName()).isEqualTo("Jane Doe");
    assertThat(sessionPrincipal.picture()).isEqualTo("https://example.com/avatar.png");
    assertThat(sessionPrincipal.roles()).containsExactly("ROLE_USER");
    assertThat(sessionPrincipal.permissions()).containsExactly("transactions:read");
  }

  @Test
  void saveIsNoOp() {
    var redisSessionSecurityContextRepository =
        new RedisSessionSecurityContextRepository(sessionCookieHelper, sessionReader);
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());

    StepVerifier.create(
            redisSessionSecurityContextRepository.save(
                mockServerWebExchange,
                new SecurityContextImpl(
                    UsernamePasswordAuthenticationToken.authenticated(
                        "principal", "session", List.of()))))
        .verifyComplete();
  }
}
