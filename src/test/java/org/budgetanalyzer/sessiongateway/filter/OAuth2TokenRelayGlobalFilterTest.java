package org.budgetanalyzer.sessiongateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.service.InternalJwtService;

@ExtendWith(MockitoExtension.class)
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
class OAuth2TokenRelayGlobalFilterTest {

  @Mock private InternalJwtService internalJwtService;
  @Mock private GatewayFilterChain chain;

  private OAuth2TokenRelayGlobalFilter oauth2TokenRelayGlobalFilter;
  private OAuth2AuthenticationToken oauth2AuthenticationToken;

  @BeforeEach
  void setUp() {
    oauth2TokenRelayGlobalFilter = new OAuth2TokenRelayGlobalFilter(internalJwtService);

    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    oauth2AuthenticationToken =
        new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    lenient().when(chain.filter(any())).thenReturn(Mono.empty());
  }

  @Test
  void filter_addsBearerHeaderWhenCachedJwtIsValid() {
    var exchange = buildExchange();
    exchange
        .getSession()
        .block()
        .getAttributes()
        .put(InternalJwtService.SESSION_INTERNAL_JWT, "cached-jwt-token");
    when(internalJwtService.needsRemint("cached-jwt-token")).thenReturn(false);

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    var captured = captureExchange();
    assertThat(captured.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .isEqualTo("Bearer cached-jwt-token");
  }

  @Test
  void filter_remintsJwtWhenCachedTokenNeedsRemint() {
    var exchange = buildExchange();
    var session = exchange.getSession().block();
    session.getAttributes().put(InternalJwtService.SESSION_INTERNAL_JWT, "old-jwt");
    session.getAttributes().put(InternalJwtService.SESSION_USER_ID, "user-456");
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("ROLE_USER"));
    session.getAttributes().put(InternalJwtService.SESSION_PERMISSIONS, List.of("read"));

    when(internalJwtService.needsRemint("old-jwt")).thenReturn(true);
    when(internalJwtService.mintToken(
            "auth0|abc123", "user-456", List.of("ROLE_USER"), List.of("read")))
        .thenReturn("new-jwt");

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    var captured = captureExchange();
    assertThat(captured.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .isEqualTo("Bearer new-jwt");
    verify(internalJwtService)
        .mintToken("auth0|abc123", "user-456", List.of("ROLE_USER"), List.of("read"));
  }

  @Test
  void filter_cachesMintedJwtInSession() {
    var exchange = buildExchange();
    var session = exchange.getSession().block();

    session.getAttributes().put(InternalJwtService.SESSION_USER_ID, "user-456");
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("ROLE_USER"));
    session.getAttributes().put(InternalJwtService.SESSION_PERMISSIONS, List.of("read"));

    when(internalJwtService.needsRemint(null)).thenReturn(true);
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("fresh-jwt");

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    assertThat(session.getAttributes().get(InternalJwtService.SESSION_INTERNAL_JWT))
        .isEqualTo("fresh-jwt");
  }

  @Test
  void filter_remintsWhenNoCachedJwtExists() {
    var exchange = buildExchange();
    var session = exchange.getSession().block();

    session.getAttributes().put(InternalJwtService.SESSION_USER_ID, "user-456");
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("ROLE_USER"));
    session.getAttributes().put(InternalJwtService.SESSION_PERMISSIONS, List.of("read"));

    when(internalJwtService.needsRemint(null)).thenReturn(true);
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("minted-jwt");

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    var captured = captureExchange();
    assertThat(captured.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
        .isEqualTo("Bearer minted-jwt");
  }

  @Test
  void filter_skipsHeaderWhenSessionMissingPermissionData() {
    var exchange = buildExchange();
    // No session attributes set — userId, roles, permissions all null
    when(internalJwtService.needsRemint(null)).thenReturn(true);

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    verify(internalJwtService, never()).mintToken(any(), any(), any(), any());

    // Original exchange should be passed through (no Authorization header)
    var captured = captureExchange();
    assertThat(captured.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
  }

  @Test
  void filter_skipsHeaderWhenUserIdMissing() {
    var exchange = buildExchange();
    var session = exchange.getSession().block();
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("ROLE_USER"));
    session.getAttributes().put(InternalJwtService.SESSION_PERMISSIONS, List.of("read"));
    // No userId

    when(internalJwtService.needsRemint(null)).thenReturn(true);

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(oauth2AuthenticationToken))))
        .block();

    verify(internalJwtService, never()).mintToken(any(), any(), any(), any());
  }

  @Test
  void filter_passesThruForUnauthenticatedRequest() {
    var exchange = buildExchange();

    // No security context at all
    StepVerifier.create(oauth2TokenRelayGlobalFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
  }

  @Test
  void filter_passesThruForNonOauthAuthentication() {
    var exchange = buildExchange();
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");

    oauth2TokenRelayGlobalFilter
        .filter(exchange, chain)
        .contextWrite(
            ReactiveSecurityContextHolder.withSecurityContext(
                Mono.just(new SecurityContextImpl(auth))))
        .block();

    // Original exchange passed through — no Authorization header
    verify(chain).filter(exchange);
  }

  @Test
  void getOrder_returnsHighestPrecedencePlus100() {
    assertThat(oauth2TokenRelayGlobalFilter.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE + 100);
  }

  private MockServerWebExchange buildExchange() {
    return MockServerWebExchange.from(MockServerHttpRequest.get("/api/test").build());
  }

  private ServerWebExchange captureExchange() {
    ArgumentCaptor<ServerWebExchange> captor = ArgumentCaptor.forClass(ServerWebExchange.class);
    verify(chain).filter(captor.capture());

    return captor.getValue();
  }
}
