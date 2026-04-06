package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.test.util.ReflectionTestUtils;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.security.OAuth2CallbackRedirectResolver;
import org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@ExtendWith(MockitoExtension.class)
class SecurityConfigTest {

  @Mock private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  @Mock private RedisAuthorizationRequestRepository authorizationRequestRepository;
  @Mock private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private ServerSecurityContextRepository serverSecurityContextRepository;
  @Mock private PermissionServiceClient permissionServiceClient;
  @Mock private SessionWriter sessionWriter;
  @Mock private SessionCookieHelper sessionCookieHelper;

  private SecurityConfig securityConfig;

  @BeforeEach
  void setUp() {
    securityConfig =
        new SecurityConfig(
            authorizationRequestResolver,
            authorizationRequestRepository,
            authorizedClientRepository,
            serverSecurityContextRepository,
            permissionServiceClient,
            sessionWriter,
            sessionCookieHelper,
            new OAuth2CallbackRedirectResolver());
  }

  @Test
  void handleAuthenticationSuccess_redirectsToOopsWhenPermissionFetchFails() {
    var oauth2AuthenticationToken = createAuthenticationToken();
    var exchange = createCallbackExchange("/dashboard");
    var webFilterExchange = new WebFilterExchange(exchange, currentExchange -> Mono.empty());

    when(permissionServiceClient.fetchPermissions(
            eq("auth0|user-123"), eq("user@example.com"), eq("Test User")))
        .thenReturn(Mono.error(new PermissionServiceClient.PermissionServiceException("boom")));

    invokeHandleAuthenticationSuccess(webFilterExchange, oauth2AuthenticationToken).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
    verifyNoInteractions(sessionWriter, sessionCookieHelper);
  }

  @Test
  void handleAuthenticationSuccess_redirectsToOopsWhenSessionCreationFails() {
    var oauth2AuthenticationToken = createAuthenticationToken();
    var exchange = createCallbackExchange("/dashboard");
    var webFilterExchange = new WebFilterExchange(exchange, currentExchange -> Mono.empty());

    when(permissionServiceClient.fetchPermissions(
            eq("auth0|user-123"), eq("user@example.com"), eq("Test User")))
        .thenReturn(
            Mono.just(
                new PermissionServiceClient.PermissionResponse(
                    "internal-user-456", List.of("ROLE_USER"), List.of("transactions:read"))));
    when(sessionWriter.createSession(
            eq("internal-user-456"),
            eq("auth0|user-123"),
            eq("user@example.com"),
            eq("Test User"),
            eq("https://cdn.example.com/avatar.png"),
            eq(List.of("ROLE_USER")),
            eq(List.of("transactions:read"))))
        .thenReturn(Mono.error(new IllegalStateException("redis unavailable")));

    invokeHandleAuthenticationSuccess(webFilterExchange, oauth2AuthenticationToken).block();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
    verify(sessionWriter)
        .createSession(
            eq("internal-user-456"),
            eq("auth0|user-123"),
            eq("user@example.com"),
            eq("Test User"),
            eq("https://cdn.example.com/avatar.png"),
            eq(List.of("ROLE_USER")),
            eq(List.of("transactions:read")));
    verifyNoInteractions(sessionCookieHelper);
  }

  @SuppressWarnings("unchecked")
  private Mono<Void> invokeHandleAuthenticationSuccess(
      WebFilterExchange webFilterExchange, Authentication authentication) {
    return (Mono<Void>)
        ReflectionTestUtils.invokeMethod(
            securityConfig, "handleAuthenticationSuccess", webFilterExchange, authentication);
  }

  private MockServerWebExchange createCallbackExchange(String returnUrl) {
    var mockServerWebExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/idp?code=test-code&state=test-state")
                .build());
    mockServerWebExchange
        .getAttributes()
        .put(
            RedisAuthorizationRequestRepository.AUTHORIZATION_REQUEST_ATTRIBUTE,
            OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://tenant.example.com/authorize")
                .clientId("test-client-id")
                .redirectUri("https://app.example.com/login/oauth2/code/idp")
                .state("test-state")
                .additionalParameters(parameters -> parameters.put("return_url", returnUrl))
                .build());
    return mockServerWebExchange;
  }

  private OAuth2AuthenticationToken createAuthenticationToken() {
    var defaultOauth2User =
        new DefaultOAuth2User(
            List.of(new SimpleGrantedAuthority("ROLE_USER")),
            Map.of(
                "sub", "auth0|user-123",
                "email", "user@example.com",
                "name", "Test User",
                "picture", "https://cdn.example.com/avatar.png"),
            "sub");

    return new OAuth2AuthenticationToken(
        defaultOauth2User, defaultOauth2User.getAuthorities(), "idp");
  }
}
