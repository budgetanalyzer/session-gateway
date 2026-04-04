package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
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

  private static final Instant NOW = Instant.parse("2026-04-02T21:30:00Z");

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
    var sessionProperties =
        new SessionProperties(
            "session:",
            900,
            300,
            900,
            new SessionProperties.CookieProperties("BA_SESSION", null, true, "Strict"));

    securityConfig =
        new SecurityConfig(
            authorizationRequestResolver,
            authorizationRequestRepository,
            authorizedClientRepository,
            serverSecurityContextRepository,
            permissionServiceClient,
            sessionWriter,
            sessionCookieHelper,
            new OAuth2CallbackRedirectResolver(),
            Clock.fixed(NOW, ZoneOffset.UTC),
            sessionProperties);
  }

  @Test
  void handleAuthenticationSuccess_redirectsToOopsWhenPermissionFetchFails() {
    var oauth2AuthenticationToken = createAuthenticationToken();
    var exchange = createCallbackExchange("/dashboard");
    var webFilterExchange = new WebFilterExchange(exchange, currentExchange -> Mono.empty());

    when(authorizedClientRepository.loadAuthorizedClient(
            eq("idp"), same(oauth2AuthenticationToken), same(exchange)))
        .thenReturn(Mono.just(createAuthorizedClient(oauth2AuthenticationToken)));
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

    when(authorizedClientRepository.loadAuthorizedClient(
            eq("idp"), same(oauth2AuthenticationToken), same(exchange)))
        .thenReturn(Mono.just(createAuthorizedClient(oauth2AuthenticationToken)));
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
            eq(List.of("transactions:read")),
            eq("refresh-token-value"),
            any(Instant.class)))
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
            eq(List.of("transactions:read")),
            eq("refresh-token-value"),
            any(Instant.class));
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

  private OAuth2AuthorizedClient createAuthorizedClient(
      OAuth2AuthenticationToken oauth2AuthenticationToken) {
    var clientRegistration =
        ClientRegistration.withRegistrationId("idp")
            .clientId("test-client-id")
            .clientSecret("test-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://tenant.example.com/authorize")
            .tokenUri("https://tenant.example.com/oauth/token")
            .scope("openid", "profile", "email")
            .userInfoUri("https://tenant.example.com/userinfo")
            .userNameAttributeName("sub")
            .jwkSetUri("https://tenant.example.com/.well-known/jwks.json")
            .build();
    var oauth2AccessToken =
        new OAuth2AccessToken(TokenType.BEARER, "access-token-value", NOW, NOW.plusSeconds(3600));
    var oauth2RefreshToken = new OAuth2RefreshToken("refresh-token-value", NOW);

    return new OAuth2AuthorizedClient(
        clientRegistration,
        oauth2AuthenticationToken.getName(),
        oauth2AccessToken,
        oauth2RefreshToken);
  }
}
