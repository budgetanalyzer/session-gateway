package org.budgetanalyzer.sessiongateway.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.service.InternalJwtService;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient.PermissionResponse;

@ExtendWith(MockitoExtension.class)
class TokenRefreshGatewayFilterFactoryTest {

  private static final Instant FIXED_NOW = Instant.parse("2025-06-15T12:00:00Z");
  private static final String IDP_SUB = "auth0|abc123";
  private static final String EMAIL = "user@example.com";
  private static final String DISPLAY_NAME = "Test User";

  @Mock private ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
  @Mock private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private PermissionServiceClient permissionServiceClient;
  @Mock private InternalJwtService internalJwtService;
  @Mock private GatewayFilterChain chain;
  @Mock private ServerWebExchange exchange;
  @Mock private WebSession session;

  private final Clock fixedClock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
  private Map<String, Object> sessionAttributes;
  private GatewayFilter gatewayFilter;
  private OAuth2AuthenticationToken oauth2AuthenticationToken;

  @BeforeEach
  void setUp() {
    var factory =
        new TokenRefreshGatewayFilterFactory(
            authorizedClientManager,
            authorizedClientRepository,
            permissionServiceClient,
            internalJwtService,
            fixedClock);
    gatewayFilter = factory.apply(new TokenRefreshGatewayFilterFactory.Config());

    var attributes = Map.<String, Object>of("sub", IDP_SUB, "email", EMAIL, "name", DISPLAY_NAME);
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    oauth2AuthenticationToken =
        new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    sessionAttributes = new HashMap<>();

    lenient().when(exchange.getPrincipal()).thenReturn(Mono.just(oauth2AuthenticationToken));
    lenient().when(exchange.getSession()).thenReturn(Mono.just(session));
    lenient().when(session.getAttributes()).thenReturn(sessionAttributes);
    lenient().when(chain.filter(any())).thenReturn(Mono.empty());
  }

  // --- Refresh threshold tests ---

  @Test
  void filter_skipsRefreshWhenTokenNotExpiringSoon() {
    // Expires in 10 min > 5 min threshold
    var client = buildClient(FIXED_NOW.plusSeconds(600));
    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientManager, never()).authorize(any());
    verify(chain).filter(exchange);
  }

  @Test
  void filter_triggersRefreshWhenTokenExpiringSoon() {
    // Expires in 3 min < 5 min threshold
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("new-jwt");

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientManager).authorize(any());
  }

  @Test
  void filter_triggersRefreshWhenTokenAlreadyExpired() {
    // Issued 30 min ago, expired 1 min ago
    var issuedAt = FIXED_NOW.minusSeconds(1800);
    var client = buildClient(issuedAt, FIXED_NOW.minusSeconds(60));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("jwt");

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientManager).authorize(any());
  }

  @Test
  void filter_skipsRefreshWhenAccessTokenIsNull() {
    // Mock an authorized client that returns null access token
    var client = mock(OAuth2AuthorizedClient.class);
    when(client.getAccessToken()).thenReturn(null);

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientManager, never()).authorize(any());
    verify(chain).filter(exchange);
  }

  @Test
  void filter_skipsRefreshWhenExpiresAtIsNull() {
    // Build token without expiresAt
    var registration = buildRegistration();
    var token =
        new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token-value", FIXED_NOW, null);
    var client = new OAuth2AuthorizedClient(registration, IDP_SUB, token);

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientManager, never()).authorize(any());
  }

  // --- Happy path tests ---

  @Test
  void filter_savesRefreshedClient() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("jwt");

    gatewayFilter.filter(exchange, chain).block();

    verify(authorizedClientRepository)
        .saveAuthorizedClient(refreshedClient, oauth2AuthenticationToken, exchange);
  }

  @Test
  void filter_fetchesPermissionsAfterRefresh() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("jwt");

    gatewayFilter.filter(exchange, chain).block();

    verify(permissionServiceClient).fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME);
  }

  @Test
  void filter_storesPermissionsInSessionAfterRefresh() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("jwt");

    gatewayFilter.filter(exchange, chain).block();

    assertThat(sessionAttributes)
        .containsEntry(InternalJwtService.SESSION_USER_ID, "user-1")
        .containsEntry(InternalJwtService.SESSION_ROLES, List.of("ROLE_USER"))
        .containsEntry(InternalJwtService.SESSION_PERMISSIONS, List.of("transactions:read"));
  }

  @Test
  void filter_mintsNewJwtAfterRefresh() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(IDP_SUB, "user-1", List.of("ROLE_USER"), List.of("read")))
        .thenReturn("minted-jwt");

    gatewayFilter.filter(exchange, chain).block();

    verify(internalJwtService).mintToken(IDP_SUB, "user-1", List.of("ROLE_USER"), List.of("read"));
    assertThat(sessionAttributes)
        .containsEntry(InternalJwtService.SESSION_INTERNAL_JWT, "minted-jwt");
  }

  // --- Error/fallback tests ---

  @Test
  void filter_fallsBackToOriginalClientOnRefreshError() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any()))
        .thenReturn(Mono.error(new RuntimeException("refresh failed")));

    StepVerifier.create(gatewayFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
    verify(permissionServiceClient, never()).fetchPermissions(any(), any(), any());
  }

  @Test
  void filter_continuesWhenRefreshReturnsEmpty() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.empty());

    StepVerifier.create(gatewayFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
  }

  @Test
  void filter_swallowsPermissionFetchError() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(Mono.error(new RuntimeException("permission service down")));

    StepVerifier.create(gatewayFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
    assertThat(sessionAttributes).doesNotContainKey(InternalJwtService.SESSION_USER_ID);
  }

  @Test
  void filter_continuesChainAfterSuccessfulRefresh() {
    var client = buildClient(FIXED_NOW.plusSeconds(180));
    var refreshedClient = buildClient(FIXED_NOW.plusSeconds(1800));

    when(authorizedClientRepository.loadAuthorizedClient(
            "idp", oauth2AuthenticationToken, exchange))
        .thenReturn(Mono.just(client));
    when(authorizedClientManager.authorize(any())).thenReturn(Mono.just(refreshedClient));
    when(authorizedClientRepository.saveAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions(IDP_SUB, EMAIL, DISPLAY_NAME))
        .thenReturn(
            Mono.just(new PermissionResponse("user-1", List.of("ROLE_USER"), List.of("read"))));
    when(internalJwtService.mintToken(anyString(), anyString(), anyList(), anyList()))
        .thenReturn("jwt");

    StepVerifier.create(gatewayFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
  }

  // --- Edge case ---

  @Test
  void filter_continuesChainForNonOauthPrincipal() {
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");
    when(exchange.getPrincipal()).thenReturn(Mono.just(auth));

    StepVerifier.create(gatewayFilter.filter(exchange, chain)).verifyComplete();

    verify(chain).filter(exchange);
    verifyNoInteractions(authorizedClientRepository);
    verifyNoInteractions(authorizedClientManager);
  }

  // --- Helpers ---

  private OAuth2AuthorizedClient buildClient(Instant expiresAt) {
    return buildClient(FIXED_NOW, expiresAt);
  }

  private OAuth2AuthorizedClient buildClient(Instant issuedAt, Instant expiresAt) {
    var registration = buildRegistration();
    var accessToken =
        new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER, "access-token", issuedAt, expiresAt);
    return new OAuth2AuthorizedClient(registration, IDP_SUB, accessToken);
  }

  private ClientRegistration buildRegistration() {
    return ClientRegistration.withRegistrationId("idp")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .clientId("test-client-id")
        .redirectUri("https://example.com/callback")
        .authorizationUri("https://idp.example.com/authorize")
        .tokenUri("https://idp.example.com/token")
        .build();
  }
}
