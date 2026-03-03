package org.budgetanalyzer.sessiongateway.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

@ExtendWith(MockitoExtension.class)
class LogoutControllerTest {

  private static final String URL_TEMPLATE =
      "https://idp.example.com/v2/logout?returnTo={returnTo}&client_id={clientId}";
  private static final String CLIENT_ID = "my-client-id";
  private static final String RETURN_TO = "https://app.example.com";

  @Mock private ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  @Mock private ServerWebExchange exchange;
  @Mock private WebSession session;
  @Mock private ServerHttpResponse response;

  private HttpHeaders headers;
  private LogoutController logoutController;
  private OAuth2AuthenticationToken oauth2AuthenticationToken;

  @BeforeEach
  void setUp() {
    logoutController =
        new LogoutController(authorizedClientRepository, URL_TEMPLATE, CLIENT_ID, RETURN_TO);
    headers = new HttpHeaders();

    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    oauth2AuthenticationToken =
        new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "auth0");

    lenient().when(exchange.getSession()).thenReturn(Mono.just(session));
    lenient().when(exchange.getResponse()).thenReturn(response);
    lenient().when(session.invalidate()).thenReturn(Mono.empty());
    lenient().when(response.getHeaders()).thenReturn(headers);
    lenient().when(response.setComplete()).thenReturn(Mono.empty());
    lenient()
        .when(authorizedClientRepository.removeAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.empty());
  }

  @Test
  void logout_removesAuthorizedClientForOauthToken() {
    logoutController.logout(exchange, oauth2AuthenticationToken).block();

    verify(authorizedClientRepository)
        .removeAuthorizedClient("auth0", oauth2AuthenticationToken, exchange);
  }

  @Test
  void logout_skipsClientRemovalForNonOauthAuth() {
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");

    logoutController.logout(exchange, auth).block();

    verifyNoInteractions(authorizedClientRepository);
  }

  @Test
  void logout_invalidatesSession() {
    logoutController.logout(exchange, oauth2AuthenticationToken).block();

    verify(session).invalidate();
  }

  @Test
  void logout_redirectsToIdpLogoutWithCorrectUrl() {
    logoutController.logout(exchange, oauth2AuthenticationToken).block();

    verify(response).setStatusCode(HttpStatus.FOUND);
    assertThat(headers.getLocation())
        .hasToString(
            "https://idp.example.com/v2/logout"
                + "?returnTo=https://app.example.com&client_id=my-client-id");
  }

  @Test
  void logout_executesStepsInOrder() {
    logoutController.logout(exchange, oauth2AuthenticationToken).block();

    // removeAuthorizedClient and session.invalidate happen during subscription (in order)
    var subscriptionOrder = inOrder(authorizedClientRepository, session);
    subscriptionOrder
        .verify(authorizedClientRepository)
        .removeAuthorizedClient(eq("auth0"), any(), any());
    subscriptionOrder.verify(session).invalidate();

    // setStatusCode and setComplete happen during assembly (in order)
    var assemblyOrder = inOrder(response);
    assemblyOrder.verify(response).setStatusCode(HttpStatus.FOUND);
    assemblyOrder.verify(response).setComplete();
  }

  @Test
  void logout_completesSuccessfully() {
    StepVerifier.create(logoutController.logout(exchange, oauth2AuthenticationToken))
        .verifyComplete();
  }

  @Test
  void logout_propagatesErrorFromClientRemoval() {
    var error = new RuntimeException("client removal failed");
    when(authorizedClientRepository.removeAuthorizedClient(any(), any(), any()))
        .thenReturn(Mono.error(error));

    StepVerifier.create(logoutController.logout(exchange, oauth2AuthenticationToken))
        .expectErrorMessage("client removal failed")
        .verify();
  }

  @Test
  void logout_propagatesErrorFromSessionInvalidation() {
    var error = new RuntimeException("session invalidation failed");
    when(session.invalidate()).thenReturn(Mono.error(error));

    StepVerifier.create(logoutController.logout(exchange, oauth2AuthenticationToken))
        .expectErrorMessage("session invalidation failed")
        .verify();
  }
}
