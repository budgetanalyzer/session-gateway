package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.session.MapSession;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.web.server.ResponseStatusException;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.api.request.TokenExchangeRequest;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient.PermissionResponse;
import org.budgetanalyzer.sessiongateway.session.ExtAuthzSessionWriter;

@ExtendWith(MockitoExtension.class)
class TokenExchangeControllerTest {

  @Mock private PermissionServiceClient permissionServiceClient;
  @Mock private ExtAuthzSessionWriter extAuthzSessionWriter;

  @SuppressWarnings("unchecked")
  @Mock
  private ReactiveSessionRepository reactiveSessionRepository;

  private WireMockServer wireMock;
  private TokenExchangeController tokenExchangeController;

  @BeforeEach
  void setUp() {
    wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMock.start();

    tokenExchangeController =
        new TokenExchangeController(
            permissionServiceClient,
            extAuthzSessionWriter,
            reactiveSessionRepository,
            "http://localhost:" + wireMock.port() + "/idp",
            1800);

    lenient()
        .when(extAuthzSessionWriter.writeSession(anyString(), anyString(), anyList(), anyList()))
        .thenReturn(Mono.empty());
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void exchangeToken_returnsSessionTokenOnSuccess() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com", "name": "Test User"}
        """);

    var mapSession = new MapSession();
    when(reactiveSessionRepository.createSession()).thenReturn(Mono.just(mapSession));
    when(reactiveSessionRepository.save(any())).thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", "Test User"))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));

    var result =
        tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")).block();

    assertThat(result).isNotNull();
    assertThat(result.token()).isEqualTo(mapSession.getId());
    assertThat(result.expiresIn()).isEqualTo(1800);
    assertThat(result.tokenType()).isEqualTo("Bearer");
  }

  @Test
  void exchangeToken_writesExtAuthzSession() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com", "name": "Test User"}
        """);

    var mapSession = new MapSession();
    when(reactiveSessionRepository.createSession()).thenReturn(Mono.just(mapSession));
    when(reactiveSessionRepository.save(any())).thenReturn(Mono.empty());
    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", "Test User"))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));

    tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")).block();

    verify(extAuthzSessionWriter)
        .writeSession(
            mapSession.getId(), "user-1", List.of("ROLE_USER"), List.of("transactions:read"));
  }

  @Test
  void exchangeToken_returns401ForInvalidToken() {
    stubUserinfo(401, "Unauthorized");

    StepVerifier.create(
            tokenExchangeController.exchangeToken(new TokenExchangeRequest("bad-token")))
        .expectErrorMatches(
            ex ->
                ex instanceof ResponseStatusException
                    && ((ResponseStatusException) ex).getStatusCode().value() == 401)
        .verify();
  }

  @Test
  void exchangeToken_returns400ForBlankAccessToken() {
    StepVerifier.create(tokenExchangeController.exchangeToken(new TokenExchangeRequest("")))
        .expectErrorMatches(
            ex ->
                ex instanceof ResponseStatusException
                    && ((ResponseStatusException) ex).getStatusCode().value() == 400)
        .verify();

    verify(permissionServiceClient, never()).fetchPermissions(any(), any(), any());
  }

  @Test
  void exchangeToken_returns400ForNullAccessToken() {
    StepVerifier.create(tokenExchangeController.exchangeToken(new TokenExchangeRequest(null)))
        .expectErrorMatches(
            ex ->
                ex instanceof ResponseStatusException
                    && ((ResponseStatusException) ex).getStatusCode().value() == 400)
        .verify();
  }

  @Test
  void exchangeToken_returns500ForPermissionServiceFailure() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com", "name": "Test User"}
        """);

    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", "Test User"))
        .thenReturn(Mono.error(new RuntimeException("permission service down")));

    StepVerifier.create(
            tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")))
        .expectErrorMatches(
            ex ->
                ex instanceof ResponseStatusException
                    && ((ResponseStatusException) ex).getStatusCode().value() == 500)
        .verify();
  }

  private void stubUserinfo(int status, String body) {
    wireMock.stubFor(
        com.github.tomakehurst.wiremock.client.WireMock.get(
                com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo("/idp/userinfo"))
            .willReturn(
                com.github.tomakehurst.wiremock.client.WireMock.aResponse()
                    .withStatus(status)
                    .withHeader("Content-Type", "application/json")
                    .withBody(body)));
  }
}
