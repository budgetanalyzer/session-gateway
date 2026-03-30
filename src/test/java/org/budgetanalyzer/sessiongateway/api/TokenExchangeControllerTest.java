package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.service.exception.ServiceUnavailableException;
import org.budgetanalyzer.sessiongateway.api.request.TokenExchangeRequest;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient.PermissionResponse;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@ExtendWith(MockitoExtension.class)
class TokenExchangeControllerTest {

  @Mock private PermissionServiceClient permissionServiceClient;
  @Mock private SessionWriter sessionWriter;

  private WireMockServer wireMockServer;
  private TokenExchangeController tokenExchangeController;
  private Clock clock;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMockServer.start();
    clock = Clock.fixed(Instant.parse("2026-03-30T00:00:00Z"), ZoneOffset.UTC);

    tokenExchangeController =
        new TokenExchangeController(
            permissionServiceClient,
            sessionWriter,
            "http://localhost:" + wireMockServer.port() + "/idp",
            clock,
            1800);
  }

  @AfterEach
  void tearDown() {
    if (wireMockServer.isRunning()) {
      wireMockServer.stop();
    }
  }

  @Test
  void exchangeToken_returnsSessionTokenOnSuccess() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com", "name": "Test User", "picture": "https://example.com/avatar.png"}
        """);
    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", "Test User"))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));
    when(sessionWriter.createSession(
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            any(),
            any(),
            any(),
            any()))
        .thenReturn(Mono.just("session-123"));

    var result =
        tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")).block();

    assertThat(result).isNotNull();
    assertThat(result.token()).isEqualTo("session-123");
    assertThat(result.expiresIn()).isEqualTo(1800);
    assertThat(result.tokenType()).isEqualTo("Bearer");
  }

  @Test
  void exchangeToken_createsUnifiedSessionHash() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com", "name": "Test User", "picture": "https://example.com/avatar.png"}
        """);
    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", "Test User"))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));
    when(sessionWriter.createSession(
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            any(),
            any(),
            any(),
            any()))
        .thenReturn(Mono.just("session-123"));

    tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")).block();

    verify(sessionWriter)
        .createSession(
            "user-1",
            "auth0|abc123",
            "user@example.com",
            "Test User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            null,
            Instant.parse("2026-03-30T00:30:00Z"));
  }

  @Test
  void exchangeToken_handlesUserinfoWithMissingOptionalFields() {
    stubUserinfo(
        200,
        """
        {"sub": "auth0|abc123", "email": "user@example.com"}
        """);
    when(permissionServiceClient.fetchPermissions("auth0|abc123", "user@example.com", ""))
        .thenReturn(
            Mono.just(
                new PermissionResponse(
                    "user-1", List.of("ROLE_USER"), List.of("transactions:read"))));
    when(sessionWriter.createSession(
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            any(),
            any(),
            any(),
            any()))
        .thenReturn(Mono.just("session-456"));

    var result =
        tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")).block();

    assertThat(result).isNotNull();
    assertThat(result.token()).isEqualTo("session-456");

    verify(sessionWriter)
        .createSession(
            "user-1",
            "auth0|abc123",
            "user@example.com",
            "",
            "",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            null,
            Instant.parse("2026-03-30T00:30:00Z"));
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
  void exchangeToken_returns503ForIdpServerError() {
    stubUserinfo(503, "Service Unavailable");

    StepVerifier.create(
            tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")))
        .expectError(ServiceUnavailableException.class)
        .verify();
  }

  @Test
  void exchangeToken_returns503ForIdpUnreachable() {
    wireMockServer.stop();

    StepVerifier.create(
            tokenExchangeController.exchangeToken(new TokenExchangeRequest("valid-token")))
        .expectError(ServiceUnavailableException.class)
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

    verify(sessionWriter, never())
        .createSession(
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            anyString(),
            any(),
            any(),
            any(),
            any());
  }

  private void stubUserinfo(int status, String body) {
    wireMockServer.stubFor(
        com.github.tomakehurst.wiremock.client.WireMock.get(
                com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo("/idp/userinfo"))
            .willReturn(
                com.github.tomakehurst.wiremock.client.WireMock.aResponse()
                    .withStatus(status)
                    .withHeader("Content-Type", "application/json")
                    .withBody(body)));
  }
}
