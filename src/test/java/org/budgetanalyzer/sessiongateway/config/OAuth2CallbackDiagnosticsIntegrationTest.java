package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.util.UriComponentsBuilder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.security.OAuth2CallbackIdpClientLoggingFilter;
import org.budgetanalyzer.sessiongateway.security.OAuth2CallbackTransportFailureWebExceptionHandler;

@TestPropertySource(
    properties = {
      "idp.http-client.max-connections=1",
      "idp.http-client.pending-acquire-max-count=10",
      "idp.http-client.pending-acquire-timeout=100ms",
      "idp.http-client.connect-timeout=1s",
      "idp.http-client.response-timeout=250ms",
      "idp.http-client.read-timeout=250ms",
      "idp.http-client.write-timeout=250ms"
    })
class OAuth2CallbackDiagnosticsIntegrationTest extends AbstractIntegrationTest {

  private static final String SECRET_AUTH_CODE = "secret-auth-code";
  private static final String SECRET_RETURN_URL = "/dashboard";
  private static final int IDP_RESPONSE_DELAY_MILLIS = 1000;

  private ListAppender<ILoggingEvent> idpClientListAppender;
  private ListAppender<ILoggingEvent> transportHandlerListAppender;
  private Logger idpClientLogger;
  private Logger transportHandlerLogger;

  @BeforeEach
  void setUpLogCapture() {
    idpClientLogger = (Logger) LoggerFactory.getLogger(OAuth2CallbackIdpClientLoggingFilter.class);
    transportHandlerLogger =
        (Logger) LoggerFactory.getLogger(OAuth2CallbackTransportFailureWebExceptionHandler.class);

    idpClientListAppender = new ListAppender<>();
    idpClientListAppender.start();
    idpClientLogger.addAppender(idpClientListAppender);

    transportHandlerListAppender = new ListAppender<>();
    transportHandlerListAppender.start();
    transportHandlerLogger.addAppender(transportHandlerListAppender);
  }

  @AfterEach
  void tearDownLogCapture() {
    idpClientLogger.detachAppender(idpClientListAppender);
    idpClientListAppender.stop();
    transportHandlerLogger.detachAppender(transportHandlerListAppender);
    transportHandlerListAppender.stop();
  }

  @Test
  void oauth2CallbackRedirectsThroughControlledFailurePathOnDedicatedIdpResponseTimeout()
      throws Exception {
    var authorizationRequest = beginAuthorization(SECRET_RETURN_URL);
    var rsaKey = createRsaKey("token-timeout-key");
    stubJwks(rsaKey);
    stubSlowSuccessfulTokenEndpoint(createIdToken(rsaKey, authorizationRequest.nonce()));
    stubOidcUserInfo(
        "auth0|user-123", "user@example.com", "Test User", "https://cdn.example.com/avatar.png");
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        "internal-user-456",
        List.of("ROLE_USER"),
        List.of("transactions:read"));

    var redirectLocation = executeCallback(authorizationRequest.state(), SECRET_AUTH_CODE);

    assertLoginFailureRedirect(redirectLocation, SECRET_RETURN_URL);
    assertSanitizedLogs(authorizationRequest.state(), SECRET_AUTH_CODE);
    assertThat(logMessages())
        .anyMatch(message -> message.contains("classification=response_timeout"))
        .anyMatch(message -> message.contains("path=/idp/oauth/token"));
  }

  @Test
  void oauth2CallbackRedirectsThroughControlledFailurePathOnDedicatedIdpJwksResponseTimeout()
      throws Exception {
    var authorizationRequest = beginAuthorization(SECRET_RETURN_URL);
    var rsaKey = createRsaKey("jwks-timeout-key");
    stubOidcTokenEndpoint(
        "access-token-value", createIdToken(rsaKey, authorizationRequest.nonce()));
    stubSlowJwks(rsaKey);
    stubOidcUserInfo(
        "auth0|user-123", "user@example.com", "Test User", "https://cdn.example.com/avatar.png");
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        "internal-user-456",
        List.of("ROLE_USER"),
        List.of("transactions:read"));

    var redirectLocation = executeCallback(authorizationRequest.state(), SECRET_AUTH_CODE);

    assertLoginFailureRedirect(redirectLocation, SECRET_RETURN_URL);
    assertSanitizedLogs(authorizationRequest.state(), SECRET_AUTH_CODE);
    assertThat(logMessages())
        .anyMatch(
            message ->
                message.contains("classification=response_timeout")
                    && message.contains("path=/idp/.well-known/jwks.json"));
    wireMockServer.verify(0, getRequestedFor(urlEqualTo("/idp/userinfo")));
  }

  @Test
  void oauth2CallbackRedirectsThroughControlledFailurePathOnDedicatedIdpUserInfoResponseTimeout()
      throws Exception {
    var authorizationRequest = beginAuthorization(SECRET_RETURN_URL);
    var rsaKey = createRsaKey("userinfo-timeout-key");
    stubOidcTokenEndpoint(
        "access-token-value", createIdToken(rsaKey, authorizationRequest.nonce()));
    stubJwks(rsaKey);
    stubSlowOidcUserInfo();
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        "internal-user-456",
        List.of("ROLE_USER"),
        List.of("transactions:read"));

    var redirectLocation = executeCallback(authorizationRequest.state(), SECRET_AUTH_CODE);

    assertLoginFailureRedirect(redirectLocation, SECRET_RETURN_URL);
    assertSanitizedLogs(authorizationRequest.state(), SECRET_AUTH_CODE);
    assertThat(logMessages())
        .anyMatch(
            message ->
                message.contains("classification=response_timeout")
                    && message.contains("path=/idp/userinfo"));
    wireMockServer.verify(0, getRequestedFor(urlPathMatching("/internal/v1/users/.*/permissions")));
  }

  @Test
  void repeatedOauth2CallbacksUseControlledFailurePathUnderConstrainedDedicatedIdpPool()
      throws Exception {
    stubSlowTokenEndpointServerError();

    var authorizationRequests =
        List.of(beginAuthorization(null), beginAuthorization(null), beginAuthorization(null));

    var executorService = Executors.newFixedThreadPool(authorizationRequests.size());
    var startLatch = new CountDownLatch(1);
    try {
      var futures =
          authorizationRequests.stream()
              .map(
                  authorizationRequest ->
                      executorService.submit(
                          () -> {
                            startLatch.await(5, TimeUnit.SECONDS);
                            return executeCallback(
                                authorizationRequest.state(),
                                "code-" + authorizationRequest.state().substring(0, 8));
                          }))
              .toList();

      startLatch.countDown();

      for (var future : futures) {
        assertLoginFailureRedirect(future.get(5, TimeUnit.SECONDS), null);
      }
    } finally {
      executorService.shutdownNow();
    }

    assertThat(logMessages()).anyMatch(message -> message.contains("pool_acquire_timeout"));
  }

  private AuthorizationRequest beginAuthorization(String returnUrl) {
    var uri =
        returnUrl == null
            ? "/oauth2/authorization/idp"
            : UriComponentsBuilder.fromPath("/oauth2/authorization/idp")
                .queryParam("returnUrl", returnUrl)
                .build()
                .toUriString();

    var authorizationResult =
        webTestClient
            .get()
            .uri(uri)
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .returnResult(Void.class);

    var authorizationLocation = authorizationResult.getResponseHeaders().getLocation();
    assertThat(authorizationLocation).isNotNull();

    var uriComponents = UriComponentsBuilder.fromUri(authorizationLocation).build();
    var state = uriComponents.getQueryParams().getFirst("state");
    var nonce = uriComponents.getQueryParams().getFirst("nonce");

    assertThat(state).isNotBlank();
    assertThat(nonce).isNotBlank();

    return new AuthorizationRequest(URLDecoder.decode(state, StandardCharsets.UTF_8), nonce);
  }

  private URI executeCallback(String state, String code) {
    var callbackResult =
        webTestClient
            .get()
            .uri(
                UriComponentsBuilder.fromPath("/login/oauth2/code/idp")
                    .queryParam("code", code)
                    .queryParam("state", state)
                    .build()
                    .toUriString())
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .returnResult(Void.class);

    return callbackResult.getResponseHeaders().getLocation();
  }

  private void assertLoginFailureRedirect(URI redirectLocation, String expectedReturnUrl) {
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/login");

    var redirectQueryParams =
        UriComponentsBuilder.fromUri(redirectLocation).build().getQueryParams();
    assertThat(redirectQueryParams.getFirst("error")).isEqualTo("auth_failed");

    if (expectedReturnUrl == null) {
      assertThat(redirectQueryParams.getFirst("returnUrl")).isNull();
      return;
    }

    assertThat(redirectQueryParams.getFirst("returnUrl")).isEqualTo(expectedReturnUrl);
  }

  private void assertSanitizedLogs(String state, String code) {
    assertThat(logMessages()).allMatch(message -> !message.contains(state));
    assertThat(logMessages()).allMatch(message -> !message.contains(code));
  }

  private List<String> logMessages() {
    return java.util.stream.Stream.concat(
            idpClientListAppender.list.stream(), transportHandlerListAppender.list.stream())
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private void stubSlowSuccessfulTokenEndpoint(String idToken) {
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withFixedDelay(IDP_RESPONSE_DELAY_MILLIS)
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "access_token": "access-token-value",
                          "id_token": "%s",
                          "token_type": "Bearer",
                          "expires_in": 3600
                        }
                        """
                            .formatted(idToken))));
  }

  private void stubSlowTokenEndpointServerError() {
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(aResponse().withFixedDelay(IDP_RESPONSE_DELAY_MILLIS).withStatus(500)));
  }

  private void stubSlowJwks(RSAKey rsaKey) {
    wireMockServer.stubFor(
        get(urlEqualTo("/idp/.well-known/jwks.json"))
            .willReturn(
                aResponse()
                    .withFixedDelay(IDP_RESPONSE_DELAY_MILLIS)
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(new JWKSet(rsaKey.toPublicJWK()).toString())));
  }

  private void stubSlowOidcUserInfo() {
    wireMockServer.stubFor(
        get(urlEqualTo("/idp/userinfo"))
            .willReturn(
                aResponse()
                    .withFixedDelay(IDP_RESPONSE_DELAY_MILLIS)
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "sub": "auth0|user-123",
                          "email": "user@example.com",
                          "name": "Test User"
                        }
                        """)));
  }

  // The context-scoped ID token decoder caches the JWK set; a distinct key ID per test forces a
  // fresh JWKS request through the dedicated IdP client.
  private RSAKey createRsaKey(String keyId) throws Exception {
    var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);

    var keyPair = keyPairGenerator.generateKeyPair();

    return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
        .privateKey((RSAPrivateKey) keyPair.getPrivate())
        .keyID(keyId)
        .build();
  }

  private String createIdToken(RSAKey rsaKey, String nonce) throws JOSEException {
    var now = Instant.now();
    var claimsSet =
        new JWTClaimsSet.Builder()
            .issuer("http://localhost:" + wireMockServer.port() + "/idp")
            .audience("test-client-id")
            .subject("auth0|user-123")
            .issueTime(java.util.Date.from(now))
            .expirationTime(java.util.Date.from(now.plusSeconds(3600)))
            .claim("nonce", nonce)
            .claim("email", "user@example.com")
            .claim("name", "Test User")
            .claim("picture", "https://cdn.example.com/avatar.png")
            .build();

    var signedJwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsaKey.getKeyID()).build(), claimsSet);
    signedJwt.sign(new RSASSASigner(rsaKey.toPrivateKey()));

    return signedJwt.serialize();
  }

  private void stubJwks(RSAKey rsaKey) {
    wireMockServer.stubFor(
        get(urlEqualTo("/idp/.well-known/jwks.json"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(new JWKSet(rsaKey.toPublicJWK()).toString())));
  }

  private record AuthorizationRequest(String state, String nonce) {}
}
