package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
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

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

@TestPropertySource(properties = "session.cookie.domain-override=budgetanalyzer.localhost")
class SecurityConfigCookieDomainOverrideIntegrationTest extends AbstractIntegrationTest {

  private static final String CLIENT_ID = "test-client-id";
  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";

  @Test
  void oauth2LoginSetsConfiguredCookieDomainOverride() throws Exception {
    var rsaKey = createRsaKey();
    stubJwks(rsaKey);

    var authorizationResult =
        webTestClient
            .get()
            .uri("/oauth2/authorization/idp?returnUrl=/dashboard")
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .returnResult(Void.class);

    var authorizationLocation = authorizationResult.getResponseHeaders().getLocation();
    assertThat(authorizationLocation).isNotNull();

    var state =
        UriComponentsBuilder.fromUri(authorizationLocation)
            .build()
            .getQueryParams()
            .getFirst("state");
    assertThat(state).isNotBlank();
    state = URLDecoder.decode(state, StandardCharsets.UTF_8);

    var nonce =
        UriComponentsBuilder.fromUri(authorizationLocation)
            .build()
            .getQueryParams()
            .getFirst("nonce");
    assertThat(nonce).isNotBlank();

    stubOidcTokenEndpoint(
        "access-token-value", createIdToken(rsaKey, nonce), "refresh-token-value");
    stubOidcUserInfo(
        "auth0|user-123", "user@example.com", "Test User", "https://cdn.example.com/avatar.png");
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        "internal-user-456",
        java.util.List.of("ROLE_USER"),
        java.util.List.of("transactions:read"));

    var callbackResult =
        webTestClient
            .get()
            .uri(
                UriComponentsBuilder.fromPath("/login/oauth2/code/idp")
                    .queryParam("code", "test-code")
                    .queryParam("state", state)
                    .build()
                    .toUriString())
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader()
            .valueEquals(HttpHeaders.LOCATION, "/dashboard")
            .returnResult(Void.class);

    var sessionCookie = callbackResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(sessionCookie).isNotNull();
    assertThat(sessionCookie.getDomain()).isEqualTo("budgetanalyzer.localhost");
  }

  private RSAKey createRsaKey() throws Exception {
    var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);

    var keyPair = keyPairGenerator.generateKeyPair();

    return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
        .privateKey((RSAPrivateKey) keyPair.getPrivate())
        .keyID("test-key-id")
        .build();
  }

  private String createIdToken(RSAKey rsaKey, String nonce) throws JOSEException {
    var now = Instant.now();
    var claimsSet =
        new JWTClaimsSet.Builder()
            .issuer("http://localhost:" + wireMockServer.port() + "/idp")
            .audience(CLIENT_ID)
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
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("test-key-id").build(), claimsSet);
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
}
