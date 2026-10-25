package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import reactor.test.StepVerifier;

class IdpReactiveJwtDecoderFactoryIntegrationTest {

  private static final String ISSUER = "https://tenant.example.com/";
  private static final String CLIENT_ID = "test-client-id";
  private static final String SUBJECT = "auth0|user-123";
  private static final String KEY_ID = "test-key-id";
  private static final String JWKS_PATH = "/.well-known/jwks.json";

  private static final WireMockServer wireMockServer = startWireMockServer();
  private static final RSAKey SIGNING_KEY = createRsaKey();

  private final IdpReactiveJwtDecoderFactory idpReactiveJwtDecoderFactory =
      new IdpReactiveJwtDecoderFactory(WebClient.create());

  private static WireMockServer startWireMockServer() {
    var wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
    wireMockServer.start();

    return wireMockServer;
  }

  @AfterAll
  static void stopWireMockServer() {
    wireMockServer.stop();
  }

  @BeforeEach
  void stubJwks() {
    wireMockServer.resetAll();
    wireMockServer.stubFor(
        get(urlEqualTo(JWKS_PATH))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(new JWKSet(SIGNING_KEY.toPublicJWK()).toString())));
  }

  @Test
  void decodesIdTokenSignedByKeyFromJwksEndpoint() throws JOSEException {
    var now = Instant.now();
    var idToken = sign(SIGNING_KEY, validClaims(now).claim("email", "user@example.com").build());
    var reactiveJwtDecoder = idpReactiveJwtDecoderFactory.createDecoder(clientRegistration());

    StepVerifier.create(reactiveJwtDecoder.decode(idToken))
        .assertNext(
            jwt -> {
              assertThat(jwt.getSubject()).isEqualTo(SUBJECT);
              assertThat(jwt.getIssuer()).hasToString(ISSUER);
              assertThat(jwt.getAudience()).containsExactly(CLIENT_ID);
              assertThat(jwt.getClaimAsString("email")).isEqualTo("user@example.com");
            })
        .verifyComplete();

    wireMockServer.verify(1, getRequestedFor(urlEqualTo(JWKS_PATH)));
  }

  @Test
  void rejectsExpiredIdTokenThroughTimestampValidation() throws JOSEException {
    var now = Instant.now();
    var idToken =
        sign(
            SIGNING_KEY,
            validClaims(now)
                .issueTime(Date.from(now.minusSeconds(900)))
                .expirationTime(Date.from(now.minusSeconds(600)))
                .build());

    assertValidationFailure(idToken, "invalid_token", "Jwt expired at");
  }

  @Test
  void rejectsNotYetValidIdTokenThroughTimestampValidation() throws JOSEException {
    var now = Instant.now();
    var idToken =
        sign(SIGNING_KEY, validClaims(now).notBeforeTime(Date.from(now.plusSeconds(600))).build());

    assertValidationFailure(idToken, "invalid_token", "Jwt used before");
  }

  @Test
  void rejectsIdTokenFromUnexpectedIssuerThroughOidcValidation() throws JOSEException {
    var now = Instant.now();
    var idToken =
        sign(SIGNING_KEY, validClaims(now).issuer("https://attacker.example.com/").build());

    assertValidationFailure(idToken, "invalid_id_token", "iss");
  }

  @Test
  void rejectsIdTokenForDifferentAudienceThroughOidcValidation() throws JOSEException {
    var now = Instant.now();
    var idToken = sign(SIGNING_KEY, validClaims(now).audience("other-client-id").build());

    assertValidationFailure(idToken, "invalid_id_token", "aud");
  }

  @Test
  void rejectsIdTokenSignedByKeyMissingFromJwksEndpoint() throws JOSEException {
    var now = Instant.now();
    var idToken = sign(createRsaKey(), validClaims(now).build());
    var reactiveJwtDecoder = idpReactiveJwtDecoderFactory.createDecoder(clientRegistration());

    StepVerifier.create(reactiveJwtDecoder.decode(idToken))
        .expectErrorSatisfies(
            throwable ->
                assertThat(throwable)
                    .isInstanceOf(BadJwtException.class)
                    .isNotInstanceOf(JwtValidationException.class))
        .verify();
  }

  @Test
  void decoderIsReusedPerRegistrationId() {
    var clientRegistration = clientRegistration();

    var firstReactiveJwtDecoder = idpReactiveJwtDecoderFactory.createDecoder(clientRegistration);
    var secondReactiveJwtDecoder = idpReactiveJwtDecoderFactory.createDecoder(clientRegistration);

    assertThat(firstReactiveJwtDecoder).isSameAs(secondReactiveJwtDecoder);
  }

  @Test
  void missingJwkSetUriThrowsOAuth2AuthenticationException() {
    var clientRegistration =
        ClientRegistration.withRegistrationId("no-jwks")
            .clientId(CLIENT_ID)
            .clientSecret("test-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://tenant.example.com/authorize")
            .tokenUri("https://tenant.example.com/oauth/token")
            .scope("openid")
            .build();

    assertThatThrownBy(() -> idpReactiveJwtDecoderFactory.createDecoder(clientRegistration))
        .isInstanceOfSatisfying(
            OAuth2AuthenticationException.class,
            exception ->
                assertThat(exception.getError().getErrorCode())
                    .isEqualTo("missing_signature_verifier"));
  }

  private void assertValidationFailure(
      String idToken, String expectedErrorCode, String expectedDescriptionFragment) {
    var reactiveJwtDecoder = idpReactiveJwtDecoderFactory.createDecoder(clientRegistration());

    StepVerifier.create(reactiveJwtDecoder.decode(idToken))
        .expectErrorSatisfies(
            throwable ->
                assertThat(throwable)
                    .isInstanceOfSatisfying(
                        JwtValidationException.class,
                        jwtValidationException ->
                            assertThat(jwtValidationException.getErrors())
                                .anySatisfy(
                                    oauth2Error -> {
                                      assertThat(oauth2Error.getErrorCode())
                                          .isEqualTo(expectedErrorCode);
                                      assertThat(oauth2Error.getDescription())
                                          .contains(expectedDescriptionFragment);
                                    })))
        .verify();
  }

  private static JWTClaimsSet.Builder validClaims(Instant now) {
    return new JWTClaimsSet.Builder()
        .issuer(ISSUER)
        .audience(CLIENT_ID)
        .subject(SUBJECT)
        .issueTime(Date.from(now.minusSeconds(60)))
        .expirationTime(Date.from(now.plusSeconds(300)));
  }

  private static String sign(RSAKey rsaKey, JWTClaimsSet jwtClaimsSet) throws JOSEException {
    var signedJwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(KEY_ID).build(), jwtClaimsSet);
    signedJwt.sign(new RSASSASigner(rsaKey.toPrivateKey()));

    return signedJwt.serialize();
  }

  private static RSAKey createRsaKey() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      var keyPair = keyPairGenerator.generateKeyPair();

      return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
          .privateKey((RSAPrivateKey) keyPair.getPrivate())
          .keyID(KEY_ID)
          .build();
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("RSA key generation is unavailable", exception);
    }
  }

  private static ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId("idp")
        .clientId(CLIENT_ID)
        .clientSecret("test-client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://tenant.example.com/authorize")
        .tokenUri("https://tenant.example.com/oauth/token")
        .scope("openid", "profile", "email")
        .userInfoUri("https://tenant.example.com/userinfo")
        .userNameAttributeName("sub")
        .issuerUri(ISSUER)
        .jwkSetUri(wireMockServer.baseUrl() + JWKS_PATH)
        .build();
  }
}
