package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.web.util.UriComponentsBuilder;

import com.github.tomakehurst.wiremock.http.Fault;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

class SecurityConfigIntegrationTest extends AbstractIntegrationTest {

  private static final String CLIENT_ID = "test-client-id";
  private static final String AUTHORIZATION_REQUEST_KEY_PREFIX = "oauth2:state:";
  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:";
  private static final RSAKey TEST_RSA_KEY = createTestRsaKey();

  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @Test
  void oauth2LoginCreatesPublicSessionCookieAndRedisSessionHashWithoutDependingOnFrameworkCookie()
      throws Exception {
    var rsaKey = TEST_RSA_KEY;
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

    var codeChallenge =
        UriComponentsBuilder.fromUri(authorizationLocation)
            .build()
            .getQueryParams()
            .getFirst("code_challenge");
    assertThat(codeChallenge).isNotBlank();
    assertThat(
            UriComponentsBuilder.fromUri(authorizationLocation)
                .build()
                .getQueryParams()
                .getFirst("code_challenge_method"))
        .isEqualTo("S256");

    var redirectUri =
        UriComponentsBuilder.fromUri(authorizationLocation)
            .build()
            .getQueryParams()
            .getFirst("redirect_uri");
    assertThat(redirectUri).isNotBlank();

    var authorizationRequestFields = readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + state);
    assertThat(authorizationRequestFields)
        .containsEntry("redirect_uri", redirectUri)
        .containsEntry("return_url", "/dashboard")
        .containsKey("nonce")
        .containsKey("code_verifier");
    assertThat(authorizationRequestFields.get("nonce")).isNotBlank();
    assertThat(authorizationRequestFields.get("code_verifier")).isNotBlank();

    stubOidcTokenEndpoint("access-token-value", createIdToken(rsaKey, nonce));
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

    assertThat(callbackResult.getResponseCookies().keySet())
        .containsExactly(PUBLIC_SESSION_COOKIE_NAME)
        .doesNotContain("SESSION")
        .allMatch(cookieName -> cookieName.equals(PUBLIC_SESSION_COOKIE_NAME));

    var sessionCookie = callbackResult.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);
    assertThat(sessionCookie).isNotNull();
    assertThat(sessionCookie.getValue()).isNotBlank();
    assertThat(sessionCookie.getDomain()).isNull();
    assertThat(sessionCookie.isHttpOnly()).isTrue();
    assertThat(sessionCookie.getPath()).isEqualTo("/");
    assertThat(sessionCookie.getSameSite()).isEqualTo("Strict");

    var sessionFields = readHashEntries(TEST_SESSION_KEY_PREFIX + sessionCookie.getValue());

    assertThat(sessionFields).isNotNull();
    assertThat(sessionFields)
        .containsEntry("user_id", "internal-user-456")
        .containsEntry("idp_sub", "auth0|user-123")
        .containsEntry("email", "user@example.com")
        .containsEntry("display_name", "Test User")
        .containsEntry("picture", "https://cdn.example.com/avatar.png")
        .containsEntry("roles", "ROLE_USER")
        .containsEntry("permissions", "transactions:read")
        .doesNotContainKey("refresh_token")
        .doesNotContainKey("token_expires_at");

    assertThat(readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + state)).isEmpty();

    var userInfo =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionCookie.getValue())
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody()
            .jsonPath("$.sub")
            .isEqualTo("auth0|user-123")
            .jsonPath("$.authenticated")
            .isEqualTo(true)
            .returnResult();

    assertThat(userInfo).isNotNull();
  }

  @Test
  void oauth2CallbackRedirectsToLoginOnTokenEndpointFailure() {
    stubTokenEndpointError();

    var authorizationResult =
        webTestClient
            .get()
            .uri("/oauth2/authorization/idp")
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
            .returnResult(Void.class);

    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/login");
    var redirectQueryParams =
        UriComponentsBuilder.fromUri(redirectLocation).build().getQueryParams();
    assertThat(redirectQueryParams.getFirst("error")).isEqualTo("auth_failed");
    assertThat(redirectQueryParams.getFirst("returnUrl")).isNull();
  }

  @Test
  void oauth2CallbackRedirectsToLoginOnTokenEndpointTransportFailure() {
    stubTokenEndpointTransportFailure();

    var authorizationResult =
        webTestClient
            .get()
            .uri("/oauth2/authorization/idp")
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
            .returnResult(Void.class);

    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/login");
    var redirectQueryParams =
        UriComponentsBuilder.fromUri(redirectLocation).build().getQueryParams();
    assertThat(redirectQueryParams.getFirst("error")).isEqualTo("auth_failed");
    assertThat(redirectQueryParams.getFirst("returnUrl")).isNull();
  }

  @Test
  void oauth2CallbackPreservesReturnUrlOnTokenEndpointFailure() {
    stubTokenEndpointError();

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
            .returnResult(Void.class);

    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/login");
    var redirectQueryParams =
        UriComponentsBuilder.fromUri(redirectLocation).build().getQueryParams();
    assertThat(redirectQueryParams.getFirst("error")).isEqualTo("auth_failed");
    assertThat(redirectQueryParams.getFirst("returnUrl")).isEqualTo("/dashboard");
  }

  @Test
  void oauth2CallbackPreservesReturnUrlOnJwksTransportFailure() throws Exception {
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

    var rsaKey = TEST_RSA_KEY;
    stubOidcTokenEndpoint("access-token-value", createIdToken(rsaKey, nonce));
    stubJwksTransportFailure();

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
            .returnResult(Void.class);

    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/login");
    var redirectQueryParams =
        UriComponentsBuilder.fromUri(redirectLocation).build().getQueryParams();
    assertThat(redirectQueryParams.getFirst("error")).isEqualTo("auth_failed");
    assertThat(redirectQueryParams.getFirst("returnUrl")).isEqualTo("/dashboard");
  }

  @Test
  void oauth2CallbackRedirectsToOopsOnPermissionServiceTransportFailure() throws Exception {
    var rsaKey = TEST_RSA_KEY;
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

    stubOidcTokenEndpoint("access-token-value", createIdToken(rsaKey, nonce));
    stubOidcUserInfo(
        "auth0|user-123", "user@example.com", "Test User", "https://cdn.example.com/avatar.png");
    stubPermissionServiceTransportFailure("auth0|user-123");

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
            .returnResult(Void.class);

    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/oops");
    assertThat(callbackResult.getResponseCookies().keySet())
        .doesNotContain(PUBLIC_SESSION_COOKIE_NAME);
  }

  private void stubTokenEndpointError() {
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token")).willReturn(aResponse().withStatus(500)));
  }

  private void stubTokenEndpointTransportFailure() {
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
  }

  private void stubJwksTransportFailure() {
    wireMockServer.stubFor(
        get(urlEqualTo("/idp/.well-known/jwks.json"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
  }

  private void stubPermissionServiceTransportFailure(String idpSub) {
    var encodedIdpSub = URLEncoder.encode(idpSub, StandardCharsets.UTF_8);

    wireMockServer.stubFor(
        get(urlPathEqualTo("/internal/v1/users/" + encodedIdpSub + "/permissions"))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
  }

  private static RSAKey createTestRsaKey() {
    try {
      var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);

      var keyPair = keyPairGenerator.generateKeyPair();

      return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
          .privateKey((RSAPrivateKey) keyPair.getPrivate())
          .keyID("test-key-id")
          .build();
    } catch (Exception exception) {
      throw new IllegalStateException("Failed to create test RSA key", exception);
    }
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

  private Map<String, String> readHashEntries(String key) {
    return reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .block();
  }
}
