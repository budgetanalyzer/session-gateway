package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.matchingJsonPath;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository.BROWSER_BINDING_COOKIE_NAME;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
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
import org.budgetanalyzer.sessiongateway.session.SessionHashFields;
import org.budgetanalyzer.sessiongateway.session.SessionTokenDigest;

class SecurityConfigIntegrationTest extends AbstractIntegrationTest {

  private static final String CLIENT_ID = "test-client-id";
  private static final String AUTHORIZATION_REQUEST_KEY_PREFIX = "oauth2:state:";
  private static final String PUBLIC_SESSION_COOKIE_NAME = "__Host-BA_SESSION";
  private static final String TEST_SESSION_KEY_PREFIX = "session:test:";
  private static final String SESSION_WRITE_FAILURE_USER_ID = "security-config-write-failure";
  private static final String LOGIN_TIMEOUT_USER_ID = "security-config-login-timeout";
  private static final int PERMISSION_SERVICE_DELAY_MILLISECONDS = 10_000;
  private static final RSAKey TEST_RSA_KEY = createTestRsaKey();

  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @Autowired private PermissionServiceProperties permissionServiceProperties;

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

    var authorizationQueryParameters =
        UriComponentsBuilder.fromUri(authorizationLocation).build().getQueryParams();
    assertThat(authorizationQueryParameters).doesNotContainKeys("audience", "response_mode");
    assertThat(authorizationQueryParameters.getFirst("response_type")).isEqualTo("code");
    var bindingCookie =
        authorizationResult.getResponseCookies().getFirst(BROWSER_BINDING_COOKIE_NAME);
    assertThat(bindingCookie).isNotNull();
    assertThat(bindingCookie.isSecure()).isTrue();
    assertThat(bindingCookie.isHttpOnly()).isTrue();
    assertThat(bindingCookie.getPath()).isEqualTo("/");
    assertThat(bindingCookie.getDomain()).isNull();
    assertThat(bindingCookie.getSameSite()).isEqualTo("Lax");
    assertThat(bindingCookie.getMaxAge()).isNegative();

    var state = authorizationQueryParameters.getFirst("state");
    assertThat(state).isNotBlank();
    state = URLDecoder.decode(state, StandardCharsets.UTF_8);

    var nonce = authorizationQueryParameters.getFirst("nonce");
    assertThat(nonce).isNotBlank();

    var codeChallenge = authorizationQueryParameters.getFirst("code_challenge");
    assertThat(codeChallenge).isNotBlank();
    assertThat(authorizationQueryParameters.getFirst("code_challenge_method")).isEqualTo("S256");

    var redirectUri = authorizationQueryParameters.getFirst("redirect_uri");
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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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
    assertThat(callbackResult.getResponseHeaders().get(HttpHeaders.SET_COOKIE))
        .filteredOn(header -> header.startsWith(PUBLIC_SESSION_COOKIE_NAME + "="))
        .containsExactly(
            PUBLIC_SESSION_COOKIE_NAME
                + "="
                + sessionCookie.getValue()
                + "; Path=/; Secure; HTTPOnly; SameSite=Strict");

    var sessionFields =
        readHashEntries(
            TEST_SESSION_KEY_PREFIX + SessionTokenDigest.sha256Hex(sessionCookie.getValue()));

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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
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

  @Test
  void oauth2CallbackRedirectsToOopsWithoutSessionWhenPermissionServiceExceedsLoginTimeout()
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

    var authorizationQueryParameters =
        UriComponentsBuilder.fromUri(authorizationResult.getResponseHeaders().getLocation())
            .build()
            .getQueryParams();
    var nonce = authorizationQueryParameters.getFirst("nonce");

    stubOidcTokenEndpoint("access-token-value", createIdToken(rsaKey, nonce));
    stubOidcUserInfo(
        "auth0|user-123", "user@example.com", "Test User", "https://cdn.example.com/avatar.png");
    stubDelayedPermissionService("auth0|user-123", PERMISSION_SERVICE_DELAY_MILLISECONDS);

    var state =
        URLDecoder.decode(authorizationQueryParameters.getFirst("state"), StandardCharsets.UTF_8);
    var startedAt = System.nanoTime();
    var callbackResult =
        webTestClient
            .mutate()
            .responseTimeout(Duration.ofMillis(PERMISSION_SERVICE_DELAY_MILLISECONDS))
            .build()
            .get()
            .uri(
                UriComponentsBuilder.fromPath("/login/oauth2/code/idp")
                    .queryParam("code", "test-code")
                    .queryParam("state", state)
                    .build()
                    .toUriString())
            .cookie(
                BROWSER_BINDING_COOKIE_NAME,
                authorizationResult
                    .getResponseCookies()
                    .getFirst(BROWSER_BINDING_COOKIE_NAME)
                    .getValue())
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .returnResult(Void.class);
    var elapsed = Duration.ofNanos(System.nanoTime() - startedAt);

    var loginTimeout = permissionServiceProperties.loginTimeout();
    assertThat(elapsed).isBetween(loginTimeout, loginTimeout.plusSeconds(3));
    var redirectLocation = callbackResult.getResponseHeaders().getLocation();
    assertThat(redirectLocation).isNotNull();
    assertThat(redirectLocation.getPath()).isEqualTo("/oops");
    assertThat(callbackResult.getResponseCookies().keySet())
        .doesNotContain(PUBLIC_SESSION_COOKIE_NAME);
    wireMockServer.verify(1, postRequestedFor(urlEqualTo(USER_SYNC_PATH)));
    assertThat(
            reactiveStringRedisTemplate
                .hasKey(SessionHashFields.USER_SESSIONS_KEY_PREFIX + LOGIN_TIMEOUT_USER_ID)
                .block())
        .isFalse();
    assertThat(
            reactiveStringRedisTemplate
                .keys(TEST_SESSION_KEY_PREFIX + "*")
                .filterWhen(
                    key ->
                        reactiveStringRedisTemplate
                            .<String, String>opsForHash()
                            .get(key, SessionHashFields.USER_ID)
                            .map(LOGIN_TIMEOUT_USER_ID::equals)
                            .defaultIfEmpty(false))
                .collectList()
                .block())
        .isEmpty();
  }

  @Test
  void oauth2CallbackRedirectsToOopsWhenSessionCreationFails() throws Exception {
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
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        SESSION_WRITE_FAILURE_USER_ID,
        java.util.List.of("ROLE_USER"),
        java.util.List.of("transactions:read"));

    var userSessionsKey =
        SessionHashFields.USER_SESSIONS_KEY_PREFIX + SESSION_WRITE_FAILURE_USER_ID;
    reactiveStringRedisTemplate
        .opsForValue()
        .set(userSessionsKey, "deliberately-not-a-set")
        .block();

    try {
      var callbackResult =
          webTestClient
              .get()
              .uri(
                  UriComponentsBuilder.fromPath("/login/oauth2/code/idp")
                      .queryParam("code", "test-code")
                      .queryParam("state", state)
                      .build()
                      .toUriString())
              .cookie(
                  BROWSER_BINDING_COOKIE_NAME,
                  authorizationResult
                      .getResponseCookies()
                      .getFirst(BROWSER_BINDING_COOKIE_NAME)
                      .getValue())
              .exchange()
              .expectStatus()
              .is3xxRedirection()
              .returnResult(Void.class);

      var redirectLocation = callbackResult.getResponseHeaders().getLocation();
      assertThat(redirectLocation).isNotNull();
      assertThat(redirectLocation.getPath()).isEqualTo("/oops");
      assertThat(callbackResult.getResponseCookies().keySet())
          .doesNotContain(PUBLIC_SESSION_COOKIE_NAME);

      wireMockServer.verify(
          1,
          postRequestedFor(urlEqualTo(USER_SYNC_PATH))
              .withRequestBody(
                  equalToJson(
                      """
                      {
                        "idpSub": "auth0|user-123",
                        "email": "user@example.com",
                        "displayName": "Test User"
                      }
                      """)));

      var failedSessionKeys =
          reactiveStringRedisTemplate
              .keys(TEST_SESSION_KEY_PREFIX + "*")
              .filterWhen(
                  key ->
                      reactiveStringRedisTemplate
                          .<String, String>opsForHash()
                          .get(key, SessionHashFields.USER_ID)
                          .map(SESSION_WRITE_FAILURE_USER_ID::equals)
                          .defaultIfEmpty(false))
              .collectList()
              .block();
      assertThat(failedSessionKeys)
          .singleElement()
          .satisfies(
              sessionKey ->
                  assertThat(readHashEntries(sessionKey))
                      .containsEntry(SessionHashFields.USER_ID, SESSION_WRITE_FAILURE_USER_ID));
    } finally {
      deleteFailedSessionCreationData(userSessionsKey);
    }
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void unboundCallbackCannotExchangeCodeOrIssueSessionAndOwnerCanStillLogin(boolean wrongBrowser)
      throws Exception {
    var owner = beginBoundLogin(null);
    var otherBrowser = beginBoundLogin(null);
    var rejected =
        invokeCallback(owner.state(), wrongBrowser ? otherBrowser.binding() : null, false);

    assertThat(rejected.getResponseHeaders().getLocation()).hasToString("/login?error=auth_failed");
    assertThat(rejected.getResponseCookies()).isEmpty();
    wireMockServer.verify(0, postRequestedFor(urlEqualTo("/idp/oauth/token")));
    assertThat(readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + owner.state())).isNotEmpty();
    completeBoundLogin(owner);
  }

  @Test
  void replayedCallbackCannotExchangeCodeOrIssueAnotherSession() throws Exception {
    var login = beginBoundLogin(null);
    completeBoundLogin(login);

    var replay = invokeCallback(login.state(), login.binding(), false);

    assertThat(replay.getResponseHeaders().getLocation()).hasToString("/login?error=auth_failed");
    assertThat(replay.getResponseCookies()).isEmpty();
    wireMockServer.verify(1, postRequestedFor(urlEqualTo("/idp/oauth/token")));
  }

  @Test
  void denialCallbackRequiresBindingAndConsumesOnlyOnceWithoutTokenExchange() {
    var login = beginBoundLogin(null);
    var otherBrowser = beginBoundLogin(null);
    var fields = readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + login.state());

    var missingBinding = invokeCallback(login.state(), null, true);
    var wrongBinding = invokeCallback(login.state(), otherBrowser.binding(), true);
    assertThat(missingBinding.getResponseHeaders().getLocation())
        .hasToString("/login?error=auth_failed");
    assertThat(wrongBinding.getResponseHeaders().getLocation())
        .hasToString("/login?error=auth_failed");
    assertThat(missingBinding.getResponseCookies()).isEmpty();
    assertThat(wrongBinding.getResponseCookies()).isEmpty();
    assertThat(readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + login.state())).isEqualTo(fields);

    var denied = invokeCallback(login.state(), login.binding(), true);
    assertThat(denied.getResponseHeaders().getLocation())
        .hasToString("/login?error=auth_failed&returnUrl=/dashboard");
    assertThat(denied.getResponseCookies()).isEmpty();
    assertThat(readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + login.state())).isEmpty();
    var replay = invokeCallback(login.state(), login.binding(), true);
    assertThat(replay.getResponseHeaders().getLocation()).hasToString("/login?error=auth_failed");
    assertThat(replay.getResponseCookies()).isEmpty();
    wireMockServer.verify(0, postRequestedFor(urlEqualTo("/idp/oauth/token")));
  }

  @Test
  void pendingTabsSharingBindingBothCompleteLogin() throws Exception {
    var firstTab = beginBoundLogin(null);
    var secondTab = beginBoundLogin(firstTab.binding());

    assertThat(secondTab.binding()).isEqualTo(firstTab.binding());
    completeBoundLogin(secondTab);
    completeBoundLogin(firstTab);
    wireMockServer.verify(2, postRequestedFor(urlEqualTo("/idp/oauth/token")));
  }

  @Test
  void firstStartsWithoutCookieFailClosedForLosingBindingAndFreshLoginSucceeds() throws Exception {
    // Both requests omit the cookie, as when sent before either Set-Cookie response is stored.
    var firstTab = beginBoundLogin(null);
    var secondTab = beginBoundLogin(null);
    assertThat(firstTab.binding()).isNotEqualTo(secondTab.binding());

    var rejected = invokeCallback(firstTab.state(), secondTab.binding(), false);
    assertThat(rejected.getResponseHeaders().getLocation()).hasToString("/login?error=auth_failed");
    assertThat(rejected.getResponseCookies()).isEmpty();
    wireMockServer.verify(0, postRequestedFor(urlEqualTo("/idp/oauth/token")));
    completeBoundLogin(secondTab);
    completeBoundLogin(beginBoundLogin(secondTab.binding()));
  }

  private BoundLogin beginBoundLogin(String binding) {
    var request = webTestClient.get().uri("/oauth2/authorization/idp?returnUrl=/dashboard");
    if (binding != null) {
      request.cookie(BROWSER_BINDING_COOKIE_NAME, binding);
    }
    var result = request.exchange().expectStatus().is3xxRedirection().returnResult(Void.class);
    var queryParameters =
        UriComponentsBuilder.fromUri(result.getResponseHeaders().getLocation())
            .build()
            .getQueryParams();
    var cookie = result.getResponseCookies().getFirst(BROWSER_BINDING_COOKIE_NAME);
    if (binding != null) {
      assertThat(cookie).isNull();
    }
    return new BoundLogin(
        URLDecoder.decode(queryParameters.getFirst("state"), StandardCharsets.UTF_8),
        queryParameters.getFirst("nonce"),
        cookie == null ? binding : cookie.getValue());
  }

  private FluxExchangeResult<Void> invokeCallback(String state, String binding, boolean denied) {
    var uriBuilder =
        UriComponentsBuilder.fromPath("/login/oauth2/code/idp").queryParam("state", state);
    if (denied) {
      uriBuilder.queryParam("error", "access_denied");
    } else {
      uriBuilder.queryParam("code", "test-code");
    }
    var request = webTestClient.get().uri(uriBuilder.build().toUriString());
    if (binding != null) {
      request.cookie(BROWSER_BINDING_COOKIE_NAME, binding);
    }
    return request.exchange().expectStatus().is3xxRedirection().returnResult(Void.class);
  }

  private void completeBoundLogin(BoundLogin login) throws Exception {
    stubJwks(TEST_RSA_KEY);
    stubOidcTokenEndpoint("access-token-value", createIdToken(TEST_RSA_KEY, login.nonce()));
    stubOidcUserInfo("auth0|user-123", "user@example.com", "Test User");
    stubPermissionService(
        "auth0|user-123",
        "user@example.com",
        "Test User",
        "internal-user-456",
        java.util.List.of("ROLE_USER"),
        java.util.List.of("transactions:read"));

    var result = invokeCallback(login.state(), login.binding(), false);

    assertThat(result.getResponseHeaders().getLocation()).hasToString("/dashboard");
    assertThat(result.getResponseCookies().keySet()).containsExactly(PUBLIC_SESSION_COOKIE_NAME);
    var cookie = result.getResponseCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);
    assertThat(cookie.getValue()).isNotEqualTo(login.binding());
    assertThat(
            readHashEntries(
                TEST_SESSION_KEY_PREFIX + SessionTokenDigest.sha256Hex(cookie.getValue())))
        .containsEntry("user_id", "internal-user-456");
    assertThat(readHashEntries(AUTHORIZATION_REQUEST_KEY_PREFIX + login.state())).isEmpty();
  }

  private record BoundLogin(String state, String nonce, String binding) {}

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
    wireMockServer.stubFor(
        post(urlEqualTo(USER_SYNC_PATH))
            .withRequestBody(matchingJsonPath("$.idpSub", equalTo(idpSub)))
            .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));
  }

  private void stubDelayedPermissionService(String idpSub, int delayMilliseconds) {
    wireMockServer.stubFor(
        post(urlEqualTo(USER_SYNC_PATH))
            .withRequestBody(matchingJsonPath("$.idpSub", equalTo(idpSub)))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "%s",
                          "roles": ["ROLE_USER"],
                          "permissions": ["transactions:read"]
                        }
                        """
                            .formatted(LOGIN_TIMEOUT_USER_ID))
                    .withFixedDelay(delayMilliseconds)));
  }

  private void deleteFailedSessionCreationData(String userSessionsKey) {
    reactiveStringRedisTemplate
        .keys(TEST_SESSION_KEY_PREFIX + "*")
        .filterWhen(
            key ->
                reactiveStringRedisTemplate
                    .<String, String>opsForHash()
                    .get(key, SessionHashFields.USER_ID)
                    .map(SESSION_WRITE_FAILURE_USER_ID::equals)
                    .defaultIfEmpty(false))
        .flatMap(reactiveStringRedisTemplate::unlink)
        .then(reactiveStringRedisTemplate.unlink(userSessionsKey))
        .then()
        .block();
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
