package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

import reactor.core.publisher.Mono;

@ExtendWith(MockitoExtension.class)
class IdpTokenRefreshClientTest {

  private static final Instant BASE_INSTANT = Instant.parse("2026-03-30T00:00:00Z");

  @Mock private ReactiveClientRegistrationRepository clientRegistrationRepository;

  private WireMockServer wireMockServer;
  private IdpTokenRefreshClient idpTokenRefreshClient;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMockServer.start();

    var clock = Clock.fixed(BASE_INSTANT, ZoneOffset.UTC);
    idpTokenRefreshClient = new IdpTokenRefreshClient(clientRegistrationRepository, clock);
  }

  @AfterEach
  void tearDown() {
    if (wireMockServer.isRunning()) {
      wireMockServer.stop();
    }
  }

  @Test
  void refresh_returnsParsedRefreshResult() {
    when(clientRegistrationRepository.findByRegistrationId("idp"))
        .thenReturn(Mono.just(clientRegistration()));
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "access_token": "new-access-token",
                          "refresh_token": "rotated-refresh-token",
                          "token_type": "Bearer",
                          "expires_in": 7200
                        }
                        """)));

    var tokenRefreshResult = idpTokenRefreshClient.refresh("refresh-token-123").block();

    assertThat(tokenRefreshResult).isNotNull();
    assertThat(tokenRefreshResult.refreshToken()).isEqualTo("rotated-refresh-token");
    assertThat(tokenRefreshResult.expiresIn()).isEqualTo(7200);
    assertThat(tokenRefreshResult.tokenExpiresAt()).isEqualTo(BASE_INSTANT.plusSeconds(7200));
    wireMockServer.verify(
        postRequestedFor(urlEqualTo("/idp/oauth/token"))
            .withRequestBody(containing("grant_type=refresh_token"))
            .withRequestBody(containing("client_id=test-client-id"))
            .withRequestBody(containing("client_secret=test-client-secret"))
            .withRequestBody(containing("refresh_token=refresh-token-123")));
  }

  @Test
  void refresh_throwsGrantRevokedExceptionForInvalidGrant() {
    when(clientRegistrationRepository.findByRegistrationId("idp"))
        .thenReturn(Mono.just(clientRegistration()));
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(401)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "error": "invalid_grant"
                        }
                        """)));

    assertThatThrownBy(() -> idpTokenRefreshClient.refresh("revoked-refresh-token").block())
        .isInstanceOf(IdpTokenRefreshClient.IdpGrantRevokedException.class)
        .hasMessageContaining("IDP grant revoked");
  }

  @Test
  void refresh_throwsRefreshExceptionFor429() {
    when(clientRegistrationRepository.findByRegistrationId("idp"))
        .thenReturn(Mono.just(clientRegistration()));
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(429)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"error\": \"too_many_requests\"}")));

    assertThatThrownBy(() -> idpTokenRefreshClient.refresh("refresh-token-123").block())
        .isInstanceOf(IdpTokenRefreshClient.IdpTokenRefreshException.class)
        .hasMessageContaining("client error");
  }

  @Test
  void refresh_throwsRefreshExceptionForNonGrantError() {
    when(clientRegistrationRepository.findByRegistrationId("idp"))
        .thenReturn(Mono.just(clientRegistration()));
    wireMockServer.stubFor(
        post(urlEqualTo("/idp/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(400)
                    .withHeader("Content-Type", "application/json")
                    .withBody("{\"error\": \"invalid_request\"}")));

    assertThatThrownBy(() -> idpTokenRefreshClient.refresh("refresh-token-123").block())
        .isInstanceOf(IdpTokenRefreshClient.IdpTokenRefreshException.class)
        .hasMessageContaining("client error");
  }

  private ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId("idp")
        .clientId("test-client-id")
        .clientSecret("test-client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("openid", "profile", "email", "offline_access")
        .authorizationUri("http://localhost:" + wireMockServer.port() + "/idp/authorize")
        .tokenUri("http://localhost:" + wireMockServer.port() + "/idp/oauth/token")
        .userInfoUri("http://localhost:" + wireMockServer.port() + "/idp/userinfo")
        .userNameAttributeName(IdTokenClaimNames.SUB)
        .clientName("idp")
        .build();
  }
}
