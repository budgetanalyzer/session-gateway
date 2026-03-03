package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.matching;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

class PermissionServiceClientTest {

  private WireMockServer wireMock;
  private PermissionServiceClient permissionServiceClient;

  @BeforeEach
  void setUp() throws Exception {
    wireMock = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMock.start();

    var rsaKey = new RSAKeyGenerator(2048).keyID("test-kid").generate();
    var jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    var encoder = new NimbusJwtEncoder(jwkSource);
    var clock = Clock.fixed(Instant.parse("2025-06-15T12:00:00Z"), ZoneOffset.UTC);
    var internalJwtService = new InternalJwtService(encoder, clock);

    var webClient = WebClient.builder().baseUrl("http://localhost:" + wireMock.port()).build();
    permissionServiceClient = new PermissionServiceClient(webClient, internalJwtService);
  }

  @AfterEach
  void tearDown() {
    wireMock.stop();
  }

  @Test
  void fetchPermissions_returnsParsedResponse() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cabc123/permissions"))
            .withQueryParam("email", equalTo("user@example.com"))
            .withQueryParam("displayName", equalTo("Test User"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "user-456",
                          "roles": ["ROLE_USER", "ROLE_ADMIN"],
                          "permissions": ["transactions:read", "transactions:write"]
                        }
                        """)));

    var response =
        permissionServiceClient
            .fetchPermissions("auth0|abc123", "user@example.com", "Test User")
            .block();

    assertThat(response).isNotNull();
    assertThat(response.userId()).isEqualTo("user-456");
    assertThat(response.roles()).containsExactly("ROLE_USER", "ROLE_ADMIN");
    assertThat(response.permissions()).containsExactly("transactions:read", "transactions:write");
  }

  @Test
  void fetchPermissions_sendsBearerToken() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cabc123/permissions"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                        {
                          "userId": "user-456",
                          "roles": [],
                          "permissions": []
                        }
                        """)));

    permissionServiceClient
        .fetchPermissions("auth0|abc123", "user@example.com", "Test User")
        .block();

    wireMock.verify(
        getRequestedFor(urlPathEqualTo("/internal/v1/users/auth0%7Cabc123/permissions"))
            .withHeader("Authorization", matching("Bearer .+")));
  }

  @Test
  void fetchPermissions_throwsOnClientError() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cnotfound/permissions"))
            .willReturn(aResponse().withStatus(404)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|notfound", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }

  @Test
  void fetchPermissions_throwsOnServerError() {
    wireMock.stubFor(
        get(urlPathEqualTo("/internal/v1/users/auth0%7Cerror/permissions"))
            .willReturn(aResponse().withStatus(500)));

    assertThatThrownBy(
            () ->
                permissionServiceClient
                    .fetchPermissions("auth0|error", "user@example.com", "Test User")
                    .block())
        .isInstanceOf(PermissionServiceClient.PermissionServiceException.class);
  }
}
