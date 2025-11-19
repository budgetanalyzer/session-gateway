package org.budgetanalyzer.sessiongateway.base;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

import com.github.tomakehurst.wiremock.WireMockServer;

import org.budgetanalyzer.sessiongateway.config.TestContainersConfig;
import org.budgetanalyzer.sessiongateway.config.WireMockConfig;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@Testcontainers
@AutoConfigureWebTestClient
@Import({TestContainersConfig.class, WireMockConfig.class})
public abstract class AbstractIntegrationTest {

  @Autowired protected WebTestClient webTestClient;

  @Autowired protected WireMockServer wireMockServer;

  @DynamicPropertySource
  static void configureProperties(DynamicPropertyRegistry registry) {
    String wireMockUrl = "http://localhost:" + WireMockConfig.getWireMockServer().port();

    // Point Auth0 OAuth2 configuration to WireMock
    registry.add(
        "spring.security.oauth2.client.provider.auth0.issuer-uri", () -> wireMockUrl + "/auth0");

    // Point downstream gateway to WireMock
    registry.add("api.gateway.url", () -> wireMockUrl + "/api-gateway");
  }

  @BeforeEach
  void resetWireMock() {
    wireMockServer.resetAll();
    stubAuth0OidcDiscovery();
  }

  protected void stubAuth0OidcDiscovery() {
    String baseUrl = "http://localhost:" + wireMockServer.port();

    wireMockServer.stubFor(
        get(urlEqualTo("/auth0/.well-known/openid-configuration"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                    {
                        "issuer": "%s/auth0",
                        "authorization_endpoint": "%s/auth0/authorize",
                        "token_endpoint": "%s/auth0/oauth/token",
                        "userinfo_endpoint": "%s/auth0/userinfo",
                        "jwks_uri": "%s/auth0/.well-known/jwks.json",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "scopes_supported": ["openid", "profile", "email"]
                    }
                    """
                            .formatted(baseUrl, baseUrl, baseUrl, baseUrl, baseUrl))));

    // Stub JWKS endpoint (required for JWT validation)
    wireMockServer.stubFor(
        get(urlEqualTo("/auth0/.well-known/jwks.json"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                    {
                        "keys": []
                    }
                    """)));
  }

  protected void stubAuth0TokenEndpoint(String accessToken, String idToken) {
    wireMockServer.stubFor(
        post(urlEqualTo("/auth0/oauth/token"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                    {
                        "access_token": "%s",
                        "id_token": "%s",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """
                            .formatted(accessToken, idToken))));
  }

  protected void stubAuth0UserInfo(String sub, String email, String name) {
    wireMockServer.stubFor(
        get(urlEqualTo("/auth0/userinfo"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                    {
                        "sub": "%s",
                        "email": "%s",
                        "name": "%s"
                    }
                    """
                            .formatted(sub, email, name))));
  }
}
