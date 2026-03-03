package org.budgetanalyzer.sessiongateway.config;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

@TestConfiguration(proxyBeanMethods = false)
public class WireMockConfig {

  private static WireMockServer wireMockServer;

  static {
    wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMockServer.start();
    stubIdpOidcDiscovery();
  }

  @Bean(destroyMethod = "stop")
  public WireMockServer wireMockServer() {
    return wireMockServer;
  }

  public static WireMockServer getWireMockServer() {
    return wireMockServer;
  }

  private static void stubIdpOidcDiscovery() {
    String baseUrl = "http://localhost:" + wireMockServer.port();

    wireMockServer.stubFor(
        get(urlEqualTo("/idp/.well-known/openid-configuration"))
            .willReturn(
                aResponse()
                    .withStatus(200)
                    .withHeader("Content-Type", "application/json")
                    .withBody(
                        """
                    {
                        "issuer": "%s/idp",
                        "authorization_endpoint": "%s/idp/authorize",
                        "token_endpoint": "%s/idp/oauth/token",
                        "userinfo_endpoint": "%s/idp/userinfo",
                        "jwks_uri": "%s/idp/.well-known/jwks.json",
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
        get(urlEqualTo("/idp/.well-known/jwks.json"))
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
}
