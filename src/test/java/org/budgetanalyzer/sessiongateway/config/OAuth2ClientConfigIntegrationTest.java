package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;

import reactor.netty.resources.ConnectionProvider;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository;

class OAuth2ClientConfigIntegrationTest extends AbstractIntegrationTest {

  @Autowired
  @Qualifier("idpConnectionProvider")
  private ConnectionProvider idpConnectionProvider;

  @Autowired private ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  @Autowired private RedisAuthorizationRequestRepository redisAuthorizationRequestRepository;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @Test
  void dedicatedIdpConnectionProviderUsesExplicitPoolSettings() {
    assertThat(idpConnectionProvider.name()).isEqualTo("idp-oidc-callback");
    assertThat(idpConnectionProvider.maxConnections()).isEqualTo(50);
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/",
        "/dashboard",
        "/settings?tab=profile&section=security",
        "/docs#intro",
        "/search?q=test%20query"
      })
  void storesSafeReturnUrl(String returnUrl) {
    assertThat(resolveAndStore(returnUrl)).containsEntry("return_url", returnUrl);
  }

  @Test
  void storesReturnUrlAtLimitAndDropsOversizedValue() {
    var returnUrl = "/" + "a".repeat(2047);
    assertThat(resolveAndStore(returnUrl)).containsEntry("return_url", returnUrl);
    assertThat(resolveAndStore(returnUrl + "a")).doesNotContainKey("return_url");
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "/path\tsegment",
        "/path with spaces",
        "/bad%escape"
      })
  void dropsUnsafeReturnUrlAndContinuesLogin(String returnUrl) {
    assertThat(resolveAndStore(returnUrl)).doesNotContainKey("return_url");
  }

  private Map<Object, Object> resolveAndStore(String returnUrl) {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("https://app.example.test/oauth2/authorization/idp")
                .queryParam("returnUrl", returnUrl));
    var authorizationRequest = authorizationRequestResolver.resolve(exchange).block();
    assertThat(authorizationRequest).isNotNull();
    assertThat(authorizationRequest.getRedirectUri())
        .isEqualTo("https://app.example.test/login/oauth2/code/idp");
    redisAuthorizationRequestRepository
        .saveAuthorizationRequest(authorizationRequest, exchange)
        .block();
    var key = "oauth2:state:" + authorizationRequest.getState();
    assertThat(reactiveStringRedisTemplate.getExpire(key).block())
        .isPositive()
        .isLessThanOrEqualTo(Duration.ofSeconds(600));
    var fields =
        reactiveStringRedisTemplate
            .opsForHash()
            .entries(key)
            .collectMap(Map.Entry::getKey, Map.Entry::getValue)
            .block();
    assertThat(fields)
        .containsKeys("redirect_uri", "browser_binding_hash", "nonce", "code_verifier");
    return fields;
  }
}
