package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.util.UriComponentsBuilder;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

@TestPropertySource(
    properties = {
      "IDP_REDIRECT_URI=https://app.example.test/login/oauth2/code/idp",
      "server.forward-headers-strategy=framework"
    })
class FixedRedirectUriIntegrationTest extends AbstractIntegrationTest {

  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;

  @Test
  void usesFixedCallbackUriDespiteForwardedHeaders() {
    var result =
        webTestClient
            .get()
            .uri("/oauth2/authorization/idp")
            .header("Forwarded", "proto=https;host=evil.example")
            .header("X-Forwarded-Host", "evil.example")
            .header("X-Forwarded-Proto", "https")
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .returnResult(Void.class);
    var parameters =
        UriComponentsBuilder.fromUri(result.getResponseHeaders().getLocation())
            .build()
            .getQueryParams();
    assertThat(URLDecoder.decode(parameters.getFirst("redirect_uri"), StandardCharsets.UTF_8))
        .isEqualTo("https://app.example.test/login/oauth2/code/idp");
    var state = URLDecoder.decode(parameters.getFirst("state"), StandardCharsets.UTF_8);
    assertThat(
            reactiveStringRedisTemplate
                .opsForHash()
                .get("oauth2:state:" + state, "redirect_uri")
                .block())
        .isEqualTo("https://app.example.test/login/oauth2/code/idp");
  }
}
