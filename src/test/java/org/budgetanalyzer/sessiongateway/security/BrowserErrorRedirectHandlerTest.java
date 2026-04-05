package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import reactor.test.StepVerifier;

class BrowserErrorRedirectHandlerTest {

  private final BrowserErrorRedirectHandler browserErrorRedirectHandler =
      new BrowserErrorRedirectHandler();

  @Test
  void nonApiPathRedirectsToOops() {
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/oops-source").build());

    StepVerifier.create(browserErrorRedirectHandler.handle(exchange, new RuntimeException("boom")))
        .verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
  }

  @Test
  void apiPathPassesThroughToSharedJsonHandler() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/auth/v1/session")
                .header("Accept", "text/html,application/xhtml+xml")
                .header("Sec-Fetch-Mode", "navigate")
                .build());
    var runtimeException = new RuntimeException("boom");

    StepVerifier.create(browserErrorRedirectHandler.handle(exchange, runtimeException))
        .expectErrorSatisfies(throwable -> assertThat(throwable).isSameAs(runtimeException))
        .verify();

    assertThat(exchange.getResponse().getStatusCode()).isNull();
    assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
  }

  @Test
  void versionedUserPathPassesThroughToSharedJsonHandler() {
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/auth/v1/user").build());
    var runtimeException = new RuntimeException("boom");

    StepVerifier.create(browserErrorRedirectHandler.handle(exchange, runtimeException))
        .expectErrorSatisfies(throwable -> assertThat(throwable).isSameAs(runtimeException))
        .verify();

    assertThat(exchange.getResponse().getStatusCode()).isNull();
  }

  @Test
  void committedResponsePassesThrough() {
    var exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/oops-source").build());
    exchange.getResponse().setStatusCode(HttpStatus.OK);
    exchange.getResponse().setComplete().block();

    var runtimeException = new RuntimeException("boom");

    StepVerifier.create(browserErrorRedirectHandler.handle(exchange, runtimeException))
        .expectErrorSatisfies(throwable -> assertThat(throwable).isSameAs(runtimeException))
        .verify();
  }

  @Test
  void callbackPathRedirectsToOopsWhenItFallsThroughToThisHandler() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/idp?code=x&state=y").build());

    StepVerifier.create(browserErrorRedirectHandler.handle(exchange, new RuntimeException("boom")))
        .verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
  }

  @Test
  void orderIsNegativeTwo() {
    assertThat(browserErrorRedirectHandler.getOrder()).isEqualTo(-2);
  }
}
