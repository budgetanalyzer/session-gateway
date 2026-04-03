package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ResponseStatusException;

import reactor.test.StepVerifier;

class GlobalBrowserErrorWebExceptionHandlerTest {

  private final GlobalBrowserErrorWebExceptionHandler handler =
      new GlobalBrowserErrorWebExceptionHandler();

  @Test
  void browserNavigationFailureRedirectsToOops() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Sec-Fetch-Mode", "navigate")
                .build());

    StepVerifier.create(handler.handle(exchange, new RuntimeException("boom"))).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(exchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
  }

  @Test
  void nonBrowserFailureReturnsJsonError() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/some-path").header("Accept", "application/json").build());

    StepVerifier.create(handler.handle(exchange, new RuntimeException("boom"))).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    assertThat(exchange.getResponse().getHeaders().getContentType())
        .isEqualTo(MediaType.APPLICATION_JSON);
  }

  @Test
  void nonBrowserResponseStatusExceptionPreservesStatusCode() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/some-path").header("Accept", "application/json").build());

    StepVerifier.create(handler.handle(exchange, new ResponseStatusException(HttpStatus.NOT_FOUND)))
        .verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(exchange.getResponse().getHeaders().getContentType())
        .isEqualTo(MediaType.APPLICATION_JSON);
  }

  @Test
  void committedResponsePassesThrough() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Sec-Fetch-Mode", "navigate")
                .build());
    exchange.getResponse().setStatusCode(HttpStatus.OK);
    exchange.getResponse().setComplete().block();

    var runtimeException = new RuntimeException("boom");

    StepVerifier.create(handler.handle(exchange, runtimeException))
        .expectErrorSatisfies(throwable -> assertThat(throwable).isSameAs(runtimeException))
        .verify();
  }

  @Test
  void callbackPathIsNotClassifiedAsBrowserNavigation() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/idp?code=x&state=y")
                .header("Sec-Fetch-Mode", "navigate")
                .build());

    StepVerifier.create(handler.handle(exchange, new RuntimeException("boom"))).verifyComplete();

    assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
    assertThat(exchange.getResponse().getHeaders().getLocation()).isNull();
  }

  @Test
  void orderIsNegativeOne() {
    assertThat(handler.getOrder()).isEqualTo(-1);
  }
}
