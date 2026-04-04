package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import reactor.test.StepVerifier;

// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
class OAuth2CallbackUnexpectedFailureWebExceptionHandlerTest {

  @Test
  void handle_redirectsCallbackExceptionsToOops() {
    var oauth2CallbackUnexpectedFailureWebExceptionHandler =
        new OAuth2CallbackUnexpectedFailureWebExceptionHandler(
            new OAuth2CallbackRedirectResolver());
    var mockServerWebExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/idp?code=test-code&state=test-state")
                .build());

    StepVerifier.create(
            oauth2CallbackUnexpectedFailureWebExceptionHandler.handle(
                mockServerWebExchange, new IllegalStateException("boom")))
        .verifyComplete();

    assertThat(mockServerWebExchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
    assertThat(mockServerWebExchange.getResponse().getHeaders().getLocation()).hasToString("/oops");
  }

  @Test
  void handle_leavesNonCallbackExceptionsUnchanged() {
    var oauth2CallbackUnexpectedFailureWebExceptionHandler =
        new OAuth2CallbackUnexpectedFailureWebExceptionHandler(
            new OAuth2CallbackRedirectResolver());
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());
    var illegalStateException = new IllegalStateException("boom");

    StepVerifier.create(
            oauth2CallbackUnexpectedFailureWebExceptionHandler.handle(
                mockServerWebExchange, illegalStateException))
        .expectErrorSatisfies(throwable -> assertThat(throwable).isSameAs(illegalStateException))
        .verify();

    assertThat(mockServerWebExchange.getResponse().getStatusCode()).isNull();
    assertThat(mockServerWebExchange.getResponse().getHeaders().getLocation()).isNull();
  }
}
