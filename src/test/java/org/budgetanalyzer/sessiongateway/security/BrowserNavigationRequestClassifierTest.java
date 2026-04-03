package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

class BrowserNavigationRequestClassifierTest {

  @Test
  void classifiesGetWithSecFetchModeNavigateAsBrowserNavigation() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Sec-Fetch-Mode", "navigate")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isTrue();
  }

  @Test
  void classifiesGetWithSecFetchDestDocumentAsBrowserNavigation() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Sec-Fetch-Dest", "document")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isTrue();
  }

  @Test
  void classifiesGetWithAcceptTextHtmlAsBrowserNavigation() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Accept", "text/html,application/xhtml+xml")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isTrue();
  }

  @Test
  void classifiesHeadWithBrowserSignalsAsBrowserNavigation() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.head("/logout").header("Sec-Fetch-Mode", "navigate").build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isTrue();
  }

  @Test
  void rejectsPostRequest() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.post("/oauth2/authorization/idp")
                .header("Sec-Fetch-Mode", "navigate")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }

  @Test
  void rejectsCallbackPath() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/login/oauth2/code/idp?code=x&state=y")
                .header("Sec-Fetch-Mode", "navigate")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "/auth/session",
        "/auth/token/exchange",
        "/user",
        "/api/some-resource",
        "/v3/api-docs",
        "/v3/api-docs/swagger-config",
        "/swagger-ui/index.html",
        "/swagger-ui.html",
        "/actuator/health"
      })
  void rejectsApiPaths(String path) {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get(path).header("Sec-Fetch-Mode", "navigate").build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }

  @Test
  void rejectsApiPathEvenWithAllBrowserSignals() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/auth/session")
                .header("Accept", "text/html")
                .header("Sec-Fetch-Mode", "navigate")
                .header("Sec-Fetch-Dest", "document")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }

  @Test
  void rejectsGetWithoutBrowserSignals() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .header("Accept", "application/json")
                .build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }

  @Test
  void rejectsGetWithWildcardAcceptOnly() {
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp").header("Accept", "*/*").build());

    assertThat(BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)).isFalse();
  }
}
