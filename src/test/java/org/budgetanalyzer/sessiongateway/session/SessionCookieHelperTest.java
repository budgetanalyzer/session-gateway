package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

class SessionCookieHelperTest {

  private final SessionCookieHelper sessionCookieHelper =
      new SessionCookieHelper("SESSION", "budgetanalyzer.localhost", true, "strict");

  @Test
  void setSessionCookieWritesExpectedCookieAttributes() {
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/auth/session").build());

    sessionCookieHelper.setSessionCookie(mockServerWebExchange, "session-123");

    var responseCookie = mockServerWebExchange.getResponse().getCookies().getFirst("SESSION");

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getValue()).isEqualTo("session-123");
    assertThat(responseCookie.getDomain()).isEqualTo("budgetanalyzer.localhost");
    assertThat(responseCookie.getPath()).isEqualTo("/");
    assertThat(responseCookie.isHttpOnly()).isTrue();
    assertThat(responseCookie.isSecure()).isTrue();
    assertThat(responseCookie.getSameSite()).isEqualTo("Strict");
  }

  @Test
  void clearSessionCookieExpiresCookieImmediately() {
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.post("/logout").build());

    sessionCookieHelper.clearSessionCookie(mockServerWebExchange);

    var responseCookie = mockServerWebExchange.getResponse().getCookies().getFirst("SESSION");

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getValue()).isEmpty();
    assertThat(responseCookie.getDomain()).isEqualTo("budgetanalyzer.localhost");
    assertThat(responseCookie.getPath()).isEqualTo("/");
    assertThat(responseCookie.isHttpOnly()).isTrue();
    assertThat(responseCookie.isSecure()).isTrue();
    assertThat(responseCookie.getSameSite()).isEqualTo("Strict");
    assertThat(responseCookie.getMaxAge()).isZero();
  }

  @Test
  void constructorRejectsUnsupportedSameSiteValue() {
    assertThatThrownBy(
            () -> new SessionCookieHelper("SESSION", "budgetanalyzer.localhost", true, "bogus"))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("session.cookie.same-site")
        .hasMessageContaining("Strict, Lax, or None");
  }

  @Test
  void readSessionIdReturnsCookieValueWhenPresent() {
    var mockServerWebExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/user")
                .cookie(new HttpCookie("SESSION", "session-123"))
                .build());

    var sessionId = sessionCookieHelper.readSessionId(mockServerWebExchange);

    assertThat(sessionId).isEqualTo("session-123");
  }

  @Test
  void readSessionIdReturnsNullWhenCookieMissing() {
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());

    var sessionId = sessionCookieHelper.readSessionId(mockServerWebExchange);

    assertThat(sessionId).isNull();
  }
}
