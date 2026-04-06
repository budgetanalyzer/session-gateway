package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;

import org.budgetanalyzer.sessiongateway.config.SessionProperties;

class SessionCookieHelperTest {

  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";

  @Test
  void setSessionCookieWritesHostOnlyCookieWhenDomainOverrideMissing() {
    var sessionCookieHelper = new SessionCookieHelper(sessionProperties(null, "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/auth/session").build());

    sessionCookieHelper.setSessionCookie(mockServerWebExchange, "session-123");

    var responseCookie =
        mockServerWebExchange.getResponse().getCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getValue()).isEqualTo("session-123");
    assertThat(responseCookie.getDomain()).isNull();
    assertThat(responseCookie.getPath()).isEqualTo("/");
    assertThat(responseCookie.isHttpOnly()).isTrue();
    assertThat(responseCookie.isSecure()).isTrue();
    assertThat(responseCookie.getSameSite()).isEqualTo("Strict");
  }

  @Test
  void setSessionCookieWritesConfiguredDomainWhenOverridePresent() {
    var sessionCookieHelper =
        new SessionCookieHelper(sessionProperties("budgetanalyzer.localhost", "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/auth/session").build());

    sessionCookieHelper.setSessionCookie(mockServerWebExchange, "session-123");

    var responseCookie =
        mockServerWebExchange.getResponse().getCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getDomain()).isEqualTo("budgetanalyzer.localhost");
  }

  @Test
  void clearSessionCookieExpiresHostOnlyCookieImmediately() {
    var sessionCookieHelper = new SessionCookieHelper(sessionProperties(null, "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.post("/logout").build());

    sessionCookieHelper.clearSessionCookie(mockServerWebExchange);

    var responseCookie =
        mockServerWebExchange.getResponse().getCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getValue()).isEmpty();
    assertThat(responseCookie.getDomain()).isNull();
    assertThat(responseCookie.getPath()).isEqualTo("/");
    assertThat(responseCookie.isHttpOnly()).isTrue();
    assertThat(responseCookie.isSecure()).isTrue();
    assertThat(responseCookie.getSameSite()).isEqualTo("Strict");
    assertThat(responseCookie.getMaxAge()).isZero();
  }

  @Test
  void clearSessionCookieExpiresConfiguredDomainCookieImmediately() {
    var sessionCookieHelper =
        new SessionCookieHelper(sessionProperties("budgetanalyzer.localhost", "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.post("/logout").build());

    sessionCookieHelper.clearSessionCookie(mockServerWebExchange);

    var responseCookie =
        mockServerWebExchange.getResponse().getCookies().getFirst(PUBLIC_SESSION_COOKIE_NAME);

    assertThat(responseCookie).isNotNull();
    assertThat(responseCookie.getDomain()).isEqualTo("budgetanalyzer.localhost");
    assertThat(responseCookie.getMaxAge()).isZero();
  }

  @Test
  void readSessionIdReturnsCookieValueWhenPresent() {
    var sessionCookieHelper = new SessionCookieHelper(sessionProperties(null, "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/user")
                .cookie(new HttpCookie(PUBLIC_SESSION_COOKIE_NAME, "session-123"))
                .build());

    var sessionId = sessionCookieHelper.readSessionId(mockServerWebExchange);

    assertThat(sessionId).isEqualTo("session-123");
  }

  @Test
  void readSessionIdReturnsNullWhenCookieMissing() {
    var sessionCookieHelper = new SessionCookieHelper(sessionProperties(null, "Strict"));
    var mockServerWebExchange =
        MockServerWebExchange.from(MockServerHttpRequest.get("/user").build());

    var sessionId = sessionCookieHelper.readSessionId(mockServerWebExchange);

    assertThat(sessionId).isNull();
  }

  private SessionProperties sessionProperties(String domainOverride, String sameSite) {
    return new SessionProperties(
        "session:",
        900,
        900,
        new SessionProperties.CookieProperties(
            PUBLIC_SESSION_COOKIE_NAME, domainOverride, true, sameSite));
  }
}
