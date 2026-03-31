package org.budgetanalyzer.sessiongateway.session;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import org.budgetanalyzer.sessiongateway.config.SessionProperties;

/** Manages session cookies on HTTP exchanges. */
@Component
public class SessionCookieHelper {

  private final SessionProperties.CookieProperties cookieProperties;
  private final String cookieName;

  /** Creates a helper that reads cookie settings from {@link SessionProperties}. */
  public SessionCookieHelper(SessionProperties sessionProperties) {
    this.cookieProperties = sessionProperties.cookie();
    this.cookieName = cookieProperties.name();
  }

  /**
   * Sets the session cookie on the response.
   *
   * @param exchange the server web exchange
   * @param sessionId the session ID to store in the cookie
   */
  public void setSessionCookie(ServerWebExchange exchange, String sessionId) {
    exchange.getResponse().addCookie(buildCookie(sessionId).build());
  }

  /**
   * Clears the session cookie by setting Max-Age to 0.
   *
   * @param exchange the server web exchange
   */
  public void clearSessionCookie(ServerWebExchange exchange) {
    exchange.getResponse().addCookie(buildCookie("").maxAge(0).build());
  }

  /**
   * Reads the session ID from the request cookie.
   *
   * @param exchange the server web exchange
   * @return the session ID, or null if no session cookie is present
   */
  public String readSessionId(ServerWebExchange exchange) {
    var cookie = exchange.getRequest().getCookies().getFirst(cookieName);
    return cookie != null ? cookie.getValue() : null;
  }

  private ResponseCookie.ResponseCookieBuilder buildCookie(String value) {
    var responseCookieBuilder =
        ResponseCookie.from(cookieName, value)
            .httpOnly(true)
            .secure(cookieProperties.secure())
            .sameSite(cookieProperties.sameSite())
            .path("/");

    if (cookieProperties.hasDomainOverride()) {
      responseCookieBuilder.domain(cookieProperties.domainOverride());
    }

    return responseCookieBuilder;
  }
}
