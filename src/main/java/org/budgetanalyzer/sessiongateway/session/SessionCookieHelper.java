package org.budgetanalyzer.sessiongateway.session;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

/** Manages session cookies on HTTP exchanges. */
@Component
public class SessionCookieHelper {

  private final String cookieName;
  private final String domainOverride;
  private final boolean secure;
  private final String sameSite;

  public SessionCookieHelper(
      @Value("${session.cookie.name:SESSION}") String cookieName,
      @Value("${session.cookie.domain-override:budgetanalyzer.localhost}") String domainOverride,
      @Value("${session.cookie.secure:true}") boolean secure,
      @Value("${session.cookie.same-site:strict}") String sameSite) {
    this.cookieName = cookieName;
    this.domainOverride = domainOverride;
    this.secure = secure;
    this.sameSite = sameSite;
  }

  /**
   * Sets the session cookie on the response.
   *
   * @param exchange the server web exchange
   * @param sessionId the session ID to store in the cookie
   */
  public void setSessionCookie(ServerWebExchange exchange, String sessionId) {
    var cookie =
        ResponseCookie.from(cookieName, sessionId)
            .httpOnly(true)
            .secure(secure)
            .sameSite(sameSite)
            .path("/")
            .domain(domainOverride)
            .build();
    exchange.getResponse().addCookie(cookie);
  }

  /**
   * Clears the session cookie by setting Max-Age to 0.
   *
   * @param exchange the server web exchange
   */
  public void clearSessionCookie(ServerWebExchange exchange) {
    var cookie =
        ResponseCookie.from(cookieName, "")
            .httpOnly(true)
            .secure(secure)
            .sameSite(sameSite)
            .path("/")
            .domain(domainOverride)
            .maxAge(0)
            .build();
    exchange.getResponse().addCookie(cookie);
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
}
