package org.budgetanalyzer.sessiongateway.api;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Logout controller for Session Gateway.
 *
 * <p>Deletes the Redis session hash, clears the session cookie, and redirects to the IDP logout
 * endpoint.
 */
@RestController
public class LogoutController {

  private static final Logger log = LoggerFactory.getLogger(LogoutController.class);

  private final String idpLogoutUrlTemplate;
  private final String clientId;
  private final String returnToUrl;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;

  public LogoutController(
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      @Value(
              "${idp.logout.url-template:"
                  + "${spring.security.oauth2.client.provider.idp.issuer-uri:}"
                  + "/v2/logout?returnTo={returnTo}&client_id={clientId}}")
          String idpLogoutUrlTemplate,
      @Value("${spring.security.oauth2.client.registration.idp.client-id:}") String clientId,
      @Value("${idp.logout.return-to:http://localhost:8080}") String returnToUrl) {
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.idpLogoutUrlTemplate = idpLogoutUrlTemplate;
    this.clientId = clientId;
    this.returnToUrl = returnToUrl;
  }

  /**
   * Logout endpoint that invalidates the session and redirects to IDP logout.
   *
   * @param exchange the server web exchange
   * @return redirect to IDP logout
   */
  @GetMapping("/logout")
  public Mono<Void> logout(ServerWebExchange exchange) {
    var sessionId = sessionCookieHelper.readSessionId(exchange);

    log.info("Processing logout request for sessionId={}", sessionId);

    return deleteSession(sessionId)
        .then(Mono.fromRunnable(() -> sessionCookieHelper.clearSessionCookie(exchange)))
        .then(redirectToIdpLogout(exchange))
        .doOnSuccess(v -> log.info("Successfully logged out sessionId={}", sessionId))
        .doOnError(error -> log.error("Error during logout", error));
  }

  private Mono<Void> deleteSession(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      log.debug("No session cookie present during logout");
      return Mono.empty();
    }

    log.debug("Deleting session {}", sessionId);
    return sessionWriter.deleteSession(sessionId).then();
  }

  /**
   * Redirects to IDP logout endpoint.
   *
   * <p>The logout URL is built from the configurable {@code idp.logout.url-template} property,
   * replacing {@code {returnTo}} and {@code {clientId}} placeholders.
   *
   * @param exchange the server web exchange
   * @return completion signal
   */
  private Mono<Void> redirectToIdpLogout(ServerWebExchange exchange) {
    var response = exchange.getResponse();

    var encodedReturnTo = URLEncoder.encode(returnToUrl, StandardCharsets.UTF_8);
    var idpLogoutUrl =
        idpLogoutUrlTemplate.replace("{returnTo}", encodedReturnTo).replace("{clientId}", clientId);
    idpLogoutUrl = idpLogoutUrl.replace("//v2/logout", "/v2/logout");

    log.debug("Redirecting to IDP logout: {}", idpLogoutUrl);

    response.setStatusCode(HttpStatus.FOUND);
    response.getHeaders().setLocation(URI.create(idpLogoutUrl));

    return response.setComplete();
  }
}
