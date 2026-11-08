package org.budgetanalyzer.sessiongateway.api;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.security.SessionLifecycleAuditLogger;
import org.budgetanalyzer.sessiongateway.security.SessionPrincipal;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionTokenDigest;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Logout controller for Session Gateway.
 *
 * <p>Deletes the Redis session hash, clears the session cookie, and redirects to the IDP logout
 * endpoint. If the session cannot be read or deleted, redirects to {@code /oops} without clearing
 * the cookie.
 */
@Tag(name = "Logout", description = "Browser logout and session invalidation")
@RestController
public class LogoutController {

  private static final Logger log = LoggerFactory.getLogger(LogoutController.class);

  private static final String OOPS_PATH = "/oops";

  private final URI idpLogoutUri;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;
  private final SessionLifecycleAuditLogger sessionLifecycleAuditLogger;

  /**
   * Creates the logout controller and builds the IDP logout URI.
   *
   * <p>The URI is built from the {@code idp.logout.url-template} property, replacing {@code
   * {returnTo}} and {@code {clientId}} placeholders, so a malformed template fails startup.
   *
   * @param sessionWriter the Redis session writer
   * @param sessionCookieHelper the session cookie helper
   * @param sessionLifecycleAuditLogger the session lifecycle audit logger
   * @param idpLogoutUrlTemplate the IDP logout URL template
   * @param clientId the OAuth2 client ID
   * @param returnToUrl the URL the IDP returns the browser to after logout
   * @throws IllegalArgumentException if the resulting logout URL is not a valid URI
   */
  public LogoutController(
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      SessionLifecycleAuditLogger sessionLifecycleAuditLogger,
      @Value(
              "${idp.logout.url-template:"
                  + "${spring.security.oauth2.client.provider.idp.issuer-uri:}"
                  + "/v2/logout?returnTo={returnTo}&client_id={clientId}}")
          String idpLogoutUrlTemplate,
      @Value("${spring.security.oauth2.client.registration.idp.client-id:}") String clientId,
      @Value("${idp.logout.return-to:http://localhost:8080}") String returnToUrl) {
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.sessionLifecycleAuditLogger = sessionLifecycleAuditLogger;
    var encodedReturnTo = URLEncoder.encode(returnToUrl, StandardCharsets.UTF_8);
    var idpLogoutUrl =
        idpLogoutUrlTemplate
            .replace("{returnTo}", encodedReturnTo)
            .replace("{clientId}", clientId)
            .replace("//v2/logout", "/v2/logout");
    this.idpLogoutUri = URI.create(idpLogoutUrl);
  }

  /**
   * Logout endpoint that invalidates the session and redirects to IDP logout.
   *
   * @param exchange the server web exchange
   * @return redirect to IDP logout, or to {@code /oops} when the session cannot be invalidated
   */
  @Operation(
      summary = "Log out",
      description =
          "Invalidates the browser session and redirects to the identity provider logout "
              + "endpoint.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "303",
            description = "Redirect to the identity provider logout endpoint",
            headers =
                @Header(
                    name = "Location",
                    description = "Identity provider logout URL",
                    schema = @Schema(type = "string", format = "uri"))),
        @ApiResponse(
            responseCode = "302",
            description = "Session could not be read or deleted; redirect to the app error route",
            headers =
                @Header(
                    name = "Location",
                    description = "Frontend app error route",
                    schema = @Schema(type = "string", example = "/oops")))
      })
  @PostMapping("/logout")
  public Mono<Void> logout(ServerWebExchange exchange) {
    var sessionId = sessionCookieHelper.readSessionId(exchange);

    log.info("Processing logout request for sessionId={}", SessionTokenDigest.logId(sessionId));

    return resolveActor(exchange)
        .onErrorResume(
            error -> {
              log.error("Failed to read session during logout", error);
              return redirectToOops(exchange, SessionLifecycleAuditLogger.ANONYMOUS_ACTOR)
                  .then(Mono.empty());
            })
        .flatMap(actor -> invalidateSession(sessionId, actor, exchange));
  }

  private Mono<String> resolveActor(ServerWebExchange exchange) {
    return exchange
        .<Authentication>getPrincipal()
        .map(Authentication::getPrincipal)
        .ofType(SessionPrincipal.class)
        .map(SessionPrincipal::userId)
        .defaultIfEmpty(SessionLifecycleAuditLogger.ANONYMOUS_ACTOR);
  }

  private Mono<Void> invalidateSession(String sessionId, String actor, ServerWebExchange exchange) {
    return deleteSession(sessionId)
        .thenReturn(actor)
        .onErrorResume(
            error -> {
              log.error("Failed to delete session during logout", error);
              return redirectToOops(exchange, actor).then(Mono.empty());
            })
        .flatMap(deletedActor -> redirectToIdpLogout(sessionId, deletedActor, exchange));
  }

  private Mono<Void> redirectToOops(ServerWebExchange exchange, String actor) {
    var response = exchange.getResponse();
    response.setStatusCode(HttpStatus.FOUND);
    response.getHeaders().setLocation(URI.create(OOPS_PATH));
    return response
        .setComplete()
        .doOnSuccess(ignored -> sessionLifecycleAuditLogger.logoutFailure(actor, exchange));
  }

  private Mono<Void> deleteSession(String sessionId) {
    if (sessionId == null || sessionId.isBlank()) {
      log.debug("No session cookie present during logout");
      return Mono.empty();
    }

    log.debug("Deleting session {}", SessionTokenDigest.logId(sessionId));
    return sessionWriter.deleteSession(sessionId).then();
  }

  private Mono<Void> redirectToIdpLogout(
      String sessionId, String actor, ServerWebExchange exchange) {
    sessionCookieHelper.clearSessionCookie(exchange);
    log.debug("Redirecting to IDP logout: {}", idpLogoutUri);

    var response = exchange.getResponse();
    response.setStatusCode(HttpStatus.SEE_OTHER);
    response.getHeaders().setLocation(idpLogoutUri);
    return response
        .setComplete()
        .doOnSuccess(
            ignored -> {
              log.info("Successfully logged out sessionId={}", SessionTokenDigest.logId(sessionId));
              sessionLifecycleAuditLogger.logoutSuccess(actor, exchange);
            });
  }
}
