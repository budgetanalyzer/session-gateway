package org.budgetanalyzer.sessiongateway.controller;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Logout controller for Session Gateway.
 *
 * <p>Phase 2 Task 2.5: Implement Logout Endpoint
 *
 * <ul>
 *   <li>Invalidates Redis session
 *   <li>Clears session cookie
 *   <li>Removes OAuth2 authorized client from session
 *   <li>Redirects to IDP logout (with returnTo parameter)
 * </ul>
 */
@RestController
public class LogoutController {

  private static final Logger log = LoggerFactory.getLogger(LogoutController.class);

  private final String idpLogoutUrlTemplate;
  private final String clientId;
  private final String returnToUrl;
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

  public LogoutController(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      @Value(
              "${idp.logout.url-template:"
                  + "${spring.security.oauth2.client.provider.idp.issuer-uri:}"
                  + "/v2/logout?returnTo={returnTo}&client_id={clientId}}")
          String idpLogoutUrlTemplate,
      @Value("${spring.security.oauth2.client.registration.idp.client-id:}") String clientId,
      @Value("${idp.logout.return-to:http://localhost:8080}") String returnToUrl) {
    this.authorizedClientRepository = authorizedClientRepository;
    this.idpLogoutUrlTemplate = idpLogoutUrlTemplate;
    this.clientId = clientId;
    this.returnToUrl = returnToUrl;
  }

  /**
   * Logout endpoint that invalidates the session and redirects to IDP logout.
   *
   * <p>Steps:
   *
   * <ol>
   *   <li>Remove OAuth2 authorized client (clears tokens from session)
   *   <li>Invalidate the session (clears Redis session)
   *   <li>Clear session cookie
   *   <li>Redirect to IDP logout (which redirects back to returnTo URL)
   * </ol>
   *
   * @param exchange the server web exchange
   * @param authentication the current authentication
   * @return redirect to IDP logout
   */
  @GetMapping("/logout")
  public Mono<Void> logout(ServerWebExchange exchange, Authentication authentication) {
    log.info("Processing logout request for user: {}", authentication.getName());

    return removeAuthorizedClient(exchange, authentication)
        .then(invalidateSession(exchange))
        .then(redirectToIdpLogout(exchange))
        .doOnSuccess(v -> log.info("Successfully logged out user: {}", authentication.getName()))
        .doOnError(error -> log.error("Error during logout", error));
  }

  /**
   * Removes the OAuth2 authorized client from the session.
   *
   * @param exchange the server web exchange
   * @param authentication the current authentication
   * @return completion signal
   */
  private Mono<Void> removeAuthorizedClient(
      ServerWebExchange exchange, Authentication authentication) {
    if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
      var registrationId = oauth2Token.getAuthorizedClientRegistrationId();

      log.debug("Removing authorized client: {}", registrationId);

      return authorizedClientRepository.removeAuthorizedClient(
          registrationId, authentication, exchange);
    }

    return Mono.empty();
  }

  /**
   * Invalidates the current session.
   *
   * @param exchange the server web exchange
   * @return completion signal
   */
  private Mono<Void> invalidateSession(ServerWebExchange exchange) {
    return exchange
        .getSession()
        .flatMap(
            session -> {
              log.debug("Invalidating session: {}", session.getId());
              return session.invalidate();
            });
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

    var idpLogoutUrl =
        idpLogoutUrlTemplate.replace("{returnTo}", returnToUrl).replace("{clientId}", clientId);

    log.debug("Redirecting to IDP logout: {}", idpLogoutUrl);

    response.setStatusCode(HttpStatus.FOUND);
    response.getHeaders().setLocation(URI.create(idpLogoutUrl));

    return response.setComplete();
  }
}
