package org.budgetanalyzer.sessiongateway.controller;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
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
 *   <li>Redirects to Auth0 logout (with returnTo parameter)
 * </ul>
 */
@RestController
public class LogoutController {

  private static final Logger logger = LoggerFactory.getLogger(LogoutController.class);

  @Value("${spring.security.oauth2.client.provider.auth0.issuer-uri:}")
  private String auth0IssuerUri;

  @Value("${spring.security.oauth2.client.registration.auth0.client-id:}")
  private String clientId;

  @Value("${auth0.logout.return-to:http://localhost:8080}")
  private String returnToUrl;

  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

  public LogoutController(ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    this.authorizedClientRepository = authorizedClientRepository;
  }

  /**
   * Logout endpoint that invalidates the session and redirects to Auth0 logout.
   *
   * <p>Steps:
   *
   * <ol>
   *   <li>Remove OAuth2 authorized client (clears tokens from session)
   *   <li>Invalidate the session (clears Redis session)
   *   <li>Clear session cookie
   *   <li>Redirect to Auth0 logout (which redirects back to returnTo URL)
   * </ol>
   *
   * @param exchange the server web exchange
   * @param authentication the current authentication
   * @return redirect to Auth0 logout
   */
  @PostMapping("/logout")
  public Mono<Void> logout(ServerWebExchange exchange, Authentication authentication) {
    logger.info("Processing logout request for user: {}", authentication.getName());

    return removeAuthorizedClient(exchange, authentication)
        .then(invalidateSession(exchange))
        .then(redirectToAuth0Logout(exchange))
        .doOnSuccess(v -> logger.info("Successfully logged out user: {}", authentication.getName()))
        .doOnError(error -> logger.error("Error during logout", error));
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

      logger.debug("Removing authorized client: {}", registrationId);

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
              logger.debug("Invalidating session: {}", session.getId());
              return session.invalidate();
            });
  }

  /**
   * Redirects to Auth0 logout endpoint.
   *
   * <p>Auth0 logout URL format: {issuer-uri}/v2/logout?returnTo={url}&client_id={client-id}
   *
   * @param exchange the server web exchange
   * @return completion signal
   */
  private Mono<Void> redirectToAuth0Logout(ServerWebExchange exchange) {
    var response = exchange.getResponse();

    // Build Auth0 logout URL
    var auth0LogoutUrl =
        String.format(
            "%s/v2/logout?returnTo=%s&client_id=%s", auth0IssuerUri, returnToUrl, clientId);

    logger.debug("Redirecting to Auth0 logout: {}", auth0LogoutUrl);

    response.setStatusCode(HttpStatus.FOUND);
    response.getHeaders().setLocation(URI.create(auth0LogoutUrl));

    return response.setComplete();
  }
}
