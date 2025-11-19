package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import reactor.core.publisher.Mono;

/**
 * Redis-backed implementation of {@link ServerRequestCache} that persists original request URIs
 * across the OAuth2 authentication flow.
 *
 * <p>This implementation addresses the Spring Security WebFlux issue where {@code
 * SPRING_SECURITY_SAVED_REQUEST} is not properly saved when using OAuth2 login (GitHub issue
 * #8967). By storing the request URI in the Redis-backed WebSession, we can retrieve it after
 * successful authentication and redirect the user to their originally requested page.
 *
 * <p><strong>Flow:</strong>
 *
 * <ol>
 *   <li>User requests protected resource: {@code /dashboard}
 *   <li>{@link #saveRequest} stores {@code /dashboard} in Redis session
 *   <li>User redirected to OAuth2 authorization (Auth0)
 *   <li>After successful auth, {@link #getRedirectUri} retrieves {@code /dashboard}
 *   <li>User redirected to original destination
 * </ol>
 *
 * <p><strong>Integration:</strong> Works with existing Redis session configuration. Uses Spring
 * Session's {@link WebSession} for storage, which is automatically persisted to Redis.
 *
 * @see <a href="https://github.com/spring-projects/spring-security/issues/8967">Spring Security
 *     Issue #8967</a>
 */
public class RedisServerRequestCache implements ServerRequestCache {

  private static final Logger log = LoggerFactory.getLogger(RedisServerRequestCache.class);

  /** Session attribute key for storing the saved request URI. */
  private static final String SAVED_REQUEST_KEY = "SPRING_SECURITY_SAVED_REQUEST";

  /**
   * Saves the current request URI to the session for later retrieval.
   *
   * <p>This method stores the full request URI (path + query parameters) in the Redis-backed
   * session. The URI will be available after OAuth2 authentication completes.
   *
   * @param exchange the current server web exchange
   * @return a {@code Mono<Void>} that completes when the request is saved
   */
  @Override
  public Mono<Void> saveRequest(ServerWebExchange exchange) {
    return exchange
        .getSession()
        .doOnNext(
            session -> {
              URI requestUri = exchange.getRequest().getURI();
              String path = requestUri.getPath();
              String query = requestUri.getQuery();

              // Build full URI (path + query parameters)
              String fullUri = query != null && !query.isEmpty() ? path + "?" + query : path;

              log.info("Saving request URI to session: {}", fullUri);
              session.getAttributes().put(SAVED_REQUEST_KEY, fullUri);
            })
        .then();
  }

  /**
   * Retrieves the saved request URI from the session.
   *
   * <p>This method is called after successful OAuth2 authentication to determine where to redirect
   * the user. If no saved request exists, it returns {@code Mono.empty()}.
   *
   * @param exchange the current server web exchange
   * @return a {@code Mono<URI>} containing the saved URI, or {@code Mono.empty()} if none exists
   */
  @Override
  public Mono<URI> getRedirectUri(ServerWebExchange exchange) {
    return exchange
        .getSession()
        .mapNotNull(
            session -> {
              String savedUri = session.getAttribute(SAVED_REQUEST_KEY);
              if (savedUri != null) {
                log.info("Retrieved saved request URI from session: {}", savedUri);
                return URI.create(savedUri);
              } else {
                log.debug("No saved request URI found in session");
                return null;
              }
            });
  }

  /**
   * Removes the saved request from the session.
   *
   * <p>This method is called after the saved request has been used to prevent stale redirects on
   * subsequent logins.
   *
   * <p><strong>Note:</strong> Spring Security WebFlux does not use the returned {@code
   * ServerHttpRequest}. This implementation returns {@code Mono.empty()} and focuses on clearing
   * the session attribute.
   *
   * @param exchange the current server web exchange
   * @return {@code Mono.empty()} as WebFlux does not use the returned request
   */
  @Override
  public Mono<org.springframework.http.server.reactive.ServerHttpRequest> removeMatchingRequest(
      ServerWebExchange exchange) {
    return exchange
        .getSession()
        .doOnNext(
            session -> {
              String savedUri = session.getAttribute(SAVED_REQUEST_KEY);
              if (savedUri != null) {
                log.debug("Clearing saved request URI from session: {}", savedUri);
                session.getAttributes().remove(SAVED_REQUEST_KEY);
              }
            })
        .then(Mono.empty());
  }
}
