package org.budgetanalyzer.sessiongateway.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Global filter for Spring Cloud Gateway Server that forwards OAuth2 access tokens to downstream
 * services.
 *
 * <p>This filter replaces the standard TokenRelay filter which is not compatible with Spring Cloud
 * Gateway Server (webflux-based). It extracts the OAuth2 access token from the authenticated user's
 * session and adds it as a Bearer token in the Authorization header for proxied requests.
 *
 * <p>The filter:
 *
 * <ol>
 *   <li>Retrieves the SecurityContext from the reactive context
 *   <li>Extracts the OAuth2AuthorizedClient from the session
 *   <li>Gets the OAuth2 access token
 *   <li>Adds "Authorization: Bearer {token}" header to the outgoing request
 * </ol>
 *
 * <p>This filter has a high order (similar to Netty Write filters) to ensure it executes after
 * security filters but before the routing filter.
 */
public class OAuth2TokenRelayGlobalFilter implements GlobalFilter, Ordered {

  private static final Logger log = LoggerFactory.getLogger(OAuth2TokenRelayGlobalFilter.class);
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

  public OAuth2TokenRelayGlobalFilter(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    this.authorizedClientRepository = authorizedClientRepository;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    String path = exchange.getRequest().getPath().toString();
    log.debug("OAuth2TokenRelayGlobalFilter executing for path: {}", path);

    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .doOnNext(auth -> log.debug("Authentication found: {}, isAuthenticated: {}",
            auth.getClass().getSimpleName(), auth.isAuthenticated()))
        .filter(Authentication::isAuthenticated)
        .filter(authentication -> authentication instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .doOnNext(token -> log.debug("OAuth2AuthenticationToken found for client: {}",
            token.getAuthorizedClientRegistrationId()))
        .flatMap(
            authenticationToken ->
                loadAuthorizedClient(authenticationToken, exchange)
                    .doOnNext(client -> log.info("OAuth2AuthorizedClient loaded, adding Authorization header for path: {}", path))
                    .map(OAuth2AuthorizedClient::getAccessToken)
                    .map(this::createAuthorizationHeader)
                    .doOnNext(authHeader -> log.info("Authorization header created: Bearer [token length={}]",
                        authHeader.substring(7).length()))
                    .map(
                        authHeader -> {
                          ServerHttpRequest mutatedRequest =
                              exchange
                                  .getRequest()
                                  .mutate()
                                  .header(HttpHeaders.AUTHORIZATION, authHeader)
                                  .build();
                          log.info("Authorization header added to request for path: {}", path);
                          return exchange.mutate().request(mutatedRequest).build();
                        }))
        .doOnError(error -> log.error("Error in OAuth2TokenRelayGlobalFilter: {}", error.getMessage(), error))
        .defaultIfEmpty(exchange)
        .doOnSuccess(v -> log.debug("OAuth2TokenRelayGlobalFilter completed for path: {}", path))
        .flatMap(chain::filter);
  }

  private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(
      OAuth2AuthenticationToken authenticationToken, ServerWebExchange exchange) {
    String clientRegistrationId = authenticationToken.getAuthorizedClientRegistrationId();
    return authorizedClientRepository.loadAuthorizedClient(
        clientRegistrationId, authenticationToken, exchange);
  }

  private String createAuthorizationHeader(OAuth2AccessToken accessToken) {
    return "Bearer " + accessToken.getTokenValue();
  }

  @Override
  public int getOrder() {
    // Order should be high enough to execute after security filters
    // but before NettyRoutingFilter (which is at Integer.MAX_VALUE)
    return Ordered.HIGHEST_PRECEDENCE + 100;
  }
}
