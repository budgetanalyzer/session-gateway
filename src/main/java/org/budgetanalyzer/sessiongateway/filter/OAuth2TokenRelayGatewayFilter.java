package org.budgetanalyzer.sessiongateway.filter;

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
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * Custom WebFilter for Spring Cloud Gateway Server that forwards OAuth2 access tokens to downstream
 * services.
 *
 * <p>This filter is necessary because the standard TokenRelay filter from Spring Cloud Gateway is
 * not compatible with Spring Cloud Gateway Server (webflux-based). It extracts the OAuth2 access
 * token from the authenticated user's session and adds it as a Bearer token in the Authorization
 * header for proxied requests.
 *
 * <p>The filter:
 *
 * <ol>
 *   <li>Retrieves the SecurityContext from the reactive context
 *   <li>Extracts the OAuth2AuthorizedClient from the session
 *   <li>Gets the OAuth2 access token
 *   <li>Adds "Authorization: Bearer {token}" header to the outgoing request
 * </ol>
 */
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2TokenRelayGatewayFilter implements WebFilter {

  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;

  public OAuth2TokenRelayGatewayFilter(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    this.authorizedClientRepository = authorizedClientRepository;
  }

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(Authentication::isAuthenticated)
        .filter(authentication -> authentication instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .flatMap(
            authenticationToken ->
                loadAuthorizedClient(authenticationToken, exchange)
                    .map(OAuth2AuthorizedClient::getAccessToken)
                    .map(this::createAuthorizationHeader)
                    .map(
                        authHeader -> {
                          ServerHttpRequest mutatedRequest =
                              exchange
                                  .getRequest()
                                  .mutate()
                                  .header(HttpHeaders.AUTHORIZATION, authHeader)
                                  .build();
                          return exchange.mutate().request(mutatedRequest).build();
                        }))
        .defaultIfEmpty(exchange)
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
}
