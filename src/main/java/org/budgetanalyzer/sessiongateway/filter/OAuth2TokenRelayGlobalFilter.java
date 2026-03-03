package org.budgetanalyzer.sessiongateway.filter;

import java.util.List;

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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.service.InternalJwtService;

/**
 * Global filter that relays the session-gateway's internal JWT to downstream services.
 *
 * <p>Reads a cached internal JWT from the session. If the cached token is missing or near expiry,
 * re-mints it from the permission data stored in the session.
 */
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2TokenRelayGlobalFilter implements GlobalFilter, Ordered {

  private static final Logger log = LoggerFactory.getLogger(OAuth2TokenRelayGlobalFilter.class);
  private final InternalJwtService internalJwtService;

  /**
   * Creates a new OAuth2TokenRelayGlobalFilter.
   *
   * @param internalJwtService the service for minting internal JWTs
   */
  public OAuth2TokenRelayGlobalFilter(InternalJwtService internalJwtService) {
    this.internalJwtService = internalJwtService;
  }

  /**
   * Adds an internal JWT Authorization header to downstream requests for authenticated users.
   *
   * <p>Uses the cached JWT from the session when available, otherwise re-mints from session
   * permission data.
   *
   * @param exchange the current server exchange
   * @param chain the gateway filter chain
   * @return completion signal
   */
  @Override
  public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    var path = exchange.getRequest().getPath().toString();
    log.debug("OAuth2TokenRelayGlobalFilter executing for path: {}", path);

    return ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .filter(Authentication::isAuthenticated)
        .filter(authentication -> authentication instanceof OAuth2AuthenticationToken)
        .cast(OAuth2AuthenticationToken.class)
        .flatMap(
            authToken ->
                exchange
                    .getSession()
                    .flatMap(
                        session -> {
                          String cachedJwt =
                              session.getAttribute(InternalJwtService.SESSION_INTERNAL_JWT);

                          if (!internalJwtService.needsRemint(cachedJwt)) {
                            log.debug("Using cached internal JWT for path: {}", path);
                            return Mono.just(cachedJwt);
                          }

                          // Re-mint from session attributes
                          String userId = session.getAttribute(InternalJwtService.SESSION_USER_ID);
                          List<String> roles =
                              session.getAttribute(InternalJwtService.SESSION_ROLES);
                          List<String> permissions =
                              session.getAttribute(InternalJwtService.SESSION_PERMISSIONS);

                          if (userId == null || roles == null || permissions == null) {
                            log.warn(
                                "Missing permission data in session for path: {}, "
                                    + "no Authorization header will be added",
                                path);
                            return Mono.empty();
                          }

                          String idpSub = authToken.getName();
                          String newJwt =
                              internalJwtService.mintToken(idpSub, userId, roles, permissions);
                          session
                              .getAttributes()
                              .put(InternalJwtService.SESSION_INTERNAL_JWT, newJwt);
                          log.info("Minted new internal JWT for path: {}", path);
                          return Mono.just(newJwt);
                        })
                    .map(
                        jwt -> {
                          ServerHttpRequest mutatedRequest =
                              exchange
                                  .getRequest()
                                  .mutate()
                                  .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                                  .build();
                          log.info("Authorization header added to request for path: {}", path);
                          return exchange.mutate().request(mutatedRequest).build();
                        }))
        .defaultIfEmpty(exchange)
        .flatMap(chain::filter);
  }

  /**
   * Returns the filter order.
   *
   * <p>Runs early in the filter chain to ensure downstream services receive the internal JWT.
   *
   * @return the filter order
   */
  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 100;
  }
}
