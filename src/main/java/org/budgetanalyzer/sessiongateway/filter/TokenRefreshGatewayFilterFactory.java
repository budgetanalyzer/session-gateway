package org.budgetanalyzer.sessiongateway.filter;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.service.InternalJwtService;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;

/**
 * Gateway filter that proactively refreshes OAuth2 access tokens before they expire.
 *
 * <p>When a token is refreshed, this filter also re-fetches the user's permissions from the
 * permission-service and re-mints the internal JWT.
 */
@Component
public class TokenRefreshGatewayFilterFactory
    extends AbstractGatewayFilterFactory<TokenRefreshGatewayFilterFactory.Config> {

  private static final Logger log = LoggerFactory.getLogger(TokenRefreshGatewayFilterFactory.class);
  private static final Duration REFRESH_THRESHOLD = Duration.ofMinutes(5);

  private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  private final PermissionServiceClient permissionServiceClient;
  private final InternalJwtService internalJwtService;
  private final Clock clock;

  public TokenRefreshGatewayFilterFactory(
      ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      PermissionServiceClient permissionServiceClient,
      InternalJwtService internalJwtService,
      Clock clock) {
    super(Config.class);
    this.authorizedClientManager = authorizedClientManager;
    this.authorizedClientRepository = authorizedClientRepository;
    this.permissionServiceClient = permissionServiceClient;
    this.internalJwtService = internalJwtService;
    this.clock = clock;
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      return exchange
          .getPrincipal()
          .filter(principal -> principal instanceof OAuth2AuthenticationToken)
          .cast(OAuth2AuthenticationToken.class)
          .flatMap(
              authToken -> {
                String registrationId = authToken.getAuthorizedClientRegistrationId();

                // Load the authorized client from the session
                return authorizedClientRepository
                    .loadAuthorizedClient(registrationId, authToken, exchange)
                    .flatMap(
                        authorizedClient -> {
                          // Check if token needs refresh
                          if (needsRefresh(authorizedClient)) {
                            log.debug(
                                "Access token expiring soon, initiating refresh for user: {}",
                                authToken.getName());
                            return refreshToken(authorizedClient, authToken, exchange);
                          } else {
                            log.trace(
                                "Access token still valid for user: {}, no refresh needed",
                                authToken.getName());
                            return Mono.just(authorizedClient);
                          }
                        });
              })
          .then(chain.filter(exchange));
    };
  }

  /**
   * Checks if the access token needs to be refreshed.
   *
   * @param authorizedClient the authorized client with token info
   * @return true if token expires within 5 minutes
   */
  private boolean needsRefresh(OAuth2AuthorizedClient authorizedClient) {
    var accessToken = authorizedClient.getAccessToken();

    if (accessToken == null || accessToken.getExpiresAt() == null) {
      log.warn("Access token or expiration is null, skipping refresh check");
      return false;
    }

    var now = clock.instant();
    var expiresAt = accessToken.getExpiresAt();
    var refreshThreshold = now.plus(REFRESH_THRESHOLD);

    var needsRefresh = expiresAt.isBefore(refreshThreshold);

    if (needsRefresh) {
      var timeUntilExpiry = Duration.between(now, expiresAt);
      log.debug(
          "Token expires in {} seconds, threshold is {} seconds",
          timeUntilExpiry.getSeconds(),
          REFRESH_THRESHOLD.getSeconds());
    }

    return needsRefresh;
  }

  /**
   * Refreshes the OAuth2 access token and re-fetches permissions.
   *
   * @param authorizedClient current authorized client
   * @param authentication user authentication
   * @param exchange the current server web exchange
   * @return refreshed authorized client
   */
  private Mono<OAuth2AuthorizedClient> refreshToken(
      OAuth2AuthorizedClient authorizedClient,
      Authentication authentication,
      ServerWebExchange exchange) {

    OAuth2AuthorizeRequest authorizeRequest =
        OAuth2AuthorizeRequest.withAuthorizedClient(authorizedClient)
            .principal(authentication)
            .build();

    return authorizedClientManager
        .authorize(authorizeRequest)
        .flatMap(
            refreshedClient -> {
              if (refreshedClient != null) {
                log.info(
                    "Successfully refreshed access token for user: {}", authentication.getName());

                // Save the refreshed client to the session, then refresh permissions
                return authorizedClientRepository
                    .saveAuthorizedClient(refreshedClient, authentication, exchange)
                    .then(refreshPermissionsAndRemint(exchange, authentication))
                    .thenReturn(refreshedClient);
              } else {
                log.warn("Token refresh returned null for user: {}", authentication.getName());
                return Mono.just(authorizedClient);
              }
            })
        .doOnError(
            error -> {
              log.error(
                  "Failed to refresh access token for user: {}", authentication.getName(), error);
            })
        .onErrorResume(
            error -> {
              // Return original client on error to avoid breaking the request
              log.warn("Falling back to existing token after refresh failure");
              return Mono.just(authorizedClient);
            });
  }

  /**
   * Re-fetches permissions from the permission-service and re-mints the internal JWT.
   *
   * <p>Errors are swallowed and logged. Unlike login, refresh failure should not break the active
   * request. Cached permissions and JWT remain valid.
   */
  private Mono<Void> refreshPermissionsAndRemint(
      ServerWebExchange exchange, Authentication authentication) {
    if (!(authentication instanceof OAuth2AuthenticationToken oauthToken)) {
      return Mono.empty();
    }

    String idpSub = oauthToken.getName();

    return permissionServiceClient
        .fetchPermissions(idpSub)
        .flatMap(
            response ->
                exchange
                    .getSession()
                    .doOnNext(
                        session -> {
                          session
                              .getAttributes()
                              .put(InternalJwtService.SESSION_USER_ID, response.userId());
                          session
                              .getAttributes()
                              .put(
                                  InternalJwtService.SESSION_ROLES,
                                  new ArrayList<>(response.roles()));
                          session
                              .getAttributes()
                              .put(
                                  InternalJwtService.SESSION_PERMISSIONS,
                                  new ArrayList<>(response.permissions()));

                          // Mint new internal JWT
                          String newJwt =
                              internalJwtService.mintToken(
                                  idpSub,
                                  response.userId(),
                                  response.roles(),
                                  response.permissions());
                          session
                              .getAttributes()
                              .put(InternalJwtService.SESSION_INTERNAL_JWT, newJwt);

                          log.info(
                              "Refreshed permissions and re-minted internal JWT for user: {}",
                              authentication.getName());
                        })
                    .then())
        .onErrorResume(
            error -> {
              log.warn(
                  "Failed to refresh permissions for user: {}, "
                      + "cached permissions and JWT remain valid",
                  authentication.getName(),
                  error);
              return Mono.empty();
            });
  }

  /** Configuration class for the filter (currently no config needed). */
  public static class Config {
    // Configuration properties can be added here if needed
  }
}
