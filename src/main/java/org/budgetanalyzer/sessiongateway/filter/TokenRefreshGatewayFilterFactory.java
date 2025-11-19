package org.budgetanalyzer.sessiongateway.filter;

import java.time.Clock;
import java.time.Duration;

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

/**
 * Gateway filter that proactively refreshes OAuth2 access tokens before they expire.
 *
 * <p>Phase 2 Task 2.4: Proactive Token Refresh
 *
 * <ul>
 *   <li>Checks if access token expires within 5 minutes
 *   <li>Automatically refreshes using refresh token if needed
 *   <li>Updates session with new tokens
 *   <li>Handles refresh token rotation (Auth0)
 *   <li>Runs before TokenRelay filter to ensure fresh token
 * </ul>
 */
@Component
public class TokenRefreshGatewayFilterFactory
    extends AbstractGatewayFilterFactory<TokenRefreshGatewayFilterFactory.Config> {

  private static final Logger logger =
      LoggerFactory.getLogger(TokenRefreshGatewayFilterFactory.class);
  private static final Duration REFRESH_THRESHOLD = Duration.ofMinutes(5);

  private final ReactiveOAuth2AuthorizedClientManager authorizedClientManager;
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  private final Clock clock;

  public TokenRefreshGatewayFilterFactory(
      ReactiveOAuth2AuthorizedClientManager authorizedClientManager,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    super(Config.class);
    this.authorizedClientManager = authorizedClientManager;
    this.authorizedClientRepository = authorizedClientRepository;
    this.clock = Clock.systemUTC();
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
                            logger.debug(
                                "Access token expiring soon, initiating refresh for user: {}",
                                authToken.getName());
                            return refreshToken(authorizedClient, authToken, exchange);
                          } else {
                            logger.trace(
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
      logger.warn("Access token or expiration is null, skipping refresh check");
      return false;
    }

    var now = clock.instant();
    var expiresAt = accessToken.getExpiresAt();
    var refreshThreshold = now.plus(REFRESH_THRESHOLD);

    var needsRefresh = expiresAt.isBefore(refreshThreshold);

    if (needsRefresh) {
      var timeUntilExpiry = Duration.between(now, expiresAt);
      logger.debug(
          "Token expires in {} seconds, threshold is {} seconds",
          timeUntilExpiry.getSeconds(),
          REFRESH_THRESHOLD.getSeconds());
    }

    return needsRefresh;
  }

  /**
   * Refreshes the OAuth2 access token using the refresh token.
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
                logger.info(
                    "Successfully refreshed access token for user: {}", authentication.getName());

                // Save the refreshed client to the session
                return authorizedClientRepository
                    .saveAuthorizedClient(refreshedClient, authentication, exchange)
                    .thenReturn(refreshedClient);
              } else {
                logger.warn("Token refresh returned null for user: {}", authentication.getName());
                return Mono.just(authorizedClient);
              }
            })
        .doOnError(
            error -> {
              logger.error(
                  "Failed to refresh access token for user: {}", authentication.getName(), error);
            })
        .onErrorResume(
            error -> {
              // Return original client on error to avoid breaking the request
              // The expired token will be caught by downstream services
              logger.warn("Falling back to existing token after refresh failure");
              return Mono.just(authorizedClient);
            });
  }

  /** Configuration class for the filter (currently no config needed). */
  public static class Config {
    // Configuration properties can be added here if needed
  }
}
