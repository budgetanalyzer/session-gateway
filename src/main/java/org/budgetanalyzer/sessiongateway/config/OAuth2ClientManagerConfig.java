package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultReactiveOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;

/**
 * Configuration for OAuth2 client manager to support token refresh.
 *
 * <p>Phase 2 Task 2.4: Proactive Token Refresh
 *
 * <p>Configures the OAuth2 authorized client manager with refresh token support. This enables
 * automatic token refresh when tokens are nearing expiration.
 */
@Configuration
public class OAuth2ClientManagerConfig {

  /**
   * Creates an OAuth2 authorized client manager with refresh token support.
   *
   * <p>The manager is used by the TokenRefreshGatewayFilterFactory to automatically refresh tokens
   * when needed.
   *
   * @param clientRegistrationRepository repository of OAuth2 client registrations
   * @param authorizedClientRepository repository for storing authorized clients
   * @return configured OAuth2 authorized client manager
   */
  @Bean
  public ReactiveOAuth2AuthorizedClientManager authorizedClientManager(
      ReactiveClientRegistrationRepository clientRegistrationRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {

    // Configure authorized client provider with refresh token support
    ReactiveOAuth2AuthorizedClientProvider authorizedClientProvider =
        ReactiveOAuth2AuthorizedClientProviderBuilder.builder()
            .authorizationCode() // Support authorization code flow
            .refreshToken() // Enable refresh token support
            .build();

    // Create the manager
    DefaultReactiveOAuth2AuthorizedClientManager authorizedClientManager =
        new DefaultReactiveOAuth2AuthorizedClientManager(
            clientRegistrationRepository, authorizedClientRepository);

    authorizedClientManager.setAuthorizedClientProvider(authorizedClientProvider);

    return authorizedClientManager;
  }
}
