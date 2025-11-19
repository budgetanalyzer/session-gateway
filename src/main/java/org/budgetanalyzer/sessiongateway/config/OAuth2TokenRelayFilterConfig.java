package org.budgetanalyzer.sessiongateway.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;

import org.budgetanalyzer.sessiongateway.filter.OAuth2TokenRelayGlobalFilter;

/**
 * Configuration for OAuth2 token relay functionality in Spring Cloud Gateway Server.
 *
 * <p>This configuration registers a custom GlobalFilter that forwards OAuth2 access tokens to
 * downstream services. This is required because the standard TokenRelay filter from Spring Cloud
 * Gateway is not compatible with Spring Cloud Gateway Server (webflux-based).
 */
@Configuration
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2TokenRelayFilterConfig {

  /**
   * Creates a GlobalFilter that forwards OAuth2 access tokens to downstream services.
   *
   * @param authorizedClientRepository the repository for loading OAuth2 authorized clients
   * @return the OAuth2 token relay global filter
   */
  @Bean
  public GlobalFilter oauth2TokenRelayGlobalFilter(
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository) {
    return new OAuth2TokenRelayGlobalFilter(authorizedClientRepository);
  }
}
