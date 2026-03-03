package org.budgetanalyzer.sessiongateway.config;

import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import org.budgetanalyzer.sessiongateway.filter.OAuth2TokenRelayGlobalFilter;
import org.budgetanalyzer.sessiongateway.service.InternalJwtService;

/**
 * Configuration for OAuth2 token relay functionality in Spring Cloud Gateway Server.
 *
 * <p>Registers a custom GlobalFilter that relays internal JWTs (minted by the session-gateway) to
 * downstream services.
 */
@Configuration
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2TokenRelayFilterConfig {

  /**
   * Creates a GlobalFilter that relays internal JWTs to downstream services.
   *
   * @param internalJwtService the service for minting and validating internal JWTs
   * @return the OAuth2 token relay global filter
   */
  @Bean
  public GlobalFilter oauth2TokenRelayGlobalFilter(InternalJwtService internalJwtService) {
    return new OAuth2TokenRelayGlobalFilter(internalJwtService);
  }
}
