package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/** Configuration for WebClient beans used by gateway services. */
@Configuration
public class WebClientConfig {

  /**
   * Provides the WebClient for communicating with the permission-service.
   *
   * @param permissionServiceProperties validated permission-service configuration
   * @return the configured WebClient
   */
  @Bean("permissionServiceWebClient")
  public WebClient permissionServiceWebClient(
      PermissionServiceProperties permissionServiceProperties) {
    return WebClient.builder().baseUrl(permissionServiceProperties.baseUrl()).build();
  }
}
