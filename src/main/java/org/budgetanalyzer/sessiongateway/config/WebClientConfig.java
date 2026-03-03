package org.budgetanalyzer.sessiongateway.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/** Configuration for WebClient beans used by gateway services. */
@Configuration
public class WebClientConfig {

  /**
   * Provides the WebClient for communicating with the permission-service.
   *
   * @param baseUrl the permission-service base URL
   * @return the configured WebClient
   */
  @Bean("permissionServiceWebClient")
  public WebClient permissionServiceWebClient(
      @Value("${permission-service.base-url}") String baseUrl) {
    return WebClient.builder().baseUrl(baseUrl).build();
  }
}
