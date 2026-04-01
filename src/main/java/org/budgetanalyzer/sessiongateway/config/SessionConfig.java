package org.budgetanalyzer.sessiongateway.config;

import java.time.Clock;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Session management configuration. */
@Configuration
@EnableConfigurationProperties(SessionProperties.class)
public class SessionConfig {

  /**
   * Provides the system UTC clock for token timestamp operations.
   *
   * @return the system UTC clock
   */
  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }
}
