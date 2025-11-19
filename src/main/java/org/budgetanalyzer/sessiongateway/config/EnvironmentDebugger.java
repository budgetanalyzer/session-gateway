package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

@Component
public class EnvironmentDebugger {

  private static final Logger log = LoggerFactory.getLogger(EnvironmentDebugger.class);
  private final Environment env;

  public EnvironmentDebugger(Environment env) {
    this.env = env;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void debugEnvironment() {
    // TODO: Use SafeLogger
    log.debug("=== ENVIRONMENT VARIABLES DEBUG ===");
    log.debug("AUTH0_CLIENT_ID: {}", maskValue(env.getProperty("AUTH0_CLIENT_ID")));
    log.debug("AUTH0_CLIENT_SECRET: {}", maskValue(env.getProperty("AUTH0_CLIENT_SECRET")));
    log.debug("AUTH0_ISSUER_URI: {}", env.getProperty("AUTH0_ISSUER_URI"));
    log.debug("AUTH0_AUDIENCE: {}", env.getProperty("AUTH0_AUDIENCE"));
    log.debug("AUTH0_LOGOUT_RETURN_TO: {}", env.getProperty("AUTH0_LOGOUT_RETURN_TO"));
    log.debug("===================================");
  }

  private String maskValue(String value) {
    if (value == null) {
      return "NOT SET";
    }

    if (value.startsWith("placeholder")) {
      return value + " (PLACEHOLDER - NOT LOADED!)";
    }

    return value.substring(0, Math.min(10, value.length())) + "...";
  }
}
