package org.budgetanalyzer.sessiongateway.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import org.budgetanalyzer.core.logging.SafeLogger;

@Component
public class EnvironmentDebugger {

  private static final Logger log = LoggerFactory.getLogger(EnvironmentDebugger.class);
  private final Environment env;

  public EnvironmentDebugger(Environment env) {
    this.env = env;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void debugEnvironment() {
    Map<String, String> auth0Config = new LinkedHashMap<>();
    auth0Config.put("AUTH0_CLIENT_ID", getPropertyValue("AUTH0_CLIENT_ID"));
    auth0Config.put("AUTH0_CLIENT_SECRET", getPropertyValue("AUTH0_CLIENT_SECRET"));
    auth0Config.put("AUTH0_ISSUER_URI", getPropertyValue("AUTH0_ISSUER_URI"));
    auth0Config.put("AUTH0_AUDIENCE", getPropertyValue("AUTH0_AUDIENCE"));
    auth0Config.put("AUTH0_LOGOUT_RETURN_TO", getPropertyValue("AUTH0_LOGOUT_RETURN_TO"));

    log.debug("Auth0 Configuration: {}", SafeLogger.toJson(auth0Config));
  }

  private String getPropertyValue(String key) {
    String value = env.getProperty(key);
    if (value == null) {
      return "NOT SET";
    }

    if (value.startsWith("placeholder")) {
      return value + " (PLACEHOLDER - NOT LOADED!)";
    }

    return value;
  }
}
