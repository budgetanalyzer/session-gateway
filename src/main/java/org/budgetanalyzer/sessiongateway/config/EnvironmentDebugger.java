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

/** Logs IDP configuration at startup for diagnostics. */
@Component
public class EnvironmentDebugger {

  private static final Logger log = LoggerFactory.getLogger(EnvironmentDebugger.class);
  private final Environment environment;

  public EnvironmentDebugger(Environment environment) {
    this.environment = environment;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void debugEnvironment() {
    Map<String, String> idpConfig = new LinkedHashMap<>();
    idpConfig.put("AUTH0_CLIENT_ID", getPropertyValue("AUTH0_CLIENT_ID"));
    idpConfig.put("AUTH0_CLIENT_SECRET", SafeLogger.mask(getPropertyValue("AUTH0_CLIENT_SECRET")));
    idpConfig.put("AUTH0_ISSUER_URI", getPropertyValue("AUTH0_ISSUER_URI"));
    idpConfig.put("IDP_AUDIENCE", getPropertyValue("IDP_AUDIENCE"));
    idpConfig.put("IDP_LOGOUT_RETURN_TO", getPropertyValue("IDP_LOGOUT_RETURN_TO"));

    log.debug("IDP Configuration: {}", SafeLogger.toJson(idpConfig));
  }

  private String getPropertyValue(String key) {
    String value = environment.getProperty(key);
    if (value == null) {
      return "NOT SET";
    }

    if (value.startsWith("placeholder")) {
      return value + " (PLACEHOLDER - NOT LOADED!)";
    }

    return value;
  }
}
