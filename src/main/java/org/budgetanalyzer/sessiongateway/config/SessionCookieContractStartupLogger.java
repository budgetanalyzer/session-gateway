package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

/** Logs the configured public session cookie contract after startup completes. */
@Component
public class SessionCookieContractStartupLogger {

  private static final Logger log =
      LoggerFactory.getLogger(SessionCookieContractStartupLogger.class);

  private final SessionProperties sessionProperties;

  public SessionCookieContractStartupLogger(SessionProperties sessionProperties) {
    this.sessionProperties = sessionProperties;
  }

  /** Logs the configured public cookie name. */
  @EventListener(ApplicationReadyEvent.class)
  public void logPublicSessionCookieContract() {
    log.info(
        "Public session cookie contract configured: name={}", sessionProperties.cookie().name());
  }
}
