package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

class SessionCookieContractStartupLoggerTest {

  private static final String HOST_ONLY_LOG_MESSAGE =
      "Public session cookie contract configured: name=BA_SESSION, domainOverrideEnabled=false";
  private static final String DOMAIN_OVERRIDE_LOG_MESSAGE =
      "Public session cookie contract configured: name=BA_SESSION, domainOverrideEnabled=true";

  private Logger logger;
  private ListAppender<ILoggingEvent> listAppender;

  @BeforeEach
  void setUp() {
    logger = (Logger) LoggerFactory.getLogger(SessionCookieContractStartupLogger.class);
    listAppender = new ListAppender<>();
    listAppender.start();
    logger.addAppender(listAppender);
  }

  @AfterEach
  void tearDown() {
    logger.detachAppender(listAppender);
    listAppender.stop();
  }

  @Test
  void logPublicSessionCookieContract_logsCookieNameAndDisabledDomainOverride() {
    var sessionProperties =
        new SessionProperties(
            "session:",
            900,
            600,
            new SessionProperties.CookieProperties("BA_SESSION", null, true, "Strict"));

    new SessionCookieContractStartupLogger(sessionProperties).logPublicSessionCookieContract();

    assertThat(listAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains(HOST_ONLY_LOG_MESSAGE);
  }

  @Test
  void logPublicSessionCookieContract_logsCookieNameAndEnabledDomainOverride() {
    var sessionProperties =
        new SessionProperties(
            "session:",
            900,
            600,
            new SessionProperties.CookieProperties(
                "BA_SESSION", "budgetanalyzer.localhost", true, "Strict"));

    new SessionCookieContractStartupLogger(sessionProperties).logPublicSessionCookieContract();

    assertThat(listAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains(DOMAIN_OVERRIDE_LOG_MESSAGE);
  }
}
