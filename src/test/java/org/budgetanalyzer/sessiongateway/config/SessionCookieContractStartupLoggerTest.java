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

  private static final String LOG_MESSAGE =
      "Public session cookie contract configured: name=__Host-BA_SESSION";

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
  void shouldLogCookieName() {
    var sessionProperties =
        new SessionProperties(
            "session:",
            900,
            28800,
            600,
            new SessionProperties.CookieProperties("__Host-BA_SESSION", true, "Strict"));

    new SessionCookieContractStartupLogger(sessionProperties).logPublicSessionCookieContract();

    assertThat(listAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains(LOG_MESSAGE);
  }
}
