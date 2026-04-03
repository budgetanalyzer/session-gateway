package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
class OAuth2CallbackIdpClientLoggingFilterTest {

  private static final String SECRET_AUTH_CODE = "secret-auth-code";
  private static final String SECRET_STATE = "secret-state";
  private static final String SECRET_TOKEN = "secret-token";

  private Logger logger;
  private ListAppender<ILoggingEvent> listAppender;

  @BeforeEach
  void setUp() {
    logger = (Logger) LoggerFactory.getLogger(OAuth2CallbackIdpClientLoggingFilter.class);
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
  void filterLogsUpstream5xxWithoutLeakingSensitiveQueryValues() {
    var oauth2CallbackIdpClientLoggingFilter = new OAuth2CallbackIdpClientLoggingFilter();
    var clientRequest =
        ClientRequest.create(
                HttpMethod.POST,
                URI.create(
                    "https://tenant.example.com/idp/oauth/token?code="
                        + SECRET_AUTH_CODE
                        + "&state="
                        + SECRET_STATE))
            .build();

    StepVerifier.create(
            oauth2CallbackIdpClientLoggingFilter.filter(
                clientRequest,
                request ->
                    Mono.just(ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR).build())))
        .expectNextCount(1)
        .verifyComplete();

    assertThat(listAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains(
            "OAuth2 callback IdP response classification=upstream_5xx"
                + " method=POST path=/idp/oauth/token status=500")
        .allMatch(message -> !message.contains(SECRET_AUTH_CODE))
        .allMatch(message -> !message.contains(SECRET_STATE))
        .allMatch(message -> !message.contains(SECRET_TOKEN));
  }

  @Test
  void filterLogsPoolAcquireTimeoutWithoutLeakingSensitiveThrowableMessage() {
    var oauth2CallbackIdpClientLoggingFilter = new OAuth2CallbackIdpClientLoggingFilter();
    var clientRequest =
        ClientRequest.create(
                HttpMethod.POST,
                URI.create(
                    "https://tenant.example.com/idp/oauth/token?code="
                        + SECRET_AUTH_CODE
                        + "&state="
                        + SECRET_STATE))
            .build();

    StepVerifier.create(
            oauth2CallbackIdpClientLoggingFilter.filter(
                clientRequest,
                request ->
                    Mono.error(
                        new PoolAcquireTimeoutException(
                            "token=" + SECRET_TOKEN + " state=" + SECRET_STATE))))
        .expectErrorSatisfies(
            throwable -> {
              assertThat(throwable).isInstanceOf(OAuth2CallbackIdpTransportException.class);
              var oauth2CallbackIdpTransportException =
                  (OAuth2CallbackIdpTransportException) throwable;
              assertThat(oauth2CallbackIdpTransportException.callbackFailureClassification())
                  .isEqualTo(OAuth2CallbackFailureClassification.POOL_ACQUIRE_TIMEOUT);
              assertThat(oauth2CallbackIdpTransportException)
                  .hasCauseInstanceOf(PoolAcquireTimeoutException.class);
            })
        .verify();

    assertThat(listAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .contains(
            "OAuth2 callback IdP request failed classification=pool_acquire_timeout"
                + " method=POST path=/idp/oauth/token"
                + " exceptionType=PoolAcquireTimeoutException")
        .allMatch(message -> !message.contains(SECRET_AUTH_CODE))
        .allMatch(message -> !message.contains(SECRET_STATE))
        .allMatch(message -> !message.contains(SECRET_TOKEN));
  }

  private static final class PoolAcquireTimeoutException extends RuntimeException {

    private PoolAcquireTimeoutException(String message) {
      super(message);
    }
  }
}
