package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.ConnectException;
import java.net.URI;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import io.netty.handler.timeout.ReadTimeoutException;

class OAuth2CallbackFailureClassifierTest {

  @Test
  void shouldReturnConnectFailureForConnectException() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(
            new WebClientRequestException(
                new ConnectException("Connection refused"),
                HttpMethod.POST,
                URI.create("https://tenant.example.com/idp/oauth/token"),
                HttpHeaders.EMPTY));

    assertThat(callbackFailureClassification)
        .contains(OAuth2CallbackFailureClassification.CONNECT_FAILURE);
  }

  @Test
  void shouldReturnResponseTimeoutForReadTimeout() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(ReadTimeoutException.INSTANCE);

    assertThat(callbackFailureClassification)
        .contains(OAuth2CallbackFailureClassification.RESPONSE_TIMEOUT);
  }

  @Test
  void shouldReturnPoolAcquireTimeoutForPoolAcquireTimeoutExceptionName() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(
            new PoolAcquireTimeoutException("pending acquire timed out"));

    assertThat(callbackFailureClassification)
        .contains(OAuth2CallbackFailureClassification.POOL_ACQUIRE_TIMEOUT);
  }

  @Test
  void shouldReturnEmptyForNonTransportFailure() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(
            new IllegalStateException("not a transport failure"));

    assertThat(callbackFailureClassification).isEmpty();
  }

  @Test
  void shouldReturnUpstream5xxForServerError() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyResponseStatus(
            org.springframework.http.HttpStatus.BAD_GATEWAY);

    assertThat(callbackFailureClassification)
        .isEqualTo(OAuth2CallbackFailureClassification.UPSTREAM_5XX);
  }

  @Test
  void shouldPreferPoolAcquireClassificationOverGenericTimeout() {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(
            new PoolAcquireTimeoutException("pool timeout", new TimeoutException("generic")));

    assertThat(callbackFailureClassification)
        .contains(OAuth2CallbackFailureClassification.POOL_ACQUIRE_TIMEOUT);
  }

  private static final class PoolAcquireTimeoutException extends RuntimeException {

    private PoolAcquireTimeoutException(String message) {
      super(message);
    }

    private PoolAcquireTimeoutException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
