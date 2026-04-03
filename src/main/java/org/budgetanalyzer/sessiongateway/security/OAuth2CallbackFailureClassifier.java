package org.budgetanalyzer.sessiongateway.security;

import java.net.ConnectException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.UnresolvedAddressException;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeoutException;

import javax.net.ssl.SSLException;

import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import io.netty.channel.ConnectTimeoutException;
import io.netty.handler.timeout.ReadTimeoutException;
import io.netty.handler.timeout.WriteTimeoutException;
import reactor.netty.http.client.PrematureCloseException;

/** Classifies browser OAuth2 callback failures into stable diagnostic categories. */
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public final class OAuth2CallbackFailureClassifier {

  private static final Set<String> POOL_ACQUIRE_FAILURE_SIMPLE_NAMES =
      Set.of("PoolAcquireTimeoutException", "PoolAcquirePendingLimitException");

  private OAuth2CallbackFailureClassifier() {}

  /**
   * Classifies a callback transport failure when one is present in the throwable chain.
   *
   * @param throwable the callback failure
   * @return the transport classification, or empty when the failure is not transport-related
   */
  public static Optional<OAuth2CallbackFailureClassification> classifyTransportFailure(
      Throwable throwable) {
    if (throwable == null) {
      return Optional.empty();
    }

    var currentThrowable = throwable;
    var fallbackTransportFailureDetected = false;
    while (currentThrowable != null) {
      var explicitClassification = classifyExplicitTransportFailure(currentThrowable);
      if (explicitClassification.isPresent()) {
        return explicitClassification;
      }

      if (isFallbackTransportFailure(currentThrowable)) {
        fallbackTransportFailureDetected = true;
      }

      currentThrowable = currentThrowable.getCause();
    }

    if (fallbackTransportFailureDetected) {
      return Optional.of(OAuth2CallbackFailureClassification.OTHER_TRANSPORT_FAILURE);
    }

    return Optional.empty();
  }

  /**
   * Classifies an upstream IdP HTTP status seen on the browser callback path.
   *
   * @param httpStatusCode the upstream status code
   * @return the status classification
   */
  public static OAuth2CallbackFailureClassification classifyResponseStatus(
      HttpStatusCode httpStatusCode) {
    if (httpStatusCode.is4xxClientError()) {
      return OAuth2CallbackFailureClassification.UPSTREAM_4XX;
    }

    if (httpStatusCode.is5xxServerError()) {
      return OAuth2CallbackFailureClassification.UPSTREAM_5XX;
    }

    return OAuth2CallbackFailureClassification.OTHER_CALLBACK_FAILURE;
  }

  private static Optional<OAuth2CallbackFailureClassification> classifyExplicitTransportFailure(
      Throwable throwable) {
    if (POOL_ACQUIRE_FAILURE_SIMPLE_NAMES.contains(throwable.getClass().getSimpleName())) {
      return Optional.of(OAuth2CallbackFailureClassification.POOL_ACQUIRE_TIMEOUT);
    }

    if (throwable instanceof ConnectException
        || throwable instanceof ConnectTimeoutException
        || throwable instanceof UnknownHostException
        || throwable instanceof UnresolvedAddressException) {
      return Optional.of(OAuth2CallbackFailureClassification.CONNECT_FAILURE);
    }

    if (throwable instanceof ReadTimeoutException
        || throwable instanceof WriteTimeoutException
        || throwable instanceof SocketTimeoutException
        || throwable instanceof TimeoutException) {
      return Optional.of(OAuth2CallbackFailureClassification.RESPONSE_TIMEOUT);
    }

    return Optional.empty();
  }

  private static boolean isFallbackTransportFailure(Throwable throwable) {
    return throwable instanceof WebClientRequestException
        || throwable instanceof SocketException
        || throwable instanceof PrematureCloseException
        || throwable instanceof ClosedChannelException
        || throwable instanceof SSLException;
  }
}
