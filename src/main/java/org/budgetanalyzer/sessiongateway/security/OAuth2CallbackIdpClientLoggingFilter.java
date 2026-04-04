package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;

import reactor.core.publisher.Mono;

/** Logs sanitized diagnostics for dedicated IdP HTTP traffic used by the OAuth2 callback path. */
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public final class OAuth2CallbackIdpClientLoggingFilter implements ExchangeFilterFunction {

  private static final Logger log =
      LoggerFactory.getLogger(OAuth2CallbackIdpClientLoggingFilter.class);

  @Override
  public Mono<ClientResponse> filter(
      ClientRequest clientRequest, ExchangeFunction exchangeFunction) {
    return exchangeFunction
        .exchange(clientRequest)
        .doOnNext(clientResponse -> logUpstreamError(clientRequest, clientResponse.statusCode()))
        .doOnError(throwable -> logTransportFailure(clientRequest, throwable))
        .onErrorMap(this::markDedicatedIdpTransportFailure);
  }

  private void logUpstreamError(ClientRequest clientRequest, HttpStatusCode httpStatusCode) {
    if (!httpStatusCode.is4xxClientError() && !httpStatusCode.is5xxServerError()) {
      return;
    }

    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyResponseStatus(httpStatusCode);
    log.warn(
        "OAuth2 callback IdP response classification={} method={} path={} status={}",
        callbackFailureClassification.logValue(),
        clientRequest.method(),
        sanitizePath(clientRequest.url()),
        httpStatusCode.value());
  }

  private void logTransportFailure(ClientRequest clientRequest, Throwable throwable) {
    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(throwable)
            .orElse(OAuth2CallbackFailureClassification.OTHER_CALLBACK_FAILURE);
    log.warn(
        "OAuth2 callback IdP request failed classification={} method={} path={} exceptionType={}",
        callbackFailureClassification.logValue(),
        clientRequest.method(),
        sanitizePath(clientRequest.url()),
        throwable.getClass().getSimpleName());
  }

  private Throwable markDedicatedIdpTransportFailure(Throwable throwable) {
    if (throwable instanceof OAuth2CallbackIdpTransportException) {
      return throwable;
    }

    var callbackFailureClassification =
        OAuth2CallbackFailureClassifier.classifyTransportFailure(throwable);
    if (callbackFailureClassification.isEmpty()) {
      return throwable;
    }

    return new OAuth2CallbackIdpTransportException(callbackFailureClassification.get(), throwable);
  }

  private String sanitizePath(URI uri) {
    var path = uri.getPath();
    if (path == null || path.isBlank()) {
      return "/";
    }

    return path;
  }
}
