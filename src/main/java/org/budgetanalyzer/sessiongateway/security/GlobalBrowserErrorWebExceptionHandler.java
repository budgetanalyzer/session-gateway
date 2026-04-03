package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Global error fallback replacing Boot's {@code DefaultErrorWebExceptionHandler}.
 *
 * <p>Browser document navigations redirect to {@code /oops}. All other requests receive a sanitized
 * JSON error response. Callback-path exceptions are not handled here; they are handled by the
 * dedicated callback {@code WebExceptionHandler} beans which have higher priority.
 */
@Component
public class GlobalBrowserErrorWebExceptionHandler implements ErrorWebExceptionHandler, Ordered {

  private static final Logger log =
      LoggerFactory.getLogger(GlobalBrowserErrorWebExceptionHandler.class);

  private static final String OOPS_PATH = "/oops";

  private static final String JSON_ERROR_BODY =
      "{\"type\":\"INTERNAL_ERROR\",\"message\":\"An unexpected error occurred\"}";

  @Override
  public int getOrder() {
    return -1;
  }

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
    if (exchange.getResponse().isCommitted()) {
      return Mono.error(throwable);
    }

    if (BrowserNavigationRequestClassifier.isBrowserNavigationRequest(exchange)) {
      log.error(
          "Global error fallback: browser navigation failure exceptionType={} path={},"
              + " redirecting to /oops",
          throwable.getClass().getSimpleName(),
          exchange.getRequest().getPath().pathWithinApplication().value());
      return redirectToOops(exchange);
    }

    log.error(
        "Global error fallback: non-browser failure exceptionType={} path={}",
        throwable.getClass().getSimpleName(),
        exchange.getRequest().getPath().pathWithinApplication().value());
    return jsonError(exchange, throwable);
  }

  private Mono<Void> redirectToOops(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getResponse().getHeaders().setLocation(URI.create(OOPS_PATH));
    return exchange.getResponse().setComplete();
  }

  private Mono<Void> jsonError(ServerWebExchange exchange, Throwable throwable) {
    var status = HttpStatus.INTERNAL_SERVER_ERROR;
    if (throwable instanceof ResponseStatusException rse) {
      var resolved = HttpStatus.resolve(rse.getStatusCode().value());
      if (resolved != null) {
        status = resolved;
      }
    }
    exchange.getResponse().setStatusCode(status);
    exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
    var buffer =
        exchange
            .getResponse()
            .bufferFactory()
            .wrap(JSON_ERROR_BODY.getBytes(StandardCharsets.UTF_8));
    return exchange.getResponse().writeWith(Mono.just(buffer));
  }
}
