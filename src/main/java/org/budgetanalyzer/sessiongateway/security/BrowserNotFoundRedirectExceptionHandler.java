package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.reactive.resource.NoResourceFoundException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Redirects unmatched non-API browser routes to the frontend-owned app error route.
 *
 * <p>API not-found responses fall through to the shared service-common JSON error contract.
 */
@Component
@ControllerAdvice
@Order(Ordered.HIGHEST_PRECEDENCE)
public class BrowserNotFoundRedirectExceptionHandler {

  private static final Logger log =
      LoggerFactory.getLogger(BrowserNotFoundRedirectExceptionHandler.class);

  private static final String OOPS_PATH = "/oops";

  /**
   * Redirects unmatched browser routes to {@code /oops}.
   *
   * @param exception the not-found exception raised for an unmatched route
   * @param exchange the current server exchange
   * @return completed redirect response for browser paths or the original exception for API paths
   */
  @ExceptionHandler(NoResourceFoundException.class)
  public Mono<Void> handle(NoResourceFoundException exception, ServerWebExchange exchange) {
    if (exchange.getResponse().isCommitted()) {
      return Mono.error(exception);
    }

    var path = exchange.getRequest().getPath().pathWithinApplication().value();
    if (BrowserErrorRedirectHandler.isApiPath(path)) {
      return Mono.error(exception);
    }

    log.error("Browser route not found: path={}, redirecting to /oops", path);
    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getResponse().getHeaders().setLocation(URI.create(OOPS_PATH));
    return exchange.getResponse().setComplete();
  }
}
