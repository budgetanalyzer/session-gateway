package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;

import reactor.core.publisher.Mono;

/**
 * Redirects non-API browser routes to the frontend-owned app error route.
 *
 * <p>API routes fall through to the shared reactive JSON error handler from service-common.
 * Callback-path exceptions are handled earlier by dedicated callback handlers with higher priority.
 */
@Component
public class BrowserErrorRedirectHandler implements WebExceptionHandler, Ordered {

  private static final Logger log = LoggerFactory.getLogger(BrowserErrorRedirectHandler.class);
  private static final Set<String> API_PATH_PREFIXES =
      Set.of("/auth/", "/api/", "/v3/api-docs", "/swagger-ui", "/actuator/");
  private static final Set<String> API_EXACT_PATHS = Set.of("/user");

  private static final String OOPS_PATH = "/oops";

  @Override
  public int getOrder() {
    return -2;
  }

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
    if (exchange.getResponse().isCommitted()) {
      return Mono.error(throwable);
    }

    var path = exchange.getRequest().getPath().pathWithinApplication().value();
    if (isApiPath(path)) {
      return Mono.error(throwable);
    }

    log.error(
        "Browser route error: exceptionType={} path={}, redirecting to /oops",
        throwable.getClass().getSimpleName(),
        path);
    return redirectToOops(exchange);
  }

  private Mono<Void> redirectToOops(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getResponse().getHeaders().setLocation(URI.create(OOPS_PATH));
    return exchange.getResponse().setComplete();
  }

  static boolean isApiPath(String path) {
    if (API_EXACT_PATHS.contains(path)) {
      return true;
    }
    for (var apiPathPrefix : API_PATH_PREFIXES) {
      if (path.startsWith(apiPathPrefix)) {
        return true;
      }
    }
    return false;
  }
}
