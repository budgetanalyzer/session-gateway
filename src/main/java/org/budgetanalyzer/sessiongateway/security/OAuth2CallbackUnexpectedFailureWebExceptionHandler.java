package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebExceptionHandler;

import reactor.core.publisher.Mono;

/** Redirects unexpected callback-completion failures to the frontend-owned app error route. */
@Component
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2CallbackUnexpectedFailureWebExceptionHandler
    implements WebExceptionHandler, Ordered {

  private static final Logger log =
      LoggerFactory.getLogger(OAuth2CallbackUnexpectedFailureWebExceptionHandler.class);

  private static final String CALLBACK_PATH_PREFIX = "/login/oauth2/code/";

  private final OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver;

  public OAuth2CallbackUnexpectedFailureWebExceptionHandler(
      OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver) {
    this.oauth2CallbackRedirectResolver = oauth2CallbackRedirectResolver;
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE + 1;
  }

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
    if (exchange.getResponse().isCommitted()
        || !isCallbackPath(exchange)
        || !(throwable instanceof Exception)) {
      return Mono.error(throwable);
    }

    var requestPath = exchange.getRequest().getPath().pathWithinApplication().value();
    log.error(
        "OAuth2 callback completion failed exceptionType={} path={}, redirecting to /oops",
        throwable.getClass().getSimpleName(),
        requestPath);

    return redirect(exchange, oauth2CallbackRedirectResolver.resolveUnexpectedFailureRedirectUrl());
  }

  private boolean isCallbackPath(ServerWebExchange exchange) {
    var requestPath = exchange.getRequest().getPath().pathWithinApplication().value();
    return requestPath.startsWith(CALLBACK_PATH_PREFIX);
  }

  private Mono<Void> redirect(ServerWebExchange exchange, String location) {
    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getResponse().getHeaders().setLocation(URI.create(location));
    return exchange.getResponse().setComplete();
  }
}
