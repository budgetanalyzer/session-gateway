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

/**
 * Redirects callback-path transport failures through the controlled OAuth2 login failure route.
 *
 * <p>This handler runs before {@link BrowserErrorRedirectHandler} so callback transport failures
 * stay on the dedicated login-failure redirect path.
 */
@Component
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2CallbackTransportFailureWebExceptionHandler
    implements WebExceptionHandler, Ordered {

  private static final Logger log =
      LoggerFactory.getLogger(OAuth2CallbackTransportFailureWebExceptionHandler.class);

  private static final String CALLBACK_PATH_PREFIX = "/login/oauth2/code/";

  private final OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver;

  public OAuth2CallbackTransportFailureWebExceptionHandler(
      OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver) {
    this.oauth2CallbackRedirectResolver = oauth2CallbackRedirectResolver;
  }

  @Override
  public int getOrder() {
    return Ordered.HIGHEST_PRECEDENCE;
  }

  @Override
  public Mono<Void> handle(ServerWebExchange exchange, Throwable throwable) {
    if (exchange.getResponse().isCommitted() || !isCallbackPath(exchange)) {
      return Mono.error(throwable);
    }

    var oauth2CallbackIdpTransportException = findDedicatedIdpTransportException(throwable);
    if (oauth2CallbackIdpTransportException.isEmpty()) {
      return Mono.error(throwable);
    }

    var requestPath = exchange.getRequest().getPath().pathWithinApplication().value();
    log.warn(
        "OAuth2 callback transport failure classification={} exceptionType={} path={},"
            + " redirecting to login",
        oauth2CallbackIdpTransportException.get().callbackFailureClassification().logValue(),
        oauth2CallbackIdpTransportException.get().getCause() == null
            ? oauth2CallbackIdpTransportException.get().getClass().getSimpleName()
            : oauth2CallbackIdpTransportException.get().getCause().getClass().getSimpleName(),
        requestPath);

    return redirect(
        exchange, oauth2CallbackRedirectResolver.resolveAuthenticationFailureRedirectUrl(exchange));
  }

  private java.util.Optional<OAuth2CallbackIdpTransportException>
      findDedicatedIdpTransportException(Throwable throwable) {
    var currentThrowable = throwable;
    while (currentThrowable != null) {
      if (currentThrowable
          instanceof OAuth2CallbackIdpTransportException oauth2CallbackIdpTransportException) {
        return java.util.Optional.of(oauth2CallbackIdpTransportException);
      }
      currentThrowable = currentThrowable.getCause();
    }
    return java.util.Optional.empty();
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
