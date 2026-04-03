package org.budgetanalyzer.sessiongateway.security;

import java.util.Set;

import org.springframework.http.HttpMethod;
import org.springframework.web.server.ServerWebExchange;

/**
 * Classifies whether a request is a browser document navigation.
 *
 * <p>Uses multiple signals beyond {@code Accept: text/html} alone to protect JSON API contracts:
 * HTTP method, {@code Sec-Fetch} headers, and explicit API path exclusion.
 */
public final class BrowserNavigationRequestClassifier {

  private static final String CALLBACK_PATH_PREFIX = "/login/oauth2/code/";

  private static final Set<String> API_PATH_PREFIXES =
      Set.of("/auth/", "/api/", "/v3/api-docs", "/swagger-ui", "/actuator/");

  private static final Set<String> API_EXACT_PATHS = Set.of("/user");

  private BrowserNavigationRequestClassifier() {}

  /** Returns {@code true} if the request looks like a browser document navigation. */
  public static boolean isBrowserNavigationRequest(ServerWebExchange exchange) {
    var request = exchange.getRequest();
    var method = request.getMethod();

    if (method != HttpMethod.GET && method != HttpMethod.HEAD) {
      return false;
    }

    var path = request.getPath().pathWithinApplication().value();

    if (path.startsWith(CALLBACK_PATH_PREFIX)) {
      return false;
    }

    if (isApiPath(path)) {
      return false;
    }

    return hasBrowserNavigationSignals(exchange);
  }

  private static boolean isApiPath(String path) {
    if (API_EXACT_PATHS.contains(path)) {
      return true;
    }
    for (var prefix : API_PATH_PREFIXES) {
      if (path.startsWith(prefix)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasBrowserNavigationSignals(ServerWebExchange exchange) {
    var headers = exchange.getRequest().getHeaders();

    var secFetchMode = headers.getFirst("Sec-Fetch-Mode");
    if ("navigate".equals(secFetchMode)) {
      return true;
    }

    var secFetchDest = headers.getFirst("Sec-Fetch-Dest");
    if ("document".equals(secFetchDest)) {
      return true;
    }

    return headers.getAccept().stream()
        .anyMatch(
            mediaType ->
                "text".equals(mediaType.getType()) && "html".equals(mediaType.getSubtype()));
  }
}
