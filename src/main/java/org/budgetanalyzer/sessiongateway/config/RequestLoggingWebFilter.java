package org.budgetanalyzer.sessiongateway.config;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Web filter to log all incoming requests for debugging OAuth2 callback issues.
 */
@Component
public class RequestLoggingWebFilter implements WebFilter {

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getURI().getPath();
    String query = exchange.getRequest().getURI().getQuery();
    String fullUrl = path + (query != null ? "?" + query : "");

    // Log all OAuth2-related requests
    if (path.contains("oauth2") || path.contains("login")) {
      System.err.println("==== INCOMING REQUEST ====");
      System.err.println("Method: " + exchange.getRequest().getMethod());
      System.err.println("Path: " + path);
      System.err.println("Query: " + query);
      System.err.println("Full URL: " + fullUrl);
      System.err.println("Host: " + exchange.getRequest().getHeaders().getHost());
      System.err.println("=========================");
    }

    return chain.filter(exchange);
  }
}
