package org.budgetanalyzer.sessiongateway.config;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * Logs all incoming requests for debugging authentication issues.
 *
 * <p>This filter runs BEFORE Spring Security filters (HIGHEST_PRECEDENCE - 100) to log every
 * request that comes in, helping diagnose authentication/authorization issues.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE - 100)
public class RequestLoggingFilter implements WebFilter {

  @Override
  public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
    String path = exchange.getRequest().getPath().value();
    String method = exchange.getRequest().getMethod().toString();

    System.err.println("==== INCOMING REQUEST ====");
    System.err.println("Method: " + method);
    System.err.println("Path: " + path);
    System.err.println(
        "Has Authorization header: "
            + exchange.getRequest().getHeaders().containsKey("Authorization"));
    System.err.println(
        "Has Cookie header: " + exchange.getRequest().getHeaders().containsKey("Cookie"));

    return chain
        .filter(exchange)
        .doFinally(
            signalType -> {
              System.err.println("==== RESPONSE FOR " + path + " ====");
              System.err.println("Status: " + exchange.getResponse().getStatusCode());
              System.err.println(
                  "Location header: " + exchange.getResponse().getHeaders().getLocation());
            });
  }
}
