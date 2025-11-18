package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
public class OAuth2LoginDebugger implements ServerAuthenticationEntryPoint {
  private static final Logger log = LoggerFactory.getLogger(OAuth2LoginDebugger.class);

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
    log.error("=== OAUTH2 AUTHENTICATION FAILED ===");
    log.error("Exception type: {}", ex.getClass().getName());
    log.error("Exception message: {}", ex.getMessage());
    log.error("Stack trace:", ex);
    log.error("====================================");

    // Continue with default behavior
    return exchange
        .getResponse()
        .writeWith(
            Mono.just(
                exchange
                    .getResponse()
                    .bufferFactory()
                    .wrap(("Authentication failed: " + ex.getMessage()).getBytes())));
  }
}
