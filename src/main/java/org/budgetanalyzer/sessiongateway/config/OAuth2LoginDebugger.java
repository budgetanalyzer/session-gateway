package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

@Component
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2LoginDebugger implements ServerAuthenticationEntryPoint {

  private static final Logger log = LoggerFactory.getLogger(OAuth2LoginDebugger.class);

  @Override
  public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
    log.warn("=== OAUTH2 AUTHENTICATION FAILED ===");
    log.warn("Exception type: {}", ex.getClass().getName());
    log.warn("Exception message: {}", ex.getMessage());
    log.warn("Stack trace:", ex);
    log.warn("====================================");

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
