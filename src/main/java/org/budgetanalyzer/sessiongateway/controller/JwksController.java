package org.budgetanalyzer.sessiongateway.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import reactor.core.publisher.Mono;

/**
 * Exposes the JWKS endpoint for backend services to validate internal JWTs.
 *
 * <p>Returns the RSA public key used by the session-gateway to sign internal JWTs. Backend services
 * use this endpoint to obtain the public key for JWT signature verification.
 */
@RestController
public class JwksController {

  private final String jwksJson;

  public JwksController(RSAKey rsaKey) {
    this.jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();
  }

  @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
  public Mono<String> jwks() {
    return Mono.just(jwksJson);
  }
}
