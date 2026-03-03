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

  /**
   * Creates a new JwksController.
   *
   * @param rsaKey the RSA key whose public component is exposed via JWKS
   */
  public JwksController(RSAKey rsaKey) {
    this.jwksJson = new JWKSet(rsaKey.toPublicJWK()).toString();
  }

  /**
   * Returns the JSON Web Key Set containing the gateway's public signing key.
   *
   * @return the JWKS JSON document
   */
  @GetMapping(value = "/.well-known/jwks.json", produces = "application/json")
  public Mono<String> jwks() {
    return Mono.just(jwksJson);
  }
}
