package org.budgetanalyzer.sessiongateway.controller;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;

class JwksControllerTest {

  @Test
  void jwks_returnsValidJwkSetWithPublicKey() throws Exception {
    RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("test-kid").generate();
    JwksController controller = new JwksController(rsaKey);

    String json = controller.jwks().block();

    assertThat(json).isNotNull();

    // Parse the response as a JWK Set
    JWKSet jwkSet = JWKSet.parse(json);
    assertThat(jwkSet.getKeys()).hasSize(1);

    RSAKey publicKey = (RSAKey) jwkSet.getKeys().get(0);
    assertThat(publicKey.getKeyID()).isEqualTo("test-kid");
    // Must be public only — no private components
    assertThat(publicKey.isPrivate()).isFalse();
  }

  @Test
  void jwks_doesNotExposePrivateKeyComponents() throws Exception {
    RSAKey rsaKey = new RSAKeyGenerator(2048).keyID("kid-123").generate();
    JwksController controller = new JwksController(rsaKey);

    String json = controller.jwks().block();

    // Private key fields must not appear in the output
    assertThat(json).doesNotContain("\"d\":");
    assertThat(json).doesNotContain("\"p\":");
    assertThat(json).doesNotContain("\"q\":");
    assertThat(json).doesNotContain("\"dp\":");
    assertThat(json).doesNotContain("\"dq\":");
    assertThat(json).doesNotContain("\"qi\":");
  }
}
