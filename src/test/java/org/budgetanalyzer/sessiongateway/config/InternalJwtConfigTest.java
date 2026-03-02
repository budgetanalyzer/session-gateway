package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.RSAKey;

class InternalJwtConfigTest {

  private final InternalJwtConfig config = new InternalJwtConfig();

  @Test
  void generatedMode_producesValidRsaKeyWithKid() {
    RSAKey rsaKey = config.rsaKey("");

    assertThat(rsaKey).isNotNull();
    assertThat(rsaKey.getKeyID()).isNotNull().isNotBlank();
    assertThat(rsaKey.isPrivate()).isTrue();
  }

  @Test
  void generatedMode_producesKeyWhenPropertyIsNull() {
    RSAKey rsaKey = config.rsaKey(null);

    assertThat(rsaKey).isNotNull();
    assertThat(rsaKey.getKeyID()).isNotNull();
    assertThat(rsaKey.isPrivate()).isTrue();
  }

  @Test
  void generatedMode_producesUniqueKeysEachTime() {
    RSAKey key1 = config.rsaKey("");
    RSAKey key2 = config.rsaKey("");

    assertThat(key1.getKeyID()).isNotEqualTo(key2.getKeyID());
  }

  @Test
  void configuredMode_loadsFromPemString() throws Exception {
    // Generate an RSA key pair using JCA
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    var keyPair = keyGen.generateKeyPair();
    RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

    // Build PEM from PKCS#8 encoded private key
    String base64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    StringBuilder pem = new StringBuilder();
    pem.append("-----BEGIN PRIVATE KEY-----\n");
    for (int i = 0; i < base64.length(); i += 64) {
      pem.append(base64, i, Math.min(i + 64, base64.length()));
      pem.append("\n");
    }
    pem.append("-----END PRIVATE KEY-----");

    RSAKey loaded = config.rsaKey(pem.toString());

    assertThat(loaded).isNotNull();
    assertThat(loaded.getKeyID()).isNotNull();
    assertThat(loaded.isPrivate()).isTrue();
  }

  @Test
  void configuredMode_throwsForInvalidPem() {
    assertThatThrownBy(() -> config.rsaKey("not-a-valid-pem"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Failed to parse RSA private key");
  }

  @Test
  void jwtEncoder_isCreatedFromRsaKey() {
    RSAKey rsaKey = config.rsaKey("");
    var encoder = config.jwtEncoder(rsaKey);

    assertThat(encoder).isNotNull();
  }
}
