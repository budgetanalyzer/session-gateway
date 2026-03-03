package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;

import org.junit.jupiter.api.Test;

import com.nimbusds.jose.jwk.RSAKey;

class InternalJwtConfigTest {

  private final InternalJwtConfig internalJwtConfig = new InternalJwtConfig();

  @Test
  void rsaKey_throwsWhenPemIsBlank() {
    assertThatThrownBy(() -> internalJwtConfig.rsaKey(""))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwt.signing.private-key-pem must be set");
  }

  @Test
  void rsaKey_throwsWhenPemIsNull() {
    assertThatThrownBy(() -> internalJwtConfig.rsaKey(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("jwt.signing.private-key-pem must be set");
  }

  @Test
  void configuredMode_loadsFromPemString() throws Exception {
    var pem = generateTestPem();

    RSAKey loaded = internalJwtConfig.rsaKey(pem);

    assertThat(loaded).isNotNull();
    assertThat(loaded.getKeyID()).isNotNull();
    assertThat(loaded.isPrivate()).isTrue();
  }

  @Test
  void configuredMode_producesDeterministicKid() throws Exception {
    var pem = generateTestPem();

    RSAKey first = internalJwtConfig.rsaKey(pem);
    RSAKey second = internalJwtConfig.rsaKey(pem);

    assertThat(first.getKeyID()).isEqualTo(second.getKeyID());
  }

  @Test
  void configuredMode_throwsForInvalidPem() {
    assertThatThrownBy(() -> internalJwtConfig.rsaKey("not-a-valid-pem"))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("Failed to parse RSA private key");
  }

  @Test
  void jwtEncoder_isCreatedFromRsaKey() throws Exception {
    var pem = generateTestPem();
    var rsaKey = internalJwtConfig.rsaKey(pem);
    var encoder = internalJwtConfig.jwtEncoder(rsaKey);

    assertThat(encoder).isNotNull();
  }

  private static String generateTestPem() throws Exception {
    var keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);

    var keyPair = keyGen.generateKeyPair();
    var privateKey = (RSAPrivateKey) keyPair.getPrivate();

    var base64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
    var pem = new StringBuilder();

    pem.append("-----BEGIN PRIVATE KEY-----\n");
    for (int i = 0; i < base64.length(); i += 64) {
      pem.append(base64, i, Math.min(i + 64, base64.length()));
      pem.append("\n");
    }
    pem.append("-----END PRIVATE KEY-----");

    return pem.toString();
  }
}
