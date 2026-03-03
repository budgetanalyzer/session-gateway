package org.budgetanalyzer.sessiongateway.config;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Configuration for internal JWT signing infrastructure.
 *
 * <p>Requires {@code jwt.signing.private-key-pem} to be set to a PEM-encoded RSA private key. The
 * application will fail to start if this property is missing or blank.
 */
@Configuration
public class InternalJwtConfig {

  private static final Logger log = LoggerFactory.getLogger(InternalJwtConfig.class);

  /**
   * Provides the system UTC clock for token timestamp operations.
   *
   * @return the system UTC clock
   */
  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }

  /**
   * Provides the RSA signing key for internal JWT minting.
   *
   * <p>The key is loaded from a PEM string and the {@code kid} is derived deterministically from
   * the public key's SHA-256 thumbprint so it remains stable across restarts.
   *
   * @param privateKeyPem the PEM-encoded RSA private key (required)
   * @return the RSA signing key
   * @throws IllegalStateException if the PEM property is missing or blank
   */
  @Bean
  public RSAKey rsaKey(@Value("${jwt.signing.private-key-pem:}") String privateKeyPem) {
    if (privateKeyPem == null || privateKeyPem.isBlank()) {
      throw new IllegalStateException(
          "jwt.signing.private-key-pem must be set. "
              + "Generate with: openssl genpkey -algorithm RSA "
              + "-pkeyopt rsa_keygen_bits:2048 -out private.pem");
    }
    return loadFromPem(privateKeyPem);
  }

  /**
   * Provides the JWT encoder backed by the RSA signing key.
   *
   * @param rsaKey the RSA signing key
   * @return the JWT encoder
   */
  @Bean
  public JwtEncoder jwtEncoder(RSAKey rsaKey) {
    JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    return new NimbusJwtEncoder(jwkSource);
  }

  private RSAKey loadFromPem(String pem) {
    try {
      // Strip PEM headers and decode Base64
      String base64 =
          pem.replace("-----BEGIN PRIVATE KEY-----", "")
              .replace("-----END PRIVATE KEY-----", "")
              .replaceAll("\\s", "");
      byte[] keyBytes = Base64.getDecoder().decode(base64);

      // Parse PKCS#8 private key and derive public key
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
      RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) keyFactory.generatePrivate(keySpec);
      RSAPublicKey publicKey =
          (RSAPublicKey)
              keyFactory.generatePublic(
                  new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));

      // Derive kid from public key thumbprint for stability across restarts
      var rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
      String kid = rsaKey.computeThumbprint("SHA-256").toString();
      RSAKey finalKey = new RSAKey.Builder(rsaKey).keyID(kid).build();
      log.info("Loaded RSA signing key from configuration (kid={})", kid);
      return finalKey;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse RSA private key from PEM configuration", e);
    }
  }
}
