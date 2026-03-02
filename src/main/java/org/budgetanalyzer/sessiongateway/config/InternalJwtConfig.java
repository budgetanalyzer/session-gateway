package org.budgetanalyzer.sessiongateway.config;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

/**
 * Configuration for internal JWT signing infrastructure.
 *
 * <p>Supports two modes:
 *
 * <ul>
 *   <li><strong>Configured mode</strong>: If {@code jwt.signing.private-key-pem} is set, loads the
 *       RSA key from the PEM string. Required for multi-instance deployments.
 *   <li><strong>Generated mode</strong>: If the property is absent, generates an ephemeral RSA
 *       2048-bit key pair at startup. This key will not survive restarts.
 * </ul>
 */
@Configuration
public class InternalJwtConfig {

  private static final Logger logger = LoggerFactory.getLogger(InternalJwtConfig.class);

  @Bean
  public Clock clock() {
    return Clock.systemUTC();
  }

  @Bean
  public RSAKey rsaKey(@Value("${jwt.signing.private-key-pem:}") String privateKeyPem) {
    if (privateKeyPem != null && !privateKeyPem.isBlank()) {
      return loadFromPem(privateKeyPem);
    }
    return generateEphemeralKey();
  }

  @Bean
  public JwtEncoder jwtEncoder(RSAKey rsaKey) {
    JWKSource<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    return new NimbusJwtEncoder(jwkSource);
  }

  @Bean("permissionServiceWebClient")
  public WebClient permissionServiceWebClient(
      @Value("${permission-service.base-url}") String baseUrl) {
    return WebClient.builder().baseUrl(baseUrl).build();
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

      String kid = UUID.randomUUID().toString();
      RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(kid).build();
      logger.info("Loaded RSA signing key from configuration (kid={})", kid);
      return rsaKey;
    } catch (Exception e) {
      throw new IllegalStateException("Failed to parse RSA private key from PEM configuration", e);
    }
  }

  private RSAKey generateEphemeralKey() {
    try {
      String kid = UUID.randomUUID().toString();
      RSAKey rsaKey = new RSAKeyGenerator(2048).keyID(kid).generate();
      logger.info(
          "Generated ephemeral RSA signing key at startup (kid={}). "
              + "This key will not survive restarts. "
              + "Set jwt.signing.private-key-pem for persistent/shared keys.",
          kid);
      return rsaKey;
    } catch (JOSEException e) {
      throw new IllegalStateException("Failed to generate RSA key pair", e);
    }
  }
}
