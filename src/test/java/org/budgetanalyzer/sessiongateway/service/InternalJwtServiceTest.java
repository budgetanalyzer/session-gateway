package org.budgetanalyzer.sessiongateway.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.SignedJWT;

class InternalJwtServiceTest {

  private static final Instant FIXED_NOW = Instant.parse("2025-06-15T12:00:00Z");
  private static final String IDP_SUB = "auth0|abc123";
  private static final String USER_ID = "user-456";
  private static final List<String> ROLES = List.of("ROLE_USER", "ROLE_ADMIN");
  private static final List<String> PERMISSIONS =
      List.of("transactions:read", "transactions:write");

  private RSAKey rsaKey;
  private InternalJwtService internalJwtService;
  private Clock fixedClock;

  @BeforeEach
  void setUp() throws Exception {
    rsaKey = new RSAKeyGenerator(2048).keyID("test-kid").generate();
    ImmutableJWKSet<SecurityContext> jwkSource = new ImmutableJWKSet<>(new JWKSet(rsaKey));
    JwtEncoder encoder = new NimbusJwtEncoder(jwkSource);
    fixedClock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
    internalJwtService = new InternalJwtService(encoder, fixedClock);
  }

  @Test
  void mintToken_producesValidJwtWithCorrectClaims() throws Exception {
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    SignedJWT parsed = SignedJWT.parse(token);
    var claims = parsed.getJWTClaimsSet();

    assertThat(claims.getIssuer()).isEqualTo("session-gateway");
    assertThat(claims.getSubject()).isEqualTo(USER_ID);
    assertThat(claims.getAudience()).containsExactly("budgetanalyzer-internal");
    assertThat(claims.getStringClaim("idp_sub")).isEqualTo(IDP_SUB);
    assertThat(claims.getStringListClaim("roles")).containsExactly("ROLE_USER", "ROLE_ADMIN");
    assertThat(claims.getStringListClaim("permissions"))
        .containsExactly("transactions:read", "transactions:write");
    assertThat(claims.getIssueTime().toInstant()).isEqualTo(FIXED_NOW);
    assertThat(claims.getExpirationTime().toInstant())
        .isEqualTo(FIXED_NOW.plus(30, ChronoUnit.MINUTES));
  }

  @Test
  void mintToken_usesRs256Algorithm() throws Exception {
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    SignedJWT parsed = SignedJWT.parse(token);
    assertThat(parsed.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
  }

  @Test
  void mintToken_signatureVerifiesWithPublicKey() throws Exception {
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    SignedJWT parsed = SignedJWT.parse(token);
    var verifier = new com.nimbusds.jose.crypto.RSASSAVerifier(rsaKey.toRSAPublicKey());
    assertThat(parsed.verify(verifier)).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForNull() {
    assertThat(internalJwtService.needsRemint(null)).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForEmpty() {
    assertThat(internalJwtService.needsRemint("")).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForBlank() {
    assertThat(internalJwtService.needsRemint("   ")).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForMalformedToken() {
    assertThat(internalJwtService.needsRemint("not-a-jwt")).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForExpiredToken() {
    // Mint a token, then advance clock past expiry
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    Clock expiredClock = Clock.fixed(FIXED_NOW.plus(31, ChronoUnit.MINUTES), ZoneOffset.UTC);
    InternalJwtService laterService = new InternalJwtService(null, expiredClock);

    assertThat(laterService.needsRemint(token)).isTrue();
  }

  @Test
  void needsRemint_returnsTrueForNearExpiryToken() {
    // Mint a token, then advance clock to within 5 min of expiry
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    // Token expires at FIXED_NOW + 30min. Clock at FIXED_NOW + 26min means 4 min left < 5 min
    // threshold
    Clock nearExpiryClock = Clock.fixed(FIXED_NOW.plus(26, ChronoUnit.MINUTES), ZoneOffset.UTC);
    InternalJwtService laterService = new InternalJwtService(null, nearExpiryClock);

    assertThat(laterService.needsRemint(token)).isTrue();
  }

  @Test
  void needsRemint_returnsFalseForFreshToken() {
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    assertThat(internalJwtService.needsRemint(token)).isFalse();
  }

  @Test
  void needsRemint_returnsFalseWhenMoreThan5MinRemaining() {
    String token = internalJwtService.mintToken(IDP_SUB, USER_ID, ROLES, PERMISSIONS);

    // Token expires at FIXED_NOW + 30min. Clock at FIXED_NOW + 20min means 10 min left > 5 min
    Clock midLifeClock = Clock.fixed(FIXED_NOW.plus(20, ChronoUnit.MINUTES), ZoneOffset.UTC);
    InternalJwtService laterService = new InternalJwtService(null, midLifeClock);

    assertThat(laterService.needsRemint(token)).isFalse();
  }
}
