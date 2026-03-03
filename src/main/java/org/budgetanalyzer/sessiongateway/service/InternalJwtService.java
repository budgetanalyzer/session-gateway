package org.budgetanalyzer.sessiongateway.service;

import java.text.ParseException;
import java.time.Clock;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.SignedJWT;

/** Service for minting and managing internal JWTs with user roles and permissions. */
@Service
public class InternalJwtService {

  /** Session attribute key for the user's internal ID. */
  public static final String SESSION_USER_ID = "INTERNAL_USER_ID";

  /** Session attribute key for the user's roles. */
  public static final String SESSION_ROLES = "INTERNAL_ROLES";

  /** Session attribute key for the user's permissions. */
  public static final String SESSION_PERMISSIONS = "INTERNAL_PERMISSIONS";

  /** Session attribute key for the cached internal JWT. */
  public static final String SESSION_INTERNAL_JWT = "INTERNAL_JWT";

  private static final Logger log = LoggerFactory.getLogger(InternalJwtService.class);
  private static final long TOKEN_LIFETIME_MINUTES = 30;
  private static final long REMINT_THRESHOLD_MINUTES = 5;

  private final JwtEncoder jwtEncoder;
  private final Clock clock;

  /**
   * Creates a new InternalJwtService.
   *
   * @param jwtEncoder the JWT encoder for signing tokens
   * @param clock the clock for determining token timestamps
   */
  public InternalJwtService(JwtEncoder jwtEncoder, Clock clock) {
    this.jwtEncoder = jwtEncoder;
    this.clock = clock;
  }

  /**
   * Mints a new internal JWT with the given claims.
   *
   * @param idpSub the IDP subject identifier
   * @param userId the internal user ID
   * @param roles the user's roles
   * @param permissions the user's permissions
   * @return signed JWT string
   */
  public String mintToken(
      String idpSub, String userId, List<String> roles, List<String> permissions) {
    var now = clock.instant();
    var claims =
        JwtClaimsSet.builder()
            .issuer("session-gateway")
            .subject(userId)
            .audience(List.of("budgetanalyzer-internal"))
            .claim("idp_sub", idpSub)
            .claim("roles", roles)
            .claim("permissions", permissions)
            .issuedAt(now)
            .expiresAt(now.plus(TOKEN_LIFETIME_MINUTES, ChronoUnit.MINUTES))
            .build();

    var token = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    log.debug("Minted internal JWT for userId={}", userId);
    return token;
  }

  /**
   * Checks whether the cached token needs to be re-minted.
   *
   * @param cachedToken the cached JWT string, may be null
   * @return true if the token is null, empty, malformed, or expires within 5 minutes
   */
  public boolean needsRemint(String cachedToken) {
    if (cachedToken == null || cachedToken.isBlank()) {
      return true;
    }

    try {
      var parsed = SignedJWT.parse(cachedToken);
      var expTime = parsed.getJWTClaimsSet().getExpirationTime();

      if (expTime == null) {
        return true;
      }

      var expiry = expTime.toInstant();
      var threshold = clock.instant().plus(REMINT_THRESHOLD_MINUTES, ChronoUnit.MINUTES);

      return expiry.isBefore(threshold);
    } catch (ParseException e) {
      log.warn("Failed to parse cached internal JWT, will remint", e);
      return true;
    }
  }
}
