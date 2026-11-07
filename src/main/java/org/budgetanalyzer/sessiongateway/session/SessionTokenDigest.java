package org.budgetanalyzer.sessiongateway.session;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

import org.budgetanalyzer.core.logging.SafeLogger;

/**
 * Derives the Redis identifier of a session from the browser session token.
 *
 * <p>The raw cookie token is a bearer credential and is never written to Redis or logs. Redis keys,
 * user index members, and log identifiers use the lowercase hex SHA-256 digest of the token
 * instead. ext_authz derives the same digest from the cookie.
 */
public final class SessionTokenDigest {

  private SessionTokenDigest() {}

  /**
   * Returns the lowercase hex SHA-256 digest of the UTF-8 session token.
   *
   * @param sessionToken the raw session token from the cookie
   * @return the 64-character lowercase hex digest
   */
  public static String sha256Hex(String sessionToken) {
    try {
      var messageDigest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of()
          .formatHex(messageDigest.digest(sessionToken.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException ex) {
      throw new IllegalStateException("SHA-256 is required by the Java platform", ex);
    }
  }

  /**
   * Returns a truncated digest prefix that identifies a session in logs.
   *
   * @param sessionToken the raw session token from the cookie, or null when no cookie was sent
   * @return the truncated digest, or {@code [null]} for a null token
   */
  public static String logId(String sessionToken) {
    return sessionToken == null
        ? SafeLogger.truncateId(null)
        : SafeLogger.truncateId(sha256Hex(sessionToken));
  }
}
