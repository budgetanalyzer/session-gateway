package org.budgetanalyzer.sessiongateway.security;

import java.net.URI;
import java.net.URISyntaxException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Validates redirect URLs to prevent open redirect vulnerabilities.
 *
 * <p>Implements security rules to ensure redirect URLs are safe and same-origin only. This prevents
 * attackers from crafting malicious URLs that redirect authenticated users to external phishing
 * sites.
 *
 * <p><strong>Security Rules:</strong>
 *
 * <ul>
 *   <li>✅ Allow: {@code /dashboard}, {@code /settings?tab=profile}
 *   <li>❌ Reject: {@code https://evil.com}, {@code //evil.com}, {@code javascript:alert(1)}
 * </ul>
 *
 * <p><strong>OWASP Reference:</strong> <a
 * href="https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html">
 * Unvalidated Redirects and Forwards</a>
 */
public final class RedirectUrlValidator {

  private static final Logger log = LoggerFactory.getLogger(RedirectUrlValidator.class);

  /** Private constructor to prevent instantiation of utility class. */
  private RedirectUrlValidator() {
    throw new UnsupportedOperationException("Utility class cannot be instantiated");
  }

  /**
   * Validates a redirect URL against security rules.
   *
   * <p>A valid redirect URL must:
   *
   * <ol>
   *   <li>Be non-null and non-empty
   *   <li>Start with {@code /} (relative path)
   *   <li>NOT start with {@code //} (protocol-relative URL)
   *   <li>NOT contain {@code ://} (absolute URL with protocol)
   *   <li>NOT contain backslashes, control characters, or whitespace
   *   <li>Parse as a URI with no scheme or authority
   * </ol>
   *
   * @param url the URL to validate
   * @return {@code true} if the URL is safe for same-origin redirect, {@code false} otherwise
   */
  public static boolean isValidRedirectUrl(String url) {
    if (url == null || url.isEmpty()) {
      log.debug("Rejected redirect URL: null or empty");
      return false;
    }

    // Must be relative path (starts with /)
    if (!url.startsWith("/")) {
      log.warn("Rejected redirect URL (not relative path): {}", sanitizeForLog(url));
      return false;
    }

    // Reject protocol-relative URLs (//example.com)
    if (url.startsWith("//")) {
      log.warn("Rejected redirect URL (protocol-relative): {}", sanitizeForLog(url));
      return false;
    }

    // Reject URLs with protocol (http://, https://, ftp://, etc.)
    if (url.contains("://")) {
      log.warn("Rejected redirect URL (contains protocol): {}", sanitizeForLog(url));
      return false;
    }

    if (url.codePoints()
        .anyMatch(
            character ->
                character == '\\'
                    || Character.isISOControl(character)
                    || Character.isWhitespace(character)
                    || Character.isSpaceChar(character)
                    || character == 0xFEFF)) {
      log.warn("Rejected redirect URL (unsafe characters): {}", sanitizeForLog(url));
      return false;
    }

    try {
      var uri = new URI(url);
      if (uri.getScheme() != null || uri.getRawAuthority() != null) {
        return false;
      }
    } catch (URISyntaxException exception) {
      log.warn("Rejected redirect URL (invalid URI): {}", sanitizeForLog(url));
      return false;
    }

    log.debug("Validated redirect URL: {}", sanitizeForLog(url));
    return true;
  }

  /**
   * Sanitizes a URL for safe logging by limiting length and removing control characters.
   *
   * @param url the URL to sanitize
   * @return sanitized URL safe for logging
   */
  private static String sanitizeForLog(String url) {
    if (url == null) {
      return "null";
    }

    // Truncate very long URLs
    var truncated = url.length() > 200 ? url.substring(0, 200) + "..." : url;

    // Remove control characters that could mess with logs
    return truncated.replaceAll("\\p{Cntrl}", "");
  }
}
