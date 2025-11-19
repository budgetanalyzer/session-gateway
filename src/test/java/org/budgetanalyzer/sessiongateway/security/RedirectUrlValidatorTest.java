package org.budgetanalyzer.sessiongateway.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Unit tests for {@link RedirectUrlValidator}.
 *
 * <p>Verifies that the validator correctly identifies safe same-origin URLs and rejects malicious
 * external redirects.
 */
class RedirectUrlValidatorTest {

  @Test
  void testValidateUrl_allowsSimpleRelativePath() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/dashboard"));
  }

  @Test
  void testValidateUrl_allowsRootPath() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/"));
  }

  @Test
  void testValidateUrl_allowsPathWithQueryParameters() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/settings?tab=profile&section=security"));
  }

  @Test
  void testValidateUrl_allowsPathWithFragment() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/docs#section-2"));
  }

  @Test
  void testValidateUrl_allowsDeepPath() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/api/v1/users/123/settings"));
  }

  @Test
  void testValidateUrl_allowsPathWithEncodedCharacters() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/search?q=test%20query"));
  }

  @Test
  void testValidateUrl_rejectsNull() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl(null));
  }

  @Test
  void testValidateUrl_rejectsEmptyString() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl(""));
  }

  @Test
  void testValidateUrl_rejectsAbsoluteHttpUrl() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("http://evil.com/phishing"));
  }

  @Test
  void testValidateUrl_rejectsAbsoluteHttpsUrl() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("https://evil.com/phishing"));
  }

  @Test
  void testValidateUrl_rejectsProtocolRelativeUrl() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("//evil.com/phishing"));
  }

  @Test
  void testValidateUrl_rejectsProtocolRelativeUrlWithPath() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("//evil.com/path/to/page"));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "JavaScript:alert(document.cookie)",
        "JAVASCRIPT:void(0)"
      })
  void testValidateUrl_rejectsJavascriptUrls(String url) {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl(url));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "data:text/html,<script>alert('XSS')</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
        "Data:text/plain,malicious"
      })
  void testValidateUrl_rejectsDataUrls(String url) {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl(url));
  }

  @Test
  void testValidateUrl_rejectsFtpProtocol() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("ftp://files.example.com/file.txt"));
  }

  @Test
  void testValidateUrl_rejectsFileProtocol() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("file:///etc/passwd"));
  }

  @Test
  void testValidateUrl_rejectsPathNotStartingWithSlash() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("dashboard"));
  }

  @Test
  void testValidateUrl_rejectsRelativePathWithDots() {
    // This should still be rejected as it doesn't start with /
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("../../../etc/passwd"));
  }

  @Test
  void testValidateUrl_allowsPathWithDotsAfterLeadingSlash() {
    // Path traversal is allowed as long as it starts with /
    // The web server/framework should handle path normalization
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/../api/users"));
  }

  @Test
  void testValidateUrl_allowsPathWithSpecialCharacters() {
    assertTrue(RedirectUrlValidator.isValidRedirectUrl("/path/with-dashes_and_underscores"));
  }

  @Test
  void testValidateUrl_rejectsUrlWithCustomProtocol() {
    assertFalse(RedirectUrlValidator.isValidRedirectUrl("custom://protocol/path"));
  }

  @Test
  void testValidateUrl_allowsVeryLongValidPath() {
    String longPath = "/path" + "/segment".repeat(100) + "?query=value";
    assertTrue(RedirectUrlValidator.isValidRedirectUrl(longPath));
  }
}
