package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;

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
  void shouldAllowSimpleRelativePath() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/dashboard")).isTrue();
  }

  @Test
  void shouldAllowRootPath() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/")).isTrue();
  }

  @Test
  void shouldAllowPathWithQueryParameters() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/settings?tab=profile&section=security"))
        .isTrue();
  }

  @Test
  void shouldAllowPathWithFragment() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/docs#section-2")).isTrue();
  }

  @Test
  void shouldAllowDeepPath() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/api/v1/users/123/settings")).isTrue();
  }

  @Test
  void shouldAllowPathWithEncodedCharacters() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/search?q=test%20query")).isTrue();
  }

  @Test
  void shouldRejectNull() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl(null)).isFalse();
  }

  @Test
  void shouldRejectEmptyString() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("")).isFalse();
  }

  @Test
  void shouldRejectAbsoluteHttpUrl() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("http://evil.com/phishing")).isFalse();
  }

  @Test
  void shouldRejectAbsoluteHttpsUrl() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("https://evil.com/phishing")).isFalse();
  }

  @Test
  void shouldRejectProtocolRelativeUrl() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("//evil.com/phishing")).isFalse();
  }

  @Test
  void shouldRejectProtocolRelativeUrlWithPath() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("//evil.com/path/to/page")).isFalse();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "javascript:alert(1)",
        "javascript:alert('XSS')",
        "JavaScript:alert(document.cookie)",
        "JAVASCRIPT:void(0)"
      })
  void shouldRejectJavascriptUrls(String url) {
    assertThat(RedirectUrlValidator.isValidRedirectUrl(url)).isFalse();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "data:text/html,<script>alert('XSS')</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
        "Data:text/plain,malicious"
      })
  void shouldRejectDataUrls(String url) {
    assertThat(RedirectUrlValidator.isValidRedirectUrl(url)).isFalse();
  }

  @Test
  void shouldRejectFtpProtocol() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("ftp://files.example.com/file.txt"))
        .isFalse();
  }

  @Test
  void shouldRejectFileProtocol() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("file:///etc/passwd")).isFalse();
  }

  @Test
  void shouldRejectPathNotStartingWithSlash() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("dashboard")).isFalse();
  }

  @Test
  void shouldRejectRelativePathWithDots() {
    // This should still be rejected as it doesn't start with /
    assertThat(RedirectUrlValidator.isValidRedirectUrl("../../../etc/passwd")).isFalse();
  }

  @Test
  void shouldAllowPathWithDotsAfterLeadingSlash() {
    // Path traversal is allowed as long as it starts with /
    // The web server/framework should handle path normalization
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/../api/users")).isTrue();
  }

  @Test
  void shouldAllowPathWithSpecialCharacters() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("/path/with-dashes_and_underscores"))
        .isTrue();
  }

  @Test
  void shouldRejectUrlWithCustomProtocol() {
    assertThat(RedirectUrlValidator.isValidRedirectUrl("custom://protocol/path")).isFalse();
  }

  @Test
  void shouldAllowVeryLongValidPath() {
    String longPath = "/path" + "/segment".repeat(100) + "?query=value";
    assertThat(RedirectUrlValidator.isValidRedirectUrl(longPath)).isTrue();
  }
}
