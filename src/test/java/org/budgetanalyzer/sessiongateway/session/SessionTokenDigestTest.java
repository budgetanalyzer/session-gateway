package org.budgetanalyzer.sessiongateway.session;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class SessionTokenDigestTest {

  // Golden vector shared with ext-authz: both services must derive this key from this cookie value.
  private static final String GOLDEN_SESSION_TOKEN = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
  private static final String GOLDEN_SESSION_DIGEST =
      "16362f566387b3cf5a6e92fb0a986c76ca20eb3a0c12cbdfbd0b29501e0c18df";
  private static final String GOLDEN_SESSION_KEY =
      "session:16362f566387b3cf5a6e92fb0a986c76ca20eb3a0c12cbdfbd0b29501e0c18df";

  @Test
  void sha256HexMatchesGoldenVector() {
    assertThat(SessionTokenDigest.sha256Hex(GOLDEN_SESSION_TOKEN)).isEqualTo(GOLDEN_SESSION_DIGEST);
  }

  @Test
  void defaultKeyPrefixPlusDigestMatchesGoldenSessionKey() {
    assertThat("session:" + SessionTokenDigest.sha256Hex(GOLDEN_SESSION_TOKEN))
        .isEqualTo(GOLDEN_SESSION_KEY);
  }

  @Test
  void sha256HexReturnsLowercaseHexWithoutRawToken() {
    var sessionDigest = SessionTokenDigest.sha256Hex(GOLDEN_SESSION_TOKEN);

    assertThat(sessionDigest).matches("[0-9a-f]{64}").doesNotContain(GOLDEN_SESSION_TOKEN);
  }

  @Test
  void logIdUsesDigestPrefixInsteadOfTokenPrefix() {
    assertThat(SessionTokenDigest.logId(GOLDEN_SESSION_TOKEN)).isEqualTo("16362f56…");
  }

  @Test
  void logIdHandlesMissingToken() {
    assertThat(SessionTokenDigest.logId(null)).isEqualTo("[null]");
  }
}
