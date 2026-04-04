package org.budgetanalyzer.sessiongateway.security;

/** Marker exception for dedicated IdP transport failures on the browser OAuth2 callback path. */
public final class OAuth2CallbackIdpTransportException extends RuntimeException {

  private final OAuth2CallbackFailureClassification callbackFailureClassification;

  /**
   * Creates a new marker exception for dedicated IdP callback transport failures.
   *
   * @param callbackFailureClassification the stable callback failure classification
   * @param cause the original transport failure
   */
  public OAuth2CallbackIdpTransportException(
      OAuth2CallbackFailureClassification callbackFailureClassification, Throwable cause) {
    super(
        "Dedicated IdP callback transport failure: " + callbackFailureClassification.logValue(),
        cause);
    this.callbackFailureClassification = callbackFailureClassification;
  }

  /**
   * Returns the stable classification used for callback diagnostics.
   *
   * @return the callback failure classification
   */
  public OAuth2CallbackFailureClassification callbackFailureClassification() {
    return callbackFailureClassification;
  }
}
