package org.budgetanalyzer.sessiongateway.security;

/** Classification categories for browser OAuth2 callback failures. */
public enum OAuth2CallbackFailureClassification {
  POOL_ACQUIRE_TIMEOUT("pool_acquire_timeout"),
  CONNECT_FAILURE("connect_failure"),
  RESPONSE_TIMEOUT("response_timeout"),
  UPSTREAM_4XX("upstream_4xx"),
  UPSTREAM_5XX("upstream_5xx"),
  OTHER_TRANSPORT_FAILURE("other_transport_failure"),
  OTHER_CALLBACK_FAILURE("other_callback_failure");

  private final String logValue;

  OAuth2CallbackFailureClassification(String logValue) {
    this.logValue = logValue;
  }

  /**
   * Returns the stable lowercase value used in structured callback diagnostics.
   *
   * @return the log-safe classification value
   */
  public String logValue() {
    return logValue;
  }
}
