package org.budgetanalyzer.sessiongateway.security;

import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import org.budgetanalyzer.service.audit.AuditLogger;
import org.budgetanalyzer.service.reactive.http.ReactiveCorrelationIdFilter;

/**
 * Emits Session Gateway login, logout, and bulk-revocation audit events through {@link
 * AuditLogger}.
 *
 * <p>Login and logout events record the status of the already completed response. Callers must emit
 * them only after the terminal redirect completes.
 */
@Component
public class SessionLifecycleAuditLogger {

  /** Actor recorded when no internal user ID is available without another lookup. */
  public static final String ANONYMOUS_ACTOR = "anonymous";

  private static final String LOGIN_SUCCESS_OPERATION = "OAUTH2_LOGIN_SUCCESS";
  private static final String LOGIN_FAILURE_OPERATION = "OAUTH2_LOGIN_FAILURE";
  private static final String LOGOUT_SUCCESS_OPERATION = "LOGOUT_SUCCESS";
  private static final String LOGOUT_FAILURE_OPERATION = "LOGOUT_FAILURE";
  private static final String REVOCATION_OPERATION = "DELETE /internal/v1/sessions/users/{userId}";

  private final AuditLogger auditLogger;

  public SessionLifecycleAuditLogger(AuditLogger auditLogger) {
    this.auditLogger = auditLogger;
  }

  /**
   * Records a completed login success redirect.
   *
   * @param userId the internal user ID of the new session
   * @param exchange the completed exchange
   */
  public void loginSuccess(String userId, ServerWebExchange exchange) {
    log(userId, LOGIN_SUCCESS_OPERATION, "", responseStatus(exchange), exchange);
  }

  /**
   * Records a completed login failure redirect.
   *
   * @param exchange the completed exchange
   */
  public void loginFailure(ServerWebExchange exchange) {
    log(ANONYMOUS_ACTOR, LOGIN_FAILURE_OPERATION, "", responseStatus(exchange), exchange);
  }

  /**
   * Records a completed logout redirect to the identity provider.
   *
   * @param actor the internal user ID, or {@link #ANONYMOUS_ACTOR}
   * @param exchange the completed exchange
   */
  public void logoutSuccess(String actor, ServerWebExchange exchange) {
    log(actor, LOGOUT_SUCCESS_OPERATION, "", responseStatus(exchange), exchange);
  }

  /**
   * Records a completed logout failure redirect.
   *
   * @param actor the internal user ID, or {@link #ANONYMOUS_ACTOR}
   * @param exchange the completed exchange
   */
  public void logoutFailure(String actor, ServerWebExchange exchange) {
    log(actor, LOGOUT_FAILURE_OPERATION, "", responseStatus(exchange), exchange);
  }

  /**
   * Records a bulk-revocation attempt.
   *
   * <p>The outcome is explicit because the controller finishes before the framework writes the
   * response.
   *
   * @param userId the internal user ID whose sessions were targeted
   * @param outcome the HTTP status returned to the caller
   * @param exchange the current exchange
   */
  public void revocation(String userId, int outcome, ServerWebExchange exchange) {
    log(ANONYMOUS_ACTOR, REVOCATION_OPERATION, userId, outcome, exchange);
  }

  private void log(
      String actor,
      String operation,
      String resourceIdentifier,
      int outcome,
      ServerWebExchange exchange) {
    auditLogger.log(actor, operation, resourceIdentifier, outcome, correlationId(exchange));
  }

  private int responseStatus(ServerWebExchange exchange) {
    return exchange.getResponse().getStatusCode().value();
  }

  private String correlationId(ServerWebExchange exchange) {
    var correlationId =
        exchange
            .getResponse()
            .getHeaders()
            .getFirst(ReactiveCorrelationIdFilter.CORRELATION_ID_HEADER);
    return correlationId == null ? "" : correlationId;
  }
}
