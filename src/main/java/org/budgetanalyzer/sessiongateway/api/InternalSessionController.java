package org.budgetanalyzer.sessiongateway.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.security.SessionLifecycleAuditLogger;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/** Internal service-to-service endpoints for session revocation. */
@RestController
@RequestMapping("/internal/v1")
public class InternalSessionController {

  private static final Logger log = LoggerFactory.getLogger(InternalSessionController.class);

  private final SessionWriter sessionWriter;
  private final SessionLifecycleAuditLogger sessionLifecycleAuditLogger;

  /**
   * Creates a new InternalSessionController.
   *
   * @param sessionWriter deletes Redis-backed sessions
   * @param sessionLifecycleAuditLogger emits session lifecycle audit events
   */
  public InternalSessionController(
      SessionWriter sessionWriter, SessionLifecycleAuditLogger sessionLifecycleAuditLogger) {
    this.sessionWriter = sessionWriter;
    this.sessionLifecycleAuditLogger = sessionLifecycleAuditLogger;
  }

  /**
   * Revokes every active session currently indexed for the given user.
   *
   * @param userId the internal user ID whose sessions should be removed
   * @param exchange the server web exchange
   * @return completion signal
   */
  @DeleteMapping("/sessions/users/{userId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public Mono<Void> deleteUserSessions(@PathVariable String userId, ServerWebExchange exchange) {
    log.info("Session revocation requested for userId={}", userId);

    return sessionWriter
        .deleteAllSessionsForUser(userId)
        .doOnSuccess(
            deletedKeyCount -> {
              log.info(
                  "Session revocation completed for userId={}, deletedSessions={}",
                  userId,
                  deletedSessionCount(deletedKeyCount));
              sessionLifecycleAuditLogger.revocation(
                  userId, HttpStatus.NO_CONTENT.value(), exchange);
            })
        .doOnError(
            exception -> {
              log.error("Session revocation failed for userId={}", userId, exception);
              sessionLifecycleAuditLogger.revocation(
                  userId, HttpStatus.INTERNAL_SERVER_ERROR.value(), exchange);
            })
        .then();
  }

  private long deletedSessionCount(long deletedKeyCount) {
    return Math.max(deletedKeyCount - 1, 0);
  }
}
