package org.budgetanalyzer.sessiongateway.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/** Internal service-to-service endpoints for session revocation. */
@RestController
@RequestMapping("/internal/v1")
public class InternalSessionController {

  private static final Logger log = LoggerFactory.getLogger(InternalSessionController.class);

  private final SessionWriter sessionWriter;

  /**
   * Creates a new InternalSessionController.
   *
   * @param sessionWriter deletes Redis-backed sessions
   */
  public InternalSessionController(SessionWriter sessionWriter) {
    this.sessionWriter = sessionWriter;
  }

  /**
   * Revokes every active session currently indexed for the given user.
   *
   * @param userId the internal user ID whose sessions should be removed
   * @return completion signal
   */
  @DeleteMapping("/sessions/users/{userId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public Mono<Void> deleteUserSessions(@PathVariable String userId) {
    log.info("Session revocation requested for userId={}", userId);

    return sessionWriter
        .deleteAllSessionsForUser(userId)
        .doOnSuccess(
            deletedKeyCount ->
                log.info(
                    "Session revocation completed for userId={}, deletedSessions={}",
                    userId,
                    deletedSessionCount(deletedKeyCount)))
        .doOnError(
            exception -> log.error("Session revocation failed for userId={}", userId, exception))
        .then();
  }

  private long deletedSessionCount(long deletedKeyCount) {
    return Math.max(deletedKeyCount - 1, 0);
  }
}
