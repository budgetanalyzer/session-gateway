package org.budgetanalyzer.sessiongateway.api;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.core.logging.SafeLogger;
import org.budgetanalyzer.sessiongateway.api.response.SessionStatusResponse;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Session heartbeat controller.
 *
 * <p>Validates the local Redis session and extends its TTL. The frontend calls this endpoint
 * periodically to keep the session alive while the user is active.
 */
@Tag(name = "Session", description = "Session heartbeat and status")
@RestController
public class SessionController {

  private static final Logger log = LoggerFactory.getLogger(SessionController.class);

  private final SessionReader sessionReader;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;
  private final Clock clock;
  private final long sessionTtlSeconds;

  /**
   * Creates a new SessionController.
   *
   * @param sessionReader reads session data from Redis
   * @param sessionWriter writes session data to Redis
   * @param sessionCookieHelper manages session cookies
   * @param clock the clock for computing expiry instants
   * @param sessionProperties validated session configuration
   */
  public SessionController(
      SessionReader sessionReader,
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      Clock clock,
      SessionProperties sessionProperties) {
    this.sessionReader = sessionReader;
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.clock = clock;
    this.sessionTtlSeconds = sessionProperties.ttlSeconds();
  }

  /**
   * Session heartbeat endpoint.
   *
   * <p>Reads the session from Redis and extends its TTL. Returns 401 if no valid session exists.
   *
   * @param exchange the server web exchange
   * @return session status with expiry metadata
   */
  @Operation(
      summary = "Session heartbeat",
      description =
          "Validates the local session and extends its TTL. Returns 401 if no valid session.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Session is valid",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = SessionStatusResponse.class))),
        @ApiResponse(responseCode = "401", description = "No valid session", content = @Content)
      })
  @GetMapping("/auth/v1/session")
  public Mono<SessionStatusResponse> getSessionStatus(ServerWebExchange exchange) {
    var sessionId = sessionCookieHelper.readSessionId(exchange);
    if (sessionId == null || sessionId.isBlank()) {
      return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    log.debug("Session heartbeat for sessionId={}", SafeLogger.truncateId(sessionId));

    return sessionReader
        .readSession(sessionId)
        .switchIfEmpty(unauthorizedAndClearCookie(exchange))
        .flatMap(sessionData -> extendSession(exchange, sessionId, sessionData));
  }

  private Mono<SessionStatusResponse> extendSession(
      ServerWebExchange exchange, String sessionId, SessionData sessionData) {
    return sessionWriter
        .updateSessionExpiry(sessionId, sessionData.userId(), sessionTtlSeconds)
        .flatMap(
            updated -> {
              if (!updated) {
                log.warn(
                    "Session {} disappeared during heartbeat", SafeLogger.truncateId(sessionId));
                return unauthorizedAndClearCookie(exchange);
              }
              return buildResponse(sessionData);
            });
  }

  private Mono<SessionStatusResponse> buildResponse(SessionData sessionData) {
    var expiresAt = clock.instant().plusSeconds(sessionTtlSeconds);

    return Mono.just(
        new SessionStatusResponse(
            true, sessionData.userId(), sessionData.roles(), expiresAt.getEpochSecond()));
  }

  private <T> Mono<T> unauthorizedAndClearCookie(ServerWebExchange exchange) {
    return Mono.defer(
        () -> {
          sessionCookieHelper.clearSessionCookie(exchange);
          return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        });
  }
}
