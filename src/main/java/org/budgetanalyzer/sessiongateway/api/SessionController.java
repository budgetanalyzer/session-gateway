package org.budgetanalyzer.sessiongateway.api;

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
import org.budgetanalyzer.service.api.ApiErrorResponse;
import org.budgetanalyzer.sessiongateway.api.response.SessionStatusResponse;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient.AccountStatus;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient.AuthorizationResponse;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Session heartbeat controller.
 *
 * <p>Validates the local Redis session, refreshes authorization from permission-service, and
 * extends its TTL. The frontend calls this endpoint periodically while the user is active.
 */
@Tag(name = "Session", description = "Session heartbeat and status")
@RestController
public class SessionController {

  private static final Logger log = LoggerFactory.getLogger(SessionController.class);

  private final SessionReader sessionReader;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;
  private final PermissionServiceClient permissionServiceClient;
  private final long sessionTtlSeconds;

  /**
   * Creates a new SessionController.
   *
   * @param sessionReader reads session data from Redis
   * @param sessionWriter writes session data to Redis
   * @param sessionCookieHelper manages session cookies
   * @param permissionServiceClient fetches current account status and grants
   * @param sessionProperties validated session configuration
   */
  public SessionController(
      SessionReader sessionReader,
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      PermissionServiceClient permissionServiceClient,
      SessionProperties sessionProperties) {
    this.sessionReader = sessionReader;
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.permissionServiceClient = permissionServiceClient;
    this.sessionTtlSeconds = sessionProperties.ttlSeconds();
  }

  /**
   * Session heartbeat endpoint.
   *
   * <p>Reads the session from Redis and extends it only after refreshing authorization. Returns 401
   * if the session or account is invalid and 503 if the refresh cannot be completed.
   *
   * @param exchange the server web exchange
   * @return session status with expiry metadata
   */
  @Operation(
      summary = "Session heartbeat",
      description =
          "Refreshes current authorization and extends the local session only after a successful "
              + "permission-service lookup.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Session is valid",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = SessionStatusResponse.class))),
        @ApiResponse(
            responseCode = "401",
            description = "No valid session or active account",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(
            responseCode = "503",
            description = "Authorization refresh or Redis update unavailable",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = ApiErrorResponse.class)))
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
        .flatMap(sessionData -> refreshSession(exchange, sessionId, sessionData))
        .onErrorMap(
            exception -> !(exception instanceof ResponseStatusException),
            exception -> {
              log.warn(
                  "Session heartbeat failed for sessionId={} exceptionType={}",
                  SafeLogger.truncateId(sessionId),
                  exception.getClass().getSimpleName());
              return new ResponseStatusException(
                  HttpStatus.SERVICE_UNAVAILABLE, "Session refresh unavailable", exception);
            });
  }

  private Mono<SessionStatusResponse> refreshSession(
      ServerWebExchange exchange, String sessionId, SessionData sessionData) {
    return permissionServiceClient
        .fetchAuthorization(sessionData.userId())
        .flatMap(
            authorizationResponse -> {
              if (authorizationResponse.status() == AccountStatus.DEACTIVATED) {
                return invalidateSession(exchange, sessionId);
              }

              return updateSession(exchange, sessionId, sessionData, authorizationResponse);
            })
        .switchIfEmpty(invalidateSession(exchange, sessionId));
  }

  private Mono<SessionStatusResponse> updateSession(
      ServerWebExchange exchange,
      String sessionId,
      SessionData sessionData,
      AuthorizationResponse authorizationResponse) {
    return sessionWriter
        .refreshSessionAuthorization(
            sessionId,
            sessionData.userId(),
            authorizationResponse.roles(),
            authorizationResponse.permissions(),
            sessionTtlSeconds)
        .map(
            expiresAt ->
                new SessionStatusResponse(
                    sessionData.userId(),
                    authorizationResponse.roles(),
                    expiresAt.getEpochSecond()))
        .switchIfEmpty(
            Mono.defer(
                () -> {
                  log.warn(
                      "Session {} disappeared during heartbeat", SafeLogger.truncateId(sessionId));
                  return unauthorizedAndClearCookie(exchange);
                }));
  }

  private Mono<SessionStatusResponse> invalidateSession(
      ServerWebExchange exchange, String sessionId) {
    return sessionWriter.deleteSession(sessionId).then(unauthorizedAndClearCookie(exchange));
  }

  private <T> Mono<T> unauthorizedAndClearCookie(ServerWebExchange exchange) {
    return Mono.defer(
        () -> {
          sessionCookieHelper.clearSessionCookie(exchange);
          return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        });
  }
}
