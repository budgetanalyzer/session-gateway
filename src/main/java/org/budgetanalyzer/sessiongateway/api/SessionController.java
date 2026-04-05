package org.budgetanalyzer.sessiongateway.api;

import java.time.Clock;
import java.time.Duration;

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
import org.budgetanalyzer.sessiongateway.service.IdpTokenRefreshClient;
import org.budgetanalyzer.sessiongateway.service.IdpTokenRefreshClient.IdpGrantRevokedException;
import org.budgetanalyzer.sessiongateway.service.IdpTokenRefreshClient.IdpTokenRefreshException;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Session heartbeat controller.
 *
 * <p>Validates the IDP grant and extends session TTL. The frontend calls this endpoint periodically
 * to keep the session alive and ensure the IDP grant has not been revoked.
 */
@Tag(name = "Session", description = "Session heartbeat and status")
@RestController
public class SessionController {

  private static final Logger log = LoggerFactory.getLogger(SessionController.class);

  private final SessionReader sessionReader;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;
  private final IdpTokenRefreshClient idpTokenRefreshClient;
  private final Clock clock;
  private final long sessionTtlSeconds;
  private final long refreshThresholdSeconds;

  /**
   * Creates a new SessionController.
   *
   * @param sessionReader reads session data from Redis
   * @param sessionWriter writes session data to Redis
   * @param sessionCookieHelper manages session cookies
   * @param idpTokenRefreshClient refreshes IDP tokens
   * @param clock the clock for computing expiry instants
   * @param sessionProperties validated session configuration
   */
  public SessionController(
      SessionReader sessionReader,
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      IdpTokenRefreshClient idpTokenRefreshClient,
      Clock clock,
      SessionProperties sessionProperties) {
    this.sessionReader = sessionReader;
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.idpTokenRefreshClient = idpTokenRefreshClient;
    this.clock = clock;
    this.sessionTtlSeconds = sessionProperties.ttlSeconds();
    this.refreshThresholdSeconds = sessionProperties.refreshThresholdSeconds();
  }

  /**
   * Session heartbeat endpoint.
   *
   * <p>Reads the session from Redis, optionally refreshes the IDP token if near expiry, and extends
   * the session TTL. Returns 401 if no valid session exists or the IDP grant was revoked.
   *
   * @param exchange the server web exchange
   * @return session status with expiry metadata
   */
  @Operation(
      summary = "Session heartbeat",
      description =
          "Validates the session, refreshes the IDP token if near expiry, "
              + "and extends the session TTL. Returns 401 if no valid session "
              + "or the IDP grant was revoked.")
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
            description = "No valid session or IDP grant revoked",
            content = @Content)
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
        .flatMap(sessionData -> processHeartbeat(exchange, sessionId, sessionData));
  }

  private Mono<SessionStatusResponse> processHeartbeat(
      ServerWebExchange exchange, String sessionId, SessionData sessionData) {
    var secondsUntilTokenExpiry =
        Duration.between(clock.instant(), sessionData.tokenExpiresAt()).toSeconds();
    var tokenExpired = secondsUntilTokenExpiry <= 0;

    if (tokenExpired && sessionData.refreshToken() == null) {
      log.warn(
          "Token expired with no refresh token for sessionId={}, denying heartbeat",
          SafeLogger.truncateId(sessionId));
      return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    var needsRefresh =
        secondsUntilTokenExpiry <= refreshThresholdSeconds && sessionData.refreshToken() != null;

    if (needsRefresh) {
      return refreshAndExtend(exchange, sessionId, sessionData);
    }

    return extendSession(exchange, sessionId, sessionData);
  }

  private Mono<SessionStatusResponse> refreshAndExtend(
      ServerWebExchange exchange, String sessionId, SessionData sessionData) {
    log.debug(
        "Token near expiry for sessionId={}, attempting IDP refresh",
        SafeLogger.truncateId(sessionId));

    return idpTokenRefreshClient
        .refresh(sessionData.refreshToken())
        .flatMap(
            refreshResult -> {
              var newRefreshToken =
                  refreshResult.refreshToken() != null
                      ? refreshResult.refreshToken()
                      : sessionData.refreshToken();

              return sessionWriter
                  .updateTokenAndExpiry(
                      sessionId,
                      sessionData.userId(),
                      newRefreshToken,
                      refreshResult.tokenExpiresAt(),
                      sessionTtlSeconds)
                  .flatMap(
                      updated -> {
                        if (!updated) {
                          log.warn(
                              "Session {} disappeared during token refresh",
                              SafeLogger.truncateId(sessionId));
                          return unauthorizedAndClearCookie(exchange);
                        }
                        return buildResponse(sessionData, true);
                      });
            })
        // Grant revocation is a deliberate IDP decision — destroy the session immediately.
        .onErrorResume(
            IdpGrantRevokedException.class,
            ex -> {
              log.warn(
                  "IDP grant revoked for sessionId={}, terminating session",
                  SafeLogger.truncateId(sessionId));
              sessionCookieHelper.clearSessionCookie(exchange);

              return sessionWriter
                  .deleteSession(sessionId)
                  .then(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)));
            })
        // Transient IDP failure (unreachable, 5xx, non-revocation 4xx): preserve the session so
        // the frontend can retry on the next heartbeat. The session only expires if TTL lapses
        // while the IDP remains down.
        .onErrorResume(
            IdpTokenRefreshException.class,
            ex -> {
              log.warn(
                  "IDP token refresh failed for sessionId={}, denying heartbeat",
                  SafeLogger.truncateId(sessionId),
                  ex);
              return Mono.error(new ResponseStatusException(HttpStatus.BAD_GATEWAY));
            });
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
              return buildResponse(sessionData, false);
            });
  }

  private Mono<SessionStatusResponse> buildResponse(
      SessionData sessionData, boolean tokenRefreshed) {
    var expiresAt = clock.instant().plusSeconds(sessionTtlSeconds);

    return Mono.just(
        new SessionStatusResponse(
            true,
            sessionData.userId(),
            sessionData.roles(),
            expiresAt.getEpochSecond(),
            tokenRefreshed));
  }

  private <T> Mono<T> unauthorizedAndClearCookie(ServerWebExchange exchange) {
    return Mono.defer(
        () -> {
          sessionCookieHelper.clearSessionCookie(exchange);
          return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
        });
  }
}
