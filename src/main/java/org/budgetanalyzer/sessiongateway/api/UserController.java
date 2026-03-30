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

import org.budgetanalyzer.sessiongateway.api.response.UserInfoResponse;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionReader;

/**
 * User information controller.
 *
 * <p>Provides endpoints for the frontend to check authentication status and retrieve user
 * information including roles for UI visibility decisions.
 */
@Tag(name = "User", description = "Authentication status and user information")
@RestController
public class UserController {

  private static final Logger log = LoggerFactory.getLogger(UserController.class);

  private final SessionReader sessionReader;
  private final SessionCookieHelper sessionCookieHelper;

  public UserController(SessionReader sessionReader, SessionCookieHelper sessionCookieHelper) {
    this.sessionReader = sessionReader;
    this.sessionCookieHelper = sessionCookieHelper;
  }

  /**
   * Returns the current authenticated user's information.
   *
   * @param exchange the current server exchange
   * @return user information including roles
   */
  @Operation(
      summary = "Get current user info",
      description =
          "Returns the authenticated user's profile and roles. "
              + "Returns 200 with user info if authenticated, or empty 401 if not.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Authenticated user info",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = UserInfoResponse.class))),
        @ApiResponse(responseCode = "401", description = "Not authenticated", content = @Content)
      })
  @GetMapping("/user")
  public Mono<UserInfoResponse> getCurrentUser(ServerWebExchange exchange) {
    var sessionId = sessionCookieHelper.readSessionId(exchange);
    if (sessionId == null || sessionId.isBlank()) {
      log.debug("No session cookie found for /user request");
      return Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED));
    }

    log.debug("User info requested for sessionId={}", sessionId);

    return sessionReader
        .readSession(sessionId)
        .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED)))
        .map(
            sessionData ->
                new UserInfoResponse(
                    sessionData.idpSub(),
                    sessionData.displayName(),
                    sessionData.email(),
                    sessionData.picture(),
                    true,
                    sessionData.roles()));
  }
}
