package org.budgetanalyzer.sessiongateway.api;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.WebSession;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.api.response.UserInfoResponse;
import org.budgetanalyzer.sessiongateway.session.SessionAttributes;

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

  /**
   * Returns the current authenticated user's information.
   *
   * <p>The frontend can call this endpoint to:
   *
   * <ul>
   *   <li>Check if the user is authenticated (200 OK if authenticated, 401 if not)
   *   <li>Get user information (name, email, etc.)
   *   <li>Get user roles for UI visibility (e.g., show admin nav for ADMIN users)
   * </ul>
   *
   * @param authentication the current authentication
   * @param session the web session containing roles and permissions
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
  public Mono<UserInfoResponse> getCurrentUser(Authentication authentication, WebSession session) {
    if (authentication == null) {
      log.debug("No authentication found for /user request");
      return Mono.empty();
    }

    log.debug("User info requested for: {}", authentication.getName());

    @SuppressWarnings("unchecked")
    var roles = (List<String>) session.getAttribute(SessionAttributes.SESSION_ROLES);
    var safeRoles = roles != null ? roles : List.<String>of();

    if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
      var oauth2User = oauth2Token.getPrincipal();

      var response =
          new UserInfoResponse(
              oauth2User.getAttribute("sub"),
              oauth2User.getAttribute("name"),
              oauth2User.getAttribute("email"),
              oauth2User.getAttribute("picture"),
              oauth2User.getAttribute("email_verified"),
              true,
              oauth2Token.getAuthorizedClientRegistrationId(),
              safeRoles);

      log.debug("Returning user info for: {}", authentication.getName());
      return Mono.just(response);
    }

    // Fallback for non-OAuth2 authentication (shouldn't happen in this app)
    var response =
        new UserInfoResponse(
            null, authentication.getName(), null, null, null, true, null, safeRoles);

    return Mono.just(response);
  }
}
