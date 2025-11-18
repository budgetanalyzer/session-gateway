package org.budgetanalyzer.sessiongateway.controller;

import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import reactor.core.publisher.Mono;

/**
 * User information controller.
 *
 * <p>Provides endpoints for the frontend to check authentication status and retrieve user
 * information.
 *
 * <p>Bonus feature for Phase 5: Frontend Integration
 */
@RestController
public class UserController {

  private static final Logger logger = LoggerFactory.getLogger(UserController.class);

  /**
   * Returns the current authenticated user's information.
   *
   * <p>The frontend can call this endpoint to:
   *
   * <ul>
   *   <li>Check if the user is authenticated (200 OK if authenticated, 401 if not)
   *   <li>Get user information (name, email, etc.)
   * </ul>
   *
   * @param authentication the current authentication
   * @return user information
   */
  @GetMapping("/user")
  public Mono<Map<String, Object>> getCurrentUser(Authentication authentication) {
    if (authentication == null) {
      logger.debug("No authentication found for /user request");
      return Mono.empty();
    }

    logger.debug("User info requested for: {}", authentication.getName());

    Map<String, Object> userInfo = new HashMap<>();

    if (authentication instanceof OAuth2AuthenticationToken oauth2Token) {
      OAuth2User oauth2User = oauth2Token.getPrincipal();

      // Extract common user attributes
      userInfo.put("sub", oauth2User.getAttribute("sub")); // User ID
      userInfo.put("name", oauth2User.getAttribute("name"));
      userInfo.put("email", oauth2User.getAttribute("email"));
      userInfo.put("picture", oauth2User.getAttribute("picture")); // Profile picture URL
      userInfo.put("emailVerified", oauth2User.getAttribute("email_verified"));

      // Add authentication metadata
      userInfo.put("authenticated", true);
      userInfo.put("registrationId", oauth2Token.getAuthorizedClientRegistrationId());

      logger.debug("Returning user info for: {}", authentication.getName());
    } else {
      // Fallback for non-OAuth2 authentication (shouldn't happen in this app)
      userInfo.put("name", authentication.getName());
      userInfo.put("authenticated", true);
    }

    return Mono.just(userInfo);
  }
}
