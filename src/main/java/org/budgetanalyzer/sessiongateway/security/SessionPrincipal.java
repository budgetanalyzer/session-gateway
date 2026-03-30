package org.budgetanalyzer.sessiongateway.security;

import java.util.List;

import org.springframework.security.core.AuthenticatedPrincipal;

/**
 * Authenticated principal reconstructed from the canonical Redis session hash.
 *
 * @param userId internal user ID from the permission service
 * @param idpSub IDP subject identifier
 * @param email user's email address
 * @param displayName user's display name
 * @param picture user's profile picture URL
 * @param roles user roles
 * @param permissions user permissions
 */
public record SessionPrincipal(
    String userId,
    String idpSub,
    String email,
    String displayName,
    String picture,
    List<String> roles,
    List<String> permissions)
    implements AuthenticatedPrincipal {

  @Override
  public String getName() {
    return idpSub;
  }
}
