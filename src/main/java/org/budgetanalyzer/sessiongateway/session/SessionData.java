package org.budgetanalyzer.sessiongateway.session;

import java.time.Instant;
import java.util.List;

/**
 * Deserialized session data from the Redis session hash.
 *
 * @param userId internal user ID from the permission service
 * @param idpSub IDP subject identifier
 * @param email user's email address
 * @param displayName user's display name
 * @param picture user's profile picture URL (may be empty)
 * @param roles user roles
 * @param permissions user permissions
 * @param createdAt when the session was created
 * @param expiresAt when the session expires
 */
public record SessionData(
    String userId,
    String idpSub,
    String email,
    String displayName,
    String picture,
    List<String> roles,
    List<String> permissions,
    Instant createdAt,
    Instant expiresAt) {}
