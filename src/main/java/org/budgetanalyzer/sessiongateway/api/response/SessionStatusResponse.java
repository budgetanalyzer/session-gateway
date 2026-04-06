package org.budgetanalyzer.sessiongateway.api.response;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response from the session heartbeat endpoint.
 *
 * @param userId the user's internal ID
 * @param roles the user's roles
 * @param expiresAt unix epoch seconds when the session expires
 */
@Schema(description = "Session status from heartbeat endpoint")
public record SessionStatusResponse(
    @Schema(description = "User's internal ID", example = "user123") String userId,
    @Schema(description = "User's roles", example = "[\"USER\"]") List<String> roles,
    @Schema(description = "Unix epoch seconds when session expires", example = "1711720800")
        long expiresAt) {}
