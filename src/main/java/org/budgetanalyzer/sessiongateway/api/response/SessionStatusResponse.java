package org.budgetanalyzer.sessiongateway.api.response;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response from the session heartbeat endpoint.
 *
 * @param authenticated always true when this response is returned
 * @param userId the user's internal ID
 * @param roles the user's roles
 * @param expiresAt unix epoch seconds when the session expires
 * @param tokenRefreshed whether the IDP token was refreshed during this heartbeat
 */
@Schema(description = "Session status from heartbeat endpoint")
public record SessionStatusResponse(
    @Schema(description = "Always true when this response is returned", example = "true")
        boolean authenticated,
    @Schema(description = "User's internal ID", example = "user123") String userId,
    @Schema(description = "User's roles", example = "[\"USER\"]") List<String> roles,
    @Schema(description = "Unix epoch seconds when session expires", example = "1711720800")
        long expiresAt,
    @Schema(description = "Whether IDP token was refreshed", example = "false")
        boolean tokenRefreshed) {}
