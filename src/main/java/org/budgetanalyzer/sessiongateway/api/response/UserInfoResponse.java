package org.budgetanalyzer.sessiongateway.api.response;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response containing the authenticated user's information.
 *
 * <p>Returned by the /user endpoint for the frontend to check authentication status, display user
 * info, and determine role-based UI visibility and action-level permission gating.
 *
 * @param sub the user's IDP subject identifier (e.g., "auth0|abc123")
 * @param name the user's display name
 * @param email the user's email address
 * @param picture the user's profile picture URL
 * @param authenticated always true when this response is returned
 * @param roles the user's roles for layout-level UI visibility (e.g., ["ADMIN"] or ["USER"])
 * @param permissions resolved permission IDs used for action-level UI gating; see
 *     permission-service for the authoritative list
 */
@Schema(description = "Authenticated user information")
public record UserInfoResponse(
    @Schema(description = "IDP subject identifier", example = "auth0|abc123") String sub,
    @Schema(description = "User's display name", example = "Jane Doe") String name,
    @Schema(description = "User's email address", example = "jane@example.com") String email,
    @Schema(description = "Profile picture URL", example = "https://example.com/photo.jpg")
        String picture,
    @Schema(description = "Always true when this response is returned", example = "true")
        boolean authenticated,
    @Schema(description = "User's roles for UI visibility", example = "[\"USER\"]")
        List<String> roles,
    @Schema(
            description = "User's resolved permissions for action-level UI gating",
            example = "[\"transactions:read\",\"transactions:read:any\"]")
        List<String> permissions) {}
