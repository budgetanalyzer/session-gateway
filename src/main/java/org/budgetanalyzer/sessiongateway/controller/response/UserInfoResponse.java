package org.budgetanalyzer.sessiongateway.controller.response;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response containing the authenticated user's information.
 *
 * <p>Returned by the /user endpoint for the frontend to check authentication status, display user
 * info, and determine role-based UI visibility.
 *
 * @param sub the user's IDP subject identifier (e.g., "auth0|abc123")
 * @param name the user's display name
 * @param email the user's email address
 * @param picture the user's profile picture URL
 * @param emailVerified whether the user's email has been verified
 * @param authenticated always true when this response is returned
 * @param registrationId the OAuth2 client registration ID (e.g., "idp")
 * @param roles the user's roles (e.g., ["ADMIN"] or ["USER"])
 */
@Schema(description = "Authenticated user information")
public record UserInfoResponse(
    @Schema(description = "IDP subject identifier", example = "auth0|abc123") String sub,
    @Schema(description = "User's display name", example = "Jane Doe") String name,
    @Schema(description = "User's email address", example = "jane@example.com") String email,
    @Schema(description = "Profile picture URL", example = "https://example.com/photo.jpg")
        String picture,
    @Schema(description = "Whether the user's email has been verified", example = "true")
        Boolean emailVerified,
    @Schema(description = "Always true when this response is returned", example = "true")
        boolean authenticated,
    @Schema(description = "OAuth2 client registration ID", example = "idp") String registrationId,
    @Schema(description = "User's roles for UI visibility", example = "[\"USER\"]")
        List<String> roles) {}
