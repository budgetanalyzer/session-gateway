package org.budgetanalyzer.sessiongateway.api.response;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Response from token exchange.
 *
 * @param token the opaque bearer token (session ID)
 * @param expiresIn token lifetime in seconds
 * @param tokenType the token type (always "Bearer")
 */
@Schema(description = "Token exchange response")
public record TokenExchangeResponse(
    @Schema(description = "Opaque bearer token", example = "abc123-session-id") String token,
    @Schema(description = "Token lifetime in seconds", example = "1800") long expiresIn,
    @Schema(description = "Token type", example = "Bearer") String tokenType) {}
