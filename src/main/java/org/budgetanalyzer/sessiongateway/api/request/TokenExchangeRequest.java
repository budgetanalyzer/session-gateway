package org.budgetanalyzer.sessiongateway.api.request;

import io.swagger.v3.oas.annotations.media.Schema;

/**
 * Request for token exchange.
 *
 * @param accessToken the IDP access token to exchange for an opaque session token
 */
@Schema(description = "Token exchange request")
public record TokenExchangeRequest(
    @Schema(description = "IDP access token", requiredMode = Schema.RequiredMode.REQUIRED)
        String accessToken) {}
