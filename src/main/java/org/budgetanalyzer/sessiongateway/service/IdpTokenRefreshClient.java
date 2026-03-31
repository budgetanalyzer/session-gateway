package org.budgetanalyzer.sessiongateway.service;

import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import reactor.core.publisher.Mono;

/**
 * Client for refreshing IDP access tokens via the OAuth2 token endpoint.
 *
 * <p>Posts a {@code refresh_token} grant to the IDP token endpoint using OAuth2 client credentials
 * from the client registration. An {@code invalid_grant} error response signals that the IDP has
 * revoked the grant; other 4xx responses are treated as transient failures.
 */
@Service
public class IdpTokenRefreshClient {

  private static final Logger log = LoggerFactory.getLogger(IdpTokenRefreshClient.class);
  private static final String REGISTRATION_ID = "idp";
  private static final String INVALID_GRANT_ERROR = "invalid_grant";

  private final ReactiveClientRegistrationRepository clientRegistrationRepository;
  private final WebClient webClient;
  private final Clock clock;

  /**
   * Creates a new IdpTokenRefreshClient.
   *
   * @param clientRegistrationRepository the OAuth2 client registration repository
   * @param clock the clock for computing token expiry instants
   */
  public IdpTokenRefreshClient(
      ReactiveClientRegistrationRepository clientRegistrationRepository, Clock clock) {
    this.clientRegistrationRepository = clientRegistrationRepository;
    this.webClient = WebClient.create();
    this.clock = clock;
  }

  /**
   * Refreshes an IDP access token using a refresh token.
   *
   * @param refreshToken the current refresh token
   * @return the refresh result containing new tokens and expiry
   */
  public Mono<TokenRefreshResult> refresh(String refreshToken) {
    log.debug("Attempting IDP token refresh");

    return clientRegistrationRepository
        .findByRegistrationId(REGISTRATION_ID)
        .switchIfEmpty(
            Mono.error(
                new IllegalStateException(
                    "OAuth2 client registration '" + REGISTRATION_ID + "' not found")))
        .flatMap(clientRegistration -> executeRefresh(clientRegistration, refreshToken));
  }

  private Mono<TokenRefreshResult> executeRefresh(
      ClientRegistration clientRegistration, String refreshToken) {
    var formData = new LinkedMultiValueMap<String, String>();
    formData.add("grant_type", "refresh_token");
    formData.add("client_id", clientRegistration.getClientId());
    formData.add("client_secret", clientRegistration.getClientSecret());
    formData.add("refresh_token", refreshToken);

    return webClient
        .post()
        .uri(clientRegistration.getProviderDetails().getTokenUri())
        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
        .body(BodyInserters.fromFormData(formData))
        .retrieve()
        .onStatus(
            HttpStatusCode::is4xxClientError,
            response ->
                response
                    .bodyToMono(String.class)
                    .defaultIfEmpty("")
                    .flatMap(
                        body -> {
                          log.warn(
                              "IDP token refresh denied ({}): {}", response.statusCode(), body);
                          if (isGrantRevocation(body)) {
                            return Mono.error(
                                new IdpGrantRevokedException(
                                    "IDP grant revoked: " + response.statusCode()));
                          }
                          return Mono.error(
                              new IdpTokenRefreshException(
                                  "IDP token endpoint client error: " + response.statusCode()));
                        }))
        .onStatus(
            HttpStatusCode::is5xxServerError,
            response ->
                Mono.error(
                    new IdpTokenRefreshException(
                        "IDP token endpoint error: " + response.statusCode())))
        .bodyToMono(TokenEndpointResponse.class)
        .onErrorMap(
            WebClientRequestException.class,
            ex -> new IdpTokenRefreshException("IDP token endpoint unreachable", ex))
        .map(this::toResult)
        .doOnSuccess(
            result ->
                log.debug("IDP token refresh successful, expires in {}s", result.expiresIn()));
  }

  private static boolean isGrantRevocation(String responseBody) {
    return responseBody.contains("\"" + INVALID_GRANT_ERROR + "\"");
  }

  private TokenRefreshResult toResult(TokenEndpointResponse tokenEndpointResponse) {
    var tokenExpiresAt = clock.instant().plusSeconds(tokenEndpointResponse.expiresIn());
    return new TokenRefreshResult(
        tokenEndpointResponse.refreshToken(), tokenEndpointResponse.expiresIn(), tokenExpiresAt);
  }

  /**
   * Result of a successful IDP token refresh.
   *
   * @param refreshToken the new refresh token (null if the IDP did not rotate)
   * @param expiresIn seconds until the new access token expires
   * @param tokenExpiresAt the computed instant when the new access token expires
   */
  public record TokenRefreshResult(String refreshToken, long expiresIn, Instant tokenExpiresAt) {}

  /** Deserialization target for the IDP token endpoint response. */
  @JsonIgnoreProperties(ignoreUnknown = true)
  private record TokenEndpointResponse(
      @JsonProperty("access_token") String accessToken,
      @JsonProperty("refresh_token") String refreshToken,
      @JsonProperty("expires_in") long expiresIn) {}

  /**
   * Thrown when the IDP returns an {@code invalid_grant} error, indicating the grant was revoked.
   *
   * <p>Callers should destroy the session immediately — this is a deliberate IDP decision (user
   * disabled, consent withdrawn), not a transient failure.
   */
  public static class IdpGrantRevokedException extends RuntimeException {

    /**
     * Creates a new IdpGrantRevokedException.
     *
     * @param message the error message
     */
    public IdpGrantRevokedException(String message) {
      super(message);
    }
  }

  /**
   * Thrown when the IDP token endpoint is unavailable or returns a non-revocation error.
   *
   * <p>Callers should treat this as a transient failure: the session should be preserved so the
   * client can retry on the next heartbeat. Contrast with {@link IdpGrantRevokedException}, which
   * signals a deliberate IDP decision requiring immediate session termination.
   */
  public static class IdpTokenRefreshException extends RuntimeException {

    /**
     * Creates a new IdpTokenRefreshException.
     *
     * @param message the error message
     */
    public IdpTokenRefreshException(String message) {
      super(message);
    }

    /**
     * Creates a new IdpTokenRefreshException with a cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public IdpTokenRefreshException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
