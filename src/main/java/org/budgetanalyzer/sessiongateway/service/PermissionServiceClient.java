package org.budgetanalyzer.sessiongateway.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.core.logging.SafeLogger;
import org.budgetanalyzer.sessiongateway.config.PermissionServiceProperties;

/** Reactive client for the permission-service internal API. */
@Service
public class PermissionServiceClient {

  private static final Logger log = LoggerFactory.getLogger(PermissionServiceClient.class);

  private final WebClient webClient;
  private final PermissionServiceProperties permissionServiceProperties;

  /**
   * Creates a new PermissionServiceClient.
   *
   * @param webClient the WebClient configured for the permission-service
   * @param permissionServiceProperties validated permission-service configuration
   */
  public PermissionServiceClient(
      @Qualifier("permissionServiceWebClient") WebClient webClient,
      PermissionServiceProperties permissionServiceProperties) {
    this.webClient = webClient;
    this.permissionServiceProperties = permissionServiceProperties;
  }

  /**
   * Fetches permissions for a user identified by their IDP subject.
   *
   * @param idpSub the IDP subject identifier
   * @param email the user's email address from the IDP
   * @param displayName the user's display name from the IDP
   * @return the user's permissions response
   */
  public Mono<PermissionResponse> fetchPermissions(
      String idpSub, String email, String displayName) {
    log.debug("Fetching permissions for idpSub={}", SafeLogger.truncateId(idpSub));

    return webClient
        .get()
        .uri(
            uriBuilder ->
                uriBuilder
                    .path("/internal/v1/users/{idpSub}/permissions")
                    .queryParam("email", email)
                    .queryParam("displayName", displayName)
                    .build(idpSub))
        .retrieve()
        .onStatus(
            HttpStatusCode::isError,
            response ->
                response
                    .bodyToMono(String.class)
                    .defaultIfEmpty("")
                    .flatMap(
                        body ->
                            Mono.error(
                                new PermissionServiceException(
                                    "Permission service returned "
                                        + response.statusCode()
                                        + ": "
                                        + body))))
        .bodyToMono(PermissionResponse.class)
        .doOnSuccess(
            r ->
                log.debug(
                    "Fetched {} roles and {} permissions for idpSub={}",
                    r.roles().size(),
                    r.permissions().size(),
                    SafeLogger.truncateId(idpSub)));
  }

  /**
   * Fetches the current account status and authorization grants by internal user ID.
   *
   * <p>A missing user is represented by an empty result. All other non-success responses, transport
   * failures, timeouts, and invalid payloads fail with {@link PermissionServiceException}.
   *
   * @param userId the internal user ID stored in the session
   * @return the current authorization, or empty when the user is missing
   */
  public Mono<AuthorizationResponse> fetchAuthorization(String userId) {
    log.debug("Refreshing authorization for userId={}", SafeLogger.truncateId(userId));

    return webClient
        .get()
        .uri("/internal/v1/users/{userId}/authorization", userId)
        .exchangeToMono(
            response -> {
              if (response.statusCode().value() == 404) {
                return response.releaseBody().then(Mono.<AuthorizationResponse>empty());
              }
              if (response.statusCode().isError()) {
                return response
                    .releaseBody()
                    .then(
                        Mono.error(
                            new PermissionServiceException(
                                "Permission service authorization lookup returned "
                                    + response.statusCode())));
              }

              return response
                  .bodyToMono(AuthorizationResponse.class)
                  .switchIfEmpty(
                      Mono.error(
                          new PermissionServiceException(
                              "Permission service authorization lookup returned an empty body")))
                  .map(
                      authorizationResponse ->
                          validateAuthorization(userId, authorizationResponse));
            })
        .timeout(permissionServiceProperties.authorizationRefreshTimeout())
        .onErrorMap(
            exception -> !(exception instanceof PermissionServiceException),
            exception ->
                new PermissionServiceException(
                    "Permission service authorization lookup failed", exception))
        .doOnNext(
            authorizationResponse ->
                log.debug(
                    "Refreshed {} roles and {} permissions for userId={}",
                    authorizationResponse.roles().size(),
                    authorizationResponse.permissions().size(),
                    SafeLogger.truncateId(userId)));
  }

  private AuthorizationResponse validateAuthorization(
      String requestedUserId, AuthorizationResponse authorizationResponse) {
    if (authorizationResponse.userId() == null
        || !authorizationResponse.userId().equals(requestedUserId)
        || authorizationResponse.status() == null
        || authorizationResponse.roles() == null
        || authorizationResponse.permissions() == null) {
      throw new PermissionServiceException(
          "Permission service authorization lookup returned an invalid payload");
    }

    return authorizationResponse;
  }

  /**
   * Response from the permission-service internal endpoint.
   *
   * @param userId the internal user ID
   * @param roles the user's roles
   * @param permissions the user's permissions
   */
  public record PermissionResponse(String userId, List<String> roles, List<String> permissions) {}

  /** Account states returned by the authorization lookup. */
  public enum AccountStatus {
    /** The account is eligible for session refresh. */
    ACTIVE,

    /** The account must not retain a browser session. */
    DEACTIVATED
  }

  /**
   * Current authorization response from permission-service.
   *
   * @param userId the internal user ID
   * @param status the current account status
   * @param roles the current roles
   * @param permissions the current permissions
   */
  public record AuthorizationResponse(
      String userId, AccountStatus status, List<String> roles, List<String> permissions) {}

  /** Exception thrown when the permission-service returns a non-2xx response. */
  public static class PermissionServiceException extends RuntimeException {

    /**
     * Creates a new PermissionServiceException.
     *
     * @param message the error message
     */
    public PermissionServiceException(String message) {
      super(message);
    }

    /**
     * Creates a new PermissionServiceException with its cause.
     *
     * @param message the error message
     * @param cause the underlying failure
     */
    public PermissionServiceException(String message, Throwable cause) {
      super(message, cause);
    }
  }
}
