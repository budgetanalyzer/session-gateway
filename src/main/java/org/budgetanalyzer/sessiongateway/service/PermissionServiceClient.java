package org.budgetanalyzer.sessiongateway.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/** Reactive client for the permission-service internal API. */
@Service
public class PermissionServiceClient {

  private static final Logger log = LoggerFactory.getLogger(PermissionServiceClient.class);

  private final WebClient webClient;

  /**
   * Creates a new PermissionServiceClient.
   *
   * @param webClient the WebClient configured for the permission-service
   */
  public PermissionServiceClient(@Qualifier("permissionServiceWebClient") WebClient webClient) {
    this.webClient = webClient;
  }

  /**
   * Fetches permissions for a user identified by their IDP subject.
   *
   * @param idpSub the IDP subject identifier
   * @return the user's permissions response
   */
  public Mono<PermissionResponse> fetchPermissions(String idpSub) {
    log.debug("Fetching permissions for idpSub={}", idpSub);

    return webClient
        .get()
        .uri("/internal/v1/users/{idpSub}/permissions", idpSub)
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
        .doOnSuccess(r -> log.debug("Fetched permissions for idpSub={}: {}", idpSub, r));
  }

  /**
   * Response from the permission-service internal endpoint.
   *
   * @param userId the internal user ID
   * @param roles the user's roles
   * @param permissions the user's permissions
   */
  public record PermissionResponse(String userId, List<String> roles, List<String> permissions) {}

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
  }
}
