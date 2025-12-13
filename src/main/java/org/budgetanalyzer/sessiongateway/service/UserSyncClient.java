package org.budgetanalyzer.sessiongateway.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/**
 * Client for syncing users to permission-service after OAuth2 login.
 *
 * <p>This client is called by the authentication success handler to ensure users exist in the
 * permission-service database before accessing protected resources.
 */
@Service
public class UserSyncClient {

  private static final Logger log = LoggerFactory.getLogger(UserSyncClient.class);

  private final WebClient webClient;

  /**
   * Constructs a new UserSyncClient.
   *
   * @param webClientBuilder the WebClient builder
   * @param baseUrl the permission-service base URL
   */
  public UserSyncClient(
      WebClient.Builder webClientBuilder,
      @Value("${budgetanalyzer.permission-service.base-url:http://localhost:8086/permission-service}")
          String baseUrl) {
    this.webClient = webClientBuilder.baseUrl(baseUrl).build();
    log.info("UserSyncClient initialized with base URL: {}", baseUrl);
  }

  /**
   * Syncs a user to permission-service.
   *
   * <p>Creates or updates the user record based on Auth0 data. The sync operation is fire-and-forget
   * - login succeeds even if sync fails. This prevents permission-service downtime from blocking
   * user logins.
   *
   * @param auth0Sub the Auth0 subject identifier
   * @param email the user's email
   * @param displayName the user's display name
   * @param accessToken the OAuth2 access token for authentication
   * @return Mono that completes when sync is done (or fails silently)
   */
  public Mono<Void> syncUser(String auth0Sub, String email, String displayName, String accessToken) {
    log.debug("Syncing user to permission-service: email={}", email);

    return webClient
        .post()
        .uri("/v1/users/sync")
        .header("Authorization", "Bearer " + accessToken)
        .bodyValue(new UserSyncRequest(auth0Sub, email, displayName))
        .retrieve()
        .bodyToMono(UserSyncResponse.class)
        .doOnSuccess(response -> log.info("User synced successfully: email={}, userId={}", email, response.userId()))
        .doOnError(e -> log.error("Failed to sync user: email={}, error={}", email, e.getMessage()))
        .onErrorResume(e -> {
          // Don't fail login if sync fails - user can still access the app
          // Sync will happen again on next login
          log.warn("User sync failed but continuing with login: email={}", email);
          return Mono.empty();
        })
        .then();
  }

  /** Request DTO for user sync. */
  record UserSyncRequest(String auth0Sub, String email, String displayName) {}

  /** Response DTO for user sync. */
  record UserSyncResponse(String userId, String email, String displayName) {}
}
