package org.budgetanalyzer.sessiongateway.api;

import java.util.ArrayList;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpStatus;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.Session;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ResponseStatusException;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.api.request.TokenExchangeRequest;
import org.budgetanalyzer.sessiongateway.api.response.TokenExchangeResponse;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.session.ExtAuthzSessionWriter;
import org.budgetanalyzer.sessiongateway.session.SessionAttributes;

/**
 * Token exchange controller for native PKCE/M2M clients.
 *
 * <p>Accepts an IDP access token and creates a Redis session, returning an opaque bearer token that
 * can be used for subsequent API requests via ext_authz validation.
 */
@Tag(name = "Token Exchange", description = "Token exchange for native clients")
@RestController
public class TokenExchangeController {

  private static final Logger log = LoggerFactory.getLogger(TokenExchangeController.class);

  private final PermissionServiceClient permissionServiceClient;
  private final ExtAuthzSessionWriter extAuthzSessionWriter;

  @SuppressWarnings("unchecked")
  private final ReactiveSessionRepository<Session> reactiveSessionRepository;

  private final WebClient userinfoWebClient;
  private final long ttlSeconds;

  /**
   * Creates a new TokenExchangeController.
   *
   * @param permissionServiceClient the permission service client
   * @param extAuthzSessionWriter the ext_authz session writer
   * @param reactiveSessionRepository the reactive session repository
   * @param issuerUri the IDP issuer URI for userinfo endpoint
   * @param ttlSeconds the session TTL in seconds
   */
  @SuppressWarnings("unchecked")
  public TokenExchangeController(
      PermissionServiceClient permissionServiceClient,
      ExtAuthzSessionWriter extAuthzSessionWriter,
      ReactiveSessionRepository<? extends Session> reactiveSessionRepository,
      @Value("${spring.security.oauth2.client.provider.idp.issuer-uri}") String issuerUri,
      @Value("${extauthz.session.ttl-seconds:1800}") long ttlSeconds) {
    this.permissionServiceClient = permissionServiceClient;
    this.extAuthzSessionWriter = extAuthzSessionWriter;
    this.reactiveSessionRepository = (ReactiveSessionRepository<Session>) reactiveSessionRepository;
    this.ttlSeconds = ttlSeconds;

    var normalizedIssuer = issuerUri.endsWith("/") ? issuerUri : issuerUri + "/";
    this.userinfoWebClient = WebClient.builder().baseUrl(normalizedIssuer + "userinfo").build();
  }

  /**
   * Exchanges an IDP access token for an opaque session bearer token.
   *
   * @param request the token exchange request containing the IDP access token
   * @return the token exchange response with an opaque bearer token
   */
  @Operation(
      summary = "Exchange IDP token for session token",
      description =
          "Validates an IDP access token via userinfo, creates a session, "
              + "and returns an opaque bearer token for native clients.")
  @ApiResponses(
      value = {
        @ApiResponse(
            responseCode = "200",
            description = "Token exchange successful",
            content =
                @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = TokenExchangeResponse.class))),
        @ApiResponse(responseCode = "400", description = "Missing or blank access token"),
        @ApiResponse(responseCode = "401", description = "Invalid IDP access token"),
        @ApiResponse(responseCode = "500", description = "Permission service error")
      })
  @PostMapping("/auth/token/exchange")
  public Mono<TokenExchangeResponse> exchangeToken(@RequestBody TokenExchangeRequest request) {
    if (request.accessToken() == null || request.accessToken().isBlank()) {
      return Mono.error(
          new ResponseStatusException(HttpStatus.BAD_REQUEST, "accessToken is required"));
    }

    log.debug("Processing token exchange request");

    return validateTokenViaUserinfo(request.accessToken()).flatMap(this::createSessionAndRespond);
  }

  private Mono<Map<String, Object>> validateTokenViaUserinfo(String accessToken) {
    return userinfoWebClient
        .get()
        .headers(h -> h.setBearerAuth(accessToken))
        .retrieve()
        .onStatus(
            status -> status.is4xxClientError() || status.is5xxServerError(),
            response ->
                Mono.error(
                    new ResponseStatusException(
                        HttpStatus.UNAUTHORIZED, "Invalid IDP access token")))
        .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {});
  }

  private Mono<TokenExchangeResponse> createSessionAndRespond(
      Map<String, Object> userinfoResponse) {
    var idpSub = (String) userinfoResponse.get("sub");
    var email = (String) userinfoResponse.getOrDefault("email", "");
    var displayName = (String) userinfoResponse.getOrDefault("name", "");

    log.debug("Token validated for idpSub={}, fetching permissions", idpSub);

    return permissionServiceClient
        .fetchPermissions(idpSub, email, displayName)
        .flatMap(
            permissionResponse ->
                reactiveSessionRepository
                    .createSession()
                    .flatMap(
                        session -> {
                          session.setAttribute(
                              SessionAttributes.SESSION_USER_ID, permissionResponse.userId());
                          session.setAttribute(
                              SessionAttributes.SESSION_ROLES,
                              new ArrayList<>(permissionResponse.roles()));
                          session.setAttribute(
                              SessionAttributes.SESSION_PERMISSIONS,
                              new ArrayList<>(permissionResponse.permissions()));

                          return reactiveSessionRepository
                              .save(session)
                              .then(
                                  extAuthzSessionWriter.writeSession(
                                      session.getId(),
                                      permissionResponse.userId(),
                                      permissionResponse.roles(),
                                      permissionResponse.permissions()))
                              .thenReturn(
                                  new TokenExchangeResponse(session.getId(), ttlSeconds, "Bearer"));
                        }))
        .doOnSuccess(response -> log.info("Token exchange successful, session created"))
        .onErrorMap(
            ex -> !(ex instanceof ResponseStatusException),
            ex ->
                new ResponseStatusException(
                    HttpStatus.INTERNAL_SERVER_ERROR, "Token exchange failed: " + ex.getMessage()));
  }
}
