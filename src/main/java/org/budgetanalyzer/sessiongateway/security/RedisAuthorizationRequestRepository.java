package org.budgetanalyzer.sessiongateway.security;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

import reactor.core.publisher.Mono;

/**
 * Redis-backed storage for OAuth2 authorization requests.
 *
 * <p>Stores only the per-request dynamic fields as a flat Redis hash at {@code
 * oauth2:state:{state}} with a 10-minute TTL. The full {@link OAuth2AuthorizationRequest} is
 * reconstructed on load using stored fields plus static properties from the OAuth2 client
 * registration.
 *
 * <p>This avoids serializing the {@link OAuth2AuthorizationRequest} object, which has no stable
 * serialization contract and couples to Spring Security internals across version upgrades.
 *
 * <p>Stored fields:
 *
 * <ul>
 *   <li>{@code redirect_uri} — the OAuth2 callback URI
 *   <li>{@code return_url} — where to redirect after login (from authorization request
 *       additionalParameters, optional)
 *   <li>{@code nonce} — OIDC nonce for ID token validation
 *   <li>{@code code_verifier} — PKCE code verifier for token exchange
 * </ul>
 */
@Component
public class RedisAuthorizationRequestRepository
    implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final String AUTHORIZATION_REQUEST_ATTRIBUTE =
      RedisAuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST";

  private static final Logger log =
      LoggerFactory.getLogger(RedisAuthorizationRequestRepository.class);

  private static final String KEY_PREFIX = "oauth2:state:";
  private static final Duration TTL = Duration.ofMinutes(10);
  private static final String REGISTRATION_ID = "idp";

  private static final String FIELD_REDIRECT_URI = "redirect_uri";
  private static final String FIELD_RETURN_URL = "return_url";
  private static final String FIELD_NONCE = "nonce";
  private static final String FIELD_CODE_VERIFIER = "code_verifier";

  private final ReactiveStringRedisTemplate redisTemplate;
  private final ReactiveClientRegistrationRepository clientRegistrationRepository;

  public RedisAuthorizationRequestRepository(
      ReactiveStringRedisTemplate redisTemplate,
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    this.redisTemplate = redisTemplate;
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  /**
   * Saves the authorization request fields to a Redis hash.
   *
   * <p>If {@code authorizationRequest} is null, removes any existing request for the exchange.
   *
   * @param authorizationRequest the authorization request, or null to remove
   * @param exchange the current server exchange
   * @return completes when the save is done
   */
  @Override
  public Mono<Void> saveAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
    if (authorizationRequest == null) {
      return removeAuthorizationRequest(exchange).then();
    }

    var fields = new HashMap<String, String>();

    fields.put(FIELD_REDIRECT_URI, authorizationRequest.getRedirectUri());

    var returnUrl =
        valueAsString(authorizationRequest.getAdditionalParameters(), FIELD_RETURN_URL)
            .orElseGet(
                () ->
                    queryParamValue(
                            authorizationRequest.getAuthorizationRequestUri(), FIELD_RETURN_URL)
                        .orElseGet(
                            () ->
                                valueAsString(
                                        exchange.getRequest().getQueryParams().toSingleValueMap(),
                                        "returnUrl")
                                    .orElse(null)));
    if (returnUrl != null) {
      fields.put(FIELD_RETURN_URL, returnUrl);
    }

    var nonce =
        valueAsString(authorizationRequest.getAttributes(), OidcParameterNames.NONCE)
            .orElseGet(
                () ->
                    valueAsString(
                            authorizationRequest.getAdditionalParameters(),
                            OidcParameterNames.NONCE)
                        .orElseGet(
                            () ->
                                queryParamValue(
                                        authorizationRequest.getAuthorizationRequestUri(),
                                        OidcParameterNames.NONCE)
                                    .orElse(null)));
    if (nonce != null) {
      fields.put(FIELD_NONCE, nonce);
    }

    var codeVerifier =
        (String) authorizationRequest.getAttributes().get(PkceParameterNames.CODE_VERIFIER);
    if (codeVerifier != null) {
      fields.put(FIELD_CODE_VERIFIER, codeVerifier);
    }

    var state = authorizationRequest.getState();
    var key = KEY_PREFIX + state;
    log.debug("Saving authorization request for state={}", state);

    return redisTemplate
        .<String, String>opsForHash()
        .putAll(key, fields)
        .then(redisTemplate.expire(key, TTL))
        .then();
  }

  /**
   * Loads the authorization request from Redis using the state parameter from the exchange.
   *
   * @param exchange the current server exchange (must contain a {@code state} query parameter)
   * @return the reconstructed authorization request, or empty if not found
   */
  @Override
  public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
    return extractState(exchange).flatMap(this::loadFromRedis);
  }

  /**
   * Removes and returns the authorization request from Redis.
   *
   * <p>Called during the OAuth2 callback to consume the one-time-use authorization request.
   *
   * @param exchange the current server exchange (must contain a {@code state} query parameter)
   * @return the reconstructed authorization request, or empty if not found
   */
  @Override
  public Mono<OAuth2AuthorizationRequest> removeAuthorizationRequest(ServerWebExchange exchange) {
    return extractState(exchange)
        .flatMap(
            state -> {
              var key = KEY_PREFIX + state;
              return loadFromRedis(state)
                  .flatMap(
                      request ->
                          redisTemplate
                              .delete(key)
                              .doOnSuccess(
                                  count ->
                                      exchange
                                          .getAttributes()
                                          .put(AUTHORIZATION_REQUEST_ATTRIBUTE, request))
                              .doOnSuccess(
                                  count ->
                                      log.debug(
                                          "Deleted authorization request for state={}", state))
                              .thenReturn(request));
            });
  }

  private Mono<String> extractState(ServerWebExchange exchange) {
    var state = exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
    return state != null ? Mono.just(state) : Mono.empty();
  }

  private java.util.Optional<String> valueAsString(Map<String, ?> values, String key) {
    var value = values.get(key);
    if (value instanceof String stringValue && !stringValue.isEmpty()) {
      return java.util.Optional.of(stringValue);
    }

    return java.util.Optional.empty();
  }

  private java.util.Optional<String> queryParamValue(String uri, String key) {
    if (uri == null || uri.isBlank()) {
      return java.util.Optional.empty();
    }

    var value = UriComponentsBuilder.fromUriString(uri).build().getQueryParams().getFirst(key);
    if (value == null || value.isBlank()) {
      return java.util.Optional.empty();
    }

    return java.util.Optional.of(value);
  }

  private Mono<OAuth2AuthorizationRequest> loadFromRedis(String state) {
    var key = KEY_PREFIX + state;
    return redisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .filter(fields -> !fields.isEmpty())
        .flatMap(fields -> reconstructRequest(state, fields));
  }

  /**
   * Reconstructs an {@link OAuth2AuthorizationRequest} from stored Redis fields and static client
   * registration properties.
   */
  private Mono<OAuth2AuthorizationRequest> reconstructRequest(
      String state, Map<String, String> fields) {
    return clientRegistrationRepository
        .findByRegistrationId(REGISTRATION_ID)
        .map(
            registration -> {
              var builder =
                  OAuth2AuthorizationRequest.authorizationCode()
                      .authorizationUri(registration.getProviderDetails().getAuthorizationUri())
                      .clientId(registration.getClientId())
                      .redirectUri(fields.get(FIELD_REDIRECT_URI))
                      .scopes(registration.getScopes())
                      .state(state);

              builder.attributes(
                  attrs -> {
                    attrs.put(OAuth2ParameterNames.REGISTRATION_ID, REGISTRATION_ID);

                    var nonce = fields.get(FIELD_NONCE);
                    if (nonce != null) {
                      attrs.put(OidcParameterNames.NONCE, nonce);
                    }

                    var codeVerifier = fields.get(FIELD_CODE_VERIFIER);
                    if (codeVerifier != null) {
                      attrs.put(PkceParameterNames.CODE_VERIFIER, codeVerifier);
                    }
                  });

              var returnUrl = fields.get(FIELD_RETURN_URL);
              if (returnUrl != null) {
                builder.additionalParameters(params -> params.put(FIELD_RETURN_URL, returnUrl));
              }

              log.debug("Reconstructed authorization request for state={}", state);
              return builder.build();
            });
  }
}
