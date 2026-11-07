package org.budgetanalyzer.sessiongateway.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.http.ResponseCookie;
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

import org.budgetanalyzer.core.logging.SafeLogger;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;

/**
 * Redis-backed storage for OAuth2 authorization requests.
 *
 * <p>Stores only the per-request dynamic fields as a flat Redis hash at {@code
 * oauth2:state:{state}} with a TTL configured through {@code session.oauth2-state-ttl-seconds}. The
 * full {@link OAuth2AuthorizationRequest} is reconstructed on load using stored fields plus static
 * properties from the OAuth2 client registration.
 *
 * <p>This avoids serializing the {@link OAuth2AuthorizationRequest} object, which has no stable
 * serialization contract and couples to Spring Security internals across version upgrades.
 *
 * <p>Stored fields:
 *
 * <ul>
 *   <li>{@code browser_binding_hash} — SHA-256 of the initiating browser binding cookie
 *   <li>{@code redirect_uri} — the OAuth2 callback URI
 *   <li>{@code return_url} — where to redirect after login (from authorization request
 *       additionalParameters, optional)
 *   <li>{@code nonce} — OIDC nonce for ID token validation
 *   <li>{@code code_verifier} — PKCE code verifier for the authorization-code exchange
 * </ul>
 */
@Component
public class RedisAuthorizationRequestRepository
    implements ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  public static final String AUTHORIZATION_REQUEST_ATTRIBUTE =
      RedisAuthorizationRequestRepository.class.getName() + ".AUTHORIZATION_REQUEST";

  public static final String BROWSER_BINDING_COOKIE_NAME = "__Host-BA_OAUTH_BINDING";

  private static final Logger log =
      LoggerFactory.getLogger(RedisAuthorizationRequestRepository.class);

  private static final SecureRandom secureRandom = new SecureRandom();
  private static final Pattern BINDING_PATTERN = Pattern.compile("[0-9a-f]{64}");

  // Atomic creation keeps the hash immutable and gives every new record a finite lifetime.
  // State is generated afresh by the authorization resolver and must never be reused.
  private static final RedisScript<Long> CREATE_REQUEST_SCRIPT =
      RedisScript.of(
          """
          if redis.call('TYPE', KEYS[1]).ok ~= 'none' then
            return 0
          end
          redis.call('HSET', KEYS[1], unpack(ARGV, 2))
          redis.call('EXPIRE', KEYS[1], ARGV[1])
          return 1
          """,
          Long.class);

  private static final String FIELD_BROWSER_BINDING_HASH = "browser_binding_hash";
  private static final String KEY_PREFIX = "oauth2:state:";
  private static final String REGISTRATION_ID = "idp";

  private static final String FIELD_REDIRECT_URI = "redirect_uri";
  private static final String FIELD_RETURN_URL = "return_url";
  private static final String FIELD_NONCE = "nonce";
  private static final String FIELD_CODE_VERIFIER = "code_verifier";

  private final ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  private final ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
  private final Duration ttl;

  public RedisAuthorizationRequestRepository(
      ReactiveStringRedisTemplate reactiveStringRedisTemplate,
      ReactiveClientRegistrationRepository reactiveClientRegistrationRepository,
      SessionProperties sessionProperties) {
    this.reactiveStringRedisTemplate = reactiveStringRedisTemplate;
    this.reactiveClientRegistrationRepository = reactiveClientRegistrationRepository;
    this.ttl = Duration.ofSeconds(sessionProperties.oauth2StateTtlSeconds());
  }

  /**
   * Creates an immutable authorization request hash bound to the initiating browser.
   *
   * <p>Only call once per fresh, random state generated at login start. State values must never be
   * reused, including after consumption or expiry.
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

    var binding = readBrowserBinding(exchange).orElseGet(this::generateBrowserBinding);
    var fields = new HashMap<String, String>();
    fields.put(FIELD_BROWSER_BINDING_HASH, hashBrowserBinding(binding));

    fields.put(FIELD_REDIRECT_URI, authorizationRequest.getRedirectUri());

    var returnUrl =
        valueAsString(authorizationRequest.getAdditionalParameters(), FIELD_RETURN_URL)
            .orElse(null);
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
    log.debug("Saving authorization request for state={}", SafeLogger.truncateId(state));

    var arguments = new ArrayList<String>();
    arguments.add(Long.toString(ttl.toSeconds()));
    fields.forEach(
        (field, value) -> {
          arguments.add(field);
          arguments.add(value);
        });

    return reactiveStringRedisTemplate
        .execute(CREATE_REQUEST_SCRIPT, List.of(KEY_PREFIX + state), arguments)
        .single()
        .flatMap(
            count -> {
              if (count != 1) {
                return Mono.error(new IllegalStateException("OAuth state already exists"));
              }
              if (readBrowserBinding(exchange).isEmpty()) {
                exchange
                    .getResponse()
                    .addCookie(
                        ResponseCookie.from(BROWSER_BINDING_COOKIE_NAME, binding)
                            .secure(true)
                            .httpOnly(true)
                            .path("/")
                            .sameSite("Lax")
                            .build());
              }
              return Mono.empty();
            });
  }

  /**
   * Loads the authorization request from Redis using the state parameter from the exchange.
   *
   * @param exchange the current server exchange (must contain a {@code state} query parameter)
   * @return the reconstructed authorization request, or empty if absent or browser binding is
   *     invalid
   */
  @Override
  public Mono<OAuth2AuthorizationRequest> loadAuthorizationRequest(ServerWebExchange exchange) {
    return extractState(exchange).flatMap(state -> loadFromRedis(state, exchange));
  }

  /**
   * Removes and returns the authorization request from Redis.
   *
   * <p>Validates browser binding before deletion. Only the callback whose deletion removes the
   * record may proceed; expiry or a competing callback fails closed. Redis errors propagate.
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
              return loadFromRedis(state, exchange)
                  .flatMap(
                      request ->
                          reactiveStringRedisTemplate
                              .delete(key)
                              .filter(count -> count == 1)
                              .doOnNext(
                                  count ->
                                      exchange
                                          .getAttributes()
                                          .put(AUTHORIZATION_REQUEST_ATTRIBUTE, request))
                              .doOnNext(
                                  count ->
                                      log.debug(
                                          "Deleted authorization request for state={}",
                                          SafeLogger.truncateId(state)))
                              .map(count -> request));
            });
  }

  private Mono<String> extractState(ServerWebExchange exchange) {
    var state = exchange.getRequest().getQueryParams().getFirst(OAuth2ParameterNames.STATE);
    return state != null ? Mono.just(state) : Mono.empty();
  }

  private Optional<String> valueAsString(Map<String, ?> values, String key) {
    var value = values.get(key);
    if (value instanceof String stringValue && !stringValue.isEmpty()) {
      return Optional.of(stringValue);
    }

    return Optional.empty();
  }

  private Optional<String> queryParamValue(String uri, String key) {
    if (uri == null || uri.isBlank()) {
      return Optional.empty();
    }

    var value = UriComponentsBuilder.fromUriString(uri).build().getQueryParams().getFirst(key);
    if (value == null || value.isBlank()) {
      return Optional.empty();
    }

    return Optional.of(value);
  }

  private Optional<String> readBrowserBinding(ServerWebExchange exchange) {
    var cookies = exchange.getRequest().getCookies().get(BROWSER_BINDING_COOKIE_NAME);
    if (cookies == null || cookies.size() != 1) {
      return Optional.empty();
    }
    var binding = cookies.getFirst().getValue();
    return BINDING_PATTERN.matcher(binding).matches() ? Optional.of(binding) : Optional.empty();
  }

  private String generateBrowserBinding() {
    var randomBytes = new byte[32];
    secureRandom.nextBytes(randomBytes);
    return HexFormat.of().formatHex(randomBytes);
  }

  private String hashBrowserBinding(String binding) {
    try {
      var messageDigest = MessageDigest.getInstance("SHA-256");
      return HexFormat.of()
          .formatHex(messageDigest.digest(binding.getBytes(StandardCharsets.US_ASCII)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is required", exception);
    }
  }

  private Mono<OAuth2AuthorizationRequest> loadFromRedis(String state, ServerWebExchange exchange) {
    var binding = readBrowserBinding(exchange);
    if (binding.isEmpty()) {
      return Mono.empty();
    }
    var bindingHash = hashBrowserBinding(binding.get()).getBytes(StandardCharsets.US_ASCII);
    var key = KEY_PREFIX + state;
    return reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .entries(key)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .filter(fields -> fields.containsKey(FIELD_BROWSER_BINDING_HASH))
        .filter(
            fields ->
                MessageDigest.isEqual(
                    bindingHash,
                    fields.get(FIELD_BROWSER_BINDING_HASH).getBytes(StandardCharsets.US_ASCII)))
        .flatMap(fields -> reconstructRequest(state, fields));
  }

  /**
   * Reconstructs an {@link OAuth2AuthorizationRequest} from stored Redis fields and static client
   * registration properties.
   */
  private Mono<OAuth2AuthorizationRequest> reconstructRequest(
      String state, Map<String, String> fields) {
    return reactiveClientRegistrationRepository
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

              log.debug(
                  "Reconstructed authorization request for state={}", SafeLogger.truncateId(state));
              return builder.build();
            });
  }
}
