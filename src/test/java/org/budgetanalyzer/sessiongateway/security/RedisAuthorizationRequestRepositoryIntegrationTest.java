package org.budgetanalyzer.sessiongateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository.AUTHORIZATION_REQUEST_ATTRIBUTE;
import static org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository.BROWSER_BINDING_COOKIE_NAME;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.lettuce.LettuceConnection;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpCookie;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import io.lettuce.core.codec.ByteArrayCodec;
import io.lettuce.core.output.IntegerOutput;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;

class RedisAuthorizationRequestRepositoryIntegrationTest extends AbstractIntegrationTest {

  private static final String KEY_PREFIX = "oauth2:state:";
  private static final String CALLBACK_PATH = "/login/oauth2/code/idp";
  private static final String BINDING_HASH_FIELD = "browser_binding_hash";
  private static final String OTHER_BINDING = "ab".repeat(32);
  private static final String REDIS_TEST_USER = "oauth-binding-delete-failure";

  @Autowired private RedisAuthorizationRequestRepository redisAuthorizationRequestRepository;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
  @Autowired private SessionProperties sessionProperties;
  @Autowired private LettuceConnectionFactory lettuceConnectionFactory;

  @Test
  void doesNotRecoverReturnUrlFromUnvalidatedRequestUris() {
    var state = UUID.randomUUID().toString();
    var authorizationRequest =
        OAuth2AuthorizationRequest.from(authorizationRequest(state))
            .additionalParameters(parameters -> parameters.remove("return_url"))
            .authorizationRequestUri("https://idp.example/authorize?return_url=/unchecked")
            .build();
    var exchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get("/oauth2/authorization/idp")
                .queryParam("returnUrl", "/also-unchecked"));

    redisAuthorizationRequestRepository
        .saveAuthorizationRequest(authorizationRequest, exchange)
        .block();

    assertThat(readFields(state)).containsKey("redirect_uri").doesNotContainKey("return_url");
  }

  @Test
  void storesOnlyBindingHashAndSetsFiniteStateLifetime() throws Exception {
    var pendingLogin = startLogin(null);
    var fields = readFields(pendingLogin.state());
    var expectedHash =
        HexFormat.of()
            .formatHex(
                MessageDigest.getInstance("SHA-256")
                    .digest(pendingLogin.binding().getBytes(StandardCharsets.US_ASCII)));

    assertThat(pendingLogin.binding()).matches("[0-9a-f]{64}");
    assertThat(pendingLogin.binding()).isNotEqualTo(pendingLogin.state());
    assertThat(fields).containsEntry(BINDING_HASH_FIELD, expectedHash);
    assertThat(fields.values()).doesNotContain(pendingLogin.binding());
    assertThat(reactiveStringRedisTemplate.getExpire(KEY_PREFIX + pendingLogin.state()).block())
        .isPositive()
        .isLessThanOrEqualTo(Duration.ofSeconds(sessionProperties.oauth2StateTtlSeconds()));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(
      strings = {
        "short",
        "not-hex",
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
      })
  void invalidBindingCannotLoadOrConsumeAndDoesNotLoseRecord(String binding) {
    var pendingLogin = startLogin(null);
    var originalFields = readFields(pendingLogin.state());
    var callbackExchange = callback(pendingLogin.state(), binding);

    StepVerifier.create(
            redisAuthorizationRequestRepository.loadAuthorizationRequest(callbackExchange))
        .verifyComplete();
    assertRejected(callbackExchange, redisAuthorizationRequestRepository);
    assertThat(readFields(pendingLogin.state())).isEqualTo(originalFields);
    assertConsumed(pendingLogin);
  }

  @Test
  void differentBrowserCannotConsumeInitiatingBrowsersRecord() {
    var browserA = startLogin(null);
    var browserB = startLogin(null);
    var originalFields = readFields(browserA.state());

    assertRejected(
        callback(browserA.state(), browserB.binding()), redisAuthorizationRequestRepository);
    assertThat(readFields(browserA.state())).isEqualTo(originalFields);
    assertConsumed(browserA);
    assertConsumed(browserB);
  }

  @Test
  void duplicateBindingCookiesAreRejectedWithoutConsumingState() {
    var pendingLogin = startLogin(null);
    var callbackExchange =
        MockServerWebExchange.from(
            MockServerHttpRequest.get(CALLBACK_PATH)
                .queryParam("state", pendingLogin.state())
                .cookie(
                    new HttpCookie(BROWSER_BINDING_COOKIE_NAME, pendingLogin.binding()),
                    new HttpCookie(BROWSER_BINDING_COOKIE_NAME, OTHER_BINDING)));

    assertRejected(callbackExchange, redisAuthorizationRequestRepository);
    assertThat(readFields(pendingLogin.state())).isNotEmpty();
    assertConsumed(pendingLogin);
  }

  @Test
  void invalidCookieAtLoginStartIsReplaced() {
    var pendingLogin = startLogin("invalid-binding");
    assertThat(pendingLogin.binding()).matches("[0-9a-f]{64}");
    assertConsumed(pendingLogin);
  }

  @Test
  void replayCannotReturnRequestOrSetCallbackAttributes() {
    var pendingLogin = startLogin(null);
    assertConsumed(pendingLogin);
    assertRejected(
        callback(pendingLogin.state(), pendingLogin.binding()),
        redisAuthorizationRequestRepository);
  }

  @Test
  void missingStateCannotReturnRequestOrSetCallbackAttributes() {
    assertRejected(
        MockServerWebExchange.from(MockServerHttpRequest.get(CALLBACK_PATH)),
        redisAuthorizationRequestRepository);
  }

  @Test
  void expiredRecordCannotBeConsumed() {
    var pendingLogin = startLogin(null);
    reactiveStringRedisTemplate.expireAt(KEY_PREFIX + pendingLogin.state(), Instant.EPOCH).block();
    assertRejected(
        callback(pendingLogin.state(), pendingLogin.binding()),
        redisAuthorizationRequestRepository);
  }

  @Test
  void expiryAfterReadBeforeDeletionCannotReturnRequestOrSetCallbackAttributes() {
    var pendingLogin = startLogin(null);
    var expiringRepository =
        new RedisAuthorizationRequestRepository(
            reactiveStringRedisTemplate,
            registrationId ->
                reactiveStringRedisTemplate
                    .expireAt(KEY_PREFIX + pendingLogin.state(), Instant.EPOCH)
                    .then(
                        reactiveClientRegistrationRepository.findByRegistrationId(registrationId)),
            sessionProperties);

    assertRejected(callback(pendingLogin.state(), pendingLogin.binding()), expiringRepository);
    assertThat(readFields(pendingLogin.state())).isEmpty();
  }

  @Test
  void competingCallbacksThatBothReadRecordHaveExactlyOneWinner() {
    var pendingLogin = startLogin(null);
    var readers = new AtomicInteger();
    var bothRead = Sinks.<Void>empty();
    var competingRepository =
        new RedisAuthorizationRequestRepository(
            reactiveStringRedisTemplate,
            registrationId ->
                Mono.defer(
                    () -> {
                      if (readers.incrementAndGet() == 2) {
                        bothRead.tryEmitEmpty();
                      }
                      return bothRead
                          .asMono()
                          .then(
                              reactiveClientRegistrationRepository.findByRegistrationId(
                                  registrationId));
                    }),
            sessionProperties);
    var firstCallback = callback(pendingLogin.state(), pendingLogin.binding());
    var secondCallback = callback(pendingLogin.state(), pendingLogin.binding());

    var requests =
        Flux.merge(
                competingRepository.removeAuthorizationRequest(firstCallback),
                competingRepository.removeAuthorizationRequest(secondCallback))
            .collectList()
            .block(Duration.ofSeconds(5));

    assertThat(readers.get()).isEqualTo(2);
    assertThat(requests)
        .singleElement()
        .extracting(OAuth2AuthorizationRequest::getState)
        .isEqualTo(pendingLogin.state());
    assertThat(
            java.util.List.of(firstCallback, secondCallback).stream()
                .filter(
                    exchange ->
                        exchange.getAttributes().containsKey(AUTHORIZATION_REQUEST_ATTRIBUTE))
                .count())
        .isEqualTo(1);
    assertThat(readFields(pendingLogin.state())).isEmpty();
  }

  @Test
  void existingStateAndBindingCannotBeOverwrittenOrLifetimeExtended() {
    var pendingLogin = startLogin(null);
    var originalFields = readFields(pendingLogin.state());
    reactiveStringRedisTemplate
        .expire(KEY_PREFIX + pendingLogin.state(), Duration.ofSeconds(30))
        .block();
    var secondStart = callback(pendingLogin.state(), OTHER_BINDING);

    StepVerifier.create(
            redisAuthorizationRequestRepository.saveAuthorizationRequest(
                authorizationRequest(pendingLogin.state()), secondStart))
        .expectError(IllegalStateException.class)
        .verify();

    assertThat(readFields(pendingLogin.state())).isEqualTo(originalFields);
    assertThat(reactiveStringRedisTemplate.getExpire(KEY_PREFIX + pendingLogin.state()).block())
        .isPositive()
        .isLessThanOrEqualTo(Duration.ofSeconds(30));
    assertThat(secondStart.getResponse().getCookies()).isEmpty();
    assertConsumed(pendingLogin);
  }

  @Test
  void sharedBindingAllowsPendingTabsToCompleteInEitherOrderWithoutRotation() {
    var firstTab = startLogin(null);
    var secondTab = startLogin(firstTab.binding());
    assertThat(secondTab.binding()).isEqualTo(firstTab.binding());
    assertConsumed(secondTab);
    assertConsumed(firstTab);
  }

  @Test
  void simultaneousFirstStartsOnlyAllowTheBindingRetainedByBrowserAndRetryWorks() {
    // Neither start sends a cookie: both requests were sent before either response arrived.
    var firstTab = startLogin(null);
    var secondTab = startLogin(null);
    assertThat(firstTab.binding()).isNotEqualTo(secondTab.binding());

    assertRejected(
        callback(firstTab.state(), secondTab.binding()), redisAuthorizationRequestRepository);
    assertThat(readFields(firstTab.state())).isNotEmpty();
    assertConsumed(secondTab);
    assertConsumed(startLogin(secondTab.binding()));
  }

  @Test
  void nullSaveAlsoRequiresBindingBeforeConsuming() {
    var pendingLogin = startLogin(null);
    var missingBinding = callback(pendingLogin.state(), null);
    redisAuthorizationRequestRepository.saveAuthorizationRequest(null, missingBinding).block();
    assertThat(readFields(pendingLogin.state())).isNotEmpty();
    var validCallback = callback(pendingLogin.state(), pendingLogin.binding());
    redisAuthorizationRequestRepository.saveAuthorizationRequest(null, validCallback).block();
    assertThat(readFields(pendingLogin.state())).isEmpty();
    assertThat(validCallback.getAttributes()).containsKey(AUTHORIZATION_REQUEST_ATTRIBUTE);
  }

  @Test
  void redisDeletionErrorCannotReturnRequestOrSetCallbackAttributes() {
    var pendingLogin = startLogin(null);
    var callbackExchange = callback(pendingLogin.state(), pendingLogin.binding());
    // A dedicated Testcontainers Redis user can read state but cannot delete it.
    try (var connection = (LettuceConnection) lettuceConnectionFactory.getConnection()) {
      connection.execute(
          "ACL",
          bytes("SETUSER"),
          bytes(REDIS_TEST_USER),
          bytes("reset"),
          bytes("on"),
          bytes("nopass"),
          bytes("~oauth2:state:*"),
          bytes("+hgetall"),
          bytes("+hello"),
          bytes("+client|setinfo"));
      var configuration =
          new RedisStandaloneConfiguration(
              lettuceConnectionFactory.getHostName(), lettuceConnectionFactory.getPort());
      configuration.setUsername(REDIS_TEST_USER);
      var restrictedConnectionFactory = new LettuceConnectionFactory(configuration);
      restrictedConnectionFactory.afterPropertiesSet();
      restrictedConnectionFactory.start();
      try {
        var restrictedRepository =
            new RedisAuthorizationRequestRepository(
                new ReactiveStringRedisTemplate(restrictedConnectionFactory),
                reactiveClientRegistrationRepository,
                sessionProperties);
        // Establish that reading succeeds so the failure under test is DEL.
        assertThat(restrictedRepository.loadAuthorizationRequest(callbackExchange).block())
            .isNotNull();
        StepVerifier.create(restrictedRepository.removeAuthorizationRequest(callbackExchange))
            .expectError(org.springframework.data.redis.RedisSystemException.class)
            .verify();
        assertThat(callbackExchange.getAttributes())
            .doesNotContainKey(AUTHORIZATION_REQUEST_ATTRIBUTE);
        assertThat(readFields(pendingLogin.state())).isNotEmpty();
      } finally {
        restrictedConnectionFactory.destroy();
        connection.execute(
            "ACL",
            new IntegerOutput<>(ByteArrayCodec.INSTANCE),
            bytes("DELUSER"),
            bytes(REDIS_TEST_USER));
      }
    }
    assertConsumed(pendingLogin);
  }

  private byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.US_ASCII);
  }

  private PendingLogin startLogin(String binding) {
    var state = UUID.randomUUID().toString();
    var exchange = callback(state, binding);
    redisAuthorizationRequestRepository
        .saveAuthorizationRequest(authorizationRequest(state), exchange)
        .block();
    var cookie = exchange.getResponse().getCookies().getFirst(BROWSER_BINDING_COOKIE_NAME);
    if (cookie != null) {
      return new PendingLogin(state, cookie.getValue());
    }
    assertThat(exchange.getResponse().getCookies()).isEmpty();
    return new PendingLogin(state, binding);
  }

  private OAuth2AuthorizationRequest authorizationRequest(String state) {
    return OAuth2AuthorizationRequest.authorizationCode()
        .authorizationUri("https://idp.example/authorize")
        .clientId("test-client-id")
        .redirectUri("https://app.example" + CALLBACK_PATH)
        .state(state)
        .build();
  }

  private MockServerWebExchange callback(String state, String binding) {
    var requestBuilder = MockServerHttpRequest.get(CALLBACK_PATH).queryParam("state", state);
    if (binding != null) {
      requestBuilder.cookie(new HttpCookie(BROWSER_BINDING_COOKIE_NAME, binding));
    }
    return MockServerWebExchange.from(requestBuilder);
  }

  private Map<String, String> readFields(String state) {
    return reactiveStringRedisTemplate
        .<String, String>opsForHash()
        .entries(KEY_PREFIX + state)
        .collectMap(Map.Entry::getKey, Map.Entry::getValue)
        .block();
  }

  private void assertRejected(
      MockServerWebExchange exchange, RedisAuthorizationRequestRepository repository) {
    StepVerifier.create(repository.removeAuthorizationRequest(exchange)).verifyComplete();
    assertThat(exchange.getAttributes()).doesNotContainKey(AUTHORIZATION_REQUEST_ATTRIBUTE);
    assertThat(exchange.getResponse().getCookies()).isEmpty();
  }

  private void assertConsumed(PendingLogin pendingLogin) {
    var exchange = callback(pendingLogin.state(), pendingLogin.binding());
    StepVerifier.create(redisAuthorizationRequestRepository.removeAuthorizationRequest(exchange))
        .assertNext(
            request -> {
              assertThat(request.getState()).isEqualTo(pendingLogin.state());
              assertThat(exchange.getAttributes())
                  .containsEntry(AUTHORIZATION_REQUEST_ATTRIBUTE, request);
            })
        .verifyComplete();
    assertThat(exchange.getResponse().getCookies()).isEmpty();
    assertThat(readFields(pendingLogin.state())).isEmpty();
  }

  private record PendingLogin(String state, String binding) {}
}
