package org.budgetanalyzer.sessiongateway.config;

import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import org.budgetanalyzer.sessiongateway.security.OAuth2CallbackIdpClientLoggingFilter;

/**
 * OAuth2 Client configuration for IDP integration.
 *
 * <p>Configures Authorization Code flow with PKCE and IDP-specific parameters:
 *
 * <ul>
 *   <li>Adds 'audience' parameter to get JWT access tokens (not opaque tokens)
 *   <li>Enables PKCE for enhanced security
 * </ul>
 */
@Configuration
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2ClientConfig {

  private static final String RETURN_URL_QUERY_PARAMETER = "returnUrl";
  private static final String RETURN_URL_ADDITIONAL_PARAMETER = "return_url";

  private final String audience;

  public OAuth2ClientConfig(@Value("${idp.audience:}") String audience) {
    this.audience = audience;
  }

  /**
   * Creates the dedicated outbound IdP connection pool used by the browser OAuth2 callback path.
   *
   * @param idpHttpClientProperties the dedicated IdP HTTP client properties
   * @return the dedicated connection provider
   */
  @Bean(destroyMethod = "dispose")
  public ConnectionProvider idpConnectionProvider(IdpHttpClientProperties idpHttpClientProperties) {
    return ConnectionProvider.builder(idpHttpClientProperties.poolName())
        .maxConnections(idpHttpClientProperties.maxConnections())
        .pendingAcquireMaxCount(idpHttpClientProperties.pendingAcquireMaxCount())
        .pendingAcquireTimeout(idpHttpClientProperties.pendingAcquireTimeout())
        .maxIdleTime(idpHttpClientProperties.maxIdleTime())
        .maxLifeTime(idpHttpClientProperties.maxLifeTime())
        .evictInBackground(idpHttpClientProperties.evictionInterval())
        .build();
  }

  /**
   * Creates the dedicated outbound IdP HTTP client for browser callback traffic.
   *
   * @param idpConnectionProvider the dedicated connection pool
   * @param idpHttpClientProperties the dedicated IdP HTTP client properties
   * @return the dedicated HTTP client
   */
  @Bean
  public HttpClient idpHttpClient(
      @Qualifier("idpConnectionProvider") ConnectionProvider idpConnectionProvider,
      IdpHttpClientProperties idpHttpClientProperties) {
    return HttpClient.create(idpConnectionProvider)
        .keepAlive(true)
        .option(
            ChannelOption.CONNECT_TIMEOUT_MILLIS,
            Math.toIntExact(idpHttpClientProperties.connectTimeout().toMillis()))
        .responseTimeout(idpHttpClientProperties.responseTimeout())
        .doOnConnected(
            connection -> {
              connection.addHandlerLast(
                  new ReadTimeoutHandler(
                      idpHttpClientProperties.readTimeout().toMillis(), TimeUnit.MILLISECONDS));
              connection.addHandlerLast(
                  new WriteTimeoutHandler(
                      idpHttpClientProperties.writeTimeout().toMillis(), TimeUnit.MILLISECONDS));
            });
  }

  /**
   * Creates the dedicated IdP WebClient for browser callback traffic.
   *
   * @param idpHttpClient the dedicated IdP HTTP client
   * @return the dedicated IdP WebClient
   */
  @Bean("idpWebClient")
  public WebClient idpWebClient(HttpClient idpHttpClient) {
    return WebClient.builder()
        .clientConnector(new ReactorClientHttpConnector(idpHttpClient))
        .filter(new OAuth2CallbackIdpClientLoggingFilter())
        .build();
  }

  /**
   * Creates the authorization-code token response client backed by the dedicated IdP WebClient.
   *
   * @param idpWebClient the dedicated IdP WebClient
   * @return the dedicated token response client
   */
  @Bean
  public ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient(@Qualifier("idpWebClient") WebClient idpWebClient) {
    var webClientReactiveAuthorizationCodeTokenResponseClient =
        new WebClientReactiveAuthorizationCodeTokenResponseClient();
    webClientReactiveAuthorizationCodeTokenResponseClient.setWebClient(idpWebClient);
    return webClientReactiveAuthorizationCodeTokenResponseClient;
  }

  /**
   * Creates the OAuth2 user service backed by the dedicated IdP WebClient.
   *
   * @param idpWebClient the dedicated IdP WebClient
   * @return the dedicated OAuth2 user service
   */
  @Bean
  public ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService(
      @Qualifier("idpWebClient") WebClient idpWebClient) {
    var defaultReactiveOauth2UserService = new DefaultReactiveOAuth2UserService();
    defaultReactiveOauth2UserService.setWebClient(idpWebClient);
    return defaultReactiveOauth2UserService;
  }

  /**
   * Creates the OIDC user service backed by the dedicated IdP WebClient.
   *
   * @param oauth2UserService the dedicated OAuth2 user service
   * @return the dedicated OIDC user service
   */
  @Bean
  public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService(
      ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService) {
    var oidcReactiveOauth2UserService = new OidcReactiveOAuth2UserService();
    oidcReactiveOauth2UserService.setOauth2UserService(oauth2UserService);
    return oidcReactiveOauth2UserService;
  }

  /**
   * Creates the reactive JWT decoder factory backed by the dedicated IdP WebClient.
   *
   * @param idpWebClient the dedicated IdP WebClient
   * @return the dedicated reactive JWT decoder factory
   */
  @Bean
  public ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory(
      @Qualifier("idpWebClient") WebClient idpWebClient) {
    return new IdpReactiveJwtDecoderFactory(idpWebClient);
  }

  /**
   * Customizes OAuth2 authorization requests to add IDP-specific parameters.
   *
   * <p>The IDP requires an 'audience' parameter to return JWT access tokens. Without this, the IDP
   * may return opaque access tokens that can't be validated by downstream services.
   *
   * @param clientRegistrationRepository the client registration repository
   * @return customized authorization request resolver
   */
  @Bean
  public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    var defaultAuthorizationRequestResolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
    defaultAuthorizationRequestResolver.setAuthorizationRequestCustomizer(
        authorizationRequestCustomizer());

    return new ServerOAuth2AuthorizationRequestResolver() {
      @Override
      public Mono<OAuth2AuthorizationRequest> resolve(ServerWebExchange exchange) {
        return defaultAuthorizationRequestResolver
            .resolve(exchange)
            .map(
                authorizationRequest ->
                    addReturnUrlAdditionalParameter(authorizationRequest, exchange));
      }

      @Override
      public Mono<OAuth2AuthorizationRequest> resolve(
          ServerWebExchange exchange, String clientRegistrationId) {
        return defaultAuthorizationRequestResolver
            .resolve(exchange, clientRegistrationId)
            .map(
                authorizationRequest ->
                    addReturnUrlAdditionalParameter(authorizationRequest, exchange));
      }
    };
  }

  /**
   * Customizer that adds the IDP audience parameter.
   *
   * @return authorization request customizer
   */
  private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
    var pkceCustomizer = OAuth2AuthorizationRequestCustomizers.withPkce();

    return authorizationRequestBuilder -> {
      pkceCustomizer.accept(authorizationRequestBuilder);

      if (audience != null && !audience.isEmpty()) {
        authorizationRequestBuilder.additionalParameters(
            params -> params.put("audience", audience));
      }
    };
  }

  private OAuth2AuthorizationRequest addReturnUrlAdditionalParameter(
      OAuth2AuthorizationRequest authorizationRequest, ServerWebExchange exchange) {
    var returnUrl = exchange.getRequest().getQueryParams().getFirst(RETURN_URL_QUERY_PARAMETER);
    if (returnUrl == null || returnUrl.isEmpty()) {
      return authorizationRequest;
    }

    return OAuth2AuthorizationRequest.from(authorizationRequest)
        .attributes(attributes -> attributes.putAll(authorizationRequest.getAttributes()))
        .additionalParameters(
            parameters -> {
              parameters.putAll(authorizationRequest.getAdditionalParameters());
              parameters.put(RETURN_URL_ADDITIONAL_PARAMETER, returnUrl);
            })
        .build();
  }
}
