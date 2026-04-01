package org.budgetanalyzer.sessiongateway.config;

import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

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
