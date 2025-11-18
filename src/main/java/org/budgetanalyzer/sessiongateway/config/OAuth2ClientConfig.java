package org.budgetanalyzer.sessiongateway.config;

import java.util.function.Consumer;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * OAuth2 Client configuration for Auth0 integration.
 *
 * <p>Configures Authorization Code flow with PKCE and Auth0-specific parameters:
 *
 * <ul>
 *   <li>Adds 'audience' parameter to get JWT access tokens (not opaque tokens)
 *   <li>Enables PKCE for enhanced security
 *   <li>Configures proper scopes (openid, profile, email)
 * </ul>
 *
 * <p>Phase 2 Task 2.1: Configure OAuth2 Client in Session Gateway
 */
@Configuration
public class OAuth2ClientConfig {

  @Value("${auth0.audience:}")
  private String audience;

  /**
   * Customizes OAuth2 authorization requests to add Auth0-specific parameters.
   *
   * <p>Auth0 requires an 'audience' parameter to return JWT access tokens. Without this, Auth0
   * returns opaque access tokens that can't be validated by downstream services.
   *
   * @param clientRegistrationRepository the client registration repository
   * @return customized authorization request resolver
   */
  @Bean
  public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ReactiveClientRegistrationRepository clientRegistrationRepository) {

    DefaultServerOAuth2AuthorizationRequestResolver resolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);

    // Customize authorization request to add audience parameter
    resolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());

    // Wrap resolver to log the final request
    return new LoggingServerOAuth2AuthorizationRequestResolver(resolver);
  }

  /**
   * Wrapper that logs authorization requests for debugging.
   */
  private static class LoggingServerOAuth2AuthorizationRequestResolver
      implements ServerOAuth2AuthorizationRequestResolver {

    private final ServerOAuth2AuthorizationRequestResolver delegate;

    public LoggingServerOAuth2AuthorizationRequestResolver(
        ServerOAuth2AuthorizationRequestResolver delegate) {
      this.delegate = delegate;
    }

    @Override
    public reactor.core.publisher.Mono<OAuth2AuthorizationRequest> resolve(
        org.springframework.web.server.ServerWebExchange exchange) {
      return delegate.resolve(exchange).doOnNext(this::logRequest);
    }

    @Override
    public reactor.core.publisher.Mono<OAuth2AuthorizationRequest> resolve(
        org.springframework.web.server.ServerWebExchange exchange, String clientRegistrationId) {
      return delegate.resolve(exchange, clientRegistrationId).doOnNext(this::logRequest);
    }

    private void logRequest(OAuth2AuthorizationRequest request) {
      if (request != null) {
        System.err.println("==== FINAL AUTHORIZATION REQUEST TO AUTH0 ====");
        System.err.println("Authorization URI: " + request.getAuthorizationUri());
        System.err.println("Redirect URI: " + request.getRedirectUri());
        System.err.println("Client ID: " + request.getClientId());
        System.err.println("Scopes: " + request.getScopes());
        System.err.println("State: " + request.getState());
        System.err.println("Additional params: " + request.getAdditionalParameters());
        System.err.println("==============================================");
      }
    }
  }

  /**
   * Customizer that adds Auth0 audience parameter to authorization requests.
   *
   * @return authorization request customizer
   */
  private Consumer<OAuth2AuthorizationRequest.Builder> authorizationRequestCustomizer() {
    return customizer -> {
      // Add audience parameter if configured
      if (audience != null && !audience.isEmpty()) {
        customizer.additionalParameters(params -> params.put("audience", audience));
      }

      // PKCE is enabled by default in Spring Security 6+ for authorization_code flow
      // No additional configuration needed

      // Debug logging to see what redirect_uri is being sent to Auth0
      System.err.println("==== OAUTH2 AUTHORIZATION REQUEST ====");
      System.err.println("Redirect URI will be set by resolver based on request");
      System.err.println("Audience: " + audience);
      System.err.println("=====================================");
    };
  }
}
