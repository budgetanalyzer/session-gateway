package org.budgetanalyzer.sessiongateway.config;

import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2ClientConfig {

  private static final Logger log = LoggerFactory.getLogger(OAuth2ClientConfig.class);

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

    var resolver =
        new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);

    // Customize authorization request to add audience parameter
    resolver.setAuthorizationRequestCustomizer(authorizationRequestCustomizer());

    // Wrap resolver to log the final request
    return new LoggingServerOAuth2AuthorizationRequestResolver(resolver);
  }

  /** Wrapper that logs authorization requests for debugging. */
  // CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
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
        log.debug("==== FINAL AUTHORIZATION REQUEST TO AUTH0 ====");
        log.debug("Authorization URI: " + request.getAuthorizationUri());
        log.debug("Redirect URI: " + request.getRedirectUri());
        log.debug("Client ID: " + request.getClientId());
        log.debug("Scopes: " + request.getScopes());
        log.debug("State: " + request.getState());
        log.debug("Additional params: " + request.getAdditionalParameters());
        log.debug("==============================================");
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
      log.debug("==== OAUTH2 AUTHORIZATION REQUEST ====");
      log.debug("Redirect URI will be set by resolver based on request");
      log.debug("Audience: " + audience);
      log.debug("=====================================");
    };
  }
}
