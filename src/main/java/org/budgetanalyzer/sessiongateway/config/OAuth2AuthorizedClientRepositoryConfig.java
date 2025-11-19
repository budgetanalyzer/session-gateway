package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;

/**
 * Configuration for OAuth2 Authorized Client Repository.
 *
 * <p>This configuration explicitly creates a {@link
 * WebSessionServerOAuth2AuthorizedClientRepository} bean to ensure OAuth2AuthorizedClient objects
 * (containing access tokens, refresh tokens, etc.) are properly persisted to the WebSession, which
 * is backed by Redis.
 *
 * <p><strong>Why this is needed:</strong>
 *
 * <ul>
 *   <li>Spring Boot's auto-configuration may not create a session-based repository by default
 *   <li>Without explicit configuration, OAuth2AuthorizedClient may not be persisted during OAuth2
 *       login
 *   <li>TokenRelay filter requires OAuth2AuthorizedClient to be in the session to add the
 *       Authorization header
 *   <li>This explicit bean ensures the OAuth2 login flow saves the authorized client to Redis
 *       sessions
 * </ul>
 *
 * <p><strong>How it works:</strong>
 *
 * <ol>
 *   <li>During OAuth2 login callback, Spring Security creates an OAuth2AuthorizedClient
 *   <li>The WebSessionServerOAuth2AuthorizedClientRepository saves it to the WebSession
 *   <li>WebSession is backed by Redis (configured in SessionConfig.java)
 *   <li>TokenRelay filter loads the OAuth2AuthorizedClient from the session and extracts the access
 *       token
 *   <li>TokenRelay adds the access token as an Authorization header to proxied requests
 * </ol>
 *
 * @see SessionConfig
 */
@Configuration
// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
public class OAuth2AuthorizedClientRepositoryConfig {

  /**
   * Creates a session-based repository for storing OAuth2 authorized clients.
   *
   * <p>The WebSessionServerOAuth2AuthorizedClientRepository stores OAuth2AuthorizedClient objects
   * in the WebSession under the attribute key: {@code
   * org.springframework.security.oauth2.client.web.server
   * .WebSessionServerOAuth2AuthorizedClientRepository}.
   *
   * <p>Since WebSession is backed by Spring Session Redis (via @EnableRedisWebSession), the
   * OAuth2AuthorizedClient will be persisted to Redis and available across requests.
   *
   * @return session-based OAuth2 authorized client repository
   */
  @Bean
  public ServerOAuth2AuthorizedClientRepository authorizedClientRepository() {
    return new WebSessionServerOAuth2AuthorizedClientRepository();
  }
}
