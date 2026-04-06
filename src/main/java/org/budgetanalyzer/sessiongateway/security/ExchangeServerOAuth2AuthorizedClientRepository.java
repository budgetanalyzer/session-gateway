package org.budgetanalyzer.sessiongateway.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Request-scoped authorized client repository for the OAuth2 callback flow.
 *
 * <p>Spring Security requires a {@link ServerOAuth2AuthorizedClientRepository} bean to drive the
 * OAuth2 login flow. We hold the authorized client only for the duration of the callback request:
 * Session Gateway no longer reads it after the success handler runs, since browser sessions are
 * created from the ID-token claims and the permission service alone.
 */
@Component
public class ExchangeServerOAuth2AuthorizedClientRepository
    implements ServerOAuth2AuthorizedClientRepository {

  private static final String AUTHORIZED_CLIENT_ATTRIBUTE =
      ExchangeServerOAuth2AuthorizedClientRepository.class.getName() + ".AUTHORIZED_CLIENT";

  @Override
  @SuppressWarnings("unchecked")
  public <T extends OAuth2AuthorizedClient> Mono<T> loadAuthorizedClient(
      String clientRegistrationId, Authentication principal, ServerWebExchange exchange) {
    var authorizedClient =
        (OAuth2AuthorizedClient) exchange.getAttribute(AUTHORIZED_CLIENT_ATTRIBUTE);

    if (authorizedClient == null) {
      return Mono.empty();
    }

    if (!authorizedClient
        .getClientRegistration()
        .getRegistrationId()
        .equals(clientRegistrationId)) {
      return Mono.empty();
    }

    return Mono.just((T) authorizedClient);
  }

  @Override
  public Mono<Void> saveAuthorizedClient(
      OAuth2AuthorizedClient authorizedClient,
      Authentication principal,
      ServerWebExchange exchange) {
    exchange.getAttributes().put(AUTHORIZED_CLIENT_ATTRIBUTE, authorizedClient);
    return Mono.empty();
  }

  @Override
  public Mono<Void> removeAuthorizedClient(
      String clientRegistrationId, Authentication principal, ServerWebExchange exchange) {
    exchange.getAttributes().remove(AUTHORIZED_CLIENT_ATTRIBUTE);
    return Mono.empty();
  }
}
