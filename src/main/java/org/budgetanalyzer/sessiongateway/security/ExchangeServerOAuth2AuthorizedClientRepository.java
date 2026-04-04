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
 * <p>Spring Security saves the authorized client before invoking the OAuth2 login success handler.
 * We only need that client during the callback request to extract the refresh token and token
 * expiry before writing our Redis session hash.
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
