package org.budgetanalyzer.sessiongateway.security;

import java.util.Optional;

import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;

/** Resolves post-callback redirects for OAuth2 browser login success and failure flows. */
@Component
public class OAuth2CallbackRedirectResolver {

  private static final String DEFAULT_REDIRECT_URL = "/";
  private static final String LOGIN_PATH = "/login";
  private static final String OOPS_PATH = "/oops";
  private static final String LOGIN_ERROR_PARAMETER = "error";
  private static final String LOGIN_ERROR_AUTH_FAILED = "auth_failed";
  private static final String LOGIN_RETURN_URL_PARAMETER = "returnUrl";
  private static final String RETURN_URL_PARAMETER = "return_url";

  /**
   * Resolves the post-login success redirect URL.
   *
   * @param exchange the current server exchange
   * @return the validated success redirect URL
   */
  public String resolveAuthenticationSuccessRedirectUrl(ServerWebExchange exchange) {
    return resolveRequestedReturnUrl(exchange).orElse(DEFAULT_REDIRECT_URL);
  }

  /**
   * Resolves the controlled login failure redirect URL.
   *
   * @param exchange the current server exchange
   * @return the login failure redirect URL
   */
  public String resolveAuthenticationFailureRedirectUrl(ServerWebExchange exchange) {
    var uriComponentsBuilder =
        UriComponentsBuilder.fromPath(LOGIN_PATH)
            .queryParam(LOGIN_ERROR_PARAMETER, LOGIN_ERROR_AUTH_FAILED);
    resolveRequestedReturnUrl(exchange)
        .ifPresent(
            returnUrl -> uriComponentsBuilder.queryParam(LOGIN_RETURN_URL_PARAMETER, returnUrl));
    return uriComponentsBuilder.build().toUriString();
  }

  /**
   * Resolves the generic callback-completion failure redirect URL.
   *
   * @return the frontend-owned app error route
   */
  public String resolveUnexpectedFailureRedirectUrl() {
    return OOPS_PATH;
  }

  private Optional<String> resolveRequestedReturnUrl(ServerWebExchange exchange) {
    var authorizationRequest =
        exchange.getAttribute(RedisAuthorizationRequestRepository.AUTHORIZATION_REQUEST_ATTRIBUTE);
    if (!(authorizationRequest instanceof OAuth2AuthorizationRequest oauth2AuthorizationRequest)) {
      return Optional.empty();
    }

    var returnUrl = oauth2AuthorizationRequest.getAdditionalParameters().get(RETURN_URL_PARAMETER);
    if (returnUrl instanceof String stringValue
        && RedirectUrlValidator.isValidRedirectUrl(stringValue)) {
      return Optional.of(stringValue);
    }

    return Optional.empty();
  }
}
