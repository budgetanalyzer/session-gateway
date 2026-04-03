package org.budgetanalyzer.sessiongateway.config;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.oidc.authentication.ReactiveOidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Reactive OIDC ID token decoder factory backed by the dedicated IdP WebClient.
 *
 * <p>Spring Security's default reactive decoder factory does not expose a WebClient hook, so this
 * factory preserves the default RS256/Auth0 assumptions while moving JWKS fetches onto the same
 * dedicated transport path as token exchange and userinfo requests.
 */
public final class IdpReactiveJwtDecoderFactory
    implements ReactiveJwtDecoderFactory<ClientRegistration> {

  private static final String MISSING_SIGNATURE_VERIFIER_ERROR_CODE = "missing_signature_verifier";

  private final WebClient webClient;
  private final Map<String, ReactiveJwtDecoder> jwtDecoders = new ConcurrentHashMap<>();

  /**
   * Creates a new IdP JWT decoder factory.
   *
   * @param webClient the dedicated IdP WebClient
   */
  public IdpReactiveJwtDecoderFactory(WebClient webClient) {
    this.webClient = webClient;
  }

  /**
   * Creates or reuses the JWT decoder for the given OIDC client registration.
   *
   * @param clientRegistration the OIDC client registration
   * @return the cached decoder for that registration
   */
  @Override
  public ReactiveJwtDecoder createDecoder(ClientRegistration clientRegistration) {
    return jwtDecoders.computeIfAbsent(
        clientRegistration.getRegistrationId(), registrationId -> buildDecoder(clientRegistration));
  }

  private ReactiveJwtDecoder buildDecoder(ClientRegistration clientRegistration) {
    var jwkSetUri = clientRegistration.getProviderDetails().getJwkSetUri();
    if (!StringUtils.hasText(jwkSetUri)) {
      var oauth2Error =
          new OAuth2Error(
              MISSING_SIGNATURE_VERIFIER_ERROR_CODE,
              "Missing JWK Set URI for registration '"
                  + clientRegistration.getRegistrationId()
                  + "'",
              null);
      throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
    }

    var nimbusReactiveJwtDecoder =
        NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
            .jwsAlgorithm(SignatureAlgorithm.RS256)
            .webClient(webClient)
            .build();
    nimbusReactiveJwtDecoder.setJwtValidator(
        JwtValidators.createDefaultWithValidators(new OidcIdTokenValidator(clientRegistration)));
    nimbusReactiveJwtDecoder.setClaimSetConverter(
        new ClaimTypeConverter(
            ReactiveOidcIdTokenDecoderFactory.createDefaultClaimTypeConverters()));
    return nimbusReactiveJwtDecoder;
  }
}
