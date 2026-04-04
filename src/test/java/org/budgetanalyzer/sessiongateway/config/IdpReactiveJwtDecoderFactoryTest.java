package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

class IdpReactiveJwtDecoderFactoryTest {

  private final IdpReactiveJwtDecoderFactory factory =
      new IdpReactiveJwtDecoderFactory(WebClient.create());

  @Test
  void decoderValidatorChainIncludesDefaultJwtValidators() {
    var decoder = factory.createDecoder(clientRegistration());

    var validator = extractValidator(decoder);
    assertThat(validator).isInstanceOf(DelegatingOAuth2TokenValidator.class);

    @SuppressWarnings("unchecked")
    var delegates =
        (Collection<OAuth2TokenValidator<Jwt>>)
            ReflectionTestUtils.getField(validator, "tokenValidators");
    assertThat(delegates)
        .hasAtLeastOneElementOfType(JwtTimestampValidator.class)
        .hasAtLeastOneElementOfType(OidcIdTokenValidator.class);
  }

  @Test
  void decoderIsCachedPerRegistrationId() {
    var registration = clientRegistration();
    var first = factory.createDecoder(registration);
    var second = factory.createDecoder(registration);
    assertThat(first).isSameAs(second);
  }

  @Test
  void missingJwkSetUriThrowsOAuth2AuthenticationException() {
    var registration =
        ClientRegistration.withRegistrationId("no-jwks")
            .clientId("test-client-id")
            .clientSecret("test-client-secret")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
            .authorizationUri("https://tenant.example.com/authorize")
            .tokenUri("https://tenant.example.com/oauth/token")
            .scope("openid")
            .build();

    assertThatThrownBy(() -> factory.createDecoder(registration))
        .isInstanceOf(OAuth2AuthenticationException.class)
        .hasMessageContaining("no-jwks");
  }

  @SuppressWarnings("unchecked")
  private static OAuth2TokenValidator<Jwt> extractValidator(Object decoder) {
    return (OAuth2TokenValidator<Jwt>) ReflectionTestUtils.getField(decoder, "jwtValidator");
  }

  private static ClientRegistration clientRegistration() {
    return ClientRegistration.withRegistrationId("idp")
        .clientId("test-client-id")
        .clientSecret("test-client-secret")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .authorizationUri("https://tenant.example.com/authorize")
        .tokenUri("https://tenant.example.com/oauth/token")
        .scope("openid", "profile", "email")
        .userInfoUri("https://tenant.example.com/userinfo")
        .userNameAttributeName("sub")
        .jwkSetUri("https://tenant.example.com/.well-known/jwks.json")
        .build();
  }
}
