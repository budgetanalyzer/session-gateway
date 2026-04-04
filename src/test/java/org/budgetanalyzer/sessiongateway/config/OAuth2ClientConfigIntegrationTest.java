package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoderFactory;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.netty.resources.ConnectionProvider;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

// CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
class OAuth2ClientConfigIntegrationTest extends AbstractIntegrationTest {

  @Autowired
  @Qualifier("idpConnectionProvider")
  private ConnectionProvider idpConnectionProvider;

  @Autowired
  private ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest>
      authorizationCodeTokenResponseClient;

  @Autowired private ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

  @Autowired private ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService;

  @Autowired private ReactiveJwtDecoderFactory<ClientRegistration> reactiveJwtDecoderFactory;

  @Autowired
  @Qualifier("idpWebClient")
  private WebClient idpWebClient;

  @Test
  void dedicatedIdpConnectionProviderUsesExplicitPoolSettings() {
    assertThat(idpConnectionProvider.name()).isEqualTo("idp-oidc-callback");
    assertThat(idpConnectionProvider.maxConnections()).isEqualTo(50);
  }

  @Test
  void oauth2CallbackBeansUseDedicatedIdpWebClient() {
    assertThat(ReflectionTestUtils.getField(authorizationCodeTokenResponseClient, "webClient"))
        .isSameAs(idpWebClient);
    assertThat(ReflectionTestUtils.getField(oauth2UserService, "webClient")).isSameAs(idpWebClient);
    assertThat(ReflectionTestUtils.getField(oidcUserService, "oauth2UserService"))
        .isSameAs(oauth2UserService);
    assertThat(reactiveJwtDecoderFactory).isInstanceOf(IdpReactiveJwtDecoderFactory.class);
    assertThat(ReflectionTestUtils.getField(reactiveJwtDecoderFactory, "webClient"))
        .isSameAs(idpWebClient);
  }
}
