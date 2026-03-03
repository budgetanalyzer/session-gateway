package org.budgetanalyzer.sessiongateway.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.server.MockWebSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.service.InternalJwtService;

class UserControllerTest {

  private final UserController userController = new UserController();

  @Test
  void getCurrentUser_returnsEmptyWhenAuthenticationIsNull() {
    var session = new MockWebSession();
    StepVerifier.create(userController.getCurrentUser(null, session)).verifyComplete();
  }

  @Test
  void getCurrentUser_returnsUserInfoForOauthToken() {
    var attributes =
        Map.<String, Object>of(
            "sub", "auth0|abc123",
            "name", "Jane Doe",
            "email", "jane@example.com",
            "picture", "https://example.com/photo.jpg",
            "email_verified", true);

    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    var session = new MockWebSession();
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("USER"));

    var result = userController.getCurrentUser(token, session).block();

    assertThat(result).isNotNull();
    assertThat(result.sub()).isEqualTo("auth0|abc123");
    assertThat(result.name()).isEqualTo("Jane Doe");
    assertThat(result.email()).isEqualTo("jane@example.com");
    assertThat(result.picture()).isEqualTo("https://example.com/photo.jpg");
    assertThat(result.emailVerified()).isTrue();
    assertThat(result.authenticated()).isTrue();
    assertThat(result.registrationId()).isEqualTo("idp");
    assertThat(result.roles()).containsExactly("USER");
  }

  @Test
  void getCurrentUser_returnsNullAttributesWhenOauthUserMissingFields() {
    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    var session = new MockWebSession();

    var result = userController.getCurrentUser(token, session).block();

    assertThat(result).isNotNull();
    assertThat(result.sub()).isEqualTo("auth0|abc123");
    assertThat(result.name()).isNull();
    assertThat(result.email()).isNull();
    assertThat(result.picture()).isNull();
    assertThat(result.emailVerified()).isNull();
  }

  @Test
  void getCurrentUser_returnsNameAndAuthenticatedForNonOauthAuth() {
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");
    var session = new MockWebSession();

    var result = userController.getCurrentUser(auth, session).block();

    assertThat(result).isNotNull();
    assertThat(result.name()).isEqualTo("bob");
    assertThat(result.authenticated()).isTrue();
    assertThat(result.sub()).isNull();
    assertThat(result.email()).isNull();
  }

  @Test
  void getCurrentUser_returnsCorrectRegistrationId() {
    var attributes = Map.<String, Object>of("sub", "google|xyz");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "google");

    var session = new MockWebSession();
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("USER"));

    var result = userController.getCurrentUser(token, session).block();

    assertThat(result).isNotNull();
    assertThat(result.registrationId()).isEqualTo("google");
  }

  @Test
  void getCurrentUser_returnsMonoWithSingleElement() {
    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    var session = new MockWebSession();

    StepVerifier.create(userController.getCurrentUser(token, session))
        .expectNextCount(1)
        .verifyComplete();
  }

  @Test
  void getCurrentUser_returnsRolesFromSession() {
    var attributes = Map.<String, Object>of("sub", "auth0|admin1");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_ADMIN")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    var session = new MockWebSession();
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("ADMIN"));

    var result = userController.getCurrentUser(token, session).block();

    assertThat(result).isNotNull();
    assertThat(result.roles()).containsExactly("ADMIN");
  }

  @Test
  void getCurrentUser_returnsEmptyRolesWhenSessionHasNoRoles() {
    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "idp");

    var session = new MockWebSession();
    // No roles set in session

    var result = userController.getCurrentUser(token, session).block();

    assertThat(result).isNotNull();
    assertThat(result.roles()).isEmpty();
  }

  @Test
  void getCurrentUser_returnsRolesForNonOauthAuth() {
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");
    var session = new MockWebSession();
    session.getAttributes().put(InternalJwtService.SESSION_ROLES, List.of("USER"));

    var result = userController.getCurrentUser(auth, session).block();

    assertThat(result).isNotNull();
    assertThat(result.roles()).containsExactly("USER");
  }
}
