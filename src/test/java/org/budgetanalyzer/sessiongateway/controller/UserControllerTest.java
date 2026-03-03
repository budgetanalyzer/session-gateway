package org.budgetanalyzer.sessiongateway.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import reactor.test.StepVerifier;

class UserControllerTest {

  private final UserController userController = new UserController();

  @Test
  void getCurrentUser_returnsEmptyWhenAuthenticationIsNull() {
    StepVerifier.create(userController.getCurrentUser(null)).verifyComplete();
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
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "auth0");

    var result = userController.getCurrentUser(token).block();

    assertThat(result)
        .containsEntry("sub", "auth0|abc123")
        .containsEntry("name", "Jane Doe")
        .containsEntry("email", "jane@example.com")
        .containsEntry("picture", "https://example.com/photo.jpg")
        .containsEntry("emailVerified", true)
        .containsEntry("authenticated", true)
        .containsEntry("registrationId", "auth0");
  }

  @Test
  void getCurrentUser_returnsNullAttributesWhenOauthUserMissingFields() {
    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "auth0");

    var result = userController.getCurrentUser(token).block();

    assertThat(result)
        .containsEntry("sub", "auth0|abc123")
        .containsEntry("name", null)
        .containsEntry("email", null)
        .containsEntry("picture", null)
        .containsEntry("emailVerified", null);
  }

  @Test
  void getCurrentUser_returnsNameAndAuthenticatedForNonOauthAuth() {
    var auth = new TestingAuthenticationToken("bob", "secret", "ROLE_USER");
    var result = userController.getCurrentUser(auth).block();

    assertThat(result)
        .containsEntry("name", "bob")
        .containsEntry("authenticated", true)
        .doesNotContainKey("sub")
        .doesNotContainKey("email");
  }

  @Test
  void getCurrentUser_returnsCorrectRegistrationId() {
    var attributes = Map.<String, Object>of("sub", "google|xyz");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "google");

    var result = userController.getCurrentUser(token).block();

    assertThat(result).containsEntry("registrationId", "google");
  }

  @Test
  void getCurrentUser_returnsMonoWithSingleElement() {
    var attributes = Map.<String, Object>of("sub", "auth0|abc123");
    var oauth2User =
        new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_USER")), attributes, "sub");
    var token = new OAuth2AuthenticationToken(oauth2User, oauth2User.getAuthorities(), "auth0");

    StepVerifier.create(userController.getCurrentUser(token)).expectNextCount(1).verifyComplete();
  }
}
