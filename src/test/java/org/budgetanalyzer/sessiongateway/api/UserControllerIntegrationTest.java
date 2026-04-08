package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import org.budgetanalyzer.sessiongateway.api.response.UserInfoResponse;
import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.config.SessionProperties;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

class UserControllerIntegrationTest extends AbstractIntegrationTest {

  private static final String TEST_SESSION_KEY_PREFIX = "session:test:";

  @Autowired private SessionWriter sessionWriter;
  @Autowired private ReactiveStringRedisTemplate reactiveStringRedisTemplate;
  @Autowired private SessionProperties sessionProperties;

  @BeforeEach
  void setUp() {
    deleteTestKeys();
  }

  @Test
  void getCurrentUser_returns401WhenOnlyFrameworkSessionCookieIsPresent() {
    var sessionId = createSession();

    var exchangeResult =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie("SESSION", sessionId)
            .exchange()
            .expectStatus()
            .isUnauthorized()
            .returnResult(String.class);

    assertThat(exchangeResult.getResponseCookies().keySet())
        .doesNotContain(sessionProperties.cookie().name());
  }

  @Test
  void getCurrentUser_returnsUserInfoWithPermissionsForRegularUser() {
    var sessionId =
        sessionWriter
            .createSession(
                "user-regular",
                "auth0|regular",
                "regular@example.com",
                "Regular User",
                "https://example.com/regular.png",
                List.of("USER"),
                List.of("transactions:read", "currencies:read"))
            .block();

    var response =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie(sessionProperties.cookie().name(), sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(UserInfoResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.sub()).isEqualTo("auth0|regular");
    assertThat(response.email()).isEqualTo("regular@example.com");
    assertThat(response.name()).isEqualTo("Regular User");
    assertThat(response.picture()).isEqualTo("https://example.com/regular.png");
    assertThat(response.authenticated()).isTrue();
    assertThat(response.roles()).containsExactly("USER");
    assertThat(response.permissions()).containsExactly("transactions:read", "currencies:read");
  }

  @Test
  void getCurrentUser_returnsUserInfoWithAdminPermissions() {
    var sessionId =
        sessionWriter
            .createSession(
                "user-admin",
                "auth0|admin",
                "admin@example.com",
                "Admin User",
                "https://example.com/admin.png",
                List.of("ADMIN"),
                List.of(
                    "transactions:read",
                    "transactions:read:any",
                    "transactions:write:any",
                    "transactions:delete:any",
                    "currencies:read"))
            .block();

    var response =
        webTestClient
            .get()
            .uri("/auth/v1/user")
            .cookie(sessionProperties.cookie().name(), sessionId)
            .exchange()
            .expectStatus()
            .isOk()
            .expectBody(UserInfoResponse.class)
            .returnResult()
            .getResponseBody();

    assertThat(response).isNotNull();
    assertThat(response.authenticated()).isTrue();
    assertThat(response.roles()).containsExactly("ADMIN");
    assertThat(response.permissions())
        .containsExactly(
            "transactions:read",
            "transactions:read:any",
            "transactions:write:any",
            "transactions:delete:any",
            "currencies:read");
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            "user-userinfo",
            "auth0|userinfo",
            "userinfo@example.com",
            "User Info",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"))
        .block();
  }

  private void deleteTestKeys() {
    reactiveStringRedisTemplate
        .keys(TEST_SESSION_KEY_PREFIX + "*")
        .collectList()
        .flatMap(
            keys ->
                keys.isEmpty()
                    ? reactor.core.publisher.Mono.empty()
                    : reactiveStringRedisTemplate
                        .delete(reactor.core.publisher.Flux.fromIterable(keys))
                        .then())
        .block();
  }
}
