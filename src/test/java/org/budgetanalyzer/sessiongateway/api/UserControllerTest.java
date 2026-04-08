package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;

class UserControllerTest {

  private final SessionReader sessionReader = Mockito.mock(SessionReader.class);
  private final SessionCookieHelper sessionCookieHelper = Mockito.mock(SessionCookieHelper.class);
  private final UserController userController =
      new UserController(sessionReader, sessionCookieHelper);
  private final ServerWebExchange exchange = Mockito.mock(ServerWebExchange.class);

  @Test
  void getCurrentUser_returns401WhenSessionCookieMissing() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn(null);

    StepVerifier.create(userController.getCurrentUser(exchange))
        .expectErrorMatches(
            error ->
                error instanceof ResponseStatusException responseStatusException
                    && responseStatusException.getStatusCode() == HttpStatus.UNAUTHORIZED)
        .verify();
  }

  @Test
  void getCurrentUser_returns401WhenSessionCookieBlank() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn("  ");

    StepVerifier.create(userController.getCurrentUser(exchange))
        .expectErrorMatches(
            error ->
                error instanceof ResponseStatusException responseStatusException
                    && responseStatusException.getStatusCode() == HttpStatus.UNAUTHORIZED)
        .verify();
  }

  @Test
  void getCurrentUser_returns401WhenSessionMissingFromRedis() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn("session-123");
    Mockito.when(sessionReader.readSession("session-123")).thenReturn(Mono.empty());

    StepVerifier.create(userController.getCurrentUser(exchange))
        .expectErrorMatches(
            error ->
                error instanceof ResponseStatusException responseStatusException
                    && responseStatusException.getStatusCode() == HttpStatus.UNAUTHORIZED)
        .verify();
  }

  @Test
  void getCurrentUser_returnsUserInfoFromSessionHash() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn("session-123");
    Mockito.when(sessionReader.readSession("session-123"))
        .thenReturn(
            Mono.just(
                new SessionData(
                    "user-1",
                    "auth0|abc123",
                    "jane@example.com",
                    "Jane Doe",
                    "https://example.com/photo.jpg",
                    List.of("USER"),
                    List.of("transactions:read"),
                    Instant.parse("2026-03-30T00:00:00Z"),
                    Instant.parse("2026-03-30T00:15:00Z"))));

    var result = userController.getCurrentUser(exchange).block();

    assertThat(result).isNotNull();
    assertThat(result.sub()).isEqualTo("auth0|abc123");
    assertThat(result.name()).isEqualTo("Jane Doe");
    assertThat(result.email()).isEqualTo("jane@example.com");
    assertThat(result.picture()).isEqualTo("https://example.com/photo.jpg");
    assertThat(result.authenticated()).isTrue();
    assertThat(result.roles()).containsExactly("USER");
    assertThat(result.permissions()).containsExactly("transactions:read");
  }

  @Test
  void getCurrentUser_returnsEmptyPermissionsWhenSessionHasNone() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn("session-empty");
    Mockito.when(sessionReader.readSession("session-empty"))
        .thenReturn(
            Mono.just(
                new SessionData(
                    "user-2",
                    "auth0|empty",
                    "empty@example.com",
                    "Empty User",
                    "",
                    List.of("USER"),
                    List.of(),
                    Instant.parse("2026-03-30T00:00:00Z"),
                    Instant.parse("2026-03-30T00:15:00Z"))));

    var result = userController.getCurrentUser(exchange).block();

    assertThat(result).isNotNull();
    assertThat(result.permissions()).isNotNull();
    assertThat(result.permissions()).isEmpty();
  }

  @Test
  void getCurrentUser_returnsAllAdminPermissions() {
    Mockito.when(sessionCookieHelper.readSessionId(exchange)).thenReturn("session-admin");
    Mockito.when(sessionReader.readSession("session-admin"))
        .thenReturn(
            Mono.just(
                new SessionData(
                    "user-admin",
                    "auth0|admin",
                    "admin@example.com",
                    "Admin User",
                    "https://example.com/admin.jpg",
                    List.of("ADMIN"),
                    List.of(
                        "transactions:read",
                        "transactions:read:any",
                        "transactions:write:any",
                        "transactions:delete:any"),
                    Instant.parse("2026-03-30T00:00:00Z"),
                    Instant.parse("2026-03-30T00:15:00Z"))));

    var result = userController.getCurrentUser(exchange).block();

    assertThat(result).isNotNull();
    assertThat(result.roles()).containsExactly("ADMIN");
    assertThat(result.permissions())
        .containsExactly(
            "transactions:read",
            "transactions:read:any",
            "transactions:write:any",
            "transactions:delete:any");
  }
}
