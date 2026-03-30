package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

@ExtendWith(MockitoExtension.class)
class LogoutControllerTest {

  private static final String URL_TEMPLATE =
      "https://idp.example.com/v2/logout?returnTo={returnTo}&client_id={clientId}";
  private static final String CLIENT_ID = "my-client-id";
  private static final String RETURN_TO = "https://app.example.com";

  @Mock private SessionWriter sessionWriter;
  @Mock private SessionCookieHelper sessionCookieHelper;
  @Mock private ServerWebExchange exchange;
  @Mock private ServerHttpResponse response;

  private HttpHeaders httpHeaders;
  private LogoutController logoutController;

  @BeforeEach
  void setUp() {
    logoutController =
        new LogoutController(
            sessionWriter, sessionCookieHelper, URL_TEMPLATE, CLIENT_ID, RETURN_TO);
    httpHeaders = new HttpHeaders();

    lenient().when(exchange.getResponse()).thenReturn(response);
    lenient().when(response.getHeaders()).thenReturn(httpHeaders);
    lenient().when(response.setComplete()).thenReturn(Mono.empty());
    lenient().when(sessionCookieHelper.readSessionId(exchange)).thenReturn("test-session-id");
    lenient().when(sessionWriter.deleteSession("test-session-id")).thenReturn(Mono.just(true));
  }

  @Test
  void logout_deletesSessionFromRedis() {
    logoutController.logout(exchange).block();

    verify(sessionWriter).deleteSession("test-session-id");
  }

  @Test
  void logout_clearsSessionCookie() {
    logoutController.logout(exchange).block();

    verify(sessionCookieHelper).clearSessionCookie(exchange);
  }

  @Test
  void logout_redirectsToIdpLogoutWithCorrectUrl() {
    logoutController.logout(exchange).block();

    verify(response).setStatusCode(HttpStatus.FOUND);
    assertThat(httpHeaders.getLocation())
        .hasToString(
            "https://idp.example.com/v2/logout"
                + "?returnTo=https%3A%2F%2Fapp.example.com&client_id=my-client-id");
  }

  @Test
  void logout_executesStepsInOrder() {
    logoutController.logout(exchange).block();

    var inOrder = inOrder(sessionWriter, sessionCookieHelper);
    inOrder.verify(sessionWriter).deleteSession("test-session-id");
    inOrder.verify(sessionCookieHelper).clearSessionCookie(exchange);

    verify(response).setStatusCode(HttpStatus.FOUND);
    verify(response).setComplete();
  }

  @Test
  void logout_completesSuccessfully() {
    StepVerifier.create(logoutController.logout(exchange)).verifyComplete();
  }

  @Test
  void logout_propagatesErrorFromSessionDeletion() {
    when(sessionWriter.deleteSession("test-session-id"))
        .thenReturn(Mono.error(new RuntimeException("session deletion failed")));

    StepVerifier.create(logoutController.logout(exchange))
        .expectErrorMessage("session deletion failed")
        .verify();
  }

  @Test
  void logout_skipsSessionDeletionWhenCookieMissing() {
    when(sessionCookieHelper.readSessionId(exchange)).thenReturn(null);

    logoutController.logout(exchange).block();

    verifyNoInteractions(sessionWriter);
    verify(sessionCookieHelper).clearSessionCookie(exchange);
  }

  @Test
  void logout_skipsSessionDeletionWhenCookieBlank() {
    when(sessionCookieHelper.readSessionId(exchange)).thenReturn("  ");

    logoutController.logout(exchange).block();

    verifyNoInteractions(sessionWriter);
    verify(sessionCookieHelper).clearSessionCookie(exchange);
  }

  @Test
  void logout_normalizesDoubleSlashInLogoutUrl() {
    var templateWithDoubleSlash =
        "https://idp.example.com//v2/logout?returnTo={returnTo}&client_id={clientId}";
    var controllerWithDoubleSlash =
        new LogoutController(
            sessionWriter, sessionCookieHelper, templateWithDoubleSlash, CLIENT_ID, RETURN_TO);

    controllerWithDoubleSlash.logout(exchange).block();

    assertThat(httpHeaders.getLocation())
        .hasToString(
            "https://idp.example.com/v2/logout"
                + "?returnTo=https%3A%2F%2Fapp.example.com&client_id=my-client-id");
  }
}
