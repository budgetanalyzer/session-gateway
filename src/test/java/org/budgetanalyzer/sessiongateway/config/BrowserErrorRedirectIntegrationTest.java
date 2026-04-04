package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.WebFilter;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.security.BrowserErrorRedirectHandler;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/**
 * Integration tests for browser error redirect routing.
 *
 * <p>Uses a test {@link WebFilter} to simulate filter-level failures that bypass controller advice,
 * exercising {@link BrowserErrorRedirectHandler} directly for browser routes and the shared
 * service-common reactive JSON handler for API routes.
 */
@Import(BrowserErrorRedirectIntegrationTest.FilterErrorSimulationConfig.class)
class BrowserErrorRedirectIntegrationTest extends AbstractIntegrationTest {

  private static final String BROWSER_SIMULATE_ERROR_PATH = "/test/simulate-filter-error";
  private static final String API_SIMULATE_ERROR_PATH = "/api/test/simulate-filter-error";
  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";

  @Autowired private SessionWriter sessionWriter;

  private ListAppender<ILoggingEvent> browserErrorRedirectHandlerListAppender;
  private Logger browserErrorRedirectHandlerLogger;

  @TestConfiguration
  static class FilterErrorSimulationConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    WebFilter filterErrorSimulationWebFilter() {
      return (exchange, chain) -> {
        var path = exchange.getRequest().getPath().pathWithinApplication().value();
        if (BROWSER_SIMULATE_ERROR_PATH.equals(path) || API_SIMULATE_ERROR_PATH.equals(path)) {
          var status = exchange.getRequest().getQueryParams().getFirst("status");
          if (status != null) {
            return Mono.error(
                new ResponseStatusException(
                    org.springframework.http.HttpStatus.valueOf(Integer.parseInt(status))));
          }
          return Mono.error(new RuntimeException("Simulated filter-level failure"));
        }
        return chain.filter(exchange);
      };
    }
  }

  @BeforeEach
  void setUpLogCapture() {
    browserErrorRedirectHandlerLogger =
        (Logger) LoggerFactory.getLogger(BrowserErrorRedirectHandler.class);
    browserErrorRedirectHandlerListAppender = new ListAppender<>();
    browserErrorRedirectHandlerListAppender.start();
    browserErrorRedirectHandlerLogger.addAppender(browserErrorRedirectHandlerListAppender);
  }

  @AfterEach
  void tearDownLogCapture() {
    browserErrorRedirectHandlerLogger.detachAppender(browserErrorRedirectHandlerListAppender);
    browserErrorRedirectHandlerListAppender.stop();
  }

  @Test
  void browserRouteFilterFailureRedirectsToOops() {
    webTestClient
        .get()
        .uri(BROWSER_SIMULATE_ERROR_PATH)
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .location("/oops");
  }

  @Test
  void browserNavigationToNonExistentPathRedirectsToOops() {
    var sessionId = createSession();

    webTestClient
        .get()
        .uri("/this/path/does/not/exist")
        .cookie(PUBLIC_SESSION_COOKIE_NAME, sessionId)
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .location("/oops");
  }

  @Test
  void apiRouteFilterFailureReturnsJson() {
    webTestClient
        .get()
        .uri(API_SIMULATE_ERROR_PATH)
        .exchange()
        .expectStatus()
        .is5xxServerError()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("INTERNAL_ERROR");
  }

  @Test
  void apiRouteResponseStatusExceptionReturnsMatchingType() {
    webTestClient
        .get()
        .uri(API_SIMULATE_ERROR_PATH + "?status=404")
        .exchange()
        .expectStatus()
        .isNotFound()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("NOT_FOUND");
  }

  @Test
  void apiSessionEndpointStaysJsonOnFailure() {
    webTestClient
        .get()
        .uri("/auth/session")
        .exchange()
        .expectStatus()
        .isUnauthorized()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("UNAUTHORIZED");
  }

  @Test
  void apiTokenExchangeEndpointStaysJsonOnFailure() {
    webTestClient
        .post()
        .uri("/auth/token/exchange")
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue("{}")
        .exchange()
        .expectStatus()
        .isBadRequest()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("INVALID_REQUEST");
  }

  @Test
  void globalHandlerLogsDoNotContainSensitiveValues() {
    webTestClient
        .get()
        .uri(BROWSER_SIMULATE_ERROR_PATH + "?code=secret-code&state=secret-state")
        .header("Cookie", "BA_SESSION=secret-session-id")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .location("/oops");

    var logMessages = logMessages();
    assertThat(logMessages).isNotEmpty();
    assertThat(logMessages)
        .allSatisfy(
            message -> {
              assertThat(message).doesNotContain("secret-code");
              assertThat(message).doesNotContain("secret-state");
              assertThat(message).doesNotContain("secret-session-id");
            });
  }

  @Test
  void browserRouteFilterFailureDoesNotProduceHtmlBody() {
    webTestClient
        .get()
        .uri(BROWSER_SIMULATE_ERROR_PATH)
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectBody()
        .isEmpty();
  }

  private List<String> logMessages() {
    return browserErrorRedirectHandlerListAppender.list.stream()
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private String createSession() {
    return sessionWriter
        .createSession(
            "user-123",
            "auth0|browser-error-test",
            "browser-error@example.com",
            "Browser Error Test User",
            "https://example.com/avatar.png",
            List.of("ROLE_USER"),
            List.of("transactions:read"),
            "refresh-token-123",
            Instant.now().plusSeconds(3600))
        .block();
  }
}
