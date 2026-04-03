package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.web.server.WebFilter;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.budgetanalyzer.sessiongateway.security.GlobalBrowserErrorWebExceptionHandler;

/**
 * Integration tests for global browser error routing.
 *
 * <p>Uses a test {@link WebFilter} to simulate filter-level failures that bypass controller advice,
 * exercising the {@link GlobalBrowserErrorWebExceptionHandler} directly.
 */
@Import(GlobalBrowserErrorRoutingIntegrationTest.FilterErrorSimulationConfig.class)
class GlobalBrowserErrorRoutingIntegrationTest extends AbstractIntegrationTest {

  private static final String SIMULATE_ERROR_PATH = "/test/simulate-filter-error";

  private ListAppender<ILoggingEvent> globalHandlerListAppender;
  private Logger globalHandlerLogger;

  @TestConfiguration
  static class FilterErrorSimulationConfig {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    WebFilter filterErrorSimulationWebFilter() {
      return (exchange, chain) -> {
        if (SIMULATE_ERROR_PATH.equals(
            exchange.getRequest().getPath().pathWithinApplication().value())) {
          return Mono.error(new RuntimeException("Simulated filter-level failure"));
        }
        return chain.filter(exchange);
      };
    }
  }

  @BeforeEach
  void setUpLogCapture() {
    globalHandlerLogger =
        (Logger) LoggerFactory.getLogger(GlobalBrowserErrorWebExceptionHandler.class);
    globalHandlerListAppender = new ListAppender<>();
    globalHandlerListAppender.start();
    globalHandlerLogger.addAppender(globalHandlerListAppender);
  }

  @AfterEach
  void tearDownLogCapture() {
    globalHandlerLogger.detachAppender(globalHandlerListAppender);
    globalHandlerListAppender.stop();
  }

  @Test
  void browserNavigationFilterFailureRedirectsToOops() {
    webTestClient
        .get()
        .uri(SIMULATE_ERROR_PATH)
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Sec-Fetch-Mode", "navigate")
        .header("Sec-Fetch-Dest", "document")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectHeader()
        .location("/oops");
  }

  @Test
  void nonBrowserFilterFailureReturnsJson() {
    webTestClient
        .get()
        .uri(SIMULATE_ERROR_PATH)
        .header("Accept", "application/json")
        .exchange()
        .expectStatus()
        .is5xxServerError()
        .expectHeader()
        .contentType(MediaType.APPLICATION_JSON)
        .expectBody()
        .jsonPath("$.type")
        .isEqualTo("INTERNAL_ERROR")
        .jsonPath("$.message")
        .isEqualTo("An unexpected error occurred");
  }

  @Test
  void apiSessionEndpointStaysJsonOnFailure() {
    webTestClient
        .get()
        .uri("/auth/session")
        .header("Accept", "text/html,application/xhtml+xml")
        .header("Sec-Fetch-Mode", "navigate")
        .exchange()
        .expectHeader()
        .value("Content-Type", contentType -> assertThat(contentType).doesNotContain("text/html"));
  }

  @Test
  void apiTokenExchangeEndpointStaysJsonOnFailure() {
    webTestClient
        .post()
        .uri("/auth/token/exchange")
        .contentType(MediaType.APPLICATION_JSON)
        .bodyValue("{}")
        .exchange()
        .expectHeader()
        .value("Content-Type", contentType -> assertThat(contentType).doesNotContain("text/html"));
  }

  @Test
  void globalHandlerLogsDoNotContainSensitiveValues() {
    webTestClient
        .get()
        .uri(SIMULATE_ERROR_PATH + "?code=secret-code&state=secret-state")
        .header("Accept", "text/html")
        .header("Sec-Fetch-Mode", "navigate")
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
  void browserNavigationFilterFailureDoesNotProduceHtmlBody() {
    webTestClient
        .get()
        .uri(SIMULATE_ERROR_PATH)
        .header("Accept", "text/html")
        .header("Sec-Fetch-Mode", "navigate")
        .exchange()
        .expectStatus()
        .is3xxRedirection()
        .expectBody()
        .isEmpty();
  }

  private List<String> logMessages() {
    return globalHandlerListAppender.list.stream().map(ILoggingEvent::getFormattedMessage).toList();
  }
}
