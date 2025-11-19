package org.budgetanalyzer.sessiongateway.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;

import reactor.core.publisher.Mono;

/**
 * Unit tests for {@link RedisServerRequestCache}.
 *
 * <p>Verifies that the cache correctly saves, retrieves, and clears request URIs from Redis
 * sessions.
 */
@ExtendWith(MockitoExtension.class)
class RedisServerRequestCacheTest {

  private static final String SAVED_REQUEST_KEY = "SPRING_SECURITY_SAVED_REQUEST";

  @Mock private ServerWebExchange exchange;

  @Mock private WebSession session;

  @Mock private ServerHttpRequest request;

  private Map<String, Object> sessionAttributes;

  private RedisServerRequestCache requestCache;

  @BeforeEach
  void setUp() {
    requestCache = new RedisServerRequestCache();
    sessionAttributes = new HashMap<>();

    // Use lenient() for all stubbings to avoid UnnecessaryStubbingException
    // when tests don't use all mocked methods
    lenient().when(exchange.getSession()).thenReturn(Mono.just(session));
    lenient().when(exchange.getRequest()).thenReturn(request);
    lenient().when(session.getAttributes()).thenReturn(sessionAttributes);
    lenient()
        .when(session.getAttribute(SAVED_REQUEST_KEY))
        .thenAnswer(invocation -> sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testSaveRequest_savesSimplePathToSession() {
    // Given
    URI requestUri = URI.create("http://localhost:8081/dashboard");
    when(request.getURI()).thenReturn(requestUri);

    // When
    requestCache.saveRequest(exchange).block();

    // Then
    assertEquals("/dashboard", sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testSaveRequest_savesPathWithQueryParameters() {
    // Given
    URI requestUri = URI.create("http://localhost:8081/settings?tab=profile&section=security");
    when(request.getURI()).thenReturn(requestUri);

    // When
    requestCache.saveRequest(exchange).block();

    // Then
    assertEquals(
        "/settings?tab=profile&section=security", sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testSaveRequest_savesRootPath() {
    // Given
    URI requestUri = URI.create("http://localhost:8081/");
    when(request.getURI()).thenReturn(requestUri);

    // When
    requestCache.saveRequest(exchange).block();

    // Then
    assertEquals("/", sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testSaveRequest_savesDeepPath() {
    // Given
    URI requestUri = URI.create("http://localhost:8081/api/v1/users/123/transactions");
    when(request.getURI()).thenReturn(requestUri);

    // When
    requestCache.saveRequest(exchange).block();

    // Then
    assertEquals("/api/v1/users/123/transactions", sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testGetRedirectUri_retrievesSavedUri() {
    // Given
    sessionAttributes.put(SAVED_REQUEST_KEY, "/dashboard");

    // When
    URI result = requestCache.getRedirectUri(exchange).block();

    // Then
    assertNotNull(result);
    assertEquals("/dashboard", result.toString());
  }

  @Test
  void testGetRedirectUri_retrievesSavedUriWithQueryParameters() {
    // Given
    sessionAttributes.put(SAVED_REQUEST_KEY, "/settings?tab=profile");

    // When
    URI result = requestCache.getRedirectUri(exchange).block();

    // Then
    assertNotNull(result);
    assertEquals("/settings?tab=profile", result.toString());
  }

  @Test
  void testGetRedirectUri_returnsEmptyWhenNoSavedRequest() {
    // Given - no saved request in session

    // When
    URI result = requestCache.getRedirectUri(exchange).block();

    // Then
    assertNull(result);
  }

  @Test
  void testGetRedirectUri_returnsEmptyWhenSavedRequestIsNull() {
    // Given
    sessionAttributes.put(SAVED_REQUEST_KEY, null);

    // When
    URI result = requestCache.getRedirectUri(exchange).block();

    // Then
    assertNull(result);
  }

  @Test
  void testRemoveMatchingRequest_clearsSessionAttribute() {
    // Given
    sessionAttributes.put(SAVED_REQUEST_KEY, "/dashboard");

    // When
    requestCache.removeMatchingRequest(exchange).block();

    // Then
    assertNull(sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testRemoveMatchingRequest_handlesNoSavedRequest() {
    // Given - no saved request in session

    // When & Then - should complete without error
    requestCache.removeMatchingRequest(exchange).block();
  }

  @Test
  void testSaveRequest_overwritesPreviousSavedRequest() {
    // Given - existing saved request
    sessionAttributes.put(SAVED_REQUEST_KEY, "/old-path");
    URI newRequestUri = URI.create("http://localhost:8081/new-path");
    when(request.getURI()).thenReturn(newRequestUri);

    // When
    requestCache.saveRequest(exchange).block();

    // Then
    assertEquals("/new-path", sessionAttributes.get(SAVED_REQUEST_KEY));
  }

  @Test
  void testFullCycle_saveRetrieveAndRemove() {
    // Given
    URI requestUri = URI.create("http://localhost:8081/dashboard?view=summary");
    when(request.getURI()).thenReturn(requestUri);

    // When - save
    requestCache.saveRequest(exchange).block();

    // Then - verify saved
    assertEquals("/dashboard?view=summary", sessionAttributes.get(SAVED_REQUEST_KEY));

    // When - retrieve
    URI retrievedUri = requestCache.getRedirectUri(exchange).block();

    // Then - verify retrieved
    assertNotNull(retrievedUri);
    assertEquals("/dashboard?view=summary", retrievedUri.toString());

    // When - remove
    requestCache.removeMatchingRequest(exchange).block();

    // Then - verify cleared
    assertNull(sessionAttributes.get(SAVED_REQUEST_KEY));

    // And - subsequent retrieve returns empty
    URI afterRemove = requestCache.getRedirectUri(exchange).block();
    assertNull(afterRemove);
  }
}
