package org.budgetanalyzer.sessiongateway.service;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;

@DisplayName("UserSyncClient")
class UserSyncClientTest {

  private static final String TEST_AUTH0_SUB = "auth0|test123";
  private static final String TEST_EMAIL = "test@example.com";
  private static final String TEST_DISPLAY_NAME = "Test User";
  private static final String TEST_ACCESS_TOKEN = "test-access-token";
  private static final String TEST_USER_ID = "usr_abc123";

  private WireMockServer wireMockServer;
  private UserSyncClient userSyncClient;

  @BeforeEach
  void setUp() {
    wireMockServer = new WireMockServer(WireMockConfiguration.options().dynamicPort());
    wireMockServer.start();

    String baseUrl = "http://localhost:" + wireMockServer.port();
    userSyncClient = new UserSyncClient(WebClient.builder(), baseUrl);
  }

  @AfterEach
  void tearDown() {
    wireMockServer.stop();
  }

  @Nested
  @DisplayName("syncUser")
  class SyncUserTests {

    @Test
    @DisplayName("should sync user successfully when permission-service returns 200")
    void shouldSyncUserSuccessfully() {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .withHeader("Authorization", equalTo("Bearer " + TEST_ACCESS_TOKEN))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withBody(
                          """
                          {
                            "userId": "%s",
                            "email": "%s",
                            "displayName": "%s"
                          }
                          """
                              .formatted(TEST_USER_ID, TEST_EMAIL, TEST_DISPLAY_NAME))));

      // Act & Assert - should complete without throwing
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME, TEST_ACCESS_TOKEN)
                  .block());

      // Verify request was made with correct payload
      wireMockServer.verify(
          postRequestedFor(urlEqualTo("/v1/users/sync"))
              .withHeader("Authorization", equalTo("Bearer " + TEST_ACCESS_TOKEN))
              .withRequestBody(
                  equalToJson(
                      """
                      {
                        "auth0Sub": "%s",
                        "email": "%s",
                        "displayName": "%s"
                      }
                      """
                          .formatted(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME))));
    }

    @Test
    @DisplayName("should sync user successfully with null displayName")
    void shouldSyncUserWithNullDisplayName() {
      // Arrange
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withBody(
                          """
                          {
                            "userId": "%s",
                            "email": "%s",
                            "displayName": null
                          }
                          """
                              .formatted(TEST_USER_ID, TEST_EMAIL))));

      // Act & Assert - should complete without throwing
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, null, TEST_ACCESS_TOKEN)
                  .block());
    }

    @Test
    @DisplayName("should complete without error when permission-service returns 500")
    void shouldCompleteWithoutErrorWhenServiceReturns500() {
      // Arrange - permission-service is down
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .willReturn(
                  aResponse()
                      .withStatus(500)
                      .withBody("Internal Server Error")));

      // Act & Assert - should complete (not fail) because sync failures shouldn't block login
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME, TEST_ACCESS_TOKEN)
                  .block());
    }

    @Test
    @DisplayName("should complete without error when permission-service returns 401")
    void shouldCompleteWithoutErrorWhenServiceReturns401() {
      // Arrange - token is invalid
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .willReturn(
                  aResponse()
                      .withStatus(401)
                      .withBody("Unauthorized")));

      // Act & Assert - should complete (not fail) because sync failures shouldn't block login
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME, TEST_ACCESS_TOKEN)
                  .block());
    }

    @Test
    @DisplayName("should complete without error when connection times out")
    void shouldCompleteWithoutErrorOnConnectionTimeout() {
      // Arrange - permission-service doesn't respond
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withFixedDelay(5000))); // 5 second delay

      // Act & Assert - should complete eventually (WebClient has default timeout)
      // Note: This test verifies error resilience, actual timeout behavior depends on WebClient config
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME, TEST_ACCESS_TOKEN)
                  .block());
    }

    @Test
    @DisplayName("should complete without error when response body is malformed")
    void shouldCompleteWithoutErrorOnMalformedResponse() {
      // Arrange - permission-service returns garbage
      wireMockServer.stubFor(
          post(urlEqualTo("/v1/users/sync"))
              .willReturn(
                  aResponse()
                      .withStatus(200)
                      .withHeader("Content-Type", "application/json")
                      .withBody("not valid json")));

      // Act & Assert - should complete (not fail) because sync failures shouldn't block login
      assertDoesNotThrow(
          () ->
              userSyncClient
                  .syncUser(TEST_AUTH0_SUB, TEST_EMAIL, TEST_DISPLAY_NAME, TEST_ACCESS_TOKEN)
                  .block());
    }
  }
}
