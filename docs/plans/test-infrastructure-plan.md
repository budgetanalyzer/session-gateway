# Test Infrastructure Implementation Plan

## Problem Statement

### Current State
The session-gateway tests are failing with:
```
SessionGatewayApplicationTests > contextLoads() FAILED
    java.net.SocketTimeoutException
        Caused by: org.springframework.web.client.ResourceAccessException
            at ClientRegistrations.java:286
```

### Root Cause Analysis

**Primary Issue: Auth0 OIDC Discovery Call Failure**
- During Spring context initialization, OAuth2 client auto-configuration attempts to fetch OIDC provider metadata
- Makes HTTP call to: `https://test.auth0.com/.well-known/openid-configuration`
- The test provides a fake issuer URI that doesn't exist
- Results in `SocketTimeoutException` → context fails to load

**Secondary Issue: Missing Redis Infrastructure**
- Tests expect Redis on `localhost:6379` for session storage
- No embedded Redis or testcontainers configured
- Would fail after Auth0 issue is resolved

**Missing Test Infrastructure**
- No testcontainers setup
- No WireMock to mock external endpoints
- No test-specific configuration
- No base test classes
- No test resources (application-test.yml)

## Solution Approach

### Pattern Selection
Follow the **currency-service testcontainers pattern** with adaptations for session-gateway's specific needs.

### Key Differences from Currency-Service

| Aspect | Currency-Service | Session-Gateway |
|--------|-----------------|-----------------|
| Database | PostgreSQL container | None (no database) |
| Messaging | RabbitMQ container | None (no messaging) |
| Cache | Redis container | Redis container ✓ |
| Security | OAuth2 Resource Server (JWT validation) | OAuth2 Client (login flow) |
| Testing Framework | MockMvc (Spring MVC) | WebTestClient (WebFlux) |
| External APIs | WireMock for FRED API | WireMock for Auth0 OIDC |

### Architecture Decision: 2-Layer Base Test Hierarchy

After analysis, session-gateway will use a **simplified 2-layer approach** instead of currency-service's 3-layer hierarchy:

**Rationale:**
- Session-gateway is a gateway service - most tests need to test HTTP routing/filtering
- No database means no repository-only tests
- Most integration tests will need the full stack: Redis + WireMock + WebTestClient
- Only exception: basic `contextLoads()` smoke test

**Hierarchy:**

```
SessionGatewayApplicationTests (standalone)
    └─ Minimal context test only

AbstractIntegrationTest (full stack)
    ├─ Redis testcontainer
    ├─ WireMock for Auth0
    └─ WebTestClient configured
        └─ All other integration tests extend this
```

**vs Currency-Service (3-layer):**
```
AbstractIntegrationTest
    └─ AbstractWireMockTest
        └─ AbstractControllerTest
```

## Implementation Plan

### 1. Update Dependencies

#### gradle/libs.versions.toml

Add versions:
```toml
[versions]
wiremock = "3.10.0"
awaitility = "4.2.2"
```

Add libraries:
```toml
[libraries]
spring-boot-testcontainers = { module = "org.springframework.boot:spring-boot-testcontainers" }
testcontainers = { module = "org.testcontainers:testcontainers" }
testcontainers-junit-jupiter = { module = "org.testcontainers:junit-jupiter" }
wiremock-standalone = { module = "org.wiremock:wiremock-standalone", version.ref = "wiremock" }
awaitility = { module = "org.awaitility:awaitility", version.ref = "awaitility" }
```

#### build.gradle.kts

Add to dependencies:
```kotlin
testImplementation(libs.spring.boot.testcontainers)
testImplementation(libs.testcontainers)
testImplementation(libs.testcontainers.junit.jupiter)
testImplementation(libs.wiremock.standalone)
testImplementation(libs.awaitility)
```

### 2. Create Test Infrastructure

#### TestContainersConfig.java
**Location:** `src/test/java/org/budgetanalyzer/sessiongateway/config/TestContainersConfig.java`

**Purpose:** Centralized testcontainers configuration using Spring Boot 3.1+ `@ServiceConnection`

**Key Features:**
- Static Redis container with `.withReuse(true)` for fast test execution
- `@ServiceConnection` auto-configures `spring.data.redis.*` properties
- No manual `@DynamicPropertySource` needed

**Implementation:**
```java
package org.budgetanalyzer.sessiongateway.config;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;

@TestConfiguration(proxyBeanMethods = false)
public class TestContainersConfig {

    static GenericContainer<?> redisContainer =
        new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379)
            .withReuse(true);

    @Bean
    @ServiceConnection(name = "redis")
    GenericContainer<?> redisContainer() {
        return redisContainer;
    }
}
```

#### WireMockConfig.java
**Location:** `src/test/java/org/budgetanalyzer/sessiongateway/config/WireMockConfig.java`

**Purpose:** Mock Auth0 OIDC endpoints and downstream NGINX Gateway

**Key Features:**
- Static initialization (available before Spring context)
- Dynamic port allocation
- Lifecycle managed via Spring bean
- Static getter for `@DynamicPropertySource`

**Implementation:**
```java
package org.budgetanalyzer.sessiongateway.config;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration(proxyBeanMethods = false)
public class WireMockConfig {

    private static WireMockServer wireMockServer;

    static {
        wireMockServer = new WireMockServer(
            WireMockConfiguration.options().dynamicPort()
        );
        wireMockServer.start();
    }

    @Bean(destroyMethod = "stop")
    public WireMockServer wireMockServer() {
        return wireMockServer;
    }

    public static WireMockServer getWireMockServer() {
        return wireMockServer;
    }
}
```

### 3. Create Base Test Class

#### AbstractIntegrationTest.java
**Location:** `src/test/java/org/budgetanalyzer/sessiongateway/base/AbstractIntegrationTest.java`

**Purpose:** Single base test class with full stack (Redis + WireMock + WebTestClient)

**Key Features:**
- `@SpringBootTest(webEnvironment = RANDOM_PORT)` for reactive testing
- Imports both TestContainersConfig and WireMockConfig
- `@DynamicPropertySource` configures OAuth2 issuer URI to WireMock
- `@BeforeEach` resets WireMock and provides Auth0 OIDC discovery stub
- `@Autowired WebTestClient` for reactive HTTP testing
- Helper methods for Auth0 OIDC endpoint stubs

**Implementation:**
```java
package org.budgetanalyzer.sessiongateway.base;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.budgetanalyzer.sessiongateway.config.TestContainersConfig;
import org.budgetanalyzer.sessiongateway.config.WireMockConfig;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

@SpringBootTest(webEnvironment = RANDOM_PORT)
@Testcontainers
@AutoConfigureWebTestClient
@Import({TestContainersConfig.class, WireMockConfig.class})
public abstract class AbstractIntegrationTest {

    @Autowired
    protected WebTestClient webTestClient;

    @Autowired
    protected WireMockServer wireMockServer;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        String wireMockUrl = "http://localhost:" + WireMockConfig.getWireMockServer().port();

        // Point Auth0 OAuth2 configuration to WireMock
        registry.add("spring.security.oauth2.client.provider.auth0.issuer-uri",
            () -> wireMockUrl + "/auth0");

        // Point downstream gateway to WireMock
        registry.add("api.gateway.url", () -> wireMockUrl + "/api-gateway");
    }

    @BeforeEach
    void resetWireMock() {
        wireMockServer.resetAll();
        stubAuth0OidcDiscovery();
    }

    protected void stubAuth0OidcDiscovery() {
        String baseUrl = "http://localhost:" + wireMockServer.port();

        wireMockServer.stubFor(get(urlEqualTo("/auth0/.well-known/openid-configuration"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                        "issuer": "%s/auth0",
                        "authorization_endpoint": "%s/auth0/authorize",
                        "token_endpoint": "%s/auth0/oauth/token",
                        "userinfo_endpoint": "%s/auth0/userinfo",
                        "jwks_uri": "%s/auth0/.well-known/jwks.json",
                        "response_types_supported": ["code"],
                        "grant_types_supported": ["authorization_code", "refresh_token"],
                        "subject_types_supported": ["public"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                        "scopes_supported": ["openid", "profile", "email"]
                    }
                    """.formatted(baseUrl, baseUrl, baseUrl, baseUrl, baseUrl))));

        // Stub JWKS endpoint (required for JWT validation)
        wireMockServer.stubFor(get(urlEqualTo("/auth0/.well-known/jwks.json"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                        "keys": []
                    }
                    """)));
    }

    protected void stubAuth0TokenEndpoint(String accessToken, String idToken) {
        wireMockServer.stubFor(post(urlEqualTo("/auth0/oauth/token"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                        "access_token": "%s",
                        "id_token": "%s",
                        "token_type": "Bearer",
                        "expires_in": 3600
                    }
                    """.formatted(accessToken, idToken))));
    }

    protected void stubAuth0UserInfo(String sub, String email, String name) {
        wireMockServer.stubFor(get(urlEqualTo("/auth0/userinfo"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                        "sub": "%s",
                        "email": "%s",
                        "name": "%s"
                    }
                    """.formatted(sub, email, name))));
    }
}
```

### 4. Create Test Resources

#### src/test/resources/application.yml

**Purpose:** Test-specific Spring configuration

**Key Configurations:**
- Redis connection (auto-configured by @ServiceConnection)
- OAuth2 client settings (issuer-uri overridden by @DynamicPropertySource)
- Session configuration
- Gateway routes (pointing to WireMock for downstream services)
- Logging for debugging

**Implementation:**
```yaml
spring:
  # Redis configuration (host/port auto-configured by @ServiceConnection)
  data:
    redis:
      timeout: 2000ms

  # Session configuration
  session:
    timeout: 30m
    redis:
      namespace: spring:session:test

  # OAuth2 Client (issuer-uri will be overridden by @DynamicPropertySource)
  security:
    oauth2:
      client:
        registration:
          auth0:
            client-id: test-client-id
            client-secret: test-client-secret
            scope:
              - openid
              - profile
              - email
            redirect-uri: "{baseUrl}/login/oauth2/code/{registrationId}"
        provider:
          auth0:
            # Will be overridden to point to WireMock
            issuer-uri: http://localhost:8080/auth0

  # Cloud Gateway routes
  cloud:
    gateway:
      routes:
        - id: api_route
          uri: ${api.gateway.url:http://localhost:8080}
          predicates:
            - Path=/api/**
          filters:
            - TokenRelay=
        - id: frontend_route
          uri: ${api.gateway.url:http://localhost:8080}
          predicates:
            - Path=/**
          filters:
            - TokenRelay=

# Logging
logging:
  level:
    org.springframework.security: DEBUG
    org.springframework.security.oauth2: DEBUG
    org.budgetanalyzer.sessiongateway: DEBUG

# Custom properties
api:
  gateway:
    url: http://localhost:8080
```

### 5. Update SessionGatewayApplicationTests

**Changes:**
1. Extend `AbstractIntegrationTest` to get full test infrastructure
2. Remove `@TestPropertySource` (now in application.yml + @DynamicPropertySource)
3. Keep simple `contextLoads()` test
4. Optionally add basic integration test

**Updated Implementation:**
```java
package org.budgetanalyzer.sessiongateway;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;
import org.junit.jupiter.api.Test;

class SessionGatewayApplicationTests extends AbstractIntegrationTest {

    @Test
    void contextLoads() {
        // Context should load successfully with mocked Auth0 and Redis testcontainer
    }

    @Test
    void healthEndpointIsAccessible() {
        webTestClient
            .get()
            .uri("/actuator/health")
            .exchange()
            .expectStatus().isOk();
    }
}
```

## Verification Steps

### 1. Format and Build
```bash
./gradlew clean spotlessApply
./gradlew clean build
```

### 2. Expected Output
```
> Task :test
SessionGatewayApplicationTests > contextLoads() PASSED
SessionGatewayApplicationTests > healthEndpointIsAccessible() PASSED

BUILD SUCCESSFUL
```

### 3. Verify Testcontainers
On first run, Docker will pull `redis:7-alpine` image. Subsequent runs will reuse the container (faster execution).

### 4. Check Logs
Look for:
- `Creating container for image: redis:7-alpine`
- `Container redis:7-alpine started`
- OAuth2 client successfully configured with WireMock issuer URI
- No `SocketTimeoutException` errors

## Future Enhancements

Once basic infrastructure is working, additional test patterns can be added:

### 1. OAuth2 Flow Integration Tests
Test the complete login flow:
- Redirect to Auth0 authorization endpoint
- Callback with authorization code
- Token exchange
- Session cookie creation

### 2. Token Refresh Tests
Test the proactive token refresh filter:
- Verify refresh happens before expiry
- Verify new tokens stored in session
- Use `awaitility` for async assertions

### 3. Gateway Filter Tests
Test individual filters in isolation:
- TokenRefreshGatewayFilterFactory
- OAuth2TokenRelayGatewayFilter
- RequestLoggingWebFilter

### 4. Proxy Route Tests
Test that requests are correctly proxied:
- JWT injection into Authorization header
- Correct routing based on path predicates
- Error handling for downstream failures

### 5. Session Management Tests
Test Redis session behavior:
- Session creation on login
- Session invalidation on logout
- Session timeout
- Concurrent sessions

## References

- **Currency-Service Implementation**: `/workspace/currency-service/src/test/java/org/budgetanalyzer/currency/`
- **Testcontainers Documentation**: https://testcontainers.com/
- **Spring Boot Testcontainers**: https://docs.spring.io/spring-boot/reference/testing/testcontainers.html
- **WireMock Documentation**: https://wiremock.org/
- **WebTestClient**: https://docs.spring.io/spring-framework/reference/testing/webtestclient.html

## Success Criteria

✅ Tests run without requiring external Docker Compose
✅ Tests run without requiring running Auth0 instance
✅ Context loads successfully with mocked dependencies
✅ Foundation established for comprehensive gateway integration tests
✅ Pattern consistent with currency-service approach
✅ Fast test execution with container reuse
