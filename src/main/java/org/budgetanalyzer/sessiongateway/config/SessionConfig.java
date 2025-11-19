package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectMapper.DefaultTyping;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

/**
 * Session management configuration.
 *
 * <p>Configures Redis-backed sessions with secure cookie attributes.
 *
 * <p>Phase 2 Task 2.2: Configure secure session cookies
 *
 * <ul>
 *   <li>HttpOnly: Prevents JavaScript access (XSS protection)
 *   <li>Secure: HTTPS only (set to false for local development)
 *   <li>SameSite=Strict: Prevents CSRF attacks
 *   <li>30 minute session timeout
 * </ul>
 */
@Configuration
@EnableRedisWebSession(maxInactiveIntervalInSeconds = 1800) // 30 minutes
public class SessionConfig {

  private static final Logger log = LoggerFactory.getLogger(SessionConfig.class);

  /**
   * Configures session cookie with security attributes.
   *
   * <p>For production, set Secure=true to enforce HTTPS.
   *
   * @return session ID resolver with secure cookie configuration
   */
  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    var resolver = new CookieWebSessionIdResolver();

    resolver.setCookieName("SESSION");

    // Configure secure cookie attributes
    resolver.addCookieInitializer(
        builder -> {
          builder.httpOnly(true); // Prevent JavaScript access (XSS protection)
          builder.secure(false); // Set to true in production (HTTPS only)
          builder.sameSite("Lax"); // Allow OAuth2 redirects while preventing CSRF
          builder.path("/"); // Available for entire application
          builder.maxAge(-1); // Session cookie (deleted when browser closes)
        });

    return resolver;
  }

  /**
   * Configures Redis serializer with Spring Security Jackson modules.
   *
   * <p>This bean configures Jackson to properly serialize Spring Security objects (including
   * HttpMethod, OAuth2 authorization requests, etc.) when storing them in Redis sessions.
   *
   * <p>Registered modules:
   *
   * <ul>
   *   <li>SecurityJackson2Modules: Spring Security class serializers
   *   <li>JavaTimeModule: Java 8 date/time serializers
   * </ul>
   *
   * @return Redis serializer with Spring Security support
   */
  @Bean
  public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
    var mapper = new ObjectMapper();

    // Register Spring Security Jackson modules to handle security classes (HttpMethod, etc.)
    mapper.registerModules(SecurityJackson2Modules.getModules(getClass().getClassLoader()));

    // Register Java 8 date/time module for proper LocalDateTime/Instant serialization
    mapper.registerModule(new JavaTimeModule());

    // Enable polymorphic type handling for proper deserialization
    mapper.activateDefaultTyping(
        mapper.getPolymorphicTypeValidator(), DefaultTyping.NON_FINAL, JsonTypeInfo.As.PROPERTY);

    return new GenericJackson2JsonRedisSerializer(mapper);
  }

  /**
   * Phase 6 Fix: Session debugging filter to log session creation and access.
   *
   * <p>This filter helps diagnose session persistence issues by logging: - Session ID - Request
   * path - Session attributes - Creation time
   *
   * @return WebFilter that logs session information
   */
  @Bean
  public WebFilter sessionLoggingFilter() {
    return (exchange, chain) -> {
      var path = exchange.getRequest().getPath().value();

      return exchange
          .getSession()
          .doOnNext(
              session -> {
                log.debug("==== SESSION DEBUG ====");
                log.debug("Path: {}", path);
                log.debug("Session ID: {}", session.getId());
                log.debug("Session creation time: {}", session.getCreationTime());
                log.debug("Session attributes: {}", session.getAttributes().keySet());
                log.debug("=======================");
              })
          .then(chain.filter(exchange));
    };
  }

  // Note: WebSessionManager bean is automatically configured by
  // @EnableRedisWebSession annotation, so we don't need to define it manually.
  // Spring Session handles the wiring between Redis and WebFlux session management.
}
