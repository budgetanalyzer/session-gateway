package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.web.server.session.CookieWebSessionIdResolver;
import org.springframework.web.server.session.WebSessionIdResolver;

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

  /**
   * Configures session cookie with security attributes.
   *
   * <p>For production, set Secure=true to enforce HTTPS.
   *
   * @return session ID resolver with secure cookie configuration
   */
  @Bean
  public WebSessionIdResolver webSessionIdResolver() {
    CookieWebSessionIdResolver resolver = new CookieWebSessionIdResolver();

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
}
