package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import reactor.core.publisher.Mono;

/**
 * Security configuration for Session Gateway.
 *
 * <p>Phase 2 Task 2.1: Implements OAuth2 login with Auth0
 *
 * <ul>
 *   <li>OAuth2 login with Authorization Code + PKCE flow
 *   <li>Session-based authentication (tokens stored server-side in Redis)
 *   <li>Public endpoints: /actuator/health, /login, /error, frontend routes (/, /assets, etc.)
 *   <li>Protected endpoints: /api/** (require authentication)
 *   <li>Custom authentication entry point: API requests get 401, browser navigation redirects to
 *       OAuth2
 * </ul>
 *
 * <p><strong>Phase 6 Fix:</strong> Uses {@link DelegatingServerAuthenticationEntryPoint} to
 * properly route API requests vs browser navigation. API requests ({@code /api/**}) return 401
 * Unauthorized, while browser navigation redirects to OAuth2. This prevents CORS errors from Auth0
 * redirects on XHR/fetch API requests.
 *
 * <p><strong>Technical Note:</strong> Spring Security WebFlux's {@code .oauth2Login()}
 * configuration internally registers its own authentication entry point that would otherwise
 * redirect ALL requests to OAuth2. Using {@code DelegatingServerAuthenticationEntryPoint} with
 * explicit path matchers ensures API requests are caught first and return 401 instead of
 * redirecting.
 *
 * @see DelegatingServerAuthenticationEntryPoint
 */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  private final OAuth2LoginDebugger oAuth2LoginDebugger;

  public SecurityConfig(
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
      OAuth2LoginDebugger oAuth2LoginDebugger) {
    this.authorizationRequestResolver = authorizationRequestResolver;
    this.oAuth2LoginDebugger = oAuth2LoginDebugger;
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    System.err.println("==== CREATING SECURITY WEB FILTER CHAIN ====");
    System.err.println("==== THIS PROVES THE BEAN IS BEING CREATED ====");

    return http.authorizeExchange(
            exchanges ->
                exchanges
                    // Allow health check endpoints without authentication
                    .pathMatchers("/actuator/health/**")
                    .permitAll()
                    // Allow login and error pages
                    .pathMatchers("/login/**", "/error", "/oauth2/**")
                    .permitAll()
                    // Allow frontend routes (served by NGINX) without authentication
                    // Users can browse the app; API calls will require authentication
                    .pathMatchers("/", "/index.html", "/assets/**", "/src/**", "/node_modules/**", "/@vite/**", "/@react-refresh", "/vite.svg")
                    .permitAll()
                    // API routes require authentication
                    .pathMatchers("/api/**")
                    .authenticated()
                    // All other requests require authentication (fallback)
                    .anyExchange()
                    .authenticated())
        // Enable OAuth2 Login
        .oauth2Login(
            oauth2 -> {
              oauth2.authorizationRequestResolver(authorizationRequestResolver);
              // Redirect to frontend root after successful login
              // Session Gateway serves frontend at /, so redirect there
              oauth2.authenticationSuccessHandler(
                  (webFilterExchange, authentication) -> {
                    System.err.println("==== OAuth2 Login Success ====");
                    System.err.println("Authentication: " + authentication.getClass().getName());
                    System.err.println("Principal: " + authentication.getName());
                    System.err.println("Redirecting to: /");
                    System.err.println("Request URI: " + webFilterExchange.getExchange().getRequest().getURI());
                    System.err.println("===============================");
                    return new RedirectServerAuthenticationSuccessHandler("/")
                        .onAuthenticationSuccess(webFilterExchange, authentication);
                  });
              // Add failure handler for debugging
              oauth2.authenticationFailureHandler(
                  (webFilterExchange, ex) -> {
                    System.err.println("==== OAuth2 Login Failed ====");
                    System.err.println("Request URI: " + webFilterExchange.getExchange().getRequest().getURI());
                    System.err.println("Error: " + ex.getClass().getName());
                    System.err.println("Message: " + ex.getMessage());
                    ex.printStackTrace();
                    System.err.println("==============================");
                    return Mono.error(ex);
                  });
            })
        // Disable CSRF for API gateway
        // Session cookies with SameSite=Lax + OAuth2 state parameter provide CSRF protection
        // OAuth2 endpoints (login/logout) don't need additional CSRF tokens
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        // Configure exception handling with delegating entry point
        // Phase 6: Use DelegatingServerAuthenticationEntryPoint to properly handle API vs browser
        // This works around Spring Security WebFlux limitation where oauth2Login() would otherwise
        // redirect ALL unauthenticated requests (including API XHR calls) to Auth0
        .exceptionHandling(
            exceptions -> {
              System.err.println("==== CONFIGURING EXCEPTION HANDLING ====");

              // Create delegating entry point to route based on request path
              DelegatingServerAuthenticationEntryPoint delegatingEntryPoint =
                  new DelegatingServerAuthenticationEntryPoint(
                      // API requests (/api/**) return 401 Unauthorized
                      // Frontend axios interceptor will catch this and redirect user to login page
                      new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                          ServerWebExchangeMatchers.pathMatchers("/api/**"),
                          (exchange, ex) -> {
                            System.err.println("==== API PATH MATCHED - RETURNING 401 ====");
                            System.err.println("Path: " + exchange.getRequest().getPath().value());
                            System.err.println("Exception: " + ex.getClass().getName());
                            // Set 401 status and commit the response
                            // This prevents OAuth2 filters from overriding with redirect
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            System.err.println("==== COMMITTING RESPONSE ====");
                            return exchange.getResponse().setComplete();
                          }));

              // Browser navigation (non-API requests) redirects to OAuth2 authorization flow
              // This is the default for all requests that don't match the above matcher
              delegatingEntryPoint.setDefaultEntryPoint(
                  (exchange, ex) -> {
                    System.err.println("==== DEFAULT ENTRY POINT - REDIRECTING TO OAUTH2 ====");
                    System.err.println("Path: " + exchange.getRequest().getPath().value());
                    System.err.println("Exception: " + ex.getClass().getName());
                    return new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/auth0")
                        .commence(exchange, ex);
                  });

              System.err.println("==== DELEGATING ENTRY POINT CONFIGURED ====");
              exceptions.authenticationEntryPoint(delegatingEntryPoint);
            })
        .build();
  }
}
