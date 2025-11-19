package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.authentication.ServerAuthenticationSuccessHandler;
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
  private final OAuth2LoginDebugger loginDebugger;
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  private final ReactiveClientRegistrationRepository clientRegistrationRepository;

  public SecurityConfig(
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
      OAuth2LoginDebugger loginDebugger,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      ReactiveClientRegistrationRepository clientRegistrationRepository) {
    this.authorizationRequestResolver = authorizationRequestResolver;
    this.loginDebugger = loginDebugger;
    this.authorizedClientRepository = authorizedClientRepository;
    this.clientRegistrationRepository = clientRegistrationRepository;
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    // TODO: use loginDebugger
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
                    .pathMatchers(
                        "/",
                        "/index.html",
                        "/assets/**",
                        "/src/**",
                        "/node_modules/**",
                        "/@vite/**",
                        "/@react-refresh",
                        "/vite.svg")
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
              // Phase 6 Fix: Custom authentication success handler that explicitly saves
              // OAuth2AuthorizedClient
              // This ensures the TokenRelay filter can find the access token
              oauth2.authenticationSuccessHandler(createOAuth2SuccessHandler());
              // Add failure handler for debugging
              oauth2.authenticationFailureHandler(
                  (webFilterExchange, ex) -> {
                    System.err.println("==== OAuth2 Login Failed ====");
                    System.err.println(
                        "Request URI: " + webFilterExchange.getExchange().getRequest().getURI());
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
        // Phase 6 Fix: Force session creation before OAuth2 authorization
        // This ensures the OAuth2 authorization request is persisted to Redis
        // before redirecting to Auth0. Without this, the session may not exist
        // when Auth0 redirects back, causing [authorization_request_not_found]
        .addFilterBefore(
            (exchange, chain) -> {
              System.err.println("==== FORCE SESSION CREATION FILTER ====");
              System.err.println("Path: " + exchange.getRequest().getPath().value());

              return exchange
                  .getSession()
                  .doOnNext(
                      session -> {
                        System.err.println("Session ID: " + session.getId());
                        System.err.println("Session creation time: " + session.getCreationTime());
                        // Force session to be created and saved
                        session.getAttributes().put("FORCE_CREATE", true);
                        System.err.println("Forced session creation");
                      })
                  .then(chain.filter(exchange));
            },
            SecurityWebFiltersOrder.AUTHENTICATION)
        .build();
  }

  /**
   * Creates a custom authentication success handler that explicitly saves the
   * OAuth2AuthorizedClient.
   *
   * <p>Phase 6 Fix: The default OAuth2 login process should automatically save the authorized
   * client, but in our Spring Security WebFlux + Spring Cloud Gateway + Redis Session
   * configuration, the authorized client is not being persisted. This custom handler explicitly
   * loads and saves it to ensure TokenRelay filter can access the access token.
   *
   * @return configured authentication success handler
   */
  // CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
  private ServerAuthenticationSuccessHandler createOAuth2SuccessHandler() {
    return new ServerAuthenticationSuccessHandler() {
      @Override
      public Mono<Void> onAuthenticationSuccess(
          WebFilterExchange webFilterExchange, Authentication authentication) {
        System.err.println("==== OAuth2 Login Success Handler ====");
        System.err.println("Authentication: " + authentication.getClass().getName());
        System.err.println("Principal: " + authentication.getName());
        System.err.println("Request URI: " + webFilterExchange.getExchange().getRequest().getURI());

        // Verify this is OAuth2 authentication
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
          System.err.println(
              "ERROR: Not an OAuth2AuthenticationToken, cannot save authorized client");
          return new RedirectServerAuthenticationSuccessHandler("/")
              .onAuthenticationSuccess(webFilterExchange, authentication);
        }

        var oauthToken = (OAuth2AuthenticationToken) authentication;
        var clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();

        System.err.println("Client Registration ID: " + clientRegistrationId);
        System.err.println("Attempting to load/save OAuth2AuthorizedClient...");

        // Get the exchange for repository operations
        var exchange = webFilterExchange.getExchange();

        // Try to load the authorized client - Spring Security might have already created it
        return authorizedClientRepository
            .loadAuthorizedClient(clientRegistrationId, authentication, exchange)
            .flatMap(
                authorizedClient -> {
                  // Client exists, explicitly save it to ensure persistence
                  System.err.println("Found OAuth2AuthorizedClient, explicitly saving...");
                  System.err.println(
                      "Access Token: "
                          + (authorizedClient.getAccessToken() != null
                              ? "present (expires: "
                                  + authorizedClient.getAccessToken().getExpiresAt()
                                  + ")"
                              : "MISSING"));
                  System.err.println(
                      "Refresh Token: "
                          + (authorizedClient.getRefreshToken() != null ? "present" : "MISSING"));

                  return authorizedClientRepository.saveAuthorizedClient(
                      authorizedClient, authentication, exchange);
                })
            .switchIfEmpty(
                // Client not found - this is the problem we're trying to fix
                // Try to retrieve from exchange attributes where Spring Security temporarily stores
                // it
                Mono.defer(
                    () -> {
                      System.err.println("OAuth2AuthorizedClient NOT found in repository!");
                      System.err.println("Checking exchange attributes...");

                      // Spring Security stores the authorized client in exchange attributes
                      // during login. Try common attribute keys
                      String[] possibleKeys = {
                        "org.springframework.security.oauth2.client.authentication"
                            + ".OAuth2AuthenticationToken",
                        "org.springframework.security.oauth2.client.OAuth2AuthorizedClient",
                        "SECURITY_CONTEXT_KEY"
                      };

                      for (String key : possibleKeys) {
                        var attr = exchange.getAttributes().get(key);
                        System.err.println("Checking attribute key: " + key + " = " + attr);
                      }

                      // Log all exchange attributes for debugging
                      System.err.println("All exchange attributes:");
                      exchange
                          .getAttributes()
                          .forEach((k, v) -> System.err.println("  " + k + " = " + v));

                      System.err.println(
                          "ERROR: Cannot save OAuth2AuthorizedClient - not found in "
                              + "repository or exchange attributes");
                      System.err.println(
                          "This will cause TokenRelay to fail. Check Spring Security "
                              + "configuration.");

                      return Mono.empty();
                    }))
            .doOnSuccess(
                v ->
                    System.err.println(
                        "OAuth2AuthorizedClient save operation completed (check for errors above)"))
            .doOnError(
                e ->
                    System.err.println(
                        "ERROR during OAuth2AuthorizedClient save: " + e.getMessage()))
            .onErrorResume(
                e -> {
                  // Log error but don't fail the login
                  System.err.println("Continuing with redirect despite save error");
                  e.printStackTrace();
                  return Mono.empty();
                })
            .then(
                Mono.defer(
                    () -> {
                      System.err.println("Redirecting to: /");
                      System.err.println("===============================");
                      return new RedirectServerAuthenticationSuccessHandler("/")
                          .onAuthenticationSuccess(webFilterExchange, authentication);
                    }));
      }
    };
  }
}
