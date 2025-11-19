package org.budgetanalyzer.sessiongateway.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.security.RedirectUrlValidator;
import org.budgetanalyzer.sessiongateway.security.RedisServerRequestCache;

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

  private static final Logger logger = LoggerFactory.getLogger(SecurityConfig.class);

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

  /**
   * Creates a Redis-backed ServerRequestCache for saving original request URIs.
   *
   * <p>This custom implementation addresses Spring Security WebFlux issue #8967 where {@code
   * SPRING_SECURITY_SAVED_REQUEST} is not properly saved during OAuth2 login. By storing request
   * URIs in Redis sessions, we can redirect users to their originally requested page after
   * authentication.
   *
   * @return Redis-backed request cache
   */
  @Bean
  public ServerRequestCache serverRequestCache() {
    return new RedisServerRequestCache();
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(
      ServerHttpSecurity http, ServerRequestCache serverRequestCache) {
    logger.info("Creating security web filter chain");

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
              oauth2.authenticationSuccessHandler(createOAuth2SuccessHandler(serverRequestCache));
              // Add failure handler for debugging
              oauth2.authenticationFailureHandler(
                  (webFilterExchange, ex) -> {
                    logger.error(
                        "OAuth2 login failed for URI: {}, error: {}",
                        webFilterExchange.getExchange().getRequest().getURI(),
                        ex.getMessage(),
                        ex);
                    return Mono.error(ex);
                  });
            })
        // Configure request cache for saving original request URIs
        .requestCache(requestCache -> requestCache.requestCache(serverRequestCache))
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
              logger.debug("Configuring exception handling with delegating entry point");

              // Create delegating entry point to route based on request path
              DelegatingServerAuthenticationEntryPoint delegatingEntryPoint =
                  new DelegatingServerAuthenticationEntryPoint(
                      // API requests (/api/**) return 401 Unauthorized
                      // Frontend axios interceptor will catch this and redirect user to login page
                      new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                          ServerWebExchangeMatchers.pathMatchers("/api/**"),
                          (exchange, ex) -> {
                            logger.debug(
                                "API path matched, returning 401 for: {}",
                                exchange.getRequest().getPath().value());
                            // Set 401 status and commit the response
                            // This prevents OAuth2 filters from overriding with redirect
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                          }));

              // Browser navigation (non-API requests) redirects to OAuth2 authorization flow
              // This is the default for all requests that don't match the above matcher
              delegatingEntryPoint.setDefaultEntryPoint(
                  (exchange, ex) -> {
                    logger.debug(
                        "Default entry point triggered, redirecting to OAuth2 for: {}",
                        exchange.getRequest().getPath().value());
                    return new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/auth0")
                        .commence(exchange, ex);
                  });

              logger.debug("Delegating entry point configured successfully");
              exceptions.authenticationEntryPoint(delegatingEntryPoint);
            })
        // Phase 6 Fix: Force session creation before OAuth2 authorization
        // This ensures the OAuth2 authorization request is persisted to Redis
        // before redirecting to Auth0. Without this, the session may not exist
        // when Auth0 redirects back, causing [authorization_request_not_found]
        .addFilterBefore(
            (exchange, chain) -> {
              logger.debug(
                  "Force session creation filter for path: {}",
                  exchange.getRequest().getPath().value());

              return exchange
                  .getSession()
                  .doOnNext(
                      session -> {
                        logger.debug(
                            "Session created - ID: {}, creation time: {}",
                            session.getId(),
                            session.getCreationTime());
                        // Force session to be created and saved
                        session.getAttributes().put("FORCE_CREATE", true);
                      })
                  .then(chain.filter(exchange));
            },
            SecurityWebFiltersOrder.AUTHENTICATION)
        .build();
  }

  /**
   * Creates a custom authentication success handler that saves the OAuth2AuthorizedClient and
   * redirects to the originally requested URL.
   *
   * <p>Phase 6 Fix: The default OAuth2 login process should automatically save the authorized
   * client, but in our Spring Security WebFlux + Spring Cloud Gateway + Redis Session
   * configuration, the authorized client is not being persisted. This custom handler explicitly
   * loads and saves it to ensure TokenRelay filter can access the access token.
   *
   * <p>Return URL Support: After successful authentication, this handler checks for a return URL in
   * the following priority order:
   *
   * <ol>
   *   <li>Explicit {@code returnUrl} from session (CUSTOM_RETURN_URL attribute)
   *   <li>Saved request from {@link ServerRequestCache} (original requested URL)
   *   <li>Default redirect to {@code /}
   * </ol>
   *
   * <p>All URLs are validated using {@link RedirectUrlValidator} to prevent open redirect
   * vulnerabilities.
   *
   * @param serverRequestCache the request cache for retrieving saved request URIs
   * @return configured authentication success handler
   */
  // CHECKSTYLE.SUPPRESS: AbbreviationAsWordInName
  private ServerAuthenticationSuccessHandler createOAuth2SuccessHandler(
      ServerRequestCache serverRequestCache) {
    return new ServerAuthenticationSuccessHandler() {
      @Override
      public Mono<Void> onAuthenticationSuccess(
          WebFilterExchange webFilterExchange, Authentication authentication) {
        logger.debug(
            "OAuth2 login success - Principal: {}, URI: {}",
            authentication.getName(),
            webFilterExchange.getExchange().getRequest().getURI());

        // Verify this is OAuth2 authentication
        if (!(authentication instanceof OAuth2AuthenticationToken)) {
          logger.warn(
              "Not an OAuth2AuthenticationToken, cannot save authorized client. Type: {}",
              authentication.getClass().getName());
          return redirectToUrl("/", webFilterExchange, authentication);
        }

        var oauthToken = (OAuth2AuthenticationToken) authentication;
        var clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();

        logger.debug(
            "Attempting to load/save OAuth2AuthorizedClient for registration ID: {}",
            clientRegistrationId);

        // Get the exchange for repository operations
        var exchange = webFilterExchange.getExchange();

        // Try to load the authorized client - Spring Security might have already created it
        return authorizedClientRepository
            .loadAuthorizedClient(clientRegistrationId, authentication, exchange)
            .flatMap(
                authorizedClient -> {
                  // Client exists, explicitly save it to ensure persistence
                  var accessToken = authorizedClient.getAccessToken();
                  var refreshToken = authorizedClient.getRefreshToken();
                  logger.debug(
                      "Found OAuth2AuthorizedClient - Access Token: {}, Refresh Token: {}",
                      accessToken != null
                          ? "present (expires: " + accessToken.getExpiresAt() + ")"
                          : "MISSING",
                      refreshToken != null ? "present" : "MISSING");

                  return authorizedClientRepository.saveAuthorizedClient(
                      authorizedClient, authentication, exchange);
                })
            .switchIfEmpty(
                // Client not found - this is the problem we're trying to fix
                // Try to retrieve from exchange attributes where Spring Security temporarily stores
                // it
                Mono.defer(
                    () -> {
                      logger.warn("OAuth2AuthorizedClient NOT found in repository");
                      logger.debug("Checking exchange attributes for authorized client...");

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
                        logger.debug("Checking attribute key: {} = {}", key, attr);
                      }

                      // Log all exchange attributes for debugging
                      if (logger.isDebugEnabled()) {
                        logger.debug("All exchange attributes:");
                        exchange.getAttributes().forEach((k, v) -> logger.debug("  {} = {}", k, v));
                      }

                      logger.error(
                          "Cannot save OAuth2AuthorizedClient - not found in repository or "
                              + "exchange attributes. This will cause TokenRelay to fail. "
                              + "Check Spring Security configuration.");

                      return Mono.empty();
                    }))
            .doOnSuccess(v -> logger.debug("OAuth2AuthorizedClient save operation completed"))
            .doOnError(
                e -> logger.error("Error during OAuth2AuthorizedClient save: {}", e.getMessage()))
            .onErrorResume(
                e -> {
                  // Log error but don't fail the login
                  logger.warn("Continuing with redirect despite save error", e);
                  return Mono.empty();
                })
            .then(determineRedirectUrl(webFilterExchange, authentication, serverRequestCache));
      }
    };
  }

  /**
   * Determines the redirect URL after successful OAuth2 authentication.
   *
   * <p>Priority order:
   *
   * <ol>
   *   <li>Explicit returnUrl from session (CUSTOM_RETURN_URL)
   *   <li>Saved request from ServerRequestCache
   *   <li>Default to "/"
   * </ol>
   *
   * @param webFilterExchange the web filter exchange
   * @param authentication the authentication
   * @param serverRequestCache the request cache for retrieving saved request URIs
   * @return Mono that completes the redirect
   */
  private Mono<Void> determineRedirectUrl(
      WebFilterExchange webFilterExchange,
      Authentication authentication,
      ServerRequestCache serverRequestCache) {
    var exchange = webFilterExchange.getExchange();

    return exchange
        .getSession()
        .flatMap(
            session -> {
              // Priority 1: Check for explicit returnUrl in session
              String explicitReturnUrl = session.getAttribute("CUSTOM_RETURN_URL");
              if (explicitReturnUrl != null) {
                logger.info("Found explicit return URL in session: {}", explicitReturnUrl);
                session.getAttributes().remove("CUSTOM_RETURN_URL");
                return validateAndRedirect(explicitReturnUrl, webFilterExchange, authentication);
              }

              // Priority 2: Check ServerRequestCache for saved request
              return serverRequestCache
                  .getRedirectUri(exchange)
                  .flatMap(
                      uri -> {
                        logger.info("Found saved request URI: {}", uri);
                        // Clear the saved request to prevent reuse
                        return serverRequestCache
                            .removeMatchingRequest(exchange)
                            .then(
                                validateAndRedirect(
                                    uri.toString(), webFilterExchange, authentication));
                      })
                  .switchIfEmpty(
                      Mono.defer(
                          () -> {
                            // Priority 3: Default to "/"
                            logger.debug("No return URL found, using default: /");
                            return redirectToUrl("/", webFilterExchange, authentication);
                          }));
            });
  }

  /**
   * Validates a redirect URL and performs the redirect if valid.
   *
   * <p>Uses {@link RedirectUrlValidator} to ensure the URL is safe (same-origin only). If the URL
   * is invalid or potentially malicious, redirects to the safe default "/" instead.
   *
   * @param redirectUrl the URL to validate and redirect to
   * @param webFilterExchange the web filter exchange
   * @param authentication the authentication
   * @return Mono that completes the redirect
   */
  private Mono<Void> validateAndRedirect(
      String redirectUrl, WebFilterExchange webFilterExchange, Authentication authentication) {

    if (RedirectUrlValidator.isValidRedirectUrl(redirectUrl)) {
      logger.info("Redirecting authenticated user to: {}", redirectUrl);
      return redirectToUrl(redirectUrl, webFilterExchange, authentication);
    } else {
      logger.warn(
          "Invalid or potentially malicious redirect URL rejected: {}, using safe default: /",
          redirectUrl);
      return redirectToUrl("/", webFilterExchange, authentication);
    }
  }

  /**
   * Performs a redirect to the specified URL.
   *
   * @param url the URL to redirect to
   * @param webFilterExchange the web filter exchange
   * @param authentication the authentication
   * @return Mono that completes the redirect
   */
  private Mono<Void> redirectToUrl(
      String url, WebFilterExchange webFilterExchange, Authentication authentication) {
    return new RedirectServerAuthenticationSuccessHandler(url)
        .onAuthenticationSuccess(webFilterExchange, authentication);
  }
}
