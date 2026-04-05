package org.budgetanalyzer.sessiongateway.config;

import java.net.URI;
import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.server.DelegatingServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.security.OAuth2CallbackRedirectResolver;
import org.budgetanalyzer.sessiongateway.security.RedisAuthorizationRequestRepository;
import org.budgetanalyzer.sessiongateway.service.PermissionServiceClient;
import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionWriter;

/** Security configuration for Session Gateway. */
@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

  private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

  private final ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver;
  private final ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest>
      authorizationRequestRepository;
  private final ServerOAuth2AuthorizedClientRepository authorizedClientRepository;
  private final ServerSecurityContextRepository serverSecurityContextRepository;
  private final PermissionServiceClient permissionServiceClient;
  private final SessionWriter sessionWriter;
  private final SessionCookieHelper sessionCookieHelper;
  private final OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver;
  private final Clock clock;
  private final SessionProperties sessionProperties;

  public SecurityConfig(
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
      RedisAuthorizationRequestRepository authorizationRequestRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      ServerSecurityContextRepository serverSecurityContextRepository,
      PermissionServiceClient permissionServiceClient,
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver,
      Clock clock,
      SessionProperties sessionProperties) {
    this.authorizationRequestResolver = authorizationRequestResolver;
    this.authorizationRequestRepository = authorizationRequestRepository;
    this.authorizedClientRepository = authorizedClientRepository;
    this.serverSecurityContextRepository = serverSecurityContextRepository;
    this.permissionServiceClient = permissionServiceClient;
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.oauth2CallbackRedirectResolver = oauth2CallbackRedirectResolver;
    this.clock = clock;
    this.sessionProperties = sessionProperties;
  }

  @Bean
  public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
    return http.authorizeExchange(
            exchanges ->
                exchanges
                    .pathMatchers("/actuator/health/**")
                    .permitAll()
                    .pathMatchers("/internal/v1/sessions/users/*")
                    .permitAll()
                    .pathMatchers(
                        "/login/**",
                        "/oauth2/**",
                        "/auth/token/exchange",
                        "/auth/v1/session",
                        "/logout",
                        "/v3/api-docs/**",
                        "/v3/api-docs.yaml",
                        "/swagger-ui/**",
                        "/swagger-ui.html")
                    .permitAll()
                    .pathMatchers("/api/**")
                    .authenticated()
                    .anyExchange()
                    .authenticated())
        .oauth2Login(
            oauth2 ->
                oauth2
                    .authorizationRequestResolver(authorizationRequestResolver)
                    .authorizationRequestRepository(authorizationRequestRepository)
                    .authorizedClientRepository(authorizedClientRepository)
                    .securityContextRepository(serverSecurityContextRepository)
                    .authenticationSuccessHandler(this::handleAuthenticationSuccess)
                    .authenticationFailureHandler(
                        (webFilterExchange, exception) -> {
                          log.warn(
                              "OAuth2 authentication failed with exceptionType={},"
                                  + " redirecting to controlled login path",
                              exception.getClass().getSimpleName());
                          return redirect(
                              webFilterExchange.getExchange(),
                              oauth2CallbackRedirectResolver
                                  .resolveAuthenticationFailureRedirectUrl(
                                      webFilterExchange.getExchange()));
                        }))
        .securityContextRepository(serverSecurityContextRepository)
        .csrf(ServerHttpSecurity.CsrfSpec::disable)
        .exceptionHandling(
            exceptions -> exceptions.authenticationEntryPoint(authenticationEntryPoint()))
        .build();
  }

  private ServerAuthenticationEntryPoint authenticationEntryPoint() {
    var delegatingEntryPoint =
        new DelegatingServerAuthenticationEntryPoint(
            new DelegatingServerAuthenticationEntryPoint.DelegateEntry(
                ServerWebExchangeMatchers.pathMatchers("/api/**", "/auth/v1/user"),
                (exchange, exception) -> unauthorized(exchange)));

    delegatingEntryPoint.setDefaultEntryPoint(
        new RedirectServerAuthenticationEntryPoint("/oauth2/authorization/idp"));
    return delegatingEntryPoint;
  }

  private Mono<Void> handleAuthenticationSuccess(
      WebFilterExchange webFilterExchange, Authentication authentication) {
    if (!(authentication instanceof OAuth2AuthenticationToken oauth2AuthenticationToken)) {
      return redirect(
          webFilterExchange.getExchange(),
          oauth2CallbackRedirectResolver.resolveAuthenticationSuccessRedirectUrl(
              webFilterExchange.getExchange()));
    }

    var exchange = webFilterExchange.getExchange();
    var idpSub = attribute(oauth2AuthenticationToken, "sub", oauth2AuthenticationToken.getName());
    var email = attribute(oauth2AuthenticationToken, "email", "");
    var displayName = attribute(oauth2AuthenticationToken, "name", "");
    var picture = attribute(oauth2AuthenticationToken, "picture", "");

    return loadAuthorizedClient(exchange, oauth2AuthenticationToken)
        .switchIfEmpty(
            Mono.error(new IllegalStateException("OAuth2 authorized client missing after login")))
        .flatMap(
            authorizedClient ->
                permissionServiceClient
                    .fetchPermissions(idpSub, email, displayName)
                    .flatMap(
                        permissionResponse ->
                            sessionWriter
                                .createSession(
                                    permissionResponse.userId(),
                                    idpSub,
                                    email,
                                    displayName,
                                    picture,
                                    permissionResponse.roles(),
                                    permissionResponse.permissions(),
                                    refreshTokenValue(authorizedClient),
                                    tokenExpiresAt(authorizedClient))
                                .flatMap(
                                    sessionId -> {
                                      sessionCookieHelper.setSessionCookie(exchange, sessionId);
                                      return redirect(
                                          exchange,
                                          oauth2CallbackRedirectResolver
                                              .resolveAuthenticationSuccessRedirectUrl(exchange));
                                    })))
        .onErrorResume(
            Exception.class,
            exception -> {
              log.error(
                  "OAuth2 callback completion failed after authentication success"
                      + " exceptionType={}, redirecting to /oops",
                  exception.getClass().getSimpleName());
              return redirect(
                  exchange, oauth2CallbackRedirectResolver.resolveUnexpectedFailureRedirectUrl());
            });
  }

  private Mono<OAuth2AuthorizedClient> loadAuthorizedClient(
      ServerWebExchange exchange, OAuth2AuthenticationToken oauth2AuthenticationToken) {
    return authorizedClientRepository.loadAuthorizedClient(
        oauth2AuthenticationToken.getAuthorizedClientRegistrationId(),
        oauth2AuthenticationToken,
        exchange);
  }

  private String attribute(
      OAuth2AuthenticationToken oauth2AuthenticationToken, String name, String defaultValue) {
    var value = oauth2AuthenticationToken.getPrincipal().getAttribute(name);
    return value != null ? value.toString() : defaultValue;
  }

  private String refreshTokenValue(OAuth2AuthorizedClient authorizedClient) {
    if (authorizedClient.getRefreshToken() == null) {
      log.warn("OAuth2 login completed without a refresh token");
      return null;
    }

    return authorizedClient.getRefreshToken().getTokenValue();
  }

  private Instant tokenExpiresAt(OAuth2AuthorizedClient authorizedClient) {
    var expiresAt = authorizedClient.getAccessToken().getExpiresAt();
    if (expiresAt != null) {
      return expiresAt;
    }

    return clock.instant().plusSeconds(sessionProperties.ttlSeconds());
  }

  private Mono<Void> redirect(ServerWebExchange exchange, String location) {
    exchange.getResponse().setStatusCode(HttpStatus.FOUND);
    exchange.getResponse().getHeaders().setLocation(URI.create(location));
    return exchange.getResponse().setComplete();
  }

  private Mono<Void> unauthorized(ServerWebExchange exchange) {
    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
    return exchange.getResponse().setComplete();
  }
}
