package org.budgetanalyzer.sessiongateway.config;

import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
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

  public SecurityConfig(
      ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
      RedisAuthorizationRequestRepository authorizationRequestRepository,
      ServerOAuth2AuthorizedClientRepository authorizedClientRepository,
      ServerSecurityContextRepository serverSecurityContextRepository,
      PermissionServiceClient permissionServiceClient,
      SessionWriter sessionWriter,
      SessionCookieHelper sessionCookieHelper,
      OAuth2CallbackRedirectResolver oauth2CallbackRedirectResolver) {
    this.authorizationRequestResolver = authorizationRequestResolver;
    this.authorizationRequestRepository = authorizationRequestRepository;
    this.authorizedClientRepository = authorizedClientRepository;
    this.serverSecurityContextRepository = serverSecurityContextRepository;
    this.permissionServiceClient = permissionServiceClient;
    this.sessionWriter = sessionWriter;
    this.sessionCookieHelper = sessionCookieHelper;
    this.oauth2CallbackRedirectResolver = oauth2CallbackRedirectResolver;
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
                        "/auth/v1/session",
                        "/logout",
                        "/v3/api-docs/**",
                        "/v3/api-docs.yaml",
                        "/swagger-ui/**",
                        "/swagger-ui.html")
                    .permitAll()
                    .pathMatchers("/auth/v1/user")
                    .authenticated()
                    .anyExchange()
                    .permitAll())
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
                ServerWebExchangeMatchers.pathMatchers("/auth/v1/user"),
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

    return permissionServiceClient
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
                        permissionResponse.permissions())
                    .flatMap(
                        sessionId -> {
                          sessionCookieHelper.setSessionCookie(exchange, sessionId);
                          return redirect(
                              exchange,
                              oauth2CallbackRedirectResolver
                                  .resolveAuthenticationSuccessRedirectUrl(exchange));
                        }))
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

  private String attribute(
      OAuth2AuthenticationToken oauth2AuthenticationToken, String name, String defaultValue) {
    var value = oauth2AuthenticationToken.getPrincipal().getAttribute(name);
    return value != null ? value.toString() : defaultValue;
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
