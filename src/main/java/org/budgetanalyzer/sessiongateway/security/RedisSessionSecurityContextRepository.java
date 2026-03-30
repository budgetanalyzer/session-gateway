package org.budgetanalyzer.sessiongateway.security;

import java.util.LinkedHashSet;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

import org.budgetanalyzer.sessiongateway.session.SessionCookieHelper;
import org.budgetanalyzer.sessiongateway.session.SessionData;
import org.budgetanalyzer.sessiongateway.session.SessionReader;

/**
 * Bridges the Redis session hash into Spring Security's reactive security context.
 *
 * <p>The login success handler writes the canonical session data to Redis. Subsequent requests load
 * the SESSION cookie, deserialize the Redis hash, and recreate an authenticated principal without
 * depending on OAuth2 client internals.
 */
@Component
public class RedisSessionSecurityContextRepository implements ServerSecurityContextRepository {

  private final SessionCookieHelper sessionCookieHelper;
  private final SessionReader sessionReader;

  public RedisSessionSecurityContextRepository(
      SessionCookieHelper sessionCookieHelper, SessionReader sessionReader) {
    this.sessionCookieHelper = sessionCookieHelper;
    this.sessionReader = sessionReader;
  }

  @Override
  public Mono<Void> save(ServerWebExchange exchange, SecurityContext securityContext) {
    return Mono.empty();
  }

  @Override
  public Mono<SecurityContext> load(ServerWebExchange exchange) {
    var sessionId = sessionCookieHelper.readSessionId(exchange);
    if (sessionId == null || sessionId.isBlank()) {
      return Mono.empty();
    }

    return sessionReader
        .readSession(sessionId)
        .map(sessionData -> toSecurityContext(sessionData, sessionId));
  }

  private SecurityContext toSecurityContext(SessionData sessionData, String sessionId) {
    var authorities = new LinkedHashSet<SimpleGrantedAuthority>();
    sessionData.roles().stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);
    sessionData.permissions().stream().map(SimpleGrantedAuthority::new).forEach(authorities::add);

    var sessionPrincipal =
        new SessionPrincipal(
            sessionData.userId(),
            sessionData.idpSub(),
            sessionData.email(),
            sessionData.displayName(),
            sessionData.picture(),
            sessionData.roles(),
            sessionData.permissions());
    var usernamePasswordAuthenticationToken =
        UsernamePasswordAuthenticationToken.authenticated(
            sessionPrincipal, sessionId, authorities.stream().toList());

    return new SecurityContextImpl(usernamePasswordAuthenticationToken);
  }
}
