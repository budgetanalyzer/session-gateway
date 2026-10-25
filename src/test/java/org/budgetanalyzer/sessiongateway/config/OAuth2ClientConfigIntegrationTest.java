package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;

import reactor.netty.resources.ConnectionProvider;

import org.budgetanalyzer.sessiongateway.base.AbstractIntegrationTest;

class OAuth2ClientConfigIntegrationTest extends AbstractIntegrationTest {

  @Autowired
  @Qualifier("idpConnectionProvider")
  private ConnectionProvider idpConnectionProvider;

  @Test
  void dedicatedIdpConnectionProviderUsesExplicitPoolSettings() {
    assertThat(idpConnectionProvider.name()).isEqualTo("idp-oidc-callback");
    assertThat(idpConnectionProvider.maxConnections()).isEqualTo(50);
  }
}
