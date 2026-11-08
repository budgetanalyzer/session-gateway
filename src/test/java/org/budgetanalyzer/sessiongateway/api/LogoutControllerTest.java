package org.budgetanalyzer.sessiongateway.api;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

import org.budgetanalyzer.service.audit.AuditLogger;
import org.budgetanalyzer.sessiongateway.security.SessionLifecycleAuditLogger;

class LogoutControllerTest {

  @Test
  void constructorRejectsMalformedIdpLogoutUrlTemplate() {
    var sessionLifecycleAuditLogger = new SessionLifecycleAuditLogger(new AuditLogger());

    assertThatThrownBy(
            () ->
                new LogoutController(
                    null,
                    null,
                    sessionLifecycleAuditLogger,
                    "https://[idp.example.com/v2/logout?returnTo={returnTo}&client_id={clientId}",
                    "test-client-id",
                    "https://app.budgetanalyzer.localhost"))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
