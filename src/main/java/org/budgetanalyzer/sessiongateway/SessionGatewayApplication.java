package org.budgetanalyzer.sessiongateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;

import org.budgetanalyzer.service.security.OAuth2ResourceServerSecurityConfig;

@SpringBootApplication(
    exclude = {
      // Session Gateway is an OAuth2 Client (BFF pattern), not a Resource Server
      // Exclude the auto-configured Resource Server security from service-common-web
      OAuth2ResourceServerSecurityConfig.class,
      // Session Gateway uses Redis only, not a database
      // Exclude DataSource and JPA auto-configuration brought in by service-common-core
      DataSourceAutoConfiguration.class,
      HibernateJpaAutoConfiguration.class
    })
public class SessionGatewayApplication {

  public static void main(String[] args) {
    SpringApplication.run(SessionGatewayApplication.class, args);
  }
}
