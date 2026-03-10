package org.budgetanalyzer.sessiongateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration;

@SpringBootApplication(
    exclude = {
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
