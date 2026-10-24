package org.budgetanalyzer.sessiongateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(
    excludeName = {
      // Session Gateway uses Redis only, not a database
      // Exclude DataSource and JPA auto-configuration if a dependency brings them onto the
      // classpath
      "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration",
      "org.springframework.boot.hibernate.autoconfigure.HibernateJpaAutoConfiguration"
    })
public class SessionGatewayApplication {

  public static void main(String[] args) {
    SpringApplication.run(SessionGatewayApplication.class, args);
  }
}
