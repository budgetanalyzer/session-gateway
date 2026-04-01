package org.budgetanalyzer.sessiongateway.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.FileSystemResource;

class SessionPropertiesTest {

  private static final String PUBLIC_SESSION_COOKIE_NAME = "BA_SESSION";

  private final ApplicationContextRunner applicationContextRunner =
      new ApplicationContextRunner()
          .withUserConfiguration(SessionPropertiesTestConfiguration.class)
          .withInitializer(
              applicationContext -> {
                var yamlPropertySources = loadMainApplicationYaml();
                yamlPropertySources.forEach(
                    propertySource ->
                        applicationContext
                            .getEnvironment()
                            .getPropertySources()
                            .addLast(propertySource));
              });

  @Test
  void bindsDefaultsFromMainApplicationConfiguration() {
    applicationContextRunner.run(
        applicationContext -> {
          assertThat(applicationContext).hasNotFailed();

          var sessionProperties = applicationContext.getBean(SessionProperties.class);

          assertThat(sessionProperties.keyPrefix()).isEqualTo("session:");
          assertThat(sessionProperties.ttlSeconds()).isEqualTo(900);
          assertThat(sessionProperties.refreshThresholdSeconds()).isEqualTo(300);
          assertThat(sessionProperties.oauth2StateTtlSeconds()).isEqualTo(900);
          assertThat(sessionProperties.cookie().name()).isEqualTo(PUBLIC_SESSION_COOKIE_NAME);
          assertThat(sessionProperties.cookie().domainOverride()).isNull();
          assertThat(sessionProperties.cookie().secure()).isTrue();
          assertThat(sessionProperties.cookie().sameSite()).isEqualTo("Strict");
        });
  }

  @Test
  void rejectsBlankCookieName() {
    applicationContextRunner
        .withPropertyValues("session.cookie.name= ")
        .run(
            applicationContext -> {
              assertThat(applicationContext).hasFailed();
              assertThat(rootCauseMessage(applicationContext)).contains("session.cookie.name");
            });
  }

  @Test
  void rejectsBlankKeyPrefix() {
    applicationContextRunner
        .withPropertyValues("session.key-prefix= ")
        .run(
            applicationContext -> {
              assertThat(applicationContext).hasFailed();
              assertThat(rootCauseMessage(applicationContext)).contains("session.key-prefix");
            });
  }

  @Test
  void rejectsRefreshThresholdThatIsNotLessThanTtl() {
    applicationContextRunner
        .withPropertyValues("session.ttl-seconds=600", "session.refresh-threshold-seconds=600")
        .run(
            applicationContext -> {
              assertThat(applicationContext).hasFailed();
              assertThat(rootCauseMessage(applicationContext))
                  .contains("session.refresh-threshold-seconds");
            });
  }

  @Test
  void rejectsUnsupportedSameSiteValue() {
    applicationContextRunner
        .withPropertyValues("session.cookie.same-site=bogus")
        .run(
            applicationContext -> {
              assertThat(applicationContext).hasFailed();
              assertThat(rootCauseMessage(applicationContext))
                  .contains("session.cookie.same-site")
                  .contains("Strict, Lax, or None");
            });
  }

  private String rootCauseMessage(
      org.springframework.boot.test.context.assertj.AssertableApplicationContext
          applicationContext) {
    var startupFailure = applicationContext.getStartupFailure();
    assertThat(startupFailure).isNotNull();

    var rootCause = startupFailure.getCause();
    while (rootCause != null && rootCause.getCause() != null) {
      rootCause = rootCause.getCause();
    }

    return rootCause != null ? rootCause.getMessage() : startupFailure.getMessage();
  }

  private List<org.springframework.core.env.PropertySource<?>> loadMainApplicationYaml() {
    var yamlPropertySourceLoader = new YamlPropertySourceLoader();

    try {
      return yamlPropertySourceLoader.load(
          "mainApplicationYaml", new FileSystemResource("src/main/resources/application.yml"));
    } catch (IOException exception) {
      throw new IllegalStateException(
          "Failed to load src/main/resources/application.yml.", exception);
    }
  }

  @Configuration
  @EnableConfigurationProperties(SessionProperties.class)
  static class SessionPropertiesTestConfiguration {}
}
