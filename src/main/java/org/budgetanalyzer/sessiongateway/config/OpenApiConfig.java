package org.budgetanalyzer.sessiongateway.config;

import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.servers.Server;

import org.budgetanalyzer.service.config.BaseOpenApiConfig;

/** OpenAPI configuration for the Session Gateway. */
@Configuration
@OpenAPIDefinition(
    info =
        @Info(
            title = "Session Gateway",
            version = "1.0",
            description = "API documentation for Session Gateway endpoints",
            contact = @Contact(name = "Bleu Rubin", email = "contact@budgetanalyzer.org"),
            license = @License(name = "MIT", url = "https://opensource.org/licenses/MIT")),
    servers = {
      @Server(url = "http://localhost:8080", description = "Local environment (via gateway)"),
      @Server(url = "http://localhost:8081", description = "Local environment (direct)"),
      @Server(url = "https://api.budgetanalyzer.org", description = "Production environment")
    })
public class OpenApiConfig extends BaseOpenApiConfig {}
