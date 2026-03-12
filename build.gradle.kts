import org.springframework.boot.gradle.tasks.run.BootRun

// TC 1.21.4 fixes Docker 29.x compatibility (1.21.3 breaks with "client version 1.32 is too old").
// Spring Boot 3.5.7 manages TC to 1.21.3, so we override it here.
extra["testcontainers.version"] = libs.versions.testcontainers.get()

plugins {
    java
    checkstyle
    alias(libs.plugins.spring.boot)
    alias(libs.plugins.spring.dependency.management)
    alias(libs.plugins.spotless)
}

group = "org.budgetanalyzer"
version = "0.0.1-SNAPSHOT"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(libs.versions.java.get().toInt())
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencyManagement {
    imports {
        mavenBom(libs.spring.cloud.dependencies.get().toString())
    }
}

dependencies {
    // Budget Analyzer Common Libraries
    // Provides: exception handling, HTTP logging, correlation IDs, safe logging utilities
    implementation(libs.service.web)

    // Spring Cloud Gateway
    implementation(libs.spring.cloud.starter.gateway.server.webflux)

    // OAuth2 Client for Auth0 integration
    implementation(libs.spring.boot.starter.oauth2.client)

    // Redis for session storage
    implementation(libs.spring.boot.starter.data.redis)
    implementation(libs.spring.session.data.redis)

    // Actuator for health checks
    implementation(libs.spring.boot.starter.actuator)

    // SpringDoc OpenAPI (WebFlux variant for reactive gateway)
    implementation(libs.springdoc.openapi)

    // Test dependencies
    testImplementation(libs.spring.boot.starter.test)
    testRuntimeOnly(libs.junit.platform.launcher)
    testImplementation(libs.spring.boot.testcontainers)
    testImplementation(libs.testcontainers)
    testImplementation(libs.testcontainers.junit.jupiter)
    testImplementation(libs.wiremock.standalone)
    testImplementation(libs.awaitility)
    testImplementation(libs.reactor.test)
}

spotless {
    java {
        googleJavaFormat(libs.versions.googleJavaFormat.get())
        trimTrailingWhitespace()
        endWithNewline()
        importOrder("java", "javax", "jakarta", "org", "com", "", "org.budgetanalyzer")
        removeUnusedImports()
    }
}

checkstyle {
    toolVersion = libs.versions.checkstyle.get()
    config = resources.text.fromUri("https://raw.githubusercontent.com/budgetanalyzer/checkstyle-config/main/checkstyle.xml")
}

tasks.named("check") {
    dependsOn("spotlessCheck")
}

val jvmArgsList = listOf(
    "--add-opens=java.base/java.nio=ALL-UNNAMED",
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED",
    "--enable-native-access=ALL-UNNAMED"
)

tasks.withType<BootRun> {
    jvmArgs = jvmArgsList

    // Load .env file if it exists
    val envFile = file(".env")
    if (envFile.exists()) {
        envFile.readLines()
            .filter { it.isNotBlank() && !it.startsWith("#") }
            .forEach { line ->
                val (key, value) = line.split("=", limit = 2)
                environment(key.trim(), value.trim())
            }
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
    jvmArgs = jvmArgsList
}

tasks.withType<Javadoc> {
    options {
        (this as StandardJavadocDocletOptions).apply {
            addStringOption("Xdoclint:none", "-quiet")
        }
    }
}
