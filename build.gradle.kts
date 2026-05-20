import org.springframework.boot.gradle.tasks.run.BootRun

val githubPackagesActor = providers.environmentVariable("GITHUB_ACTOR")
val githubPackagesToken = providers.environmentVariable("GITHUB_TOKEN")

plugins {
    java
    checkstyle
    jacoco
    alias(libs.plugins.spring.boot)
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
    maven {
        name = "GitHubPackages"
        url = uri("https://maven.pkg.github.com/budgetanalyzer/service-common")
        credentials {
            username = githubPackagesActor.orNull ?: ""
            password = githubPackagesToken.orNull ?: ""
        }
        content {
            includeGroup("org.budgetanalyzer")
        }
    }
    mavenCentral()
}

dependencies {
    implementation(platform(libs.budgetanalyzer.spring.platform))

    // Budget Analyzer Common Libraries
    // Provides: exception handling, HTTP logging, correlation IDs, safe logging utilities
    implementation(libs.service.web)

    // Spring WebFlux (reactive web)
    implementation(libs.spring.boot.starter.webflux)

    // OAuth2 Client for Auth0 integration
    implementation(libs.spring.boot.starter.oauth2.client)

    // Redis for session storage
    implementation(libs.spring.boot.starter.data.redis)

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

jacoco {
    toolVersion = libs.versions.jacoco.get()
}

tasks.named("check") {
    dependsOn("spotlessCheck", tasks.jacocoTestCoverageVerification)
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
    finalizedBy(tasks.jacocoTestReport)
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
        csv.required.set(false)
    }
}

tasks.jacocoTestCoverageVerification {
    dependsOn(tasks.test)
    violationRules {
        rule {
            limit {
                counter = "LINE"
                value = "COVEREDRATIO"
                minimum = "0.90".toBigDecimal()
            }
            limit {
                counter = "BRANCH"
                value = "COVEREDRATIO"
                minimum = "0.65".toBigDecimal()
            }
        }
    }
}

tasks.withType<Javadoc> {
    options {
        (this as StandardJavadocDocletOptions).apply {
            addStringOption("Xdoclint:all,-missing", "-quiet")
        }
    }
}
