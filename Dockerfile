# syntax=docker/dockerfile:1.7

# Build stage
FROM eclipse-temurin:25-jdk-alpine@sha256:30d9f87d702c2c1c601ed0d31e0c88ea1ea474ee7676cda7b7a59e759181c4dd AS build
WORKDIR /app

# Copy gradle wrapper and configuration
COPY gradlew .
COPY gradle gradle
COPY build.gradle.kts .
COPY settings.gradle.kts .

# Release and isolated CI builds pass GitHub Packages credentials as BuildKit
# secrets so the builder can resolve service-common without host Maven Local.
RUN --mount=type=cache,target=/root/.gradle \
    --mount=type=secret,id=github_actor,required=false \
    --mount=type=secret,id=github_token,required=false \
    export GITHUB_ACTOR="$(cat /run/secrets/github_actor 2>/dev/null || true)" && \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)" && \
    ./gradlew dependencies --no-daemon

# Copy source code
COPY src src

# Build the application
RUN --mount=type=cache,target=/root/.gradle \
    --mount=type=secret,id=github_actor,required=false \
    --mount=type=secret,id=github_token,required=false \
    export GITHUB_ACTOR="$(cat /run/secrets/github_actor 2>/dev/null || true)" && \
    export GITHUB_TOKEN="$(cat /run/secrets/github_token 2>/dev/null || true)" && \
    ./gradlew bootJar --no-daemon

# Runtime stage
FROM eclipse-temurin:25-jre-alpine@sha256:c707c0d18cb9e8556380719f80d96a7529d0746fbb42143893949b98ed2f8943
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -u 1001 -S appuser -G appgroup

# Copy the built artifact
COPY --from=build /app/build/libs/*.jar app.jar

# Set ownership
RUN chown -R appuser:appgroup /app

USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8081/actuator/health || exit 1

EXPOSE 8081

ENTRYPOINT ["java", \
    "--add-opens=java.base/java.nio=ALL-UNNAMED", \
    "--add-opens=java.base/sun.nio.ch=ALL-UNNAMED", \
    "--enable-native-access=ALL-UNNAMED", \
    "-jar", "app.jar"]
