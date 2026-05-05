# Local Development

## Prerequisites

- Java 24
- Shared local platform running from `../orchestration` (`tilt up`)
- Redis available to the service with the `session-gateway` ACL user
- Permission-service reachable at the configured `PERMISSION_SERVICE_URL` (required for login)

**Shared platform setup**: See [getting-started.md](https://github.com/budgetanalyzer/orchestration/blob/main/docs/development/getting-started.md)

**Service-common artifact resolution**: Local builds resolve `service-common`
from `mavenLocal()` — no GitHub credentials required. Default GitHub Actions
`build.yml` runs and release builds resolve the pinned `serviceCommon` version
from GitHub Packages. The full contract is documented in orchestration:
[service-common artifact resolution](https://github.com/budgetanalyzer/orchestration/blob/main/docs/development/service-common-artifact-resolution.md).
This service imports `org.budgetanalyzer:spring-platform` for shared Spring
dependency management and keeps `org.budgetanalyzer:service-web` explicit for
reactive runtime utilities.

## Start the Service

```bash
cd ../orchestration
tilt up

# In separate terminals, expose the dependencies used by direct bootRun
kubectl port-forward -n infrastructure pod/redis-0 6379:6379
kubectl port-forward deployment/permission-service 8086:8086

cd ../session-gateway
export SPRING_DATA_REDIS_PASSWORD=your_session_gateway_redis_password
export SPRING_DATA_REDIS_SSL_ENABLED=true
export SPRING_DATA_REDIS_SSL_BUNDLE=infra-ca
export INFRA_CA_CERT_PATH="file:$(cd ../orchestration && pwd)/nginx/certs/infra/infra-ca.pem"
export PERMISSION_SERVICE_URL=http://localhost:8086

./gradlew bootRun
```

`SPRING_DATA_REDIS_USERNAME` defaults to `session-gateway`. If you are reusing
values from `../orchestration/.env`, map `REDIS_SESSION_GATEWAY_PASSWORD` to
`SPRING_DATA_REDIS_PASSWORD`. The CA path must point at the host-side file
created by `../orchestration/scripts/bootstrap/setup-infra-tls.sh`. Full browser behavior still runs through
`https://app.budgetanalyzer.localhost` in the shared dev environment.

## Health Check

```bash
curl http://localhost:8081/actuator/health
```

## Build

```bash
./gradlew build
```

## Run Tests

```bash
./gradlew test
```

## Code Formatting

```bash
./gradlew clean spotlessApply
```
