# Dependency Automation

The workspace-wide operating policy, cost boundary, and failure triage are
owned by
[orchestration's dependency automation guide](../../orchestration/docs/dependency-automation.md).
This document records only the `session-gateway` integration and review checks.

## Update discovery

`renovate.json` extends the shared Budget Analyzer preset from orchestration's
default branch. Renovate's native Gradle, Gradle Wrapper, Dockerfile, and GitHub
Actions managers discover this repository's version catalog, build script,
wrapper distribution, base images, and workflow actions. Catalog extraction
includes the `serviceCommon` version shared by the declared `spring-platform`
and `service-web` coordinates.

`service-common` is hosted in GitHub Packages. Configure the Mend Renovate
Community App's supported encrypted Maven credentials and verify authenticated
lookups for both internal coordinates. Never put a package token in this
repository or the shared preset.

Renovate proposes changes only to direct declarations. Spring Framework,
Spring Security, Reactor, Reactor Netty, Netty, Jackson, Lettuce, and other
versions inherited through the Spring platform remain represented by the
resolved dependency graph described below. A Spring Boot or `serviceCommon`
proposal is not proof that every inherited vulnerability is fixed.

## Resolved reactive dependency graph

`.github/workflows/dependency-submission.yml` submits the graph from trusted
`main` pushes, weekly runs, and `main` workflow dispatches. It uses the official
Gradle dependency-submission action without configuration filters so all
projects and all resolvable configurations are included. Application, runtime,
build, and test dependency trees must remain covered; do not add filters without
proving equivalent coverage.

Before graph generation, the workflow checks authenticated access to both
declared `service-common` POMs and runs a complete build with configuration
caching disabled. This prevents a graph task's successful exit from masking
unresolved application or test configurations. The graph action uses its basic
cache provider and submits the snapshot directly; it does not retain the graph
as an artifact or publish a Build Scan.

Remote package resolution uses `SERVICE_COMMON_PACKAGES_USERNAME` and
`SERVICE_COMMON_PACKAGES_READ_TOKEN`, exposed to Gradle as `GITHUB_ACTOR` and
`GITHUB_TOKEN`. These package-read credentials are distinct from
`${{ github.token }}`, which the action uses only for submission under the job's
`contents: write` permission. The workflow-level default remains no
permissions.

The workflow must fail when package credentials are missing, either declared
`service-common` artifact cannot be read, dependency resolution is incomplete,
or GitHub rejects submission. Do not substitute Maven Local, omit internal
dependencies, filter failed configurations, or treat graph-generation failure
as a clean security result.

An accepted hosted graph must demonstrate the service's actual reactive tree,
including Spring WebFlux, Reactor Core, Reactor Netty, Netty, Spring Security,
Spring Framework, Jackson, and Lettuce where resolved in application runtime or
test configurations. Inspect Lettuce's Netty path as well as WebFlux's HTTP
client and server paths. Embedded Tomcat is not expected in this reactive
service and must not be added as an artificial acceptance condition.

## Build artifact policy

`.github/workflows/build.yml` runs for `main` pushes, pull requests targeting
`main`, and manual dispatches of `main`. Gradle uses its normal cache. Successful
builds upload neither the application JAR nor test results. A failed build
uploads only JUnit XML, retained for one day.

## Bot pull request checks

Every Renovate pull request remains non-automerged. Review the resolved
dependency diff, release notes, Java 25 and Spring compatibility, image ARM64
support, and whether a proposed direct dependency actually remediates an
inherited alert. Major updates remain visible in the Dependency Dashboard and
require approval.

Run the required repository validation in order:

```bash
./gradlew clean spotlessApply
./gradlew clean build
```

Bot pull requests use the existing `build.yml` pull-request workflow. Forked or
otherwise untrusted pull requests do not receive package-read secrets, so a
failure to resolve `service-common` there is an unavailable-secret condition,
not evidence that the dependency is absent. Do not add `pull_request_target` or
expose package credentials to untrusted dependency branches.

## Production verification

After workflow or dependency-automation changes:

1. Validate `renovate.json` in strict mode and confirm the hosted Renovate log
   or Dependency Dashboard resolves the shared preset and both internal Maven
   coordinates without authentication or lookup failures.
2. Confirm one `main` dependency-submission run passes both POM preflights, the
   complete build, and direct graph submission.
3. Inspect the accepted graph for the reactive dependency families listed
   above. Use Gradle dependency insight to explain inherited paths or a missing
   expected family; do not infer coverage from a BOM update alone.
4. Confirm dependency graph and Dependabot alerts remain enabled while
   overlapping Dependabot version-update and security-update pull requests
   remain disabled.
5. Confirm a successful normal Build run uploads no application JAR and no test
   results. A failed run may retain only the one-day JUnit XML artifact.
