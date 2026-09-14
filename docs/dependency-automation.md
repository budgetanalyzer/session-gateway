# Dependency Automation

The workspace-wide operating policy, activation steps, cost boundary, and
failure triage are owned by
[orchestration's dependency automation guide](../../orchestration/docs/dependency-automation.md).
This document records only the `session-gateway` integration and review checks.

## Update discovery

`renovate.json` extends the shared Budget Analyzer preset. Renovate's native
Gradle, Gradle Wrapper, Dockerfile, and GitHub Actions managers discover this
repository's version catalog, build script, wrapper distribution, base images,
and workflow actions. The catalog extraction includes the `serviceCommon`
version shared by the declared `spring-platform` and `service-web` coordinates.

`service-common` is hosted in GitHub Packages. Extraction does not prove that
Renovate can look up those private Maven coordinates. Before activation,
configure the Mend Renovate Community App's supported encrypted Maven
credentials and verify an authenticated lookup. Never put a package token in
this repository or the shared preset.

The Phase 7 credential-free extraction found 39 dependency occurrences across
eight files: 19 Gradle occurrences in three files, one wrapper occurrence,
three Dockerfile occurrences, and 16 GitHub Actions occurrences in three
workflows. Public lookups returned 45 candidate branches before schedule,
concurrency, and dashboard controls. The run extracted both internal
coordinates but could not look them up, and Actions lookups reported that a
GitHub token was required. Those authenticated lookups remain pending Phase 12.

Renovate proposes changes only to direct declarations. Spring Framework,
Spring Security, Reactor, Reactor Netty, Netty, Jackson, Lettuce, and other
versions inherited through the Spring platform remain represented by the
resolved dependency graph described below. A Spring Boot or `serviceCommon`
proposal is not proof that every inherited vulnerability is fixed.

## Resolved reactive dependency graph

`.github/workflows/dependency-submission.yml` preserves graph submission on
trusted `main` pushes, weekly runs, and `main` dispatches. It also accepts the
exact `dependency-automation-trial` ref. Trial runs preserve the complete
authenticated build and use the official Gradle generation-only graph path
until both the protected trial ref is the current default and the trial graph
submission variable is enabled. It resolves all projects and all resolvable
configurations so application, runtime, build, and test dependency trees are
included. Do not add configuration filters without proving equivalent coverage.

Remote resolution uses `SERVICE_COMMON_PACKAGES_USERNAME` and
`SERVICE_COMMON_PACKAGES_READ_TOKEN`, exposed to Gradle as `GITHUB_ACTOR` and
`GITHUB_TOKEN`. These package-read credentials are distinct from
`${{ github.token }}`, which the action uses to submit the graph with the job's
only elevated permission, `contents: write`. The snapshot is submitted directly
and is not retained as an artifact or published as a Build Scan.

The workflow must fail when package credentials are missing, either declared
`service-common` artifact cannot be read, dependency resolution is incomplete,
or GitHub rejects submission. Do not substitute Maven Local, omit the internal
dependencies, filter failed configurations, or treat graph-generation failure
as a clean security result. A build step resolves and verifies the application
and test trees before the official action performs its unfiltered graph pass;
this prevents the graph task's zero exit status from masking unresolved
configurations.

The accepted hosted graph must demonstrate the service's actual reactive tree,
including Spring WebFlux, Reactor Core, Reactor Netty, Netty, Spring Security,
Spring Framework, and Jackson where resolved in application runtime or test
configurations. Inspect Lettuce's Netty path as well as WebFlux's HTTP client and
server path. Embedded Tomcat is not an expected dependency for this reactive
service and must not be added as an artificial acceptance condition.

The credential-free Phase 7 run generated an official local plugin snapshot,
but it is deliberately recorded as incomplete. It contained 87 build/tool
coordinates and zero `org.budgetanalyzer`, Spring WebFlux, Spring Security,
Reactor, Reactor Netty, Netty, or Lettuce coordinates. Its only Spring
coordinates were `spring-core` and `spring-jcl`, alongside build-plugin Jackson
coordinates. Gradle's `runtimeClasspath` report marked every application
dependency failed, and
`./gradlew dependencyInsight --dependency org.budgetanalyzer:service-web
--configuration runtimeClasspath` identified HTTP 401 from GitHub Packages for
`service-web` 0.0.16. No Netty coverage is available from that partial snapshot.
This is authentication-dependent local evidence, not a submitted graph or a
claim that those dependencies are absent.

## Phase 12 branch measurement controls

`build.yml` accepts trial-branch pushes and pull requests based on either `main`
or the exact trial branch. Trial builds measure the application JAR, test
results, and build failure log with optional caches and uploads initially off.
The graph workflow measures its complete generated report and resolution log.
Trial schedule, cache, upload, and submission expansion follows the variables in
the
[orchestration trial workflow policy](../../orchestration/docs/dependency-automation.md#trial-workflow-controls).
Any enabled trial upload is one sealed archive retained for one day and must fit
beneath the 25 MiB cap. Production `main` uploads and graph submission are
unchanged.

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

## Phase 12 authenticated evidence handoff

Phase 7 intentionally uses no GitHub, GitHub Packages, image-registry, or Mend
credentials. The following `session-gateway` checks remain pending Phase 12:

1. Publish the orchestration shared preset, install the Mend Renovate Community
   App for this repository, grant alert-read access, and configure its supported
   encrypted Maven host rule. Retain the hosted Renovate log or Dependency
   Dashboard URL proving successful preset resolution and lookups for Actions,
   `org.budgetanalyzer:spring-platform`, and
   `org.budgetanalyzer:service-web`, with no authentication, configuration,
   timeout, or lookup failures.
2. From trusted `main`, dispatch or observe
   `.github/workflows/dependency-submission.yml`. Leave
   `SERVICE_COMMON_PACKAGES_USERNAME` and
   `SERVICE_COMMON_PACKAGES_READ_TOKEN` in the repository secret store without
   exposing their values to an agent. Retain the successful workflow URL and
   accepted GitHub snapshot proving both POM preflights, successful
   `./gradlew --no-daemon --no-configuration-cache build`, complete application
   runtime and test resolution, and graph submission with `${{ github.token }}`.
3. In that accepted snapshot, retain package/configuration evidence for Spring
   WebFlux, Reactor Core, Reactor Netty, Netty, Spring Security, Spring
   Framework, Jackson, and Lettuce where actually resolved. Use Gradle dependency
   insight to explain the inherited path and any missing expected family. Do not
   infer remediation from a Boot or BOM update alone, and do not require Tomcat.
4. Run the existing trusted build for the selected bot branch with package-read
   secrets available and retain its URL. A historical build or a local
   Maven-cached build is not evidence that the new workflow resolved remotely.
5. Confirm the dependency graph and Dependabot alerts are enabled while
   overlapping Dependabot version-update and security-update pull requests remain
   disabled. Retain alert URLs or explained misses for inherited reactive and
   Spring dependencies after the complete graph is accepted.

The orchestration coverage report owns the final cross-repository acceptance
record. Phase 12 must copy these URLs and explained misses there; local Phase 7
preparation does not activate automation or establish vulnerability-review
parity.
