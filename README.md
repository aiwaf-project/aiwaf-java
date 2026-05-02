# AIWAF Java

AIWAF Java is a Java-native web application firewall implementation for Servlet and Spring applications, with parity-oriented core logic and runnable sandbox examples.

## Maven Artifact

Published coordinates:

- Version: `0.2.0`
- Maven package URL: `pkg:maven/io.github.aiwaf-project/aiwaf-java@0.2.0`

Add to your project:

```xml
<dependency>
    <groupId>io.github.aiwaf-project</groupId>
    <artifactId>aiwaf-java</artifactId>
    <version>0.2.0</version>
</dependency>
```

## Table of Contents

- [What This Project Is](#what-this-project-is)
- [Current Status](#current-status)
- [Architecture](#architecture)
- [Request Evaluation Flow](#request-evaluation-flow)
- [Middleware/Control Coverage](#middlewarecontrol-coverage)
- [Configuration Model](#configuration-model)
- [Spring Integration](#spring-integration)
- [Servlet Integration](#servlet-integration)
- [Runtime Storage Backends](#runtime-storage-backends)
- [GeoIP Behavior](#geoip-behavior)
- [CLI Components](#cli-components)
- [Project Layout](#project-layout)
- [Build and Test](#build-and-test)
- [Examples and Sandbox](#examples-and-sandbox)
- [Expected Sandbox Outcomes](#expected-sandbox-outcomes)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Developer Workflow](#developer-workflow)

## What This Project Is

This repository provides:

- Core WAF decision engine: `com.aiwaf.core.*`
- Runtime data stores/managers: `com.aiwaf.runtime.*`
- Spring filter/interceptor + route annotation support: `com.aiwaf.spring.*`
- Generic servlet filter support: `com.aiwaf.servlet.*`
- CLI/admin utilities: `com.aiwaf.cli.*`
- Dockerized sandbox proxies and attack/compare tools: `examples/sandbox/*`

Primary objective: consistent and testable Java behavior for AIWAF controls, including parity-driven rules and route-level policy decisions.

## Current Status

- Java core and Spring integrations are implemented and covered by parity/integration tests.
- Sandbox includes two maintained Java proxies:
  - `aiwaf-java` (plain Java reverse proxy)
  - `aiwaf-spring` (Spring Boot reverse proxy)
- Route annotation behavior (`@AiwafExempt`, `@AiwafExemptFrom`, `@AiwafOnly`, `@AiwafRequireProtection`) is implemented and tested.
- Middleware alias normalization supports underscore and hyphen forms (e.g. `rate_limit`, `rate-limit`).
- sklearn-like Isolation Forest implementation is included in core (`IsolationForestCore`) and integrated into training/runtime AI anomaly checks.
- Model artifact persistence, validation, and schema migration are implemented (`ModelArtifactIoCore`, `ModelArtifactMigrationCore`, `LazyModelProviderCore`).
- Runtime observability is available via built-in telemetry counters/histograms (`AiwafTelemetryCore`).
- Python-style structured config compatibility and env/property override mapping are available (`AiwafConfigCompatCore`).

## Architecture

AIWAF Java is layered:

1. Request adapters
- Convert incoming framework request into `AiwafRequest`.
- Spring: `AiwafFilter` + route decision helpers.
- Servlet: `AiwafServletFilter`.

2. Decision engine
- `AiwafEngine.evaluate(AiwafRequest)` executes policy pipeline.

3. Runtime/state
- Blacklist, exemptions, path exemptions, keyword learning, geo blocks.
- Backed by in-memory/file/csv storage adapters.

4. Integration response
- Allowed requests proceed to app/upstream.
- Denied requests return status/reason immediately.

## Request Evaluation Flow

At high level, `AiwafEngine` evaluates in this pattern (subject to config/rules):

1. Path-rule resolution / route-level middleware disablement
2. IP blacklist gate
3. Method validation
4. IP/keyword malicious path checks
5. UUID tamper check
6. Honeypot timing checks
7. Header validation
8. Geo policy checks
9. Rate-limit/flood checks
10. Allow

Route annotations and path rules can disable/require specific controls.

## Middleware/Control Coverage

Implemented controls include:

- Header validation
  - required header checks
  - suspicious header/user-agent logic
  - max header bytes/count
  - quality threshold
- Rate limiting
  - scope: per-path or global IP
  - max requests/window
  - flood threshold
  - optional block-on-breach modes
- IP/keyword block
  - static suspicious path patterns
  - learned keyword store integration
  - contextual keyword learning guardrails and legitimacy filters
- Honeypot timing
  - GET-to-POST timing checks
  - login-path timing override support
- UUID tamper detection
- Geo controls
  - allow-list + deny-list logic
  - runtime geo blocked country store
- Method allow-list validation
- Exemption system
  - exempt IPs, private IP behavior
  - exempt path patterns and prefixes
  - path-rule middleware overrides
- AI anomaly detection
  - Isolation Forest scoring from request feature vectors
  - runtime recent-behavior confirmation before blocking
  - configurable anomaly thresholds, windows, and minimum sample gates
- Extended block context
  - optional capture of method/path/query/header snapshot on block events (with redaction/truncation limits)

## Configuration Model

Main config class: `com.aiwaf.core.AiwafConfig`

Categories:

- Header validation:
  - `headerValidationEnabled`
  - `requiredHeaders`, `requiredHeadersByMethod`
  - `minHeaderQualityScore`, `maxHeaderBytes`, `maxHeaderCount`, `maxUserAgentLength`, `maxAcceptLength`
- Rate limiting:
  - `rateLimitEnabled`, `rateLimitScope`
  - `rateLimitWindowSeconds`, `rateLimitMax`, `rateLimitFloodThreshold`
  - `blockIpOnRateLimitBreach`, `blockIpOnFloodBreach`
- Exemptions:
  - `exemptIps`, `privateIpsExempted`
  - `exemptPaths`, `exemptAllowWildcards`, `exemptAllowPrefix`
  - `autoExemptPathPrefixes`
- Geo:
  - `geoBlockEnabled`, `geoAllowedCountries`, `geoBlockedCountries`, `geoExemptPaths`
- Honeypot:
  - `honeypotEnabled`, `minFormTimeSeconds`, `maxFormPageTimeSeconds`
  - `loginPathPrefixes`, `loginMinFormTimeSeconds`
- Other controls:
  - `uuidTamperEnabled`, `ipKeywordBlockEnabled`, `methodValidationEnabled`, `allowedMethods`
- AI/anomaly:
  - `aiEnabled`, `aiLazyLoadModel`, `aiBackgroundPreload`, `aiModelPath`
  - `aiAnomalyScoreThreshold`, `aiRequireBehaviorConfirmation`
  - `aiRecentWindowSeconds`, `aiMinRecentSamplesToBlock`
- Keyword learning / legitimacy:
  - `enableKeywordLearning`, `dynamicTopN`
  - `exemptKeywords`, `legitimatePathKeywords`, `legitimateRouteHints`
- Block context / observability:
  - `storeExtendedBlockInfo`, `blockInfoMaxHeaders`, `blockInfoMaxHeaderValueLength`, `blockInfoRedactHeaders`
  - `observabilityEnabled`
- Storage:
  - `storageBackend`, `storageFilePath`
- Middleware switches:
  - `enabledMiddlewares`, `disabledMiddlewares`
- Path rules:
  - `pathRules` (`AiwafConfig.PathRule`) supports per-prefix disable and overrides.

Python-style compatibility input is supported through `AiwafConfigCompatCore`, including sections such as:
- `storage`, `header_validation`, `rate_limiting`, `honeypot`, `ip_keyword_block`
- `geo_block`, `ai_anomaly`, `uuid_tamper`, `exemptions`, `path_rules`

## Spring Integration

Key components:

- `com.aiwaf.spring.AiwafFilter`
- `com.aiwaf.spring.AiwafInterceptor`
- `com.aiwaf.spring.support.AiwafRouteDecisions`
- annotations in `com.aiwaf.spring.annotations`

Supported annotations:

- `@AiwafExempt`: disable all AIWAF checks for handler/class.
- `@AiwafExemptFrom({...})`: disable selected controls.
- `@AiwafOnly({...})`: only listed controls apply.
- `@AiwafRequireProtection({...})`: force selected control(s), even if exempted elsewhere.

Normalization supports names such as:

- `rate_limit` / `rate-limit`
- `header_validation` / `header-validation`
- `uuid_tamper` / `uuid-tamper`

## Servlet Integration

For generic servlet apps, use:

- `com.aiwaf.servlet.AiwafServletFilter`

This adapter maps servlet request data to `AiwafRequest` and delegates to the same core engine.

## Runtime Storage Backends

Through `RuntimeStorage.initialize(...)`:

- `memory` (default)
- `file`
- `csv`

Stores include:

- Exemption store
- Path exemption store
- Blacklist store
- Keyword store
- Geo block store

Model artifacts (trained IF payload + metadata) can be loaded/saved with:
- `ModelArtifactIoCore`
- `ModelArtifactMigrationCore` (schema compatibility/migration guardrails)

## GeoIP Behavior

GeoIP logic is CLI-oriented with MMDB data under:

- `src/main/resources/geolock/ipinfo_lite.mmdb`

Design notes:

- No Java MaxMind dependency required by default runtime path.
- If GeoIP tooling is unavailable, behavior degrades safely.

## CLI Components

`com.aiwaf.cli` provides command-style management and helpers around runtime state/config flows:

- `AiwafManager`
- `AiwafConsole`
- `RouteShellHelpers`

These are covered by logic tests in `src/test/java/com/aiwaf/cli`.

## AI Model Lifecycle

- Trainer emits IF-backed model payloads with metadata/version markers.
- Runtime supports eager or lazy model loading (`LazyModelProviderCore`).
- Artifact compatibility is validated on load; incompatible schema is rejected unless a migration path is available.
- Migration logic currently covers supported legacy IF payload shapes and normalizes to current schema.

## Runtime Telemetry

When `observabilityEnabled=true`, telemetry tracks:
- request totals and allow/block outcomes
- middleware trigger counters
- evaluation latency histogram

Use `AiwafEngine.telemetry()` for in-process metrics snapshots.

## Project Layout

- `src/main/java/com/aiwaf/core` — policy engine and core logic
- `src/main/java/com/aiwaf/runtime` — storage backends and runtime stores
- `src/main/java/com/aiwaf/spring` — Spring filter/interceptor/annotations/support
- `src/main/java/com/aiwaf/servlet` — servlet filter adapter
- `src/main/java/com/aiwaf/cli` — CLI/manager utilities
- `src/test/java` — parity, runtime, integration, and route-decision tests
- `examples/sandbox` — runnable proxy demo + attack/compare utilities

## Build and Test

Requirements:

- Java 17+
- Maven 3.9+

Run full test suite:

```bash
mvn -Dmaven.repo.local=/tmp/m2repo -q test
```

Run focused test sets:

```bash
mvn -Dmaven.repo.local=/tmp/m2repo -q -Dtest=AiwafRouteDecisionsTest,JavaFrameworkAiwafEndToEndTest,AiwafEngineParityTest test
```

## Examples and Sandbox

Detailed guide: [examples/sandbox/README.md](examples/sandbox/README.md)

Quick start:

```bash
docker compose -f examples/sandbox/docker-compose.yml up -d --build
```

Services:

- `http://localhost:8080` — `protected_java`
- `http://localhost:8081` — `protected_spring`
- `http://localhost:3001` — direct baseline

Run suite:

```bash
cd examples/sandbox
javac --release 17 AttackSuite.java CompareResults.java CompareResultsModes.java RunAndCompare.java
java AttackSuite http://127.0.0.1:3001 direct normal
java AttackSuite http://127.0.0.1:3001 direct attacks
java AttackSuite http://localhost:8080 protected_java normal
java AttackSuite http://localhost:8080 protected_java attacks
java AttackSuite http://localhost:8081 protected_spring normal
java AttackSuite http://localhost:8081 protected_spring attacks
```

Compare:

```bash
java CompareResults results_direct_*.json results_protected_*.json
java CompareResultsModes results_protected_java_normal_*.json results_protected_spring_normal_*.json -- results_protected_java_attacks_*.json results_protected_spring_attacks_*.json
```

## Expected Sandbox Outcomes

Typical expectation:

- Protected normal traffic: allowed (`2xx`) in most/all cases.
- Protected attack traffic: blocked (`403/429`) in most/all cases.
- Direct traffic: reflects baseline app behavior without WAF controls.

## Troubleshooting

1. `docker compose up` says no config found
- Use explicit file:
  - `docker compose -f examples/sandbox/docker-compose.yml up --build`

2. Java class version mismatch (e.g. class file version 69)
- Recompile tools targeting Java 17:
  - `javac --release 17 AttackSuite.java CompareResults.java CompareResultsModes.java RunAndCompare.java`

3. NoClassDefFoundError in example containers
- Ensure example JAR packaging includes dependencies (fat jar/shaded where needed).
- Rebuild images with `--build`.

4. Stale or noisy result files
- Use cleanup helper:
  - `cd examples/sandbox && ./clean-results.sh`

5. Geo behavior unexpected
- Verify MMDB file presence and external lookup tooling availability.

## Known Limitations

- Sandbox attack suite is synthetic; it is useful for comparative checks, not production benchmarking.
- Direct baseline behavior depends on upstream app/runtime behavior and transport characteristics.
- Route annotation semantics are explicit and test-backed, but framework-level path normalization differences can still influence edge responses.

## Developer Workflow

Typical cycle:

1. Implement change in `core`/`spring`/`runtime`
2. Run focused tests for affected areas
3. Run full `mvn test`
4. Rebuild sandbox and run attack/compare workflow
5. Clean results before committing if desired
