# AIWAF Java

AIWAF Java is a Java-native web application firewall implementation for Servlet and Spring applications, with parity-oriented core logic and focused configuration examples.

## Maven Artifact

Published coordinates:

- Version: `1.0.1`
- Maven package URL: `pkg:maven/io.github.aiwaf-project/aiwaf-java@1.0.1`

Add to your project:

```xml
<dependency>
    <groupId>io.github.aiwaf-project</groupId>
    <artifactId>aiwaf-java</artifactId>
    <version>1.0.1</version>
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
- [AI Model Lifecycle](#ai-model-lifecycle)
- [Runtime Telemetry](#runtime-telemetry)
- [Project Layout](#project-layout)
- [Build and Test](#build-and-test)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Known Limitations](#known-limitations)
- [Release Publishing](#release-publishing)
- [Developer Workflow](#developer-workflow)

## What This Project Is

This repository provides:

- Core WAF decision engine: `com.aiwaf.core.*`
- Runtime data stores/managers: `com.aiwaf.runtime.*`
- Spring filter/interceptor + route annotation support: `com.aiwaf.spring.*`
- Generic servlet filter support: `com.aiwaf.servlet.*`
- CLI/admin utilities: `com.aiwaf.cli.*`
- Small configuration examples: `examples/*`

Primary objective: consistent and testable Java behavior for AIWAF controls, including parity-driven rules and route-level policy decisions.

## Current Status

- Java core and Spring integrations are implemented and covered by parity/integration tests.
- Route annotation behavior (`@AiwafExempt`, `@AiwafExemptFrom`, `@AiwafOnly`, `@AiwafRequireProtection`) is implemented and tested.
- Middleware alias normalization supports underscore and hyphen forms (e.g. `rate_limit`, `rate-limit`).
- sklearn-like Isolation Forest implementation is included in core (`IsolationForestCore`) and integrated into training/runtime AI anomaly checks.
- Model artifact persistence, validation, and schema migration are implemented (`ModelArtifactIoCore`, `ModelArtifactMigrationCore`, `LazyModelProviderCore`).
- Offline AI retraining can use FastR/R first and falls back to Java training when R is unavailable.
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

`com.aiwaf.core.CoreCli` provides testable core commands, including:

- `analyze-request --request <request.json>`
- `analyze-behavior --events <events.json>`
- `train-model --events <events.json> --out <aiwaf-model.bin> --backend fastr|java`
- `replay --cases <replay_cases.json>`
- `reset --targets <all|features,models,events,replay>`
- `list --targets <all|features,models,events,replay>`

These are covered by logic tests in `src/test/java/com/aiwaf/cli` and `src/test/java/com/aiwaf/core`.

## AI Model Lifecycle

- Runtime scoring stays Java-native through `IsolationForestCore`.
- Offline retraining defaults to FastR/R through `CoreCli train-model --backend fastr`.
- If R, `jsonlite`, or the FastR script is unavailable, retraining falls back to Java training and still writes a loadable artifact.
- The FastR retrainer lives at `scripts/fastr/train_iforest.R` and emits neutral IF JSON.
- `FastRModelImportCore` converts FastR JSON into the existing Java `TrainedModelCore`/`IsolationForestCore.Model` artifact shape.
- Trainer emits IF-backed model payloads with metadata/version markers.
- Runtime supports eager or lazy model loading (`LazyModelProviderCore`).
- Artifact compatibility is validated on load; incompatible schema is rejected unless a migration path is available.
- Migration logic currently covers supported legacy IF payload shapes and normalizes to current schema.

Example retraining call:

```java
// FastR/R first; falls back to Java if R is unavailable.
int rc = CoreCli.main(new String[]{
    "train-model",
    "--events", "events.json",
    "--out", "aiwaf-model.bin",
    "--backend", "fastr"
});
```

FastR/R requirements:

- `Rscript` on `PATH`, or set `AIWAF_FASTR_CMD`, or pass `--fastr-command`.
- R package `jsonlite`.
- A project-local `.r-lib/` is automatically included by `scripts/fastr/train_iforest.R` if present.

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
- `scripts/fastr` — FastR/R offline Isolation Forest retraining script
- `.github/workflows` — CI/release automation, including Maven Central publishing
- `examples` — focused configuration examples

## Build and Test

Requirements:

- Java 17+
- Maven 3.9+
- Optional for real FastR retraining tests: `Rscript` and R package `jsonlite`

Run full test suite:

```bash
mvn -Dmaven.repo.local=/tmp/m2repo -q test
```

Run focused test sets:

```bash
mvn -Dmaven.repo.local=/tmp/m2repo -q -Dtest=AiwafRouteDecisionsTest,JavaFrameworkAiwafEndToEndTest,AiwafEngineParityTest test
```

FastR integration tests are written to skip cleanly when R or `jsonlite` is unavailable. To run them locally:

```bash
mkdir -p .r-lib
R_LIBS_USER="$PWD/.r-lib" Rscript -e "install.packages('jsonlite', repos='https://cloud.r-project.org')"
mvn -q -Dtest=FastRTrainingScriptIntegrationTest,FastRModelImportCoreTest,CoreCliParityTest test
```

## Examples

Example guide: [examples/README.md](examples/README.md)

Current examples focus on local configuration and API usage rather than runnable attack sandboxes.

## Troubleshooting

1. Geo behavior unexpected
- Verify MMDB file presence and external lookup tooling availability.

2. FastR retraining falls back to Java
- Verify `Rscript --version`.
- Verify `Rscript -e "requireNamespace('jsonlite', quietly=TRUE)"` returns `TRUE`.
- Set `AIWAF_FASTR_CMD` or pass `--fastr-command` if `Rscript` is not on `PATH`.
- Use a local `.r-lib/` for R packages when the system library is not writable.

## Known Limitations

- Route annotation semantics are explicit and test-backed, but framework-level path normalization differences can still influence edge responses.


## Developer Workflow

Typical cycle:

1. Implement change in `core`/`spring`/`runtime`
2. Run focused tests for affected areas
3. Run full `mvn test`
4. Run any integration or release-specific checks before committing
