# AIWAF Java

AIWAF Java is a Java-native web application firewall implementation for Servlet and Spring applications, with parity-oriented core logic and focused configuration examples.

## Maven Artifact

Published coordinates:

- Version: `1.1.0`
- Maven package URL: `pkg:maven/io.github.aiwaf-project/aiwaf-java@1.1.0`

Add to your project:

```xml
<dependency>
    <groupId>io.github.aiwaf-project</groupId>
    <artifactId>aiwaf-java</artifactId>
    <version>1.1.0</version>
</dependency>
```

## Table of Contents

- [What This Project Is](#what-this-project-is)
- [Current Status](#current-status)
- [Architecture](#architecture)
- [Request Evaluation Flow](#request-evaluation-flow)
- [Middleware/Control Coverage](#middlewarecontrol-coverage)
- [Configuration Model](#configuration-model)
- [Security Hardening](#security-hardening)
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
- Request-boundary hardening includes trusted-proxy validation, bounded replayable body inspection, strict parameter limits, and Java serialization payload rejection.
- Persistence uses filtered deserialization, atomic writes, symbolic-link rejection, owner-only permissions where supported, and optional HMAC-SHA256 verification.
- CI security checks cover CodeQL, secret scanning, dependency vulnerability scanning, and CycloneDX SBOM generation.

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

1. Request shape, body encoding, serialization, and route media-type validation
2. Path-rule resolution / route-level middleware disablement
3. IP blacklist gate
4. Method validation
5. IP/keyword malicious path checks
6. UUID tamper check
7. Honeypot timing checks
8. Header validation
9. Geo policy checks
10. Rate-limit/flood checks
11. AI anomaly evaluation
12. Allow

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
  - `maxRuntimeStateEntries` bounds attacker-controlled runtime state; saturation preserves active buckets and rejects untrackable new keys
- Request boundary:
  - `maxRequestBodyBytes`, `requestBodyInspectionBytes`, `requestBodyInspectionEnabled`
  - `allowCompressedRequestBodies`
  - `maxParameterCount`, `maxParameterBytes`, `allowDuplicateParameters`
  - `allowedContentTypesByPathPrefix`
- Trusted proxies:
  - `trustedProxyCidrs`, `maxForwardedForEntries`
  - forwarding and country headers are ignored unless the direct peer belongs to a trusted proxy CIDR
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
  - `sensitiveParameterNames`, `logQueryParameters`
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

## Security Hardening

### Secure defaults

- Private IP addresses are not exempt by default.
- HTTP method validation is enabled by default.
- Compressed request bodies are rejected by default.
- Request bodies are capped at 1 MiB and up to 64 KiB is inspected and replayed to downstream handlers.
- Duplicate parameters, oversized parameter collections, Java serialization streams, and unexpected route media types are rejected.
- Rate-limit state is bounded without evicting active protection when capacity is exhausted.

### Trusted proxies

Only loopback proxies are trusted by default. Configure every proxy or load balancer that directly connects to the application:

```java
AiwafConfig config = new AiwafConfig();
config.trustedProxyCidrs = new HashSet<>(Set.of(
    "127.0.0.0/8",
    "::1/128",
    "10.20.0.0/16",
    "2001:db8:1234::/48"
));
```

`X-Forwarded-For`, `X-Real-IP`, and `X-Country` are ignored when the direct peer is not trusted. Trusted proxies should overwrite client-supplied forwarding headers.

### Route media-type policies

Use longest-prefix matching to restrict request media types:

```java
config.allowedContentTypesByPathPrefix.put(
    "/api/",
    Set.of("application/json")
);
config.allowedContentTypesByPathPrefix.put(
    "/api/uploads/",
    Set.of("multipart/form-data")
);
```

### Signed persistence

Model artifacts, file storage, and exported configuration use atomic writes and reject symbolic-link targets. Configure an HMAC key to sign new artifacts and verify existing artifacts:

```bash
export AIWAF_ARTIFACT_HMAC_KEY='replace-with-a-long-random-secret'
export AIWAF_REQUIRE_ARTIFACT_SIGNATURE=true
```

When `AIWAF_ARTIFACT_HMAC_KEY` is configured, artifacts without a valid adjacent `.hmac` file are rejected. Enable `AIWAF_REQUIRE_ARTIFACT_SIGNATURE` to fail closed when the key is unavailable.

Native Java serialization is retained only for backward-compatible local persistence and is protected by purpose-specific exact class allowlists and resource limits. It must never be used directly on request data.

### Security automation

The `Security` GitHub Actions workflow runs:

- The full Maven test suite
- OWASP Dependency-Check with a CVSS 7 failure threshold
- CodeQL extended security queries
- Gitleaks history scanning
- CycloneDX JSON and XML SBOM generation

Configure the optional `NVD_API_KEY` repository secret to improve Dependency-Check update reliability.

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
