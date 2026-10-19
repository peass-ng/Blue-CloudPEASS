# Cloud Functions literal environment secret review

Implemented an opt-in, offline dual-detector projection and an **unregistered** pure predicate. Shared transport, engine, registration, selection flags and canonical mappings remain root-owned. The proposed native ID is `gcp.review.function.literal_environment_secret_indicators`, using the existing `secrets` finding type.

## Acquisition and privacy

The existing `Transport.request` decodes successful HTTP JSON and calls `sanitize(data)` immediately before its application-cache write. The sanitizer drops literal environment values and retains names, so the later `functions()` inventory callback cannot scan values. The proposed hook inspects the original response at that transport boundary, returns sanitized data with redacted indicators, and allows the existing sanitizer/cache pipeline to continue.

Runtime `serviceConfig.environmentVariables` and build-time `buildConfig.environmentVariables` are scanned separately. Both are exact provider-returned literal maps; Secret Manager payloads, function archives, runtime memory, logs and historical revisions are not read. The projector binds the HTTPS host, GET method, requested project, location and optional function name. Field masks, unsupported bodies, foreign identities and explicitly incomplete responses cannot produce a clean result. Default-off output matches the existing names-only sanitizer and invokes no detectors.

A second proposed hunk prevents `env_names()` from synthesizing an empty map when the transport already retained `environmentVariableNames`. Without this guard, later envelope sanitization overwrites actual retained names with an empty list. No shared code was edited.

The existing Kingfisher SDK detection-only adapter and TruffleHog stdin adapter run with verification, verification cache, updates and archive traversal disabled. Existing process-random HMAC fingerprints merge exact matched values across engines and surfaces; raw values, raw hashes, snippets, stderr and exception text are not retained. The existing engine already runs `deduplicate_secret_findings`, so an engine patch is unnecessary.

## Bounds and verdicts

Limits are 128 pairs per map, 16 KiB per value, 128 KiB per function including context, 1 MiB and 100 functions per response page, and a 30-second page deadline. Each engine receives at most ten seconds per surface and half the remaining page budget; transport cancellation is checked before every surface scan. Oversized input is rejected before detector invocation, without a truncated negative verdict.

PASS requires complete runtime/build maps and successful completion by both pinned detectors on both surfaces. FAIL requires complete coverage and a supported likely-secret match. Disabled, denied, incomplete, malformed, foreign, cancelled, exhausted or partially failed scans yield UNKNOWN; redacted partial-positive observations remain in the projection. PASS describes only these returned maps and supported detector rules, and detection never asserts credential validity.

Proposed failure evidence:

> A likely secret was detected in the function’s literal environment values. The value is hidden; detection did not validate the credential.

## Four exact upstream omissions

All four Steampipe controls are pinned to `3ac653021a284b68c69b14c75afa2ebc1feff665`. Their evaluators emit constant INFO with a manual-verification message; they do not inspect environment values.

| Source ID | Existing canonical requirement | Proposed review |
| --- | --- | --- |
| `gcp-compliance.control.cis_v130_1_18` | `gcp-compliance.benchmark.cis_v130` / same control ID | Add the value detector as PARTIAL |
| `gcp-compliance.control.cis_v200_1_18` | `gcp-compliance.benchmark.cis_v200` / same control ID | Add the value detector as PARTIAL |
| `gcp-compliance.control.cis_v300_1_17` | `gcp-compliance.benchmark.cis_v300` / same control ID | Add the value detector as PARTIAL |
| `gcp-compliance.control.cis_v400_1_17` | `gcp-compliance.benchmark.cis_v400` / same control ID | Add the value detector as PARTIAL |

The four canonical requirements already have PARTIAL links to the names-only native `gcp.htbp.function.secret_env_from_secret_manager`. Value detection augments that heuristic; it does not establish exhaustive secret absence or complete Secret Manager migration. Exact upstream URLs, evaluator hashes and canonical candidates are recorded in `function-secret-review.json`.

## Integration and validation

Root proposal artifacts:

- `/tmp/peasso-gcp-review-20261019/function-secret-proposals/transport-pre-cache.patch`: both precise transport and names-preservation hunks.
- `/tmp/peasso-gcp-review-20261019/function-secret-proposals/admission.json`: declaration, existing secrets type, explicit default-off selection proposal and four PARTIAL mapping candidates.

Validation: `.venv/bin/python -m pytest -q tests/test_gcp_function_secret_review_20261019.py` — **36 passed**, including real installed Kingfisher 1.4.0 and TruffleHog 3.92.5, with synthetic tokens only. Tests exercise positive matches under benign variable names, complete negatives, cross-tool/surface deduplication, all bounds, absent/failed detectors, explicit opt-in, cancellation, foreign identity, masked requests and denied HTTP.

Integration tests compile the actual current Transport and GCPCollector classes with the exact proposal hunks in memory, then run mock HTTP through cache hits, functions hydration, envelope sanitization and snapshot serialization. They prove raw values are absent from cached data, request evidence, snapshots and detector-result caches; production hooks are still pending root admission.

Provider fields are documented in the [Functions v2 REST resource](https://cloud.google.com/functions/docs/reference/rest/v2/projects.locations.functions#ServiceConfig), including runtime `ServiceConfig` and build-time `BuildConfig` maps.
