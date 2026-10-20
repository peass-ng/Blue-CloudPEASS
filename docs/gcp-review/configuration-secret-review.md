# GCP configuration secret expansion

Implemented seven **unregistered** pure predicates and a transient projector for Compute Engine instance/template/project metadata, Cloud Run service/job literals, and Cloud Build trigger/build inline configuration. Existing Functions modules were not changed. Root owns hook application, registration, canonical copy, selection admission and groups; this report does not claim production coverage before those changes.

## Exact native coverage

| Native kind | Provider-returned fields inspected | Primary schema |
| --- | --- | --- |
| `instance` | `metadata.items[].value`, including inline startup/shutdown scripts and other literals | [Compute instances](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances) |
| `instance_template` | `properties.metadata.items[].value` | [Compute templates](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instanceTemplates) |
| `project` | `commonInstanceMetadata.items[].value` from Compute project hydration, retained inside CRM project `computeConfig` | [Compute projects](https://docs.cloud.google.com/compute/docs/reference/rest/v1/projects) |
| `cloudrun_service` | `template.containers[].env[].value`, `args[]`, `command[]` | [Services](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.services), [Container](https://docs.cloud.google.com/run/docs/reference/rest/v2/Container) |
| `cloudrun_job` | `template.template.containers[].env[].value`, `args[]`, `command[]` | [Jobs](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.jobs), [TaskTemplate](https://docs.cloud.google.com/run/docs/reference/rest/v2/TaskTemplate) |
| `cloudbuild_trigger` | Trigger substitutions plus inline Build substitutions, global `options.env[]` and step `env[]`, `script`, `args[]` | [Triggers](https://docs.cloud.google.com/build/docs/api/reference/rest/v1/projects.locations.triggers), [Build](https://docs.cloud.google.com/build/docs/api/reference/rest/v1/projects.builds) |
| `cloudbuild_build` | Returned Build substitutions, global `options.env[]` and step `env[]`, `script`, `args[]` | [Build](https://docs.cloud.google.com/build/docs/api/reference/rest/v1/projects.builds) |

Only existing native GET paths are used. Compute self-links bind requested project, location, object name and aggregate group. Run names bind the requested project/location/name; Build IDs and resource names bind the requested native parent, with Build `projectId` also checked. Field masks, foreign identities and incomplete responses cannot establish clean coverage.

Secret Manager references, encrypted Build secrets, external startup/shutdown script URLs, remote build files, archives/images, logs, old revisions and runtime process contents are not fetched. A remote trigger filename/autodetect/gitFileSource configuration yields UNKNOWN for the inline-build check. Cloud Run omitted literal EnvVar values use the documented empty default; missing required parent configuration remains UNKNOWN.

## Explicit opt-in and safe persistence

The existing public `content_secret_scans` flag must be exactly true. The resource kind must also be present in the engine-owned `_content_secret_scan_kinds` list, derived from **named selected checks**. Selecting a category or framework alone does not activate content detection.

The proposed transport hook runs on successful raw JSON before the application cache and before the existing sanitizer discards values. Cloud Build scripts and substitutions currently survive the transport sanitizer until later inventory projection; the new projector removes those literal values before cache even when detection is disabled. Compute security-setting keys, valid boolean representations, native metadata fingerprints and source-request provenance remain compatible with the existing sanitizer.

Kingfisher 1.4.0 uses SDK detection only. TruffleHog 3.92.5 reads stdin with verification, update checks, verification cache and archive traversal disabled. Both reuse `peaso.secret_scanning` and its process-random HMAC fingerprints. Only redacted observations survive. The existing engine deduplicator emits one finding for the same matched value across both engines and all services.

Limits: 100 resources per response, 256 literal parts per resource, 64 KiB per value, 256 KiB per resource payload, 1 MiB per response payload, 16 containers, 64 Build steps, and a 30-second response scan budget. Each detector receives at most ten seconds and half the remaining page budget; transport cancellation is checked before each resource. Bounds reject content before detector invocation and never turn truncated content into a negative verdict.

PASS requires complete results from both pinned detectors and no supported match in the declared returned fields. FAIL requires complete coverage and a likely-secret match; credentials are never validated. Disabled, unselected, missing, denied, truncated, foreign, malformed, cancelled or failed-detector states are UNKNOWN. A PASS does not assert exhaustive secret absence or compliance with an entire requirement.

Check titles state the desired configuration, such as “Cloud Run service literal configuration has no detected secrets.” All seven declarations use the existing `secrets` finding type. Failure evidence is concise:

> A likely secret was detected in the resource’s returned literal configuration. The value is hidden; neither detector validated the credential.

## Root integration artifacts

The directory `/tmp/peasso-gcp-review-20261019/configuration-secret-proposals` contains:

- `pre-cache-and-selection.patch`: precise shared transport hook, seven engine selection mappings, and safe-marker retention through the Cloud Build history allowlist.
- `admission.json`: seven declarations, existing secrets type assignments, and the common gate contract; no new compliance mappings are asserted.
- `runtime-cases.json`: source-produced PASS/FAIL/UNKNOWN items and full indexes for every native ID, with no raw synthetic credential retained.

The project marker remains inside existing `computeConfig`. Trigger projection already retains the safe marker; returned Build history needs the supplied allowlist hunk. Existing engine value deduplication needs no change. Shared files and prior Functions modules were not edited by this worker.

## Focused verification

Validation: `.venv/bin/python -m pytest -q tests/test_gcp_configuration_secret_review_20261019.py` — **152 passed in 29.92 seconds, no skips**, using the installed pinned detectors. The proposed shared-file patch also passes `git apply --check`. Tests exercise native-schema positives/negatives, benign variable names, seven-service value deduplication, explicit opt-in and selection gating, masked/foreign/partial responses, missing parents, all input bounds, cancellation/deadlines and detector failure.

Mock HTTP tests compile the actual Transport with the exact proposed hook in memory and prove raw values do not enter cached responses or request evidence. Full native GCPCollector pipeline tests cover all seven kinds through hydration, transformation, envelope sanitization and snapshot serialization. Compatibility tests compare all three Compute projections with the current sanitizer across nine valid setting representations and native provenance.
