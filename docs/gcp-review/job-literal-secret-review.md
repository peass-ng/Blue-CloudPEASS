# Dataflow, Batch and Dataproc literal secret scanning

Four native producers and checks now pass **50 focused tests**, including the
independent Dataflow provenance acceptance case. Root installed the shared
collector scheduling and registry invocation; this follow-up tests that actual
scheduling with mocked credentials/HTTP and blocked Python socket/DNS access.
[The JSON receipt](job-literal-secret-review.json) records exact source and fixture
hashes, APIs, native fields, branches and proof limits.

The owned collector, pure check, tests and report were updated, and
`peaso/checks/gcp_job_literal_secret_fixtures.json.gz` supplies twelve native-source
PASS/FAIL/UNKNOWN cases to the idempotent `install()` hook. No shared runtime,
registry, catalog or infrastructure files were edited by this worker.

## Native producer contracts

| Check kind | Read APIs / permissions | Assessed literal configuration |
| --- | --- | --- |
| `dataflow_job` | v1b3 regional jobs.list and jobs.get; `dataflow.jobs.list`, `dataflow.jobs.get` | Bounded returned Environment, including sdkPipelineOptions, worker metadata and poolArgs |
| `batch_job` | v1 regional jobs.list; `batch.jobs.list` | Task/runnable literal environments, script text and container command/options/plain credentials |
| `dataproc_cluster` | Existing v1 regional clusters.list; `dataproc.clusters.list` | softwareConfig.properties and gceClusterConfig.metadata |
| `dataproc_job` | v1 regional jobs.list; `dataproc.jobs.list` | Properties, args, script variables, inline query lists and selected class/tag/logging options |

Primary discovery documents were downloaded and hashed before choosing fields.
The exact paths, method IDs and native schema properties appear in JSON and the
adjacent proposal cache. The failed intermediate fixture incident described below used a fixed fake token; the final verification made no service network calls.

Dataflow list views are a critical boundary: **jobs.list always returns
summaries**, including when the caller requests `JOB_VIEW_ALL`. Each discovered
ID therefore requires an exact regional GET with `view=JOB_VIEW_ALL`. A summary
cannot establish absence of environment literals. Missing Environment or a
pending, queued or unknown job state is UNKNOWN. This follows Google's
[list contract](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.locations.jobs/list)
and [Job/Environment schema](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.locations.jobs).

Batch includes taskSpec.environment.variables, deprecated taskSpec.environments,
taskEnvironments.variables and runnable.environment.variables. Script.text and
container commands, entrypoint, options, username and plaintext password are
literal values. Script.path is an unfetched host-file reference. secretVariables,
encryptedVariables and a container.password Secret Manager name are shape-checked
references/ciphertext, never secret-store reads or decrypted values. Google
explicitly warns that a plaintext registry password exposes it to job viewers.
See the [native Batch schema](https://docs.cloud.google.com/batch/docs/reference/rest/v1/projects.locations.jobs).

Dataproc cluster scans reuse the existing regional inventory API after native
project identity completes. Only the two configured maps are assessed; a virtual
cluster without GCE config is unsupported. initializationActions.executableFile
is a GCS reference, not proof of the script's contents. The default pre-cache
scrub removes these literal maps with unavailable field coverage while preserving
native CMEK/security configuration and pagination. See the
[cluster schema](https://docs.cloud.google.com/dataproc/docs/reference/rest/v1/projects.regions.clusters).

Dataproc job scans require one supported job union: Hadoop, Spark, PySpark, Hive,
Pig, SparkR, SparkSql, Presto, Trino or Flink. Script/JAR/Python/R/query-file,
archive and savepoint URIs are not downloaded. Inline queries are scanned as
text, without SQL execution. Nonempty unreachable encrypted-parameter reports
make coverage incomplete; no separate KMS decrypt occurs. See the
[job schema](https://docs.cloud.google.com/dataproc/docs/reference/rest/v1/projects.regions.jobs).

## Activation, identity and budgets

Require boolean `content_secret_scans=true` plus an explicitly named check mapped
to its kind in engine-derived `_content_secret_scan_kinds`. Category/framework
selection alone does not activate scans. The exact check IDs are:

- `gcp.review.dataflow_job.literal_configuration_secret_indicators`
- `gcp.review.batch_job.literal_configuration_secret_indicators`
- `gcp.review.dataproc_cluster.literal_configuration_secret_indicators`
- `gcp.review.dataproc_job.literal_configuration_secret_indicators`

Dataflow, Batch and Dataproc-job inventories are new and must be excluded from
broad/default inventories. Without activation they perform zero new service
configuration calls or scanner calls. Existing inactive Dataproc cluster metadata
collection retains its ordinary API path.

Only explicitly requested project scopes are eligible. Completed CRM v3 numeric
project name and projectId bind ID/number aliases; contradictory optional legacy
projectNumber fails. This also binds Batch names that contain the project number.
Dataflow project/location/ID, Batch job name/UID/task-group parent, Dataproc cluster
project/name/UUID and Dataproc job reference/UUID are validated. Dataproc region
is bound by the authenticated fixed regional endpoint because its row lacks a
region field.

Use explicit dataflow_regions, batch_regions and dataproc_regions, or an explicit
common regions list. At most five unique non-global regions are allowed. No
automatic region enumeration is added. Missing or invalid active selection is
unavailable/error coverage, never a clean empty service.

| Bound | Enforced candidate limit |
| --- | --- |
| New HTTP calls / adapter deadline | 64 / 60 seconds, shared across kinds/scopes |
| Wire JSON/body and total | 512 KiB / 4 MiB |
| Scanned JSON/row and total | 128 KiB / 1 MiB |
| Literal string/key | 16 KiB / 256 bytes |
| Tree size/depth; map/array width | 2048 nodes / 8; 128 elements |
| Returned resources; pages/region | 20 total; 2 |
| Detector timeout | At most 5 seconds each and half remaining deadline |
| Redacted observations | 256 leaks, 512 locations |

Normal transport call/deadline/cancellation limits also apply. Optional maps
omitted on a complete selected parent mean no configured literals. Missing
required parents, sanitized/partial flags, unsupported shapes, failed engines,
oversized content or exhausted budgets stay UNKNOWN. Empty native failedLocation
or unreachable arrays are accepted; nonempty arrays, duplicate resources/cursors
and truncated pagination cannot produce complete collections.

Full-view Dataflow jobs can exceed the wire cap because of non-environment job
fields, even when the environment itself is small. Those jobs remain UNKNOWN.
A future whole-Environment field-mask optimization needs separate native proof.
Chunked responses without Content-Length are also conservatively unsupported.

## Redaction and transport

The dedicated reader constructs fixed native GETs and never caches raw service
configuration. It uses an isolated no-proxy/no-auth/no-cookie session, validated
Bearer credentials, ADC header-case normalization and quota-project forwarding.
It refuses redirects/error bodies, verifies prepared response URL/history,
Content-Length, complete bytes, JSON type/encoding and unique keys, and closes
responses/session on every path. Request evidence contains exact operation IDs
and scope/region, with no literal URL, query cursor, name or exception text.

Both pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 run offline detection. No
Validator/Revoker is used; TruffleHog retains `--no-verification --no-update
--no-verification-cache --force-skip-archives`. There are no submits, cancels,
task execution, SSH, managed secret/password retrieval or SQL connections. Final
fixtures block Python socket/DNS access; OS subprocess egress isolation and actual
network timing are not attested. The intermediate fixture incident is recorded below.

scan_content's `_redact_values` callback supplies the union of detected strings
directly to redact_matches before metadata is retained. Repeated known values
in names/descriptions/labels are hidden, and altered facts become unavailable.
Native fixtures use real schema fields and valid lowercase labels rather than
inventing Job.description fields; arbitrary SDK-option descriptions remain
inside the native Dataflow Environment. Shared helper tests separately prove
generic name/description redaction and cache behavior.

The projection retains an opaque marker identity and a canonical native resource
reference included in the same scan/redaction step for triage. Raw configuration,
snippets, detected values, error bodies and exception messages never persist.
The process-keyed exact-value HMAC and existing engine merge produce one hidden
finding across all four owners and both tools. Cross-process/cross-run merging
is outside that key domain's guarantee.

Positive evidence is service-specific and two sentences: a likely secret was
found in that service's literal configuration; its value is hidden and detection
did not validate it. Negative evidence is limited to returned selected
configuration, excluding referenced content and intended managed secrets.

## Provenance correction, proof and root integration

Each Dataflow projection retains the original list receipt and its own exact
`JOB_VIEW_ALL` GET receipt in `_coverage` and item provenance. A failed GET retains
its failed request receipt and yields UNKNOWN. Per-item yields prevent another
job's GET from entering that item's generic provenance. GET receipts add a safe
opaque resource identity; Batch and Dataproc projections retain their exact list
page receipt. The consumer requires these collected receipt links before accepting
a complete scan.

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_gcp_job_literal_secret_review_20261019.py tests/test_gcp_secret_integration_acceptance_review.py::test_candidate_dataflow_each_item_links_its_own_full_read_not_another_job
```

**50 passed in 13.01 seconds**: 49 owned module cases and the independent root
acceptance case. Eight real-tool cases cover native positive/negative responses
for the four kinds; another proves one hidden exact-value finding across all
four owners. Additional cases cover successful/denied sibling GET provenance,
actual installed collector scheduling, activation, identity, references, framing,
limits, cancellation, privacy and idempotent installation. Earlier accepted review
also attributed two existing shared redaction tests; those were not rerun here.

The fixture helper uses actual `GCPCollector.collect` with normal CRM v3/Compute
identity jobs and installed dependent scheduling. Only credentials and HTTP are
mocked. There is no scheduling replacement or skip-if-produced fallback. Socket
connect/connect_ex/create_connection and DNS getaddrinfo fail closed; an explicit
test asserts the guard. The twelve-case export uses the same guarded helper.

An intermediate failed run reached default HTTP with a fixed fake Bearer token
and received 401 responses after shared scheduling changed. No real credentials
or job configuration payload were sent. This was reported to the coordinator.
The final isolated run and export followed removal of those scheduling overrides
and interception of the dedicated `requests.Session` seam. The whole task must
therefore not be described as having made zero live calls.

Complete source-produced PASS/FAIL/UNKNOWN items and callback indexes for all four
checks are in `/tmp/peasso-gcp-review-20261019/job-literal-secret-proposals/runtime-cases.json`.
The adjacent exporter uses installed detectors. UNKNOWN comes from valid typed
literals over the 16 KiB string bound, without hand-authored markers. Deterministic
gzip registry fixtures contain those same twelve item/index pairs plus empty and
malformed sentinels; the installer registers each check only once.

Root's normal registry hook is
`gcp_job_literal_secret_review_20261019.install()`. Root owns collector, intake,
planner and catalog integration; observed installed shared source hashes are
snapshots, not certification of all routing branches. Exact hooks, case hashes
and remaining scope limits are recorded in the JSON receipt and adjacent
`integration.md` proposal. Capped opt-in cluster inventory must retain partial
coverage for other checks. No real-cloud authorization, whole-service absence,
referenced code contents, Dataproc serverless batches or workflow templates are
certified.
