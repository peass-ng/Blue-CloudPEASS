# Composer and Workbench literal secret review

Implemented two high severity checks using the existing **secrets** group, with
**46 focused tests passing in 13.92 seconds**. Scans inspect successful original
metadata response JSON before sanitization and caching. They add no service
requests. [The JSON receipt](notebook-airflow-secret-review.json) records APIs,
permissions, hashes, tested branches and unresolved contracts.

| Service | Returned literal fields | Existing native API |
| --- | --- | --- |
| Cloud Composer | `config.softwareConfig.envVariables`, `airflowConfigOverrides`, `pypiPackages` | Composer v1 regional `environments.list` |
| Workbench v2 | `gceSetup.metadata`, `gceSetup.systemMetadata` | Notebooks v2 `instances.list`, including `locations/-` |

The pure checks, producer, gzip native fixtures and focused tests are new owned
files. Root installed the shared pre-cache hook, downstream coverage preservation,
registry invocation, named planner mapping and finding-type metadata during this
dispatch. This worker did not edit shared runtime or catalog files.

## Native contracts and scope

Google defines Composer's three software fields as optional string maps. They
can contain literal configuration, so all returned keys and values are inspected
within the bounds below. PyPI strings are inspected as returned JSON, without
installing packages or following references; the synthetic credential test does
not establish which such strings real Composer create/update accepts. See the
[SoftwareConfig schema](https://docs.cloud.google.com/composer/docs/reference/rest/v1/projects.locations.environments#SoftwareConfig).

The [Composer list](https://docs.cloud.google.com/composer/docs/reference/rest/v1/projects.locations.environments/list)
and [get](https://docs.cloud.google.com/composer/docs/reference/rest/v1/projects.locations.environments/get)
methods use `composer.environments.list` and `composer.environments.get` respectively.
The current collector uses list. The producer also accepts an already-existing
full native GET; it never issues one itself.

Workbench custom metadata is a string map. Google's schema also exposes
`systemMetadata`, the output-only subset of metadata recognized by Workbench.
Both are scanned and scrubbed because this mirror can retain a duplicate value.
Inline startup/post-startup scripts are text values only, never executed.
External script URLs remain unfetched references. See the
[GceSetup schema](https://docs.cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances#GceSetup).
The native [list](https://docs.cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/list)
and [get](https://docs.cloud.google.com/vertex-ai/docs/workbench/reference/rest/v2/projects.locations.instances/get)
permissions are `notebooks.instances.list` and `notebooks.instances.get`.

Exact HTTPS hosts, versions, GET method, requested project scope, location and
resource name must bind. Only Workbench list accepts `locations/-`; Composer
requires a concrete region. Unproven project ID/number aliases are UNKNOWN.
No fields mask or request body is accepted. Current list support permits only
pageSize/pageToken; native filters/orderBy are outside this candidate contract.

An omitted optional map on a complete, present, unmasked parent is an empty
selected configuration. Missing parent configuration, prior names-only scrubs,
wrong types, incomplete locations/collections, missing/failed tools, limits and
unbound responses cannot prove absence and remain UNKNOWN.

## Activation, privacy and compatibility

Scanning requires boolean `content_secret_scans=true` and the corresponding
exact internally selected kind. Category/framework selection is insufficient.
The check IDs are:

- `gcp.review.composer_environment.literal_configuration_secret_indicators`
- `gcp.review.workbench_instance.literal_configuration_secret_indicators`

The default-off projection removes selected literal values before cache without
invoking detectors. Composer's removed maps receive unavailable coverage on
`softwareConfig` itself. Workbench retains recognized safe security switches,
sets other metadata values to `None` with per-key unavailable coverage, and keeps
omission distinguishable from redaction. Native CMEK, private-environment,
Shielded VM and public-IP facts remain available.

Descriptions, labels and annotations are conservatively dropped recursively,
with unavailable coverage, even on pages without detections. This prevents an
earlier page from retaining a free-form duplicate of a later detected literal.
The shared `scan_content` callback passes detected values directly to
`redact_matches`; other known reflections are hidden and changed facts become
unavailable before serialization. The existing generic sanitizer can remove some
sensitive keys and their coverage entirely, including `startup-script`; these
are unavailable facts. Current Workbench root-access/public-IP predicates are
directly tested for retained settings, genuine omitted defaults and redacted
invalid values.

Both pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 use the existing offline shared
adapters. No credential validation, Validator/Revoker, managed password retrieval
or Secret Manager access occurs. A shared process-keyed exact-value HMAC yields
one hidden leak across tools and both services; locations contain only fixed
configuration paths and line numbers. Raw matches, snippets, tool output and
exception text are not returned or cached. Cross-process/run identity is not
claimed.

## Bounds and proof

One transport-shared content budget caps 20 pages, 100 resources, 1 MiB scanned
payload and 60 seconds across both kinds. Each page allows at most 50 resources;
each map 128 pairs, keys 256 bytes, values 16 KiB and a complete row payload
128 KiB. Each engine gets at most five seconds and half the remaining deadline.
Leak evidence is capped at 256 values and 512 locations. Existing transport
page/call/deadline/cancellation budgets remain in force. These are scan limits;
this module does not add a bounded media reader or claim to bound the generic
collector's original JSON HTTP body size. Standalone callers must pass the shared
budget to obtain limits across responses.

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_gcp_notebook_airflow_secret_review_20261019.py
```

All **46 tests passed**. Native integration tests run actual `GCPCollector.collect`,
existing service jobs, installed transport pre-cache hooks and downstream scrubs.
Only HTTP responses and fake credential headers are mocked. Python socket
connect/connect_ex/create_connection and DNS are blocked, with an explicit escape
assertion. No authenticated live-cloud calls occurred in this dispatch; OS-level
subprocess egress isolation is not attested.

Real offline tools prove both services' positive/negative cases, PyPI-only
configuration detection, a Workbench systemMetadata-only detection, clean external
references, privacy and one exact-value finding across owners. Contract tests
cover activation, identity, masks, missing/unsupported configuration, limits,
cancellation, denied HTTP, one-engine failure, nested coverage and installation.
Existing Workbench predicates and shared scanner/merge implementations are reused
with attribution in the JSON receipt; no full suite was run.

Six complete source-produced PASS/FAIL/UNKNOWN item/index/evidence cases and the
reproducer live under
`/tmp/peasso-gcp-review-20261019/notebook-airflow-secret-proposals`.
UNKNOWN cases use actual native-shaped configured strings over the 16 KiB bound.
The deterministic gzip fixture contains those same six pairs plus missing and
malformed sentinels; normal `install()` is idempotent. The adjacent integration
proposal specifies exact hook, budget, named selection and registry requirements.

This proves selected returned configuration behavior with synthetic native-shaped
responses, not real-cloud authorization or whole-service absence. Composer DAG
source, Workbench files/disks, packages/images, external scripts and managed
secret values are outside coverage. Source hashes pin observed shared state,
not every root-owned catalog, planner or hosted routing branch.
