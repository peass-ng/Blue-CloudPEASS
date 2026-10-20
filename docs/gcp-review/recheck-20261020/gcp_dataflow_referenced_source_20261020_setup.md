# Selected Dataflow referenced package proposal

This is an **unregistered optional reader and pure evaluator proposal**. It is
local only: there is no CLI, engine, registry, collector scheduling, metadata,
canonical check, UI or deployment integration. The existing reconciliation
report remains historical. The new receipt narrows one native association gap;
it does not claim complete Dataflow source coverage or numbered upstream
compliance equivalence.

The exact proposed check ID is
`gcp.review.dataflow.selected_package_referenced_source_secret_indicators`.
The reader requires `check_ids` to equal a list containing that one ID and
`content_secret_scans` to be the boolean `true`. Default scans, categories,
inventory names, private kind options and other named checks grant no access.
Every supplied selector is validated before authentication, even when disabled.

Call the proposal directly with an existing GCP `Transport` and explicit
in-memory options:

```python
from peaso.collectors import gcp_dataflow_referenced_source_20261020 as reader
from peaso.checks import gcp_dataflow_referenced_source_20261020 as consumer

options = {
    "content_secret_scans": True,
    "selected_dataflow_referenced_sources": [{
        "resource": "projects/example-project/locations/us-central1/jobs/2026-10-20_01_23_45-123456789",
        "worker_pool": 0,
        "package": 0,
        "name": "workflow.tar.gz",
        "bucket": "example-source-bucket",
        "object": "staged/workflow.tar.gz",
        "generation": "12345",
        "format": "tar.gz"
    }]
}
# transport is supplied by the caller; this module does not obtain credentials.
capture = reader.capture(transport, ["projects/example-project"], options, [reader.CHECK])
results = [consumer.evaluate(item, capture) for item in capture["items"]]
```

This example is an API contract, not a request to perform live reads. Never
persist source bytes, bearer headers, raw selectors/options or native job
bodies. The returned capture contains opaque process-local HMAC identities,
redacted findings, detector status and this reader's own GET receipts. Its
receipt hashes are provenance references, not signatures or protection against
an actor fabricating an entire capture. Production admission and signed
snapshot integration remain separate work.

The native contract and fetched primary-source SHA-256 values are in
[the primary contract](gcp_dataflow_referenced_source_20261020_primary_contract.json).
[The regional jobs.get method](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.locations.jobs/get)
supports `view=JOB_VIEW_ALL`.
[Job and package fields](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.jobs#Package)
provide `id`, `projectId`, `location`, `createTime`,
`environment.workerPools[].packages[].name`, `.location`, and optional `.sha256`.
The package checksum is hexadecimal, not base64. Present checksums must match
SHA-256 of the captured object bytes, before parsing/decompression; malformed
or mismatching checksums are unbound `UNKNOWN`, even if the content would
contain a secret. Omitted checksums permit only a current-reference capture.
Matching checksums also do not establish historical execution.

Native package locations must equal the selected bucket/object using one of
these exact forms: `storage.googleapis.com/BUCKET/OBJECT`,
`https://storage.googleapis.com/BUCKET/OBJECT`,
`BUCKET.storage.googleapis.com/OBJECT`, or its `https://` form. The current
Apache Beam package constructor and its `STORAGE_API_SERVICE` constant, pinned
in the primary contract, independently establish the first form. The other
forms follow the REST GCS resource families. There is no arbitrary URL fetch:
the reader constructs the Storage JSON API object route itself. `gs://`,
signed/query/fragment URLs, encoded aliases, prefixes and ambiguous paths are
conservatively unsupported in this proposal.

Each selector produces nine uncached GET operations in this order:

1. CRM v3 project identity: exact project ID, active state and project number.
2. Regional Dataflow job with `JOB_VIEW_ALL`: exact native job ID, region,
   project, timezone-bearing creation time, selected package index/name/location
   and optional hex digest.
3. Exact bucket metadata: `projectNumber` must match that project.
4. Exact latest object metadata, without a generation parameter: latest
   generation must equal the explicit selected generation.
5. Exact object media GET with both `generation` and `ifGenerationMatch` set.
6. Latest object metadata again, equal to step 4.
7. Native job again: immutable identity and selected package tuple equal to
   step 2. A location spelling or digest-presence change also invalidates it.
8. Bucket ownership metadata again, equal to step 3.
9. Project identity again, equal to step 1.

Only then are the captured bytes scanned. Missing/mismatching native fields,
partial/error responses, changed ownership/identity/reference/generation,
permission denial, redirects, compressed/ranged/chunked HTTP framing, incorrect
media generation, unavailable credentials and truncated streams produce
`UNKNOWN`. Responses must have bounded explicit Content-Length. No retries,
list calls, object writes, secret-store reads, credential validation or workload
execution occur. Current/job-terminal states accepted are RUNNING, DONE,
FAILED, CANCELLED, UPDATED and DRAINED; pending/stopped/transitional states and
missing optional identity fields are conservatively unavailable.

Minimal read permissions for this proposal are:

| Operation | Permission | Boundary |
| --- | --- | --- |
| Regional job GET | `dataflow.jobs.get` | Selected job in its project |
| CRM project GET | `resourcemanager.projects.get` | Selected project |
| Bucket metadata GET | `storage.buckets.get` | Explicit same-project bucket |
| Object metadata/media GET | `storage.objects.get` | Explicit selected object |

Permission references:
[Dataflow jobs.get](https://docs.cloud.google.com/dataflow/docs/reference/rest/v1b3/projects.locations.jobs/get),
[CRM projects.get](https://docs.cloud.google.com/resource-manager/reference/rest/v3/projects/get),
[Storage buckets.get](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets/get),
[Storage objects.get](https://docs.cloud.google.com/storage/docs/json_api/v1/objects/get).
The Dataflow method accepts the `cloud-platform` or `compute` OAuth scope;
the union of CRM/Storage reads requires scopes appropriate to those services
(normally `cloud-platform`) plus the explicit IAM read permissions. No broad
admin role, project/bucket/object listing or worker service-account
impersonation is required. Each request uses the caller's token, not the
Dataflow worker identity. A token fingerprint must remain unchanged throughout
the capture; token refresh conservatively invalidates the result. This is an
opaque continuity check, not an independent identity or credential-validation
claim.

Bounds are one to four selectors across one to eight explicit project scopes,
unique native package slots, 100 maximum native worker pools and 100 package
entries in the selected pool, 36 GET calls, 120 seconds, 64 KiB per metadata
response, 1 MiB per compressed/plain object, and 8 MiB aggregate wire bytes.
Existing transport call budgets, cancellation and deadlines can tighten these
limits. No source is discovered through arbitrary bucket enumeration.

Formats are strict UTF-8 text with supported native text/JSON/YAML/XML/JS MIME,
or explicit ZIP, tar and tar.gz with the existing archive MIME allowlists.
Archives reuse the reviewed memory parsers without modifying their globals.
Limits are 1 MiB per text member, 4 MiB expanded per archive, 8 MiB expanded
total, 100 archive entries per object, 200 total, and compression-ratio limits
from those parsers (200 for ZIP members/gzip expansion with their small-input
floor). Failed archives consume their reserved expansion/member budget.
No filesystem extraction occurs. Nested archives, links, special files,
unsafe paths, unsupported archive encodings, binary/class/pyc content and
oversized content are incomplete. JARs/wheels containing binary artifacts
cannot receive a complete clean verdict. Some earlier fully inspected text
members can still yield trusted incomplete positive findings.

Both actual offline detectors are required for a complete negative result:
Kingfisher SDK **1.4.0** and TruffleHog **3.92.5**. TruffleHog runs with
verification, updates, verification cache and archive traversal disabled;
Kingfisher uses the detection-only SDK and disables its rules cache. Values
merge through the shared process HMAC, across engines/members/selections and
other compatible readers in the same process. Output contains no secret
values or member names. Trusted hits from a successful detector remain
`FAIL` with `complete=false` when another detector or later member fails.
Incomplete negatives are `UNKNOWN`. A complete clean result applies only to
the selected current captured package bytes and supported detector rules.

Remaining scope: `stepsLocation` graph objects; arbitrary pipeline options,
input/output/temp prefixes and `tempFiles`; Flex template specs and container
images; cross-project buckets; unlisted URI encodings; binaries; package
dependencies beyond explicitly selected objects; historical/original
executed/deployed source; live cloud verification; and runtime registration.
Before/after observation cannot eliminate ABA changes between reads or prove
continuous ownership. No custom company criteria are introduced.

Run only the bounded directed offline acceptance:

```sh
.venv/bin/python -m pytest -q tests/gcp_dataflow_referenced_source_20261020_test.py
```

The native and receipt fixture files are new-only synthetic evidence. Receipt
fixtures came from the real reader through fake native HTTP with installed
detectors; they contain no workload source bytes and are not live attestations.
