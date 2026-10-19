# Selected Cloud Storage text-object secret scanning

The native adapter and pure check are implemented and tested, with **52 focused
checks passing** after correction of native CRM v3 project binding. The check remains unregistered and its production collection
job remains unwired: root owns admission, selection, catalog and scheduling.
[The JSON receipt](selected-object-secret-review.json) records exact methods,
fields, source hashes, branches and proof limits.

The new files are
[`gcp_selected_object_secret_indicators.py`](../../peaso/collectors/gcp_selected_object_secret_indicators.py),
[`gcp_selected_object_secret_review_20261019.py`](../../peaso/checks/gcp_selected_object_secret_review_20261019.py)
and [the focused tests](../../tests/test_gcp_selected_object_secret_review_20261019.py).
No shared runtime files were edited.

## Exact selection and native binding

Scanning requires `content_secret_scans=true`, the engine-derived named kind
`gcs_selected_object`, and `selected_gcs_objects`, a list of at most ten exact
entries:

```json
[{"project_scope":"projects/example","bucket":"selected-bucket","object":"config/settings.env","generation":"1234"}]
```

Every project must be an explicitly selected collector scope. No object listing,
prefix discovery, latest-generation aliases or arbitrary URLs are accepted.
False/missing opt-in or absent named kind makes zero additional object HTTP
requests and zero detector calls. Invalid active selections are rejected before
credentials; root must preserve that as admission/error coverage rather than
convert it into a clean empty scan.

Object metadata does not identify its owning project. The adapter therefore
requires completed native project and bucket envelopes in the requested scope,
with the project's numeric CRM v3 `name=projects/{number}` matching the selected bucket's
[`projectNumber`](https://cloud.google.com/storage/docs/json_api/v1/buckets).
The requested project ID must match native `projectId`, or the requested numeric
scope must match that native name. CRM v3 has no `projectNumber` field; a supplied
legacy field is accepted only if identical to the numeric name. Legacy-only,
missing-name, nonnumeric-name and contradictory metadata remain UNKNOWN before
credentials. See the primary [CRM v3 discovery schema](https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v3).
Missing, partial, denied, duplicate or conflicting identity evidence prevents
content reads. Existing bucket metadata collection also hydrates IAM; a denied
inventory conservatively blocks scanning even if object GET alone is allowed.

The fixed request is
`GET https://storage.googleapis.com/storage/v1/b/{encoded_bucket}/o/{encoded_object}`,
using `storage.objects.get`. Metadata requests select only
`bucket,name,generation,size,contentType,contentEncoding,customerEncryption` with
`projection=noAcl`. Both requests send the exact selected `generation` and
`ifGenerationMatch`; the second adds `alt=media`. These are the native
[Objects.get metadata/media contracts](https://cloud.google.com/storage/docs/json_api/v1/objects/get).
No additional bucket/project calls are introduced by this adapter.

## Content, budgets and privacy

Only complete strict UTF-8 text is initially supported, with approved text MIME
types. Binary control characters and recognized archive magic are rejected even
if mislabeled as text. Archives, binary files, customer-supplied encryption,
encoded content and media without Content-Length remain UNKNOWN.

| Bound | Enforced adapter limit |
| --- | --- |
| Explicit objects | 10, across all selected scopes |
| Content per object / total | 1 MiB / 8 MiB |
| Metadata response | 16 KiB |
| HTTP calls | 20, also consuming shared transport call budget |
| Object listing pages | 0 |
| Adapter deadline | 30 seconds, also constrained by transport deadlines |
| Detector timeout | At most 5 seconds per engine and half remaining time |
| Stream chunk / findings | 16 KiB / 256 leaks and 512 locations per object |

Requests stream from the fixed HTTPS endpoint with redirects disabled and
`Accept-Encoding: identity`. Successful media must have exact native generation,
matching content type, no Content-Range, identity encoding and Content-Length
equal to both metadata size and the complete body byte count. Overlong,
truncated, denied, redirected and oversized responses cannot be scanned as clean
text. Error bodies are never read. Every response closes in `finally`.

The reader consumes the real Transport session, credentials, lock, call budget,
cancellation checks and deadlines. It bypasses the generic JSON cache. Before
blocking reads it tightens requests/urllib3 socket timeouts to the remaining
deadline. That internal socket representation is a dependency compatibility
boundary; mocked in-memory streams do not prove actual network timing.

Only opaque selection IDs, scope, sizes, statuses, detector labels and keyed
redacted observations survive. Object names can themselves contain secrets, so
the persisted ID is a SHA-256 of the selection tuple rather than its literal
path or a content hash. The user's private selection can map that ID back to a
resource. No raw bytes, snippets, authorization headers, exception messages,
error bodies, signed URLs or object names enter the transport evidence or safe
outcome cache.

## Detection and consumer behavior

Transient bytes go through the existing Kingfisher 1.4.0 and TruffleHog 3.92.5
adapters before serialization. Kingfisher uses detection only; TruffleHog runs
with `--no-verification --no-update --no-verification-cache --force-skip-archives`.
No credential validation, rotation, Secret Manager access, KMS value access or
live cloud call was performed. No OS network-isolation claim is made.

The existing process-keyed HMAC merges the exact detector-returned secret across
tools and owners. The test with the installed tools finds one synthetic token
in two native object responses, then produces one hidden finding with both
detectors and both opaque object locations. Cross-process/cross-run merging is
not guaranteed because the existing random key resets.

The pure consumer requires an exact GCP scope, opaque identity, unique collected
envelope, complete producer marker and both unique pinned engine records. A
missing engine makes UNKNOWN, including when a partial positive is redacted in
the producer projection. A complete negative is restricted to the selected text
object; it does not establish bucket-wide or service-wide absence.

Positive evidence is two sentences: “A likely secret was detected in an
explicitly selected Cloud Storage text object. The value is hidden; detection
did not validate the credential.” Existing secrets grouping and the shared
deduplication stage should be preserved during installation.

## Root installation and validation

The exact integration proposal is
`/tmp/peasso-gcp-review-20261019/selected-object-secret-proposals/integration.md`.
It adds the named check-to-kind mapping, strict public option validation,
registry/catalog entries and kind dependencies. Schedule
`collection_pages(self, scope)` after native project and bucket inventories
finish. It yields ordinary `(items, request_id)` pages and preserves both metadata
and media request IDs through `GCPCollector.envelope`.

The corrected focused command passed **52 adapter cases**:

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_gcp_selected_object_secret_review_20261019.py
```

Proof covers actual `GCPCollector.collect()` with unmodified native scope jobs,
CRM v3 GET, Compute project hydration, bucket listing/IAM and streamed object
metadata/media all passing through mocked HTTP to the callback. Only the future
kind admission and proposed dependent job are injected on the test instance;
shared runtime files remain unchanged. Both project ID and numeric scope paths
are covered with native CRM v3 responses that contain no `projectNumber`.

Other proof covers real collector/transport/envelope seams with mocked native HTTP,
selection and project binding, response closure and privacy, generation/length
integrity, binary/archive/encoding rejection, cancellation and budgets, forged
consumer evidence, missing engines and two installed detector cases. It does
not claim the production job/registry is installed, actual cloud permissions are
available or network timing has been certified. Root still needs the installed
engine-selection/registration path verified after integration.

Source-produced PASS, FAIL and UNKNOWN items and complete callback indexes are
exported in
`/tmp/peasso-gcp-review-20261019/selected-object-secret-proposals/runtime-cases.json`.
The adjacent `export_runtime_cases.py` reproduces them through the same full
native collection pipeline with installed offline detectors. FAIL requires both
detector labels; UNKNOWN comes from an unreadable media response. The export
also includes a registry-fixture-shaped mapping for root integration.

The earlier 49-check receipt did not prove native CRM binding: its prepopulated
project fixture invented legacy `projectNumber`. Root review correctly rejected
that proof. This revision replaces that fixture, derives the number from the
actual producer's numeric resource name, and adds the complete collection path.
