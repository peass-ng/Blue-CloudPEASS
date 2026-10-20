# Explicit selected GCS archive secret scans

The new native archive adapter and pure check are implemented, with **44 focused
tests passing**. Production registration, intake and scheduling remain root-owned
and uninstalled. [The JSON receipt](selected-archive-secret-review.json) records
exact source hashes, native contracts, tested branches and remaining limits.

The implementation is in
[`gcp_selected_archive_secret_indicators.py`](../../peaso/collectors/gcp_selected_archive_secret_indicators.py)
and the unregistered evaluator in
[`gcp_selected_archive_secret_review_20261019.py`](../../peaso/checks/gcp_selected_archive_secret_review_20261019.py).
Only new archive-owned files were changed; the text reader, AWS code and shared
runtime were left untouched.

## Selection and native proof

Require `content_secret_scans=true`, the named-check-derived private kind
`gcs_selected_archive`, and a `selected_gcs_archives` list of exact tuples:

```json
[{"project_scope":"projects/example","bucket":"selected-bucket","object":"source.zip","generation":"1234","format":"zip"}]
```

The other formats are `tar` and `tar.gz`. There is no automatic format, arbitrary
URL, latest alias, prefix or object enumeration. Every project scope must be
explicitly selected. Extra keys, invalid generations, foreign scopes and
duplicate native object tuples are rejected before credentials. Missing opt-in
or named kind performs zero extra object calls and zero detector calls.

The adapter reuses the unchanged selected-text reader's native ownership and
streaming boundary. Completed project and bucket inventories must bind CRM v3
numeric `Project.name` and `projectId` to the requested scope, then match native
`Bucket.projectNumber`. A contradictory optional legacy project number fails.
See the primary [CRM v3 schema](https://cloudresourcemanager.googleapis.com/$discovery/rest?version=v3).

Reads use `storage.objects.get`, with `storage.objects.get` permission, at fixed
`https://storage.googleapis.com/storage/v1/b/{encoded_bucket}/o/{encoded_object}`.
Metadata uses only `bucket,name,generation,size,contentType,contentEncoding,customerEncryption`.
The exact selected generation and `ifGenerationMatch` bind both metadata and
the subsequent streamed `alt=media` read. These are the native
[Objects.get metadata/media contracts](https://cloud.google.com/storage/docs/json_api/v1/objects/get).
No additional project/bucket requests or permissions are introduced.

Before media retrieval, native bucket/name/generation, positive bounded size,
selected format MIME and encryption/encoding are checked. ZIP accepts
`application/zip` or `application/x-zip-compressed`; tar accepts
`application/x-tar` or `application/tar`; tar.gz accepts `application/gzip` or
`application/x-gzip`. Generic octet-stream is conservatively unsupported.

The shared reader refuses redirects, reads no error bodies, streams raw bytes,
requires complete length/generation/type integrity, refuses HTTP content
encoding or partial ranges, and closes every response. Both metadata and media
request IDs reach the ordinary collector envelope. Raw archive bytes never enter
the JSON transport cache.

## Memory-only parsing and limits

The existing audited `aws_package_content_indicators.scan_zip` and `scan_tar`
parser code is reused with a private per-call globals mapping for GCP limits and
the detector callback. AWS globals remain unchanged. No AWS download, account,
context, request or heuristic helper is invoked. The deadline facade exposes
only `check_deadline`, delegating to GCP cancellation/deadline checks.

| Bound | Limit |
| --- | --- |
| Explicit archive targets | 10; root should also cap text+archive intake together |
| Compressed bytes/object | 1 MiB |
| Compressed total / HTTP calls / deadline | 8 MiB / 20 / 30 seconds, shared with text reads |
| Expanded/archive / total | 4 MiB / 8 MiB |
| Members/archive / total | 100 / 200 |
| Regular text member | 1 MiB |
| ZIP/gzip expansion ratio | 200, with the parser's 1024-byte floor |
| Detector timeout | At most 5 seconds each and half remaining shared deadline |
| Object listing pages | 0 |

ZIP expansion counts actual uncompressed file bytes; tar counts decompressed
container bytes including headers and padding. Failed parses consume their full
reserved expanded/member allowance, so malformed archives cannot reset the
scan-wide work budget. The normal transport call/cancellation/deadline limits
also apply across scopes and both content kinds.

There is no extraction or execution. Traversal, absolute/unsafe/duplicate paths,
links/devices/special tar members, encrypted or unsupported ZIP compression,
truncation, CRC/terminator errors, nested archives, known binary member suffixes,
invalid UTF-8/control-character binary, bombs, member/byte/time limits and
trailing or multi-member gzip make UNKNOWN. Containers without regular-file
detector coverage are UNKNOWN. A regular zero-byte text file can be a complete
bounded observation.

Only complete supported archives are assessed. Any unsupported member or
incomplete detector makes the whole archive UNKNOWN; partial parser results are
not emitted as complete findings. This strict text-member scope can make an
otherwise valid binary-containing deployment archive unassessable.

## Hidden findings and coverage

Every regular UTF-8 member goes through the existing Kingfisher 1.4.0 and
TruffleHog 3.92.5 detection adapters. Kingfisher does not validate or revoke;
TruffleHog retains `--no-verification --no-update --no-verification-cache
--force-skip-archives`. Scanner archive traversal stays disabled because the
bounded local parser supplies each member. No credential validation, intended
Secret Manager/KMS value retrieval or live-cloud call occurred. OS-level network
isolation and actual network deadline timing are not attested.

The existing process HMAC and finding merge combine one exact value across
tools, files, archives and services. A real-tool test produces one hidden finding
from four file locations across ZIP and tar.gz archives plus a Function literal
environment location, with both detector labels and both check owners.
Cross-process/cross-run merging remains outside that key domain's guarantee.

Persisted owners are opaque archive IDs; file locations are `archive.member-N`
ordinals and optional line numbers. Raw object/member names, contents, snippets,
error bodies, URLs, authorization headers and exception text never persist. A
synthetic token deliberately used as a member filename does not appear in the
result, scanner cache or evidence.

The desired state is “Selected Cloud Storage archive has no detected secrets.”
Positive evidence is two sentences: “A likely secret was detected in a text
member of an explicitly selected Cloud Storage archive. The value is hidden;
detection did not validate the credential.” Negative evidence applies only to
the complete selected archive's supported members.

Explicit selected GCS archives can cover a chosen Function source, Composer
archive or build artifact **only when native service references actually bind
that exact bucket/object/generation**. This task does not discover those
references, follow signed source URLs, inspect OCI images or claim automatic
coverage of every service, bucket or artifact.

## Validation and installation

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_gcp_selected_archive_secret_review_20261019.py
```

All **44 cases passed**. Six installed-tool cases cover ZIP/tar/tar.gz positive
and negative native responses. Other tests cover zero-call defaults, strict
selection, native integrity and ownership, unsafe archive variants, shared
budgets, private parser bindings, missing engines, tampered consumer coverage,
empty files, member limits, cancellation and cross-service exact-value merging.

The actual `GCPCollector.collect()` proof leaves native CRM v3, Compute hydration
and bucket listing/IAM jobs unchanged. Only the proposed archive kind admission
and dependent job are injected on one test instance. Response/Raw/basic fixture
helpers and the native HTTP sequence are attributed to the corrected
selected-object tests; no legacy project fields are invented.

Complete source-produced PASS/FAIL/UNKNOWN items and callback indexes are in
`/tmp/peasso-gcp-review-20261019/selected-archive-secret-proposals/runtime-cases.json`.
The adjacent exporter reproduces them through the native collection pipeline
with installed detectors, without marker literals. Root's exact admission,
named-kind, dependency, registry/catalog and scheduling proposal is in
`integration.md` in the same directory. Root still needs installed intake and
registry/selection tests before promoting production support.

Parser globals and requests/urllib3 socket internals are compatibility boundaries
identified by the source hashes in JSON. The offline mocked HTTP proof does not
attest real cloud authorization or actual network timing.
