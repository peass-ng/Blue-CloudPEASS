# Selected Artifact Registry File secret review

Implemented a bounded selected-file adapter and high severity desired-state check
for the existing **secrets** group. **51 focused tests passed in 12.95 seconds**,
including the actual installed collector pipeline and real offline detection for
UTF-8, ZIP, tar and tar.gz. [The JSON receipt](artifact-file-secret-review.json)
records exact APIs, native fields, permissions, source hashes and proof limits.

The new check is
`gcp.review.artifactregistry.selected_file_secret_indicators`, with kind
`artifact_selected_file`. Root owns shared admission, collector scheduling,
registry invocation, group metadata and canonical integration; this worker edited
only the new owned adapter/check/gzip/tests/reports and proposal artifacts.

## Native read and content binding

Google's [File schema](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.files)
provides canonical `name`, decimal-string `sizeBytes` and typed `hashes` with
base64 values. A native SHA256 must decode to exactly 32 bytes and equal the
user-selected lowercase hex digest. The complete downloaded bytes must match
that digest and native size before any result can be complete. MD5 or DIRSUM
cannot substitute for missing SHA256; ancillary hashes are shape-checked.

The [File GET](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.files/get)
uses `GET https://artifactregistry.googleapis.com/v1/{name}` with minimal
`fields=name,sizeBytes,hashes`. Native media uses
`GET https://artifactregistry.googleapis.com/download/v1/{name}:download?alt=media`,
as specified by Google's [download guide](https://docs.cloud.google.com/artifact-registry/docs/repositories/download-files).
The [download method](https://docs.cloud.google.com/artifact-registry/docs/reference/rest/v1/projects.locations.repositories.files/download)
and metadata GET both require `artifactregistry.files.get`.

The schema's `a%2Fb%2Fc.txt` example is tested directly: its canonical escaped File
ID appears once in both prepared URLs, without raw slash substitution or `%252F`
double encoding. Noncanonical escapes, traversal and ambiguous decoded percent-HH
sequences are rejected. Literal filenames containing such sequences are outside
this conservative contract.

Ordinary native project and repository collections must already be complete.
CRM v3 numeric project name plus projectId bind the scope; the exact repository
must occur once with explicit standard mode and a known non-Docker format.
Missing/unknown mode, remote, virtual, AOSS, Docker, foreign or partial authority
remains UNKNOWN before any File read. Binding fields use the existing strict
field accessor, so unrelated repository IAM hydration does not invalidate valid
name/mode/format facts. Successful File reads establish those specific reads were
authorized; this is not an effective IAM policy verdict.

## Selection, transport and privacy

Activation requires boolean `content_secret_scans=true`, the exact internally
named check kind, and `selected_artifact_files`: one to eight exact objects with
`project_scope`, canonical File `name`, `sha256` and `format`. All scopes must be
explicitly requested, the entire selection is validated before credentials, and
duplicate native names or extra keys are rejected. Category/framework selection
does not enable content. With no opt-in or named kind the adapter creates zero
sessions, credentials, File calls or detector calls. It does not enumerate files,
packages, versions or mutable tags.

The dedicated uncached session disables ambient proxies and netrc, uses an
identity auth callback, clears cookies before/after reads, and sends minimal
validated native Bearer headers. It makes only fixed Google-host HTTPS GETs,
without auth helpers, challenge fallback, redirects or a retry path. Response
URL/history, identity encoding, no ranges, required Content-Length and complete
streamed bytes are verified. Responses and the session close on all read paths;
remaining deadlines are applied per socket read where available.

Native/error bodies, selected digests, filenames, URLs, member names and snippets
never enter evidence or the transport cache. Receipts contain fixed operation,
scope, status/byte counts and an opaque target identity. Both complete request
receipts bind each resulting item through coverage and provenance.

## Bounded formats and detection

| Limit | Enforced bound |
| --- | --- |
| Selection / new GET calls | 8 files / 16 calls across scopes |
| Media / total media | 1 MiB per file / 8 MiB total |
| Metadata | 16 KiB per response |
| Content deadline | 30 seconds plus existing transport limits |
| Expanded archive / total expansion | 4 MiB / 8 MiB |
| Member / members | 1 MiB / 100 per archive, 200 total |
| Expansion ratio | 200 times, with the audited parser's small-file allowance |
| Detector time | At most 5 seconds each and half remaining deadline |

UTF-8 files also charge expanded-byte/member totals. Failed archive parses consume
their reserved allowance. No pagination is added. Strict UTF-8 text rejects
binary/control/archive data. Archives reuse the unchanged audited GCP archive
facade and ZIP/tar parsers with private per-call globals/context; AWS scanner
globals, network and credential helpers are untouched. No disk extraction,
installation or execution occurs. Traversal, links, encryption, truncation,
nested/binary members, unsupported formats and decompression limits are UNKNOWN.
The File schema supplies no MIME field: caller-selected format must pass actual
byte/parser validation rather than an invented native MIME assertion.

Pinned Kingfisher 1.4.0 and TruffleHog 3.92.5 use existing offline adapters, without
credential verification, validators or revokers. Their shared process-keyed exact
value HMAC combines both tools and repeated values across files/services. Evidence
has hidden fingerprints and fixed `artifact.content` or `archive.member-N`
locations. Missing/failed tools or incomplete content remain UNKNOWN. Negative
results cover only the exact full digest-verified selected content.

## Proof, fixtures and remaining limits

```sh
PYTHONPATH=. .venv/bin/python -m pytest -q tests/test_gcp_artifact_file_secret_review_20261019.py
```

All **51 tests passed**. Eight real-tool cases prove positive/negative behavior
for the four formats. Other directed cases cover cross-file/member dedup,
unchanged AWS globals, exact native hashes/size/name, full stream integrity,
private names, default zero calls, unsafe archives, bounds, cancellation,
one-engine failure, and idempotent fixture installation.

The native integration case runs actual `GCPCollector.collect`: CRM v3/Compute,
repository list/IAM hydration, the root-installed dependent File job and the
pure consumer. Only HTTP and fake native headers are mocked; no scheduling
injection or fallback is used. Other producer tests independently use native
stream fixtures and the actual envelope/provenance implementation. Python socket
connect/connect_ex/create_connection and DNS fail closed, including an explicit
escape assertion. No authenticated live-cloud calls occurred; OS-level subprocess
egress isolation is not attested.

The adjacent proposal directory contains primary discovery, exact root hooks,
and complete source-produced PASS/FAIL/UNKNOWN item/index/evidence exports.
The deterministic gzip fixture contains those same three cases plus missing and
malformed sentinels. UNKNOWN is actual native digest-bound binary content selected
as UTF-8, without invented private markers. `install()` is a normal idempotent
registry hook. Exact artifact/source hashes are recorded in the JSON receipt.

This is selected-content coverage, not all-package/repository/service absence.
Remote/virtual/Docker repositories, managed secret stores, unsupported package
formats and unselected files are not assessed. File names may be mutable: the
selected/native SHA256 and actual bytes bind content, without claiming a native
generation precondition or immutable name. Missing Content-Length, redirects,
unsupported canonical names and unavailable hashes stay UNKNOWN. Native-shaped
fixtures do not certify real-cloud authorization or every root-owned intake,
planner, hosted, registry or catalog branch.
