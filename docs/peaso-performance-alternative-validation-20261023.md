# Alternative CSPM workflow optimizations: implementation and qualification

This implements qualified parts of 14 of the [20 alternative opportunities](peaso-performance-alternative-roadmap-20261023.md). One prototype was rejected on measured regression; five remain unqualified. These are workflow changes across publication, audit processing, private evidence, historical ingestion, storage and API reads. They do not change check selection, findings, detector coverage or AI model inputs.

The initial comparison baseline is `19cb2da9`. A [follow-up qualification](peaso-history-expansion-validation-20261023.md) against `3359a8fb` adds bounded audit expansion (#14); its measurements are recorded separately. Implementation was rebased onto `6d8a1f23`, preserving concurrent scheduling, worker-control, privilege-query, display and artifact-cache changes. The overlapping artifact-cache implementation from main was retained in full; this branch adds workflow qualification and independent regression cases for it. No cloud deployment or live customer scan was performed. Hosted index improvements need the accompanying Terraform deployment.

## Measurements

macOS arm64, CPython 3.13.11; median of three CPU/wall trials, with a separate traced-Python-allocation trial. These are declared synthetic offline workflows, not cloud scan speedup estimates. Traced allocations are not process RSS. Small absolute timings and comparisons from different workflows should not be added together. [Raw measurements](benchmarks/peaso-alternative-workflows-20261023.json) include exact values and equality assertions.

| Workflow | CPU before → after | Peak Python allocation before → after | Other evidence |
|---|---:|---:|---|
| Two native-schema-1.1 publications, 2,000 findings each | 518 → 423 ms | 23.700 → 23.710 MB | PUTs 86 → 37; wall 658 → 478 ms with declared 10 ms synthetic PUT latency |
| Audit normalization, 10,000 unrelated events | 396 → 365 ms | 14,064 → 13,272 B | Complete normalized output compared against original; all existing audit fixtures exercised separately |
| Twenty private checkpoints, 1,000 encrypted records | 162 → 9.0 ms | 766 → 765 KB | Same decrypted document; encrypted index reused only while all dependencies match |
| Forty verified reads of a 1,000-object manifest | 33.1 → 4.0 ms | 67.38 → 0.51 MB | Current bytes read and hashed every time |
| Stage and durably commit 1,000 historical findings | 59.9 → 41.8 ms | 67.43 → 3.40 MB | Writer body 12.1 → 2.3 ms; same object/event/chunk counts |
| AWS AI credential input preparation | 23.9 → 13.1 ms | 910 → 8.9 KB | Exact selected credentials; no model invocation |
| Kubernetes AI credential input preparation | 141.6 → 10.0 ms | 910 → 8.9 KB | Exact selected credentials; GCP/Azure also avoid unused AWS traversal |
| Queued discovery, 20,100 jobs / 100 queued | 64.7 → 0.97 ms | 6.95 → 0.19 MB | Requests 41 → 2; discovery only, authoritative FIFO admission still scans |
| Five workspace memberships, real SDK + moto | 9.76 → 4.67 ms | 181 → 133 KB | SDK requests 11 → 2; authoritative membership reads retained |
| Twenty HTTP reads, loopback HTTP/1.1 | 23.3 → 7.4 ms | 100 → 68 KB | Connections 20 → 1; declared 10 ms connection setup; no Google/TLS measurement |
| Large legacy grouped local JSON download | 93.4 → 48.0 ms | 53.49 → 30.52 MB | Full response JSON equals stored owned artifact; 10,000 findings |

Publication retains a small bounded digest/reference map, increasing this measured peak by about 9 KB (0.04%). It reduces uploads, CPU and elapsed time; it does not claim a RAM reduction. A schema-1.0 publication replay also preserves full JSON/Markdown payloads and reduces PUTs 66 → 27. Private checkpoints retain encrypted metadata, and the first complete index construction still determines peak allocation.

The manifest allocation improvement comes partly from reading `fstat().st_size + 1` rather than reserving a 64 MiB maximum for every tiny file. Existing size/type/path checks and live digest verification remain. The extra byte detects growth beyond the observed size.

## Disposition of every candidate

| # | Candidate | Final disposition and quality boundary |
|---|---|---|
| 1 | Compose artifact reuse and batching | Applied. Exact encoded-byte reuse within and across successful batches. Cache publication follows durable flush and context success; manifests flush pending artifacts even on a cache hit. Failed writes, closed writers, tenant mismatch and deletion during publication are covered. Producers and deletion serialize; same-thread deletion during an active batch is rejected. Custom backends retain their own behavior. |
| 2 | Indexed queue/claim discovery | Applied partially. Configurable keys-only state index nominates work; strong base reads and existing conditional leases grant authority. FIFO admission deliberately retains its strong scan because an eventually consistent index can omit an older waiter. |
| 3 | Source/operation normalizer dispatch | Applied to 61 proven leading source-rejection guards. Handler order, overlaps and original normalizers remain. Only plain dictionaries with plain-string sources take the shortcut; unusual source values and custom mappings execute original guards. No speculative operation filtering. |
| 4 | Incremental private evidence index | Applied at checkpoint boundary. Complete capture identity, cipher identity/context, scope, encrypted records and related postings qualify unchanged-index reuse. Incomplete status stays live; records are freshly copied. Unknown cipher/capture implementations remain authoritative. The admitted evidence helper is unchanged. |
| 5 | Shorten historical write transactions | Applied via prepared immutable finding-ID validation receipts. Full validation happens during staging; the transaction rechecks live bytes and membership under the existing fence. Duplicate/foreign-event, lease and atomic-commit checks remain inside the transaction. |
| 6 | Reuse parsed manifests after live verification | Applied. One bounded immutable manifest representation, keyed by complete tenant/job/ref/digest. Missing, changed, oversized or unsafe files still fail live verification; no filesystem-mtime trust. |
| 7 | Active-job expiration index | Applied to active-state discovery. Current rows and deadlines remain authoritative; terminal-history rows are avoided when configured. Index lag can defer recovery to a later scheduler tick. |
| 8 | Due-schedule index | Applied. Time-bounded keys-only query, strong current-row hydration and enabled/time filtering. Existing conditional advancement remains authoritative; stale index rows cannot run a paused/future schedule. Index lag can delay discovery. |
| 9 | AI batches by context bytes | Held. Changing batch boundaries changes model context and may change decisions. No representative quality evaluation established equivalence; no batch truncation or coverage reduction shipped. |
| 10 | Exact AI input preparation reuse | Applied to provider-specific credential selection. Stream AWS account references, skip unused AWS inference for other providers, and collect Kubernetes references once per batch. Narrowing and complete reviewer payload semantics remain unchanged. |
| 11 | No-op secret resealing | Held. Direct helper edits triggered authenticated native source admission and were reverted. No receipt repinning or admission bypass was used. A separate authenticated source transition and qualified no-op workload are needed. Candidate 4 captures the verified checkpoint benefit without changing that helper. |
| 12 | Least-privilege projection reuse | Held. Mutable resource identity alone cannot qualify cached results; complete content, renderer and runtime bindings need an independently qualified design. No stale projection cache shipped. |
| 13 | GCP audit HTTP pooling | Applied. One requests Session per source operation, shared by project verification and pages, closed with credentials on exit. Tenant operations do not share sessions or tokens. Existing redirects, response limits and deadlines remain. |
| 14 | Streaming audit JSON input | Applied partially in the [bounded gzip expansion follow-up](peaso-history-expansion-validation-20261023.md). Single-member C decoding and bounded compatibility reads reduce CPU and allocation while retaining the full JSON parser, exact limit checks and atomic per-object rejection. Full streaming JSON parsing remains unqualified. |
| 15 | Overlap audit-object downloads | Held. Prefetch can retain extra raw buffers and download unused objects beyond event caps. No measured CPU/RAM/coverage win was established for a bounded design. |
| 16 | Compiled Sigma candidate plans | Rejected. Full preparation-inclusive replay doubled CPU (9.25 → 19.14 ms) and increased allocations (79 → 350 KB). Fingerprinting dominated savings. Prototype removed from production. |
| 17 | Skip unchanged publication preparation | Applied partially in the [publication inventory follow-up](peaso-publication-inventory-validation-20261023.md): share one freshly frozen native inventory between resource chunks and least-privilege projection within a single publication. Cross-publication component caching remains unqualified; no mutable snapshot-ID shortcut shipped. |
| 18 | Revision/status feed | Held. Requires a durable revision protocol covering runtime, reviews, AI, progress and authorization. No stale TTL response cache or incomplete invalidation protocol shipped. |
| 19 | Raw local report download | Applied narrowly to standard FileArtifacts and generated legacy grouped JSON at least 256 KiB. FileResponse avoids hydration and reserialization. Modern reports retain live runtime/AI overlays; small files and custom adapters retain the original path. Authorization and no-store behavior are tested. |
| 20 | Batched workspace hydration | Applied. Up to 100 strongly consistent keys per request, bounded unprocessed-key retries and explicit failure rather than partial authorization results. Metadata and current membership are read together; stale membership references alone grant nothing. |

Held candidates are unproven, not claims that further improvements are impossible. They need additional design and evidence before meeting the requested quality and resource gates.

## Deployment and consistency

Terraform adds `work-state(status, created)` and `schedule-time(kind, next_run)` keys-only GSIs using existing attributes, environment configuration, and scoped Query/BatchGetItem permissions. No shadow queue or application data migration is introduced. There are additional index write/storage costs; measure them on the deployed workload. Terraform may require staged GSI creation depending on provider/service update constraints; validate the deployment plan before applying.

Code with no configured index retains scanning. Missing/unavailable index configuration falls back to existing strong scans. During an IAM rollout, denied BatchGetItem falls back to individual strongly consistent reads. Throttling is not silently converted into a scan storm. GSI discovery is eventual; admission, claims, membership and schedule advancement use current authoritative data. Existing targeted collector/analyzer paths remain targeted.

## Validation and reproduction

The broad combined run produced **2,627 passed, 3 skipped, 18 subtests passed, 22 failures**. An isolated untouched `19cb2da9` checkout reproduced **20 of those failures**, including older API fixtures, the packaging fixture's incomplete source tree, gzip materializer bytes and a moto concurrent-dictionary race. The two additional failures were the expected source-inventory gate: after reviewing the exact SDK client closure, the inventory was updated. No native admission receipts were changed.

After rebasing current main, **141 integration tests passed**, including the source gate, scheduled credentials, calendar schedules, worker diagnostics/control, privilege pages and least-privilege details. **39 focused checkpoint, DynamoDB index, artifact reuse and history tests passed**, including cipher-context rotation and custom-cipher fallback. Other focused runs passed 1,948 audit tests, 171 AI/storage tests and 37 historical tests. These counts overlap and must not be summed. Test fixture corrections separate cold-import startup from the network-overlap deadline and keep AWS live credential capture prohibited.

After retaining concurrent main commit `6d8a1f23` unchanged, all **60 artifact/cache/source-gate tests passed**. The native-schema publication replay was repeated against the retained implementation; its full bundle hashes and 86 → 37 upload reduction remained identical.

The final affected-workflow run passed 283 cases and exposed four AI test fixtures using a literal `sealed` connector credential. Current main now decrypts those credentials for scheduling eligibility. Replacing the placeholders with valid encrypted renewable test credentials preserved the missing-AI-access assertions; the complete AI suite then passed **167 tests**. The other **120 cases** in that final run passed unchanged.

Terraform 1.14.3 `fmt -check` and `validate` passed using an offline provider mirror; the older system Terraform 1.5.7 cannot parse this repository. No Terraform apply was run. Existing deprecated `hash_key` warnings remain.

Run with the repository environment:

```sh
python -m examples.benchmark_peaso_alternative_optimizations --baseline 19cb2da9
python -m examples.benchmark_peaso_alternative_optimizations --baseline 19cb2da9 --sections publication --compact
python -m examples.benchmark_peaso_alternative_io --baseline 19cb2da9
python -m pytest -q tests/test_attack_normalizer_dispatch.py tests/test_private_evidence_checkpoint.py tests/test_dynamodb_work_indexes.py tests/test_report_artifact_reuse.py tests/test_attack_history_ledger.py
```

The benchmark scripts load the selected original functions/classes from Git into a separate namespace. They do not replace admitted runtime helpers. The I/O script uses real botocore with moto, a loopback HTTP server, a FastAPI download and FULL-durable SQLite staging/commit. Publication compares recursively decoded full bundle content, including JSON and Markdown, and declares the synthetic transport latency explicitly.
