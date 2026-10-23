# Twenty additional CSPM performance opportunities

Research baseline: `099548d1`, 23 October 2026. This is a proposed work list, not twenty implemented improvements. The earlier implementation window has ended; this change adds research and an offline reproducer only. No production behavior changes.

These alternatives exclude all twenty areas assigned to the other model: native startup proofs, dependency-based checkpoint evaluation, secret detector cohorts, finding query postings, streaming report publication, Trivy reader leases, identical-image analysis, registry pipelines, collector submission windows, throttling-domain scheduling, collector enrichment concurrency, reachability preparation, network selector parsing, privilege query caching, graph cache budgets, archive decompression, native joins, static finding metadata, worker control projections, and scan-history pagination.

The ranking weighs repeated work, affected workload size, and confidence in the mechanism. It is not a ranking of measured end-to-end savings. Only the two observations below were measured. Large audit histories and multi-tenant deployments will rank differently from small local scans.

## Reproduced observations

Run `python examples/benchmark_peaso_alternative_research.py` in the repository environment. The successful reproducer uses synthetic input, a fake S3 client, and an explicit synthetic rule; it needs no credentials, remote rule pack, or cloud calls. Python 3.13.11 produced:

| Observation | Existing behavior |
|---|---|
| Two identical direct writes through `ReusableReportArtifacts` | 1 PUT; same reference; 1 reuse entry |
| Two identical writes through its delegated batch contexts | 2 PUTs; different references; 0 reuse entries |
| 200 unrelated synthetic AWS audit events, one nonmatching rule | 58,200 normalizer calls across 290 distinct normalizers; zero detections |
| Unprofiled CPU for that audit input | 0.00626 seconds in one run; descriptive only, not a stable benchmark |

The audit call count is a call-profile result, including nested normalization. Its unprofiled CPU time was measured separately. Neither experiment measures a proposed speedup or establishes production traffic frequency.

## Ranked alternatives

### 1. Compose artifact reuse with upload batching

**Evidence:** [`report_reuse.py`](../peaso/storage/report_reuse.py), `__getattr__`, delegates `batch()` to S3. [`reports.py`](../peaso/storage/reports.py), `publish_report`, then publishes through the returned underlying writer. The wrapper's reuse cache is bypassed. Preencoded chunk writes also need explicit wrapper support; delegation must not silently bypass deduplication there. [`worker.py`](../peaso/worker.py) uses one wrapper across checkpoint/native/final publications.

**Change:** Provide a composed batch adapter supporting JSON, text, and preencoded JSON. Deduplicate exact bytes while retaining bounded concurrent uploads. Use short cache locks and per-key in-flight ownership; the current `_publish` lock spans a synchronous upload.

**Expected impact:** Fewer uploads, compression passes, and duplicate durable objects between publications; concurrent distinct uploads remain possible. This fixes composition of existing optimizations rather than introducing streaming publication.

**Quality and validation:** Cache only successful durable writes, bind tenant/scan/backend/kind/content type, invalidate after deletion, and preserve the manifest barrier. Exercise repeated complete publications, Unicode chunk boundaries, upload failures, concurrent duplicates, and custom backend fallbacks. Measure PUT counts, bytes, wall time, and peak RAM.

### 2. Give queue admission and worker claims an indexed access path

**Evidence:** [`dynamodb.py`](../peaso/storage/dynamodb.py), `queued_jobs`, calls `_scan('job')` and sorts the queued subset. Untargeted `claim` also scans jobs. [`scheduler_handler.py`](../peaso/server/scheduler_handler.py) consumes the global queued list.

**Change:** Maintain sharded queue/state access keys ordered by queue time and identity, with bounded candidate reads. Continue conditionally claiming against the authoritative job record. Include expired leases in a recovery access path.

**Expected impact:** Work scales with eligible candidates instead of all historical jobs and unrelated table items. This concerns dispatch/admission, not the other model's tenant scan-history endpoint.

**Quality and validation:** Preserve admitted-only collector eligibility, ordering/fairness, resume attempts, leases, deadlines, capacity reservations, and duplicate-dispatch safety. Index lag must delay work safely rather than lose it; provide reconciliation. Benchmark idle and busy scheduling with 100,000 terminal jobs, concurrent schedulers, and stale index entries.

### 3. Dispatch audit normalizers by source and operation

**Evidence:** [`rules.py`](../peaso/attack_detection/rules.py), nested `normalize` in `detect_aws_events`, invokes a long list of provider-specific normalizers for each event. The offline call count above demonstrates the fan-out. Sigma candidate rules are already indexed later; that does not avoid this earlier normalization work.

**Change:** Build a conservative registry from exact raw `eventSource`/`eventName` selectors to eligible normalizers. Retain wildcard handlers and multiple handlers where their semantics overlap. Preserve existing output order.

**Expected impact:** Lower CPU per event throughout interactive and historical AWS audit analysis. Savings depend on event distribution and history volume, not the number of selected Sigma rules alone.

**Quality and validation:** Treat dispatch metadata as a superset, never a replacement for normalizer validation. Differentially replay all positive/negative fixtures and randomized malformed records, including missing/non-string fields and multi-output events. Compare ordered detections and evidence exactly.

### 4. Maintain private-evidence indexes incrementally

**Evidence:** [`secret_evidence.py`](../peaso/secret_evidence.py), `Capture.document`, decrypts every retained record and walks every location to reconstruct resource/scope postings, then encrypts the index. [`worker.py`](../peaso/worker.py), checkpoint callback, repeats this before every public checkpoint, and persists the complete private document.

**Change:** Update non-value lookup postings as evidence changes, track a complete private-document revision, and skip rebuilding/writing an unchanged document after confirming its durable predecessor. Keep whole-document persistence initially; a journal would be a separate, more invasive design.

**Expected impact:** Remove repeated decryption/index construction and unchanged encrypted uploads across checkpoints. This changes private evidence persistence, not detector batching or public dependency evaluation.

**Quality and validation:** Every mutation, including aliases, related locations, incomplete flags, and snapshot binding, must change the revision. Preserve private-before-public ordering and serialized handoff. Verify exact decrypted documents, missing-object recovery, late alias changes, concurrent callbacks, and failure retries. Retain no extra plaintext secret values.

### 5. Shorten historical audit database write transactions

**Evidence:** [`attack_history_sqlite.py`](../peaso/storage/attack_history_sqlite.py), `commit_cloudtrail_object`, opens `BEGIN IMMEDIATE`, then reads/validates a manifest and finding chunks from the filesystem while holding the write transaction. This can block unrelated job updates, lease work, and other tenants.

**Change:** Prepare bounded immutable, digest-verified ledger inputs before acquiring the database write lock. Inside the transaction, recheck authoritative references, generation/ownership, deadline, dedup identities, and any required live-integrity fence before committing.

**Expected impact:** Shorter global writer occupancy and lower concurrent API/worker tail latency, even if total parsing CPU is unchanged.

**Quality and validation:** Preparation cannot grant authority. A reference, generation, file-integrity, or lease change must force rejection/revalidation. Test mutations between preparation and commit, conflicting event IDs, process death, and expired leases. Measure write-lock duration and concurrent lease/commit p95, with identical FULL durability.

### 6. Reuse parsed historical manifests after live digest verification

**Evidence:** The same object commit repeatedly calls [`attack_history_ledger.py`](../peaso/storage/attack_history_ledger.py), `get_manifest`. Each access reads/hashes the blob, parses JSON, reserializes it canonically, constructs object records, sorts them for validation, and validates every entry. Manifests may contain 100,000 objects. `DayManifest.contains` is already binary search; replacing that lookup offers little value.

**Change:** Keep a bounded, immutable parsed-manifest representation keyed by tenant/job/reference/digest/schema. Continue securely opening, bounding, and hashing current bytes on every access; reuse parsing/schema validation only after those bytes match the previously validated digest.

**Expected impact:** Avoid repeated JSON decoding, canonical encoding, object allocation, and sorting. Live file reading/hashing remains O(manifest bytes); do not claim this eliminates all repeated I/O or makes the full commit O(log n).

**Quality and validation:** Preserve symlink/type/size checks, corruption detection, tenant binding, and current tamper rejection. Never treat mtime or path identity as proof. Compare malformed manifests, on-disk replacement, same-size corruption, and warm/cold behavior. Budget retained bytes, not merely entry count.

### 7. Index active-job deadlines for expiration

**Evidence:** [`dynamodb.py`](../peaso/storage/dynamodb.py), `expire`, enumerates `_scan('job')`; `_expire_job` then discards terminal and not-yet-due jobs. The scheduler invokes this maintenance path separately from queue admission.

**Change:** Maintain a sparse, sharded deadline access path containing nonterminal jobs. Read only expired candidates and perform the existing authoritative conditional transition.

**Expected impact:** Cleanup reads scale with due active jobs rather than retained scan history. It remains useful independently of queue indexing because expiration has different selection/order and runs across active states.

**Quality and validation:** Preserve queue-exhausted versus timed-out classification, exact attempt fencing, and one-time reservation release. Handle stale index entries, retries, resumed jobs, and index-lag reconciliation. Compare maintenance reads/CPU at realistic terminal-to-active ratios.

### 8. Index enabled schedules by next execution time

**Evidence:** [`dynamodb.py`](../peaso/storage/dynamodb.py), `due_schedules`, scans all schedule records and filters `enabled`/`next_run`. [`worker.py`](../peaso/worker.py), `schedule`, consumes that list.

**Change:** Use a sparse enabled-schedule index with time ordering and bounded due queries; update it atomically with schedule revisions. Keep conditional trigger logic authoritative.

**Expected impact:** Recurring scheduler cost scales with due schedules rather than all tenants' disabled and future schedules. This is a separate persistent workload from queue admission and deadline cleanup.

**Quality and validation:** Preserve timezone/DST calculations, concurrent edits/deletions, disabled identities, and exactly-once schedule advancement. Test delayed index visibility and reconciliation so no schedule is silently missed. Measure reads and tick latency with mostly future/disabled schedules.

### 9. Balance AI batches by complete input size

**Evidence:** [`ai/pipeline.py`](../peaso/ai/pipeline.py), `review_batches.batches`, slices findings into groups of 40 regardless of referenced native-resource size. A bounded shared queue and memory-based concurrency admission already exist.

**Change:** Prepare complete per-finding input sizes, form deterministic batches by bytes or conservatively estimated tokens, and distribute expensive batches to reduce the final straggler. Keep an explicit oversized-single-finding path.

**Expected impact:** Lower context-pressure failures, input serialization peaks, and uneven batch completion times. This changes AI task composition, not collector queues or detector cohorts.

**Quality and validation:** Do not truncate evidence, omit findings, split required cross-finding context, change credential scopes, or silently reduce review coverage. Batch composition can affect model judgments: compare review completeness, attribution, retries, quality evaluation results, and context limits before rollout. Measure full-stage latency and peak concurrent memory.

### 10. Prepare exact AI evidence inputs once per review revision

**Evidence:** `review_fingerprints` calls `review_context`, `findings_document`, and `review_credentials` for every finding. The actual batch execution traverses references and selects access contexts again. Credential selection scans entries and constructs scope/reference sets repeatedly.

**Change:** Use bounded, revision-bound prepared finding references, canonical evidence components, and credential-scope indexes shared by fingerprint construction and actual invocation. Preserve the exact existing per-finding fingerprint byte contract unless deliberately versioned.

**Expected impact:** Lower CPU and allocation in AI orchestration before model invocation, especially with many findings sharing large resources or capture contexts. This is dynamic evidence and authorization-input work, not static finding taxonomy preparation.

**Quality and validation:** Bind provider, native/resource revision, reviewer identity, credential capture/expiry, audience, and access boundary. No plaintext credentials or full evidence in persistent caches. Differentially compare fingerprints, actual reviewer documents, and narrowed credentials, including mutations between checkpoints and expiry.

### 11. Avoid resealing unchanged secret observations

**Evidence:** [`secret_evidence.py`](../peaso/secret_evidence.py), `Capture.remember`, decrypts an existing record, performs list membership and set/sort work, and encrypts it again even when an observation adds no location, detector, or check ID. Frequently repeated secrets grow location lists and make membership checks increasingly expensive.

**Change:** Maintain bounded membership indexes for location/detector/check attribution and return after identity validation when the semantic record is unchanged. Keep encrypted records authoritative; avoid adding a plaintext-value cache. Preserve list order when a new item is added.

**Expected impact:** Less cryptographic and quadratic membership work for duplicated observations across sources/detectors. This complements checkpoint index maintenance but targets collection-time merging, not document publication.

**Quality and validation:** Do not merge distinct values with a colliding fingerprint, lose detector attribution, or alter admission limits silently. The existing byte-accounting path even charges serialization of an empty new-check list; define and test intended accounting before changing it. Stress repeated/no-op and new-location observations, collision checks, aliases, and every configured limit.

### 12. Reuse the complete least-privilege projection within a scan revision

**Evidence:** [`reports.py`](../peaso/storage/reports.py), `_publish_report`, computes `project_least_privilege` from the snapshot. [`ai/pipeline.py`](../peaso/ai/pipeline.py), priorities stage, computes `project` again. [`worker.py`](../peaso/worker.py) can publish native and final reports for the same completed inventory.

**Change:** Prepare the projection once for an exact immutable native snapshot and projection version, then pass it to the publisher and AI priorities input. Recompute when the inventory or any projection dependency changes.

**Expected impact:** Remove repeated whole-inventory least-privilege analysis across phases. This is not extending an individual native join or caching privilege-graph query results.

**Quality and validation:** Keep provider binding, source admission, unknown/missing evidence, and resource attribution exact. Review/AI mutations must not modify the shared projection. Compare complete projection outputs and all consumers with full recomputation for every provider and incomplete snapshots. Measure actual invocations and full native-to-final scan time.

### 13. Reuse HTTP connections across GCP audit pages

**Evidence:** [`server/gcp_attack_logs.py`](../peaso/server/gcp_attack_logs.py), `_request`, uses top-level `requests.request` for project verification and each logging page. That interface creates a short-lived session per call, so this code has no shared page-to-page connection pool. `_entries` can read 20 pages.

**Change:** Own one `requests.Session` for a single source operation and close it afterward. Pass it through project verification and pagination. Preserve existing request headers and explicit response-body closure.

**Expected impact:** Avoid repeated connection/TLS setup during multi-page audit reads. This saves transport setup rather than changing page concurrency or provider pacing.

**Quality and validation:** Keep destination restrictions, redirect refusal, timeouts, response-byte limits, project approval, and continuation semantics. Isolate credentials per operation; never reuse a mutable session across unrelated tenants. Verify identical requests/errors and measure connection count plus real or simulated TLS latency.

### 14. Parse audit input incrementally

**Evidence:** [`server/attack_logs.py`](../peaso/server/attack_logs.py), S3 branch of `analyze_aws_source`, retains compressed bytes, a complete expanded GZIP body, decoded JSON records, and an accumulated event list. Other audit adapters also accumulate their bounded event sets before detection.

**Change:** Stream the audit JSON `Records` array through account validation and normalization, retaining only necessary correlation inputs and bounded output buffers. Start with the historical large-object path where the RAM impact is largest.

**Expected impact:** Fewer simultaneous representations of audit records and lower peak memory. This targets audit-log ingestion, not the other model's TAR/image archive scanner.

**Quality and validation:** Preserve GZIP integrity/trailing-data handling, compressed/expanded/event limits, account isolation, exact truncation flags, and all events needed by correlations. Do not publish detections from an invalid object if the current contract rejects the object atomically. Compare complete detections and coverage under malformed JSON, corrupt trailers, foreign events, and cap boundaries.

### 15. Overlap independent audit-object downloads

**Evidence:** The same S3 audit-source path downloads listed objects in a serial loop, then decompresses/parses each before requesting the next. This is independent of container registry downloads and collector enrichment.

**Change:** Prefetch a small number of immutable object bodies while the consumer parses/detects the previous object. Reserve compressed bytes before submission and consume in the original listed order. Keep parsing/correlation state under one ordered owner initially.

**Expected impact:** Hide object GET latency for multi-object audit reviews without multiplying CPU-heavy parsers.

**Quality and validation:** Preserve exact object selection, total compressed-byte accounting, MAX_EVENTS/MAX_OBJECTS behavior, size-change detection, response closure, and coverage/error attribution. Cancel and drain unused requests at the same boundary as the serial path. Measure whole-source latency, peak queued bytes, and exact detection/coverage parity with slow or failed out-of-order transfers.

### 16. Compile Sigma candidate indexes once per selected rule pack

**Evidence:** [`rules.py`](../peaso/attack_detection/rules.py), `_detect_events`, rebuilds source/name candidate buckets for the selected rules each invocation. AWS calls it for primary events and again for correlated events. Rule YAML parsing is already cached; the candidate execution structure is not reused here.

**Change:** Compile immutable, order-preserving candidate postings once per complete pack content/product/selection semantics version. Reuse that plan across direct and correlated passes, and optionally across operations under a byte budget.

**Expected impact:** Remove repeated rule-plan construction, particularly for many small objects, empty batches, and large rule packs. This is audit rule execution, not CSPM finding query indexing.

**Quality and validation:** Never key only by mutable Rule identity. Preserve wildcard buckets, OR lists, bool-versus-number equality, unsupported-value behavior, raw-versus-derived rules, path prefixes, and selected-rule ordering. Test mutated selections and pack changes. Measure plan-build time and full historical throughput; event matching itself may still dominate.

### 17. Skip unchanged publication component preparation

**Evidence:** Exact-byte artifact reuse occurs after JSON serialization and hashing. [`reports.py`](../peaso/storage/reports.py), `_publish_report`, still prepares finding detail/summary chunks, coverage/resources, projections, and rendered downloads during repeated native/final publications. Fixing item 1 saves duplicate writes but does not by itself remove that preparation work.

**Change:** Carry validated immutable component references forward when their complete publication inputs and renderer/schema versions are unchanged. Initially target native coverage/resources/graphs that an AI-only final update cannot change. Leave changed report/AI/runtime components on the normal path.

**Expected impact:** Eliminate whole unchanged publication tasks rather than only making serialization incremental. This is post-analysis artifact preparation; it does not replace the other model's dependency-based evaluator or streaming serializer.

**Quality and validation:** Bind tenant/scan, exact data revision, metadata/template versions, schema, and content type; no mutable-object-identity shortcuts. Keep source validation, object-existence requirements, and atomic manifests. Compare every decoded component and final download against full publication after targeted dependency mutations and missing-object recovery.

### 18. Poll revisions and invalidate only changed API views

**Evidence:** [`frontend/src/api.ts`](../frontend/src/api.ts), `useApi`, polls enabled queries every four seconds when requested. [`App.tsx`](../frontend/src/App.tsx) continuously polls scan listings and AI availability; publication sequence changes invalidate cached queries containing the selected scan ID. Partial summaries already stop their own polling after completion, and React Query already handles query sharing: neither should be presented as missing.

**Change:** Expose a small authorized revision/status feed or conditional revision response and derive affected-view invalidations from component revisions. Persist revisions with their updates rather than recomputing them by loading the full report. Replace repeated full payload reads when nothing changed; keep foreground checks and a bounded fallback poll.

**Expected impact:** Fewer full responses, artifact reads, and redundant panel refreshes per active dashboard. This reduces demand rather than optimizing storage history pagination or finding search.

**Quality and validation:** Every request still authenticates and checks current workspace ownership. Include review, publication, AI, runtime/progress, and identity configuration changes in the correct revision domains; avoid a global stale-data TTL. Measure backend requests/bytes/artifact reads per idle and active browser session, and verify timely cross-tab/external updates.

### 19. Avoid decoding and reserializing completed local downloads

**Evidence:** [`server/app.py`](../peaso/server/app.py), `report`, already presigns hosted downloads. Local JSON falls through `owned_report`, which loads the full stored report, injects current runtime, and serializes it again. The grouped local path also decodes/reencodes the generated artifact.

**Change:** Design a raw-artifact response path for file storage. Grouped immutable JSON can use its stored representation; ungrouped JSON requires a schema-aware way to add the exact live runtime field without hydrating the entire findings tree. Retain the existing path for legacy formats and stage overlays.

**Expected impact:** Lower local download CPU and memory for very large reports. This is download serving, not streaming report generation/publication.

**Quality and validation:** Simply returning stored bytes is incorrect when runtime or AI overlays differ. Preserve all current parsed JSON fields, filename, authorization, private-data boundaries, and formatting promises. Use an explicit encoding contract without duplicate JSON keys; otherwise fall back. Compare full parsed downloads, including current runtime and partial-stage cases, and benchmark peak RSS plus download latency.

### 20. Batch workspace reference hydration

**Evidence:** [`dynamodb.py`](../peaso/storage/dynamodb.py), `workspaces`, queries references then performs a workspace read and membership read per workspace. `workspace_invitations` also hydrates workspace metadata one reference at a time. Creating workspaces is capped at five per user; memberships in workspaces created by others can add reads. This ranks below whole-scan opportunities because it serves workspace navigation rather than scan execution.

**Change:** Batch the known metadata/member keys with strongly consistent BatchGetItem reads, bounded retries for unprocessed keys, and deterministic result reconstruction. Combine invitation metadata hydration where useful.

**Expected impact:** Reduce sequential network round trips on workspace switching and invitation views. This is a control-plane latency improvement, not a major scan CPU reduction.

**Quality and validation:** Continue reading authoritative membership; a user reference alone grants nothing. Preserve missing/deleted workspace handling, role changes, name sorting, tenant isolation, and failure behavior. Compare request counts, p95 latency, and concurrent membership revocation cases.

## Delivery and measurement order

Start with 1, 2, 3, and 4: they have direct call-path evidence and broad repeated-work mechanisms. For a history-heavy deployment, move 5 and 6 alongside them. Develop the three storage indexes independently because each needs a schema/migration/reconciliation plan; they are three access patterns, not three claimed benchmark wins.

For each implementation, record representative input size, cold/warm state, whole-feature wall time, CPU, peak RSS, external request/byte counts, and exact output/coverage parity. Repeat with concurrency and realistic failure injection. Avoid expanding pools when measurements show CPU or provider limits dominate. The two synthetic observations in this report justify investigation; they do not justify a promised percentage improvement.
