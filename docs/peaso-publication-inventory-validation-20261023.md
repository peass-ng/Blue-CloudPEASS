# Reuse native inventory preparation within report publication

Follow-up to [the alternative workflow qualifications](peaso-performance-alternative-validation-20261023.md), baseline `6b997cdc`. Candidate 17 now has a qualified partial implementation: resource downloads and least-privilege projection share one freshly built native inventory during the same publication. Five candidates remain held; one prototype was rejected earlier.

`resources(snapshot)` computes native identities, sorts and deduplicates resources, and freezes their complete native data. Publication previously did this independently for resource chunks and least-privilege projection. It now prepares the full inventory once, gives resource chunks their existing filtered view, and passes the complete inventory to the unchanged projection. The temporary list is released before later graph/network projections. Nothing survives to another publication or snapshot revision, and no evaluator, authorization, deadline, storage or manifest barrier is skipped.

Markdown expansion still prepares its own inventory through the original engine. An experiment to share that third preparation changed an authenticated engine file and was rejected by source admission. That experiment was reverted completely; no engine source, native admission receipts or frozen fixtures were changed in the shipped implementation. Reusing complete projections across phases or publications still needs independent immutable-input and runtime qualification.

## Measurements

macOS arm64, CPython 3.13.11. A native AWS snapshot contains 2,000 buckets, each with 40 nested synthetic native fields. The real evaluator produces a compact report before timing. Each comparison publishes the entire report using actual sanitization, grouping, Markdown expansion, resource chunks, least-privilege projection, graph/network artifacts and manifest publication.

Three alternating before/after trials measure CPU and wall time; separate trials measure traced Python allocation. Local storage uses `FileArtifacts`; hosted-codec storage uses `S3Artifacts`, its bounded batch, encryption/compression options and a local file-backed object transport. No artificial PUT latency or cloud calls are involved. The baseline loads the original publisher and original resource-chunk helper from Git. Native catalog initialization and input construction are outside timing. All trial values are retained in the [raw results](benchmarks/peaso-publication-inventory-20261023.json).

| Complete publication | CPU before → after | Wall before → after | Peak Python allocation before → after |
|---|---:|---:|---:|
| Local durable artifacts | 895 → 713 ms | 931 → 774 ms | 95.587 → 95.585 MB |
| Hosted codec, local transport | 909 → 710 ms | 877 → 675 ms | 95.591 → 95.596 MB |

CPU falls about 20–22% and elapsed time about 17–23% in this declared inventory-heavy replay. Peak allocation is essentially unchanged; the hosted difference is about 5 KB (0.006%), so this is not claimed as a peak-RAM reduction. Avoided freezing reduces repeated allocation work, but other publication stages determine the measured peak. These measurements are not process RSS or whole-scan/cloud speedup estimates.

All eight complete-bundle hashes per backend match across baseline/optimized timing and allocation trials. Recursive comparison includes JSON, exact Markdown and native artifacts, normalizing generated reference names only. Both input snapshot and report remain unchanged.

## Validation

- The report/least-privilege regression run passed **77 tests**. Three engine cross-process reproducibility tests hit their existing 30-second subprocess timeout (Azure, GCP, Kubernetes).
- An untouched baseline checkout reproduced those **same three timeouts**, with two other reproducibility tests passing. These failures do not execute report publication.
- **11 follow-up inventory/source-gate tests passed**. They check a single publication-owned preparation, complete least-privilege context despite filtered resource downloads, untouched inputs, and fresh native data in a later publication. The nonempty hidden-role projection prevents the filtering assertion from being vacuous.
- The SDK source closure review changes only `reports.py`; its 30 SDK client sites and service set are unchanged. Standard artifact adapters and custom callers that omit the private prepared-inventory argument retain the previous resource-chunk behavior.

After rebasing onto `77956d65`, preserving concurrent IAM usage collectors and worker finalization, **64 integration cases passed**. A fresh **9-case SDK gate run passed** after clearing stale local bytecode from rapid gate regeneration; the source pin itself matched the manifest. These counts overlap. The only production-runtime difference from that main revision is `reports.py`.

A subsequent rebase preserved `d6bb3dfb` (sealed IAM policy-view reuse). All **59 publication, report-expansion, policy-cache and SDK-gate tests passed** on that combined tree. The engine and IAM implementation from main were retained unchanged.

Reproduce with the repository environment:

```sh
python -m examples.benchmark_peaso_publication_inventory --baseline 6b997cdc --resources 2000 --fields 40
python -m pytest -q tests/test_publication_inventory.py tests/test_peaso_report_dedupe_frameworks.py tests/test_report_artifact_reuse.py tests/test_report_artifact_batch_reuse.py tests/test_peaso_least_privilege.py tests/test_least_privilege_permissions.py tests/test_peaso_api_service_model_gate.py
```
