# Exact AI review fingerprint preparation

This extends qualified candidate 10 in the [alternative workflow review](peaso-performance-alternative-validation-20261023.md), using `5af7c210` as the comparison baseline. The overall disposition remains 14 candidates partially or fully qualified, five held and one rejected.

Each finding previously traversed its evidence twice to identify native resource references: once for review context and again for its document. Fingerprint preparation now computes those references once and passes them to both helpers. The helpers still apply their original inventory-key and resource-row-ID intersections, sorting, observation rendering and document construction. The temporary reference set is released before credential selection and hashing. Nothing is retained across calls or revisions.

Credential preparation also returns an empty selection when no entry belongs to the requested provider, after the existing requested-scope shape validation. Traversing AWS native evidence cannot select a credential when that provider has no entry. Supplied-context account/scope/cluster selection and captured/expiry metadata remain unchanged. Model inputs, batch boundaries, coverage, authorization and hashes retain their original behavior.

## Measurements

macOS arm64, CPython 3.13.11. Each of 12 cases fingerprints 1,000 findings against ten native resources, with 200 evidence strings per finding and 200 native strings per resource. All four providers exercise absent, matching and other-provider access contexts. Both implementations are warmed before three alternating CPU/wall trials; traced Python allocation is measured separately. The baseline loads the original fingerprint function and all three original helpers from Git. Every trial compares the complete fingerprint map. No model or cloud calls are made.

| Provider/access context | CPU before → after (ms) | Wall before → after (ms) | CPU reduction |
|---|---:|---:|---:|
| aws/none | 127.1 → 51.4 | 128.0 → 52.3 | 59.6% |
| aws/matching | 133.0 → 113.0 | 133.3 → 113.2 | 15.1% |
| aws/other-provider | 130.4 → 49.1 | 130.6 → 49.1 | 62.4% |
| gcp/none | 81.0 → 64.4 | 84.4 → 66.9 | 20.5% |
| gcp/matching | 77.5 → 58.4 | 78.4 → 58.7 | 24.7% |
| gcp/other-provider | 90.4 → 67.8 | 93.1 → 68.1 | 25.0% |
| azure/none | 99.8 → 54.2 | 106.2 → 54.7 | 45.6% |
| azure/matching | 77.6 → 63.6 | 81.7 → 65.4 | 18.1% |
| azure/other-provider | 78.3 → 57.3 | 78.9 → 57.8 | 26.8% |
| k8s/none | 82.8 → 52.7 | 83.2 → 53.3 | 36.4% |
| k8s/matching | 162.8 → 143.7 | 170.0 → 163.3 | 11.7% |
| k8s/other-provider | 73.5 → 63.1 | 73.7 → 64.0 | 14.2% |

These synthetic workflows show 14–62% lower median CPU and 4–62% lower median wall time. Absolute times and variability are recorded in the [raw measurements](benchmarks/peaso-ai-reference-preparation-20261023.json); this is not a whole-scan or model-latency speedup estimate. Peak traced Python allocation falls only 224 bytes in every case, so peak RAM is essentially unchanged. Traced allocation is not process RSS.

## Validation

The affected AI review, provider, deadline, progressive-analyzer and worker-progress suite passed **310 tests, with two skipped**. A focused fingerprint/source-gate run passed **24 tests**; counts overlap. Twelve golden hashes were generated with the unchanged baseline implementation. Additional cases verify input immutability, fresh references after evidence changes, native resource changes, captured/expiry metadata changes, duplicate findings, mismatched inventory keys/resource IDs, and preserved malformed-scope rejection.

The reviewed SDK closure changes only `peaso/ai/pipeline.py`; its 30 direct SDK client sites and service set are unchanged. No engine source, native admission receipt or observed finding evidence was changed.

Reproduce with the repository environment:

```sh
python -m examples.benchmark_peaso_ai_reference_preparation --baseline 5af7c210 --findings 1000 --fields 200
NO_PROXY='*' python -m pytest -q tests/test_ai_fingerprint_preparation.py tests/test_peaso_ai_review.py tests/test_peaso_ai_deadlines.py tests/test_peaso_ai_providers.py tests/test_progressive_analyzer_20261022.py tests/test_worker_progress_20261022.py tests/test_peaso_api_service_model_gate.py
```
