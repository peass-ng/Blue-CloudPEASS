# Historical and interactive CloudTrail expansion qualification

Follow-up to [the alternative workflow batch](peaso-performance-alternative-validation-20261023.md), baseline `3359a8fb`. Candidate 14 now has a qualified partial implementation: reduce gzip allocation and decoding overhead, preserving the existing full-object JSON parser. The six remaining held candidates are unchanged.

Historical reads requested up to 50,000,001 expanded bytes at once, and interactive previews requested up to 5,000,001. Python's buffered reader could reserve a large output buffer even for a tiny gzip file. The new shared reader uses the standard-library C gzip decoder with an explicit maximum output length for complete single-member objects. It accepts that output only after the decoder reports a validated end of stream and any trailing bytes are exclusively gzip zero padding.

Multiple members, unusual headers and decoder errors use `GzipFile` as the authoritative compatibility path. That path grows buffers in bounded chunks instead of reserving the full ceiling. The first-read size hint is untrusted and clamped; it never establishes the accepted object length. All members and trailers must still be consumed. Speculative buffers are released before compatibility decoding. No partial document or record is emitted.

The JSON parser, supported encodings, duplicate-key behavior, compressed identity/digest checks, expansion limits, record limits, account/region validation, event ordering and body closure remain. This changes neither CloudTrail coverage nor detection rules. Full streaming JSON parsing remains unqualified because replacing the parser would require separate semantic and atomic-rejection evidence.

## Measurements

macOS arm64 / CPython 3.13.11. Median of three complete source-reader CPU/wall trials, with separate tracemalloc trials. Historical transport is an in-memory S3 stub. Preview invokes the source-analysis function with an in-memory session and `rules=[]` to isolate object reading and filtering. No live cloud requests or model calls; these are component measurements, not full-scan or HTTP endpoint latency estimates. Python allocations are not process RSS.

| Replay | CPU before → after | Wall before → after | Peak Python allocation before → after |
|---|---:|---:|---:|
| 10,000 small historical objects, 10 records each | 188 → 125 ms | 188 → 126 ms | 66.85 MB → 54 KB |
| 1,000 medium historical objects, 1,000 records each | 812 → 792 ms | 814 → 794 ms | 67.53 MB → 2.54 MB |
| 10 large historical objects, 20,000 records each | 202 → 184 ms | 205 → 184 ms | 80.54 MB → 43.25 MB |
| Interactive preview, 100 records | 0.269 → 0.211 ms | 0.270 → 0.212 ms | 10.05 MB → 55 KB |

All complete returned results matched the original. Medium-object CPU savings are modest; memory reduction is the principal benefit there. A chunk-only prototype had inconsistent CPU savings, so it was replaced by bounded C decoding for the ordinary single-member case. Compatibility fallback may repeat decoding of the first member; no CPU improvement is claimed for malformed or multi-member objects. Those inputs retain their previous acceptance and error behavior.

[Raw measurements](benchmarks/peaso-history-expansion-20261023.json) record exact results. The benchmark also compares success payloads and exact failure outcomes against the original reader across **756 cases**, including malformed deflate streams and truncated second members.

## Verification

- **119 history/API tests passed**, covering durable history ingestion, checkpoint storage, preview coverage and error codes, exact expansion limits, chunk boundaries, UTF-8/16/32, duplicate keys, multiple gzip members, zero padding, invalid CRC/ISIZE, truncated input, invalid JSON tails and body closure.
- **9 SDK source-gate tests passed** after reviewing the two changed callers and new standard-library-only helper. The 30 existing SDK client sites and service set are unchanged; the credential session factory is untouched.
- **1 native admission smoke test passed**. No native source epoch, admission receipt or frozen fixture was repinned.

Reproduce with the repository environment:

```sh
python -m examples.benchmark_peaso_history_expansion --baseline 3359a8fb
python -m pytest -q tests/test_attack_history_expansion.py tests/test_attack_detection_history_s3.py tests/test_attack_history_worker_s3.py tests/test_attack_history_ledger.py tests/test_attack_history_sqlite.py tests/test_attack_log_source.py tests/test_peaso_api_service_model_gate.py
```

The benchmark requires Git access to the baseline commit. Changes to the malformed-input corpus can be qualified independently using its `qualification` function; they do not change production parsing.
