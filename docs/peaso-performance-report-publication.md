# Report publication performance

Hosted report publication previously serialized finding rows for oversized-detail
decisions, serialized them again for chunk sizing, then serialized the assembled
chunk for storage. It also waited for each S3 PUT before preparing the next
independent artifact.

The hosted publisher now encodes each ordinary finding once and reuses those
bytes in its chunk. Coverage and native-resource chunks use the same path.
The 250-row and 2 MiB boundaries, UTF-8 JSON bytes, oversized-detail routing,
hydration, summaries, and stored artifact contents remain unchanged. The legacy
ASCII-escaped size rule still decides whether a finding needs a separate detail
artifact, including large Unicode evidence.

S3 publication overlaps at most four uploads. The producer queues only immutable
bytes, with at most eight pending uploads and 16 MiB of pending uncompressed
bodies. An artifact larger than that budget first drains pending work and then
uploads synchronously. Compression adds temporary worker allocations beyond the
pending-body budget. Local and custom stores retain synchronous publication.

Every dependency must finish successfully before the manifest is uploaded.
Upload failures propagate to the caller and prevent manifest publication, even
if an earlier flush exception was caught inside the batch. All workers are
joined on success or failure. Existing tenant/reference validation, gzip policy,
encryption, private-secret references and download restrictions still apply.

Reproduce the complete publisher comparison with:

```sh
python -m examples.benchmark_peaso_report_publication --findings 10000 --latency-ms 20 --memory
python -m examples.benchmark_peaso_report_publication --findings 10000 --latency-ms 0 --compact --memory
```

The reference publisher preserves the predecessor's complete function bodies.
Both paths run the actual sanitization, review application, grouping, Markdown
generation, optional native expansion, indexes, compression, and manifest
publication. Native catalog initialization and fixture preparation are outside
the timing, as publication follows scan evaluation. Artifact content digests
normalize generated references only, and the benchmark checks input immutability,
KMS requests and manifest ordering. S3 latency is simulated; this is not a live
cloud benchmark. Optional allocation peaks include the simulated object store
and are not process RSS.

Measured on Python 3.13.11 with three interleaved runs per variant:

| Complete publication | Median wall seconds, before → after | Median CPU seconds, before → after | Peak allocated MB, before → after |
| --- | --- | --- | --- |
| 10,000 findings, zero PUT delay | 1.410 → 1.156 | 0.800 → 0.688 | 70.00 → 70.01 |
| 10,000 findings, 20 ms per PUT | 4.993 → 1.655 | 0.837 → 0.712 | 70.00 → 70.01 |
| 2,000 findings, compact native report, 20 ms per PUT | 1.558 → 0.588 | 0.342 → 0.324 | 23.85 → 23.86 |

All cases produced identical complete artifact content digests, object counts
and unchanged inputs. The 10,000-finding cases wrote 129 artifacts; the compact
case wrote 43. The memory difference was approximately 8 KiB, rather than a
meaningful reduction in whole-publisher allocation peak. A 1,000-finding,
zero-latency control had effectively unchanged wall time (0.173 → 0.172 seconds)
and about 6 ms more CPU (0.089 → 0.095 seconds). Thread setup has a small fixed
cost; the measured gains come from large reports and hosted I/O. Host contention
also makes wall measurements noisier than process CPU measurements.

Focused tests cover exact chunk bytes and boundaries, large Unicode details,
nonfinite JSON rejection, bounded backpressure, mutable producer input, actual
overlap, failed uploads, worker cleanup, tenant boundaries, private-secret
references and the synchronous backend fallback.
Complete-publisher parity tests also include compact/native reports, Unicode
detail placement, AI artifacts and private-value canaries across every output.
