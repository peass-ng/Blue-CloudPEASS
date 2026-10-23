# Network workflow performance

Topology construction repeatedly traversed the same native resource for network
observations, provider service references and catalog references. The graph now
shares already recorded observations with its reference readers and projects
native network data once per resource. A projection is created lazily and
released as that resource finishes; a second projected inventory is never kept.

A bounded cache classifies repeated schema field names once. It holds at most
4,096 exact string keys of at most 128 characters and retains no native field
values. Long or custom string keys retain the original classifier path.
Credential filtering, URL sanitization, Multus handling and structured network
proofs retain their original predicates and output order.

Topology identities are prepared once and reused across graph phases, avoiding
repeated identity hashing after global-cache eviction. Duplicate native rows
still contribute every original reference. Duplicate node identities use the
original observation readers so an earlier row cannot inherit a later row's
observations. Nodes, edges, evidence paths and input data retain their original
semantics.

Three interleaved runs on Python 3.13.11, 500 workloads per scenario:

| Complete network workflow | Median CPU seconds, before → after | CPU speedup | Median wall seconds, before → after | Peak allocated MB, before → after |
| --- | --- | --- | --- | --- |
| aws | 0.243 → 0.203 | 1.20× | 0.542 → 0.433 | 14.57 → 14.57 |
| azure | 2.321 → 1.906 | 1.22× | 4.869 → 4.605 | 43.53 → 43.48 |
| gcp | 0.302 → 0.161 | 1.88× | 0.697 → 0.387 | 9.96 → 9.89 |
| k8s | 0.158 → 0.135 | 1.17× | 0.313 → 0.320 | 8.41 → 8.41 |
| gcp_native | 0.352 → 0.307 | 1.15× | 0.924 → 0.828 | 14.45 → 14.45 |

Each workflow includes network findings, complete topology, internet annotation
and principal correlation. Previously shipped workload and selector indexes
remain enabled in the reference. Every output digest and input snapshot matched;
all four provider cases exercised real principal cards. The native GCP case
also covers shared networks and firewall rules. These are offline synthetic
inventories; collection, native compliance checks, other analysis families and
report rendering are outside the measurements.

Wall times are noisy on the shared host: the Kubernetes case had effectively
unchanged wall time while consuming less CPU. Separate memory runs use
tracemalloc and do not measure RSS. Whole-stage allocation peaks were essentially
unchanged or slightly lower; per-resource projection reuse bounds temporary
memory rather than eliminating the retained graph itself.

Reproduce:

```sh
python -m examples.benchmark_peaso_network_workflows --scenario gcp --size 500 --memory
python -m examples.benchmark_peaso_network_workflows --scenario azure --size 500 --memory
python -m examples.benchmark_peaso_network_workflows --scenario topology --size 70000
```

Focused regressions cover every provider, duplicate identities, malformed native
values, empty/generator inputs, cache eviction, credential-bearing branches,
exact reference paths and prompt release of projections without requiring cyclic
GC. Broader graph/reachability/catalog validation passed 774 tests with four
skips. Two existing catalog audits failed identically against the unchanged HEAD
constants: unclassified Kubernetes endpoints and a local botocore installation
without the `eventbridgev2` service model.

The 140,000-resource topology control produced identical 140,000 nodes and
70,000 edges: median CPU fell from 14.989 to 9.661 seconds and wall time from
35.799 to 21.051 seconds. Identity hashes fell from 420,000 to 140,000 with the
unchanged production cache capacity. This inventory contains networks and
subnets, so findings and principal-card counts are correctly zero. Three
interleaved runs included complete findings, topology, annotation and principal
projection; output verification streamed canonical JSON outside the timed stage.

Only four reviewed presentation-source identities and their manifest digest are
updated. Native admission, evaluator registration and collection receipts are
unchanged. The original frozen evidence witnesses remain intact. A separate
fixture maintenance change records the already merged documentation-source
corrections: six historical AWS witnesses now fail exact-source matching and six
GCP witnesses match their restored anchors. Prior text and all original inputs
remain recorded, and native/cold comparisons enforce current behavior.
