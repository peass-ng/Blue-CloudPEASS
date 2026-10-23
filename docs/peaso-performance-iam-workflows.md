# IAM stage reuse

IAM projection now prepares graph identities once for its graph-building phases, shares decoded policies only through immutable views, and reuses a decoded trust document only when its sealed source object still matches. Repeated AWS/Azure action lists share classification profiles within the current analysis context. Profiles retain no resource, condition, grant or access decision and are limited to 1,024 entries and 2 MiB. Unsupported inputs and exhausted admission budgets retain complete evaluation.

GCP and Kubernetes trust boundaries retain a lowercase domain view within the owning context. Normal set mutations invalidate it, including failed and reentrant updates; caller-owned sets and string subclasses keep fresh normalization. No finding, grant, evidence entry, graph edge or risk classification is removed.

Run `python -m examples.benchmark_peaso_iam_workflows --scenario encoded --size 200 --memory`. The reference disables these reuse paths and uses the predecessor graph builder, whose AST was checked against the predecessor implementation. Both variants run complete IAM reviews, graph construction and principal projection. Three interleaved runs compare complete output digests and unchanged input snapshots. A separate traced run measures allocations.

| Scenario | Size | Wall speedup | CPU speedup |
| --- | ---: | ---: | ---: |
| Encoded AWS policies | 200 roles | 1.44x | 1.30x |
| AWS action lists | 500 roles | 1.49x | 1.27x |
| Azure action lists | 500 definitions and assignments | 1.92x | 2.11x |
| GCP shared domain boundary | 500 policies | 1.80x | 1.83x |
| Kubernetes shared domain boundary | 500 bindings | 2.18x | 2.18x |

All output digests matched. The encoded-policy scenario emitted 600 findings, 420 nodes, 4,200 edges and 200 principal cards; peak traced allocations fell from 48,542,968 to 32,348,970 bytes (33%). These synthetic measurements exclude collection, native checks, other analyses and rendering, and allocation peaks are not process RSS.

Focused validation passed 170 tests, including the complete frozen evidence corpus, cache limits and concurrency, mutable and malformed input fallbacks, immutable document ownership, graph folding and deferral, and inventories exceeding the identity-cache capacity. The graph reference retains original ordering and complete evidence, including equal IDs. Native source admission is unchanged; the reviewed presentation bindings cover only the changed IAM and trust helper source files.

The existing IAM and native-formatter regression batch also passed 89 tests. Two legacy demo expectations for retired manual findings were excluded after reproducing their failures with the predecessor algorithm; their behavior is unchanged by this optimization.
