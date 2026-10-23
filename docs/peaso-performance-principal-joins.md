# Ordered identity and workload joins

Principal projection now narrows workload, service-account, impersonation and federation joins with ordered candidate indexes. Every caller rechecks its original relationship predicate. Source order, duplicate input rows, missing facts, conditions, healthy-backend evidence, ingress port matching and group-derived grants remain intact.

Index postings keep a single position directly and dense position arrays for shared keys, with one retained row reference per indexed source row. Broad alias requests coalesce singleton positions before merging. Evidence lists build indexes after eight entries and retain unique buckets inline. Small pod scopes keep their exact selector loop without a separate label index. Admission budgets affect indexing only; exhausted budgets use the complete original evaluation.

Run `python -m examples.benchmark_peaso_principal_workflows --scenario aws --size 500 --memory`. Three interleaved runs execute complete IAM reviews, IAM graph construction and principal/workload projection; federation also evaluates federation findings. A separate traced run measures allocations. The existing-GCP control also builds network findings and topology. Both variants retain prior IAM optimizations and the GCP joins already on main. No cloud collection or native checks run during measurement. All complete output digests match and input snapshots remain unchanged.

| Scenario, size 500 | Wall speedup | CPU speedup | Added peak allocation |
| --- | ---: | ---: | ---: |
| AWS workloads | 3.10x | 2.92x | +80 KiB |
| Azure workloads | 1.08x | 1.14x | +240 KiB |
| ALB workloads | 4.57x | 5.49x | +158 KiB |
| Kubernetes workloads | 8.19x | 8.38x | +184 KiB |
| GCP account scope joins | 1.34x | 1.23x | +43 KiB |
| Existing GCP network control | 0.91x | 0.95x | -79 KiB |
| Azure federation | 1.28x | 2.33x | +148 KiB |
| Kubernetes impersonation | 3.16x | 2.72x | +53 KiB |
| Shared principal evidence | 1.30x | 1.33x | +1415 KiB |

The indexes trade bounded scratch space for fewer repeated scans. These scenarios added about 0.5–4.4% peak allocations for the improved stages; the existing-GCP control used slightly less allocation and showed no speed improvement. Peaks cover one traced stage, not total process RSS. Node, edge, finding, signal and grant-review counts are included in the benchmark output.

Validation passed 395 workflow, storage, malformed-input, capacity, ordering and privilege-projection tests. Of these, 64 focused checks were rerun after the final singleton fast path and passed. The index reference is the original current-main implementation, and all native source-admission files remain unchanged.

After the final single-hit fast path, a larger existing-GCP control (1,500 workloads / 6,000 resources) used 0.832 CPU seconds versus 0.869 for the predecessor (1.04x), with identical 1,500 findings, 7,501 nodes, 6,000 edges and 1,500 principal cards. This confirms that the small 500-workload control variation does not establish a material regression.
