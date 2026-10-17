# PEASO quality review: unfinished release work

Updated 2026-10-10 at 20:47 UTC. This is an evidence-based work list,
not a declaration that the platform is ready. No cloud resources were created
for this review.

## Supported coverage and remaining work

`scripts/peaso_catalog_audit.py` captures the materialized catalogs, records their
SHA256 digests, checks for edits during the capture, and distinguishes source
references, automated predicates, manual requirements and invalid predicates.
It does not import an upstream scanner or execute an evaluator.

| Provider | Unique native predicates | Ported references | Merged references | Rejected/manual references | Pending references |
| --- | ---: | ---: | ---: | ---: | ---: |
| AWS | 502 | 585 | 130 | 271 | 1,350 |
| Azure | 482 | 519 | 336 | 539 | 468 |
| GCP | 287 | 376 | 118 | 165 | 105 |
| Kubernetes | 886 | 690 | 58 | 134 | 0 |
| Total | 2,157 | 2,170 | 642 | 1,109 | 1,923 |

The 561 references for other providers are out of scope. The 1,109 rejected
references consist of **527 manual requirements** and **582 reviewed invalid
predicates**. Manual requirements remain available for human attestation and
are not represented as automated checks. Review reasons are preserved; this
metadata audit does not independently establish the correctness of every reason.

Of 160 materialized frameworks for the four target providers, **138 still have
pending source references**. Consequently comprehensive framework coverage is
not established. At the earlier 20:43 capture, runtime registration matched all
1,940 then-materialized native IDs. The lead's subsequent focused gate reports
2,157 native bindings; the capture at 20:47 verifies their materialized mappings.

The earlier 20:43 audit found five stale fields in `catalog_summary.json`: predicate count,
disposition counts, supported references, manual requirements and invalid
predicates. The runtime metadata matches the captured manifest. The registry
owner has since regenerated the catalogs. The **20:47 capture is stable and
has zero catalog-consistency issues**, including all framework/control/version
mappings. A stale summary must not be used as the release coverage figure.

```sh
.venv/bin/python scripts/peaso_catalog_audit.py --require-complete
```

This command currently exits with failure because coverage is incomplete.
It catches duplicate identifiers, missing
native predicates, cross-provider mappings, dropped framework IDs, unsupported
provider dispositions, undeclared collection inputs, cloud calls during ordinary
evaluation, stale framework counts, missing manual requirements, compressed
manifest divergence and concurrent catalog edits. Twelve tests exercise these
gates, including lost control versions and a consistent-but-incomplete catalog.

## Current test evidence

| Scope | Result |
| --- | --- |
| All `test_peaso_checks*.py` and `test_peaso_collectors*.py`, after latest regeneration | 19,559 passed, 8 failed; 64.26 seconds |
| Catalog consistency audit | 12 passed; 0.16 seconds |
| Explicit native configuration API pipeline, all four providers | 4 passed; 20.15 seconds |

The broad native gate above was repeated after the newest catalog regeneration;
the earlier run was 17,918 passed and eight failed. The lead independently
reports a focused source/batch/reference gate of **10,894 passed in 25.31 seconds**.

The native API acceptance uses `hardening` and `network` selectors. It runs both
worker stages, verifies JSON and Markdown publication, retrieves network graphs,
and checks that another tenant cannot access the scan, report or graph. It does
not establish success of default selections, live hosted jobs or every category.

The eight native suite failures are:

- Three `test_peaso_checks_aws_b_customer_policy.py` tests. New collector
  operations are not yet in the reviewed action list; the policy generator
  fails closed. `LookupEvents` itself is already handled correctly. The current
  first missing mapping is `accessanalyzer:ListAnalyzers`.
- Four `test_shared_new_paas_collection_is_authoritative_and_read_only` cases
  in `test_peaso_checks_azure_ports_paas.py`. Registry collection makes four
  requests, and Cosmos, Databricks and Kusto make three, against fixtures that
  expect two. Diagnostic collection and registry detail hydration are real reads.
- `test_azure_graph_pagination_then_arm_details_cross_subscription` in
  `test_peaso_collectors_azurek8s.py`: eight requests versus six expected.

The AWS policy review also needs Account alternate contacts, EC2 flow logs,
default EBS encryption, image/snapshot public-access blocking, instance metadata
defaults and Organizations description mappings. This is a static policy change;
do not grant wildcard permissions or modify live IAM merely to make tests pass.
`sts:AssumeRole` is an authentication operation and is intentionally not a grant
in the metadata collection policy.

The separate 48 reachability failures previously reproduced all attempted to
mutate sealed fixtures before evaluation. Correct the fixture construction,
retain snapshot immutability and reseal each modified variant. The two default
API e2e failures still need a fresh supervisor-owned run and sanitized underlying
exception. This native subset is not the complete repository gate, and no new
checkpoint commit is authorized by these results alone.

## Measured map limits

The new reproduction uses ordinary structural display graphs, with no cloud
calls or IAM technique evaluator:

```sh
.venv/bin/python examples/benchmark_peaso_display.py --size 10000
```

| Synthetic fixture | Input | Returned display nodes | Requested rendered budget | Finding |
| --- | --- | ---: | ---: | --- |
| Flat principals | 10,000 nodes | 500 | 500 | Within budget |
| Separate networks | 5,000 VPC nodes | 5,000 | 500 | Preserved containers exceed the budget |
| Hub page | 10,001 nodes / 10,000 edges | 10,001 | 500 | Boundary stubs are created for edges later truncated |

The hub page limits edges to 1,000 but still returns all 10,001 nodes. CPU
projection is fast on these fixtures, but that does not establish browser layout
or rendering performance. Rich-node and edge limits must include containers,
context nodes and boundary stubs, with explicit counts and drill-down references
for omitted detail. Truncation must never hide the fact that additional evidence
or connections exist.

Graph fixes need fixtures for many network roots, one high-degree hub, deep
containment, overlapping CIDRs, cross-scope links and scope/risk filters. Validate
node/edge conservation or explicit truncation metadata, endpoint integrity and
input immutability. Keep all underlying relationships in the stored full graph.
The network worker and supervisor performance owner must coordinate ownership
before editing shared projection code.

## Evaluation throughput and report size

The existing guarded RDS benchmark was independently repeated:

```sh
.venv/bin/python examples/benchmark_peaso_aws_b.py --resources 50000
```

It evaluated 50,000 independent encryption booleans in **1.526936 seconds**
(32,745 findings/second), preserved exactly 25,000 PASS and 25,000 FAIL, made no
SDK import or network connection attempts, and left the input snapshot unchanged.
The JSON report is **87,093,644 bytes**. This measures one native predicate,
not all rules, fresh collection, report rendering or browser performance.

Further optimization should measure repeated per-finding rule metadata and
framework/remediation strings, shared fact normalization, collection request
deduplication and scoped lookup indexes. Preserve all result counts, evidence,
unknown states and report compatibility before accepting a faster representation.
Collection, evaluation, serialization and browser rendering require separate
benchmarks. No claim that the engine is universally as fast as possible is made.

## Outstanding owners and coordination

The existing Orca run is `run_405fd85cc6f5`. Runtime status remains disconnected;
`orca computer capabilities --json` returned `runtime_unavailable` with
`Could not connect to the running Orca app. Restart Orca and try again.`
No worker is stopped, duplicated or treated as complete on this evidence.

| Work | Existing intended owner |
| --- | --- |
| Source review completion, summary consistency and all framework/control mappings | `ctx_b7fd18004ec0` |
| AWS-A review and collector evidence | `ctx_f2b5ca158b85` |
| AWS-B review, verified customer policy, native performance and reports | `ctx_741938b42211` |
| Azure review, facts, request coalescing and five failing fixtures | `ctx_924afa35a1d8` |
| GCP/K8s review, metadata and cloud joins | `ctx_b9797ff7c175` |
| Reachability fixtures and network regression review | `ctx_94110af67a35` |
| Live GCP/GKE acceptance | `ctx_d12c7cfe9bea` |
| Shared graph projection performance changes | Supervisor performance owner, coordinated with network owner |

New follow-ups cannot be claimed delivered until the runtime reconnects.
The supplied privilege-escalation code remains supervisor-owned and unchanged;
this review has not established exhaustive YAML coverage or evaluator correctness.

## Cloud cleanup and release state

The GKE acceptance failed with zero usable Kubernetes inventory (HTTP 412), so
successful GKE scanning and the cross-cloud join remain open. At 20:29 UTC its
private ledger verified deletion of the cluster, VPC, subnet and both service
accounts. It also verified removal of the exact temporary project IAM membership,
both generated firewall rules, the node, disk, instance group/manager and routes.
The private kubeconfig was deleted and the user's default kubeconfig was unchanged.

The hosted platform has not passed deployment acceptance. The release needs:

1. No pending source references and complete, consistent materialized catalogs.
2. Reviewed pass/fail/unknown/denied/applicability behavior and collector evidence
   for each supported predicate; manual requirements kept explicit.
3. A fresh fully green repository suite from the supervisor, plus default API,
   CLI, Compose and hosted authentication/quota/scan acceptance.
4. Bounded network/IAM views and reproducible collection/evaluation/report/UI
   scale measurements without lost checks or relationships.
5. Live provider coverage and teardown evidence, including successful GKE
   acceptance, plus the actual authorized hosted deployment.

Zero false positives across every configuration of every cloud, detection of
every exposure and perpetual exhaustive service coverage are not verified or
promised. Missing evidence must remain visible as uncertainty, with regression
fixtures for every identified counterexample.

An independent offline negative-evidence probe evaluated all **2,157 native
predicates** against both an empty object and a denied object (**4,314
evaluations**). Every result was UNKNOWN or DENIED; there were no PASS/FAIL
results and no network attempts. This validates that baseline, without proving
all richer malformed inputs, applicability branches or cross-resource joins.
