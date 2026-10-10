# Defensive IAM and network snapshot review

`peaso.analysis` builds read-only projections from schema 1.0 immutable native
snapshots. The implemented IAM map is **Declared Access and Trust**, with
conditional risk-review annotations. It is not a proven privilege escalation
graph. The network map separates native inventory associations from rule
candidates, and does not infer routed connectivity or telemetry-confirmed reachability.

## Public contract

```python
from peaso.analysis import analyze, analyze_findings, build_graphs, filter_graph, project_graph

result = analyze(snapshot, categories=["least_privilege", "exposure", "iam_graph", "network"])
findings = analyze_findings(snapshot, resources, index=None)
graphs = build_graphs(snapshot, resources, index=None, max_nodes=500)
review = filter_graph(graphs["iam"], risk="high_risk_grant")
overview = project_graph(graphs["network"], max_nodes=100)
```

`analyze` validates the snapshot digest and returns findings, graphs, and normalized
resource envelopes. The engine passes its already validated resources into the
other functions. `ANALYSIS_CHECKS` exports public selection metadata;
`REQUIRED_TYPES` supplies collection-planning requirements by provider/category.
No analysis code invokes provider APIs, writes cloud configuration, generates an
Access Analyzer, or retrieves secret values. Existing bundled standalone
permission criticality is reused after an on-disk guard prevents its network
fallback. Permission combinations and technique prerequisites are not evaluated.

`analysis_context(snapshot)` can wrap findings and graph construction together
to reuse scan-local grants/usage and indexed collection provenance. ContextVar
isolation prevents cross-scan reuse of facts and bounded permission classifications
are keyed by provider, permission, and the bundled rulepack SHA256. The shared
classifier's bundled-path resolver supports repository or installed data;
the rule file is guarded before the classifier can load it, so missing packaged
data yields unknown criticality instead of a remote fetch. Rulepack files are
immutable for a running process; updating deployed data requires a process restart.

Finding IDs remain stable across snapshot timestamps for the same provider,
scope, native resource, category, and check. Each security result maps to
**HackTricks Cloud Best Practices**. Analysis does not assert a blanket NIST
mapping or certification. Recommendations require owner review, business need,
conditions, usage coverage, impact assessment, and rollback before access changes.
Findings are ranked by severity and emitted as `MANUAL` or `UNKNOWN`.

## Native evidence and uncertainty

| Provider | Supported declared facts | Required unresolved context |
| --- | --- | --- |
| AWS | User/group membership, inline and managed policy sources/default-version documents, role trust, standalone grant criticality, VPC/subnet/interfaces/security-group/routes/peering/LB references | Deny precedence, permissions boundaries/SCPs, resource restrictions, conditions, federation, NACLs and routing |
| GCP | IAM bindings/conditions, collected role permissions, service-account references, global/shared host-project networks, subnet/interface/firewall/LB references | Inheritance and denied role visibility, deny and principal access boundaries, group expansion, hierarchical firewall priority/target semantics |
| Azure | Native role assignments/definitions, directory identities/membership, declared authorization scope, action/data-action exclusions, VNet/subnet/NIC/VM/NSG/LB references | Tenant affiliation when unknown, management-group and directory visibility, deny assignments, activation/conditions, combined NIC/subnet enforcement |
| Kubernetes | Roles/cluster roles/bindings/subjects, API-group/resource/subresource/verb/name constraints, workload identities, namespace containment, service/policy selector declarations | Aggregated role expansion, admission, authentication, CNI enforcement, selector matching, retained audit visibility |

Source evidence preserves snapshot ID, native ID, resource type, collection scope
and status, native field path, and available request/provenance references.
Role/policy/principal cards retain raw grants/trust, restrictions, usage
observations, direct referenced-grant evidence, and `effective_access: unknown`.
AWS Deny statements remain visible but are excluded from allow-grant risk
findings. Azure `notActions`/`notDataActions` remain exclusions, not modeled denies.
Kubernetes resource names and GCP/Azure conditions are retained without guessing
runtime evaluation. Missing, denied, partial, or malformed facts produce unknown
context rather than an assertion of safe access. Malformed facts retain a node
and explicitly partial graph status when relationship projection cannot finish.

Usage cards preserve the provided last-used observations, observation window,
completeness, and provider observation context. A missing last-used date does not
prove inactivity. The inactive-identity filter applies only to a supplied explicit
zero-activity observation and means **no activity observed in that window**.
`safe_to_remove` is always false. Audit retention, data-event logging, federation,
region boundaries, and telemetry outside the window can all invalidate an unused
access conclusion; no automated permission-removal recommendation is produced.

`snapshot.metadata.trusted_scope_ids` is an explicit string list, or a provider-keyed
mapping of lists: AWS account IDs, GCP project IDs, Azure tenant IDs. GCP may also
use explicit `trusted_domains`. No default scope becomes a trust allowlist.
An AWS ARN account and GCP service-account email project may establish an affiliation;
an Azure object ID alone cannot establish a tenant. Outcomes are allowlisted,
external, public, everyone-authenticated, or unknown. Provider wildcard subjects
are represented by an explicit everyone entity. Allow declarations with public
or external principals remain conditional because denies and controls may restrict
effective access. Native public asset/configuration checks remain in the check
registry; analysis enriches public-principal and network-rule review evidence.

## Graph semantics and display

Nodes retain globally distinct provider/scope/native-kind/native-ID identities and
link back to the engine resource ID. Observed relationship edges include membership,
policy attachment, role definition/binding, trust, workload identity, and native
resource associations. Risk annotations distinguish `observed`, `derived`,
`conditional`, and `unknown`. A direct attachment or membership can derive a
review marker from a high-impact declaration; it does not prove inherited effective
access or a usable chain. Query filters are `high_risk_grant`, `external_trust`, and
`inactive_identity`, plus scope/type/text. Adjacent context is returned explicitly.
There is no chain search, technique-to-permission/exact-target catalog, or
shortest-path claim of exploitability.

Network nodes expose `native_kind`, `provider_specific`, `display_group`, and
observed `parent_id`/`parent_edge_refs` layout hints. Ambiguous containment retains
`parent_candidates`; it never silently chooses one. Parent hints prefer subnet
over VPC when both are declared, preserving individual VPC/VNet/global-network
roots. GCP selfLinks retain global scope and shared host-project identities;
external host projects remain reference-only unless collected. A Kubernetes
namespace is an administrative containment group, never a subnet. Workload
selector nodes retain native selectors and explicitly do not expand matching
workloads. Peering and routes establish structural relationships, not containment
or reachability. Scope IDs preserve cross-account/cross-project separation even
where native names and address ranges overlap.

Edges use `layer: structural` for native associations and `layer: modeled_rule`
for unrestricted-source rule candidates, with evidence and uncertainty in the
inspector. AWS IPv4/IPv6 ingress ranges, GCP direction/disabled/source selectors,
Azure inbound Allow/Internet and native priority, and Kubernetes additive ingress
rules/IP-block exceptions retain their own semantics. An empty Kubernetes ingress
list admits no ingress through that policy; an empty ingress rule permits all
sources at the policy layer. Neither implies Internet reachability. Firewall
denies, priorities, target selectors, resource attachments, routes, CNI behavior,
and public addressing are not resolved into end-to-end connectivity. Telemetry
is explicitly separate and is not synthesized from inventory.

Projection is linear over observed nodes/edges; no all-pairs reachability is
computed. Over the node budget, IAM groups by provider/scope/native type;
network roots remain individually distinct while descendants group by parent and
native type. Aggregate nodes/edges retain original `underlying_count`, `node_refs`,
`resource_refs`, and `edge_refs`. Edge evidence samples at most 20 underlying facts
and discloses sampling. Rebuild the same immutable graph with `max_nodes` at least
the original `projection.node_count`, then resolve expansion references. The
budget is soft when the number of distinct root/scope/type groups itself exceeds
it; projection discloses that condition. Report consumers can keep the full graph
and ask for a separate overview for rendering.

## Risk catalog and validation

`peaso/risk_catalog/reviews.yaml` contains four original high-level provider review
themes and an explicit unsupported list. All four themes are `manual-review`;
their presence is not exhaustive control coverage. It pins the HackTricks
repository revision already recorded in `risk_rules/hacktricks-source.json`.
Descriptions are original authored text under the repository AGPL-3.0-only
license. Upstream source licensing is **unverified** and is disclosed separately;
this catalog imports no upstream prose or new recipe data and does not relicense
existing bundled material.

The validator checks exact allowed schema fields, required provider/coverage/
missing-context/mitigation disclosures, pinned source references, source revision
and repository against the existing lockfile, and SHA256 integrity of all four
bundled canonical rule files. It validates license disclosure and rejects a
verified-source-license claim without an artifact supported by the schema; it
does not resolve legal terms or guarantee source accuracy. Undeclared extra fields,
including action/target recipe fields, fail validation.

## Verification and limits

```sh
python -m pytest -q tests/test_peaso_analysis.py tests/test_peaso_engine.py
python scripts/peaso_validate_risk_catalog.py
```

The analysis suite covers all four native provider fixture shapes and engine
integration from sealed snapshots; source/usage gaps, deny/boundary/condition
preservation, public IPv6 and allow/deny/disabled native semantics, unknown tenant
affiliation, explicit allowlists, shared global GCP host networks, namespace and
same-name RBAC separation, overlapping resource IDs/address ranges, three distinct
VPC roots, malformed input, stable comparison IDs, and a 1,500-member group with
collapsed counts/evidence references. Network access during snapshot evaluation
is forbidden by the integration fixture. No live cloud account, live telemetry,
effective-access calculation, or routed reachability claim was validated by these
tests. Imported production snapshots use the identical engine contract, subject
to the collection and context limits above.

A saved QA Azure snapshot with 4,912 resources was also evaluated offline for
performance verification. After adding scan-local derivation/provenance caches
and bounded standalone-criticality caching, canonical findings and raw graph
output were exactly equal to the pre-optimization output: 3,657 findings,
including 64 `UNKNOWN` findings. Measured optimized runs took 6.739 seconds cold
and 1.075 seconds warm, including equality checking on this machine; the original
profiled analysis took 20.118 seconds with cProfile overhead, so that figure is
not a direct timing comparison. This is saved-snapshot integration evidence,
not new live-cloud collection or an effective-access validation.
