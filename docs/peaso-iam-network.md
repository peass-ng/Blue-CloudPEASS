# Defensive IAM and network snapshot review

`peaso.analysis` builds read-only projections from schema 1.0 immutable native
snapshots. The backend IAM graph is **Declared Access and Trust**, with
conditional risk-review annotations; reports and CLI consumers retain it, while
the console has no dedicated IAM map page. It is not a proven privilege escalation
graph. The Network Map separates native inventory associations from rule
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

**Default trust boundary** (`peaso/analysis/trust.py`): the scanned AWS accounts
(scope prefixes, caller identities, `aws_account`), collected AWS Organizations member
accounts (`organization_account`), scanned GCP projects, and the Azure tenant and
subscriptions are trusted by default. `snapshot.metadata.trusted_scope_ids` (an
explicit string list, or a provider-keyed mapping of lists) and GCP `trusted_domains`
remain *additional* allowlists. An AWS ARN account and GCP service-account email
project establish an affiliation; an Azure object ID alone cannot establish a tenant
(collected `directory_service_principal.appOwnerOrganizationId` and guest users can).
Outcomes are allowlisted, external, public, everyone-authenticated, provider-service,
or unknown.

`analysis.principal_exposure` statuses:

- **FAIL**: a public principal (`*`, `allUsers`, `allAuthenticatedUsers`) without a
  restrictive condition, or any principal outside the trust boundary (evidence lists
  `external_scope_ids`; severity is medium when `sts:ExternalId` is required).
- **MANUAL**: a public principal restricted by a positive condition (aws:SourceVpc,
  SourceVpce, PrincipalOrgID/OrgPaths, SourceAccount/SourceArn, PrincipalAccount/Arn,
  non-/0 SourceIp and similar; `IfExists`, `Not*` and wildcard values do not count),
  a public principal on a VPC-bound policy (VPC endpoint, EFS), or an AWS service
  principal on a resource policy without aws:SourceAccount/SourceArn (confused deputy).
  Service principals in role trust policies and provider service agents are skipped.
- **UNKNOWN**: the principal cannot be attributed to a scope (no scanned account known,
  deleted-principal unique IDs, Azure object IDs without directory facts).

`analysis.federated_trust` reviews web-identity trust: AWS roles trusting GitHub,
GitLab, Terraform Cloud, other OIDC issuers or EKS without a positive `sub` condition,
or with a wildcard that does not pin the owner/tenant (`repo:*`), FAIL (critical for
multi-tenant issuers); Cognito trust without `aud` FAILs and guest (`amr`
unauthenticated) access to a pinned pool is MANUAL. GCP workload identity providers
without `attributeCondition` FAIL for multi-tenant issuers, and Azure federated
credentials with wildcard claim expressions FAIL.

Native public asset/configuration checks remain in the check registry; analysis
enriches them with path evidence. `aws.s3.public_access_block` evaluates the
effective bucket OR account Block Public Access (s3control) and is UNKNOWN when the
bucket setting is incomplete and the account setting was not collected.

## Internet exposure

`analysis.internet_exposure` (`peaso/analysis/internet_exposure.py`) evaluates each
asset with a public address or endpoint from 0.0.0.0/0 and ::/0 with exact per-protocol
port-interval arithmetic:

- AWS: public IPv4/IPv6 on instances and unattached ENIs through route table (active
  default route to an IGW), NACL (ordered, /0 rules) and security groups (union of /0
  rules); internet-facing ALB/NLB/Classic listeners intersected with SGs and NACLs;
  publicly accessible RDS/Redshift; non-VPC OpenSearch; EKS `publicAccessCidrs`;
  Lambda URLs with `AuthType NONE` plus a public `InvokeFunctionUrl` statement; REST
  and HTTP APIs (PRIVATE or disabled execute-api endpoints PASS; method/route auth is
  UNKNOWN until collected); RDS snapshots shared with `all` or external accounts; S3
  buckets public by policy or ACL after effective Block Public Access.
- GCP: instance external IPs through firewall policies and VPC firewall rules
  (priority, deny-before-allow at equal priority, target tags and service accounts,
  implied deny); external forwarding rules through target proxy, URL map and backend
  service Cloud Armor attachment; Cloud Run/Functions ingress plus allUsers or
  allAuthenticatedUsers invokers; Cloud SQL authorized networks; GKE authorized
  networks; buckets with public bindings unless public access prevention is enforced.
- Azure: NIC public IPs (reported on the VM) through subnet and NIC NSGs, which must
  both allow (priority order, defaults, ASG membership; Standard SKU with no NSG is
  closed, Basic is open); public load balancer and inbound NAT rules resolved to the
  backend NIC NSGs; Application Gateway listeners; App Service public network access
  and access restrictions; AKS authorized IP ranges; storage network rules and
  anonymous blob access; SQL firewall 0.0.0.0-255.255.255.255.
- Kubernetes: LoadBalancer services (internal annotations, private addresses,
  `loadBalancerSourceRanges` and the source-range annotation), NodePort services on
  nodes with public ExternalIPs, public `externalIPs`, and Ingress addresses with
  allowlist annotations.

FAIL means the primary filtering layers are collected and admit traffic; secondary
gaps (route, NACL, public IP details) are listed in `unresolved`. PASS means a
collected layer blocks. UNKNOWN means a primary layer (security group, NSG, firewall,
invoker policy, listener, API authorization, sharing attributes) is missing. Evidence
lists `exposed_ports`, `public_addresses`, the per-layer `path`, `unresolved` layers
and `collector_facts_needed`. Stopped instances keep FAIL at one lower severity. A
per-scope UNKNOWN `inventory:internet_exposure` finding lists denied or failed
exposure inventories. The network graph receives one synthetic Internet node and
`internet_exposure` edges (layer `exposure`) to every exposed or unresolved asset,
which carries an `internet_exposed` risk annotation and an `exposure` summary.

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
The UI's Network Map uses these containment hints for native React Flow network
compounds and uses ELK only to place the top-level network groups. It does not
assign a child to an ambiguous `parent_candidates` set. AWS VPC, GCP global/shared
network, Azure VNet, and Kubernetes cluster tabs appear only for collected provider
resources. Subnetworks and subnets can contain interfaces/workloads; namespaces
contain Kubernetes workloads. Collapsed resources and cross-boundary edges disclose
counts. ELK root-edge sections and cross-hierarchy React Flow routes are rendered
by the registered network edge type. The first map uses the bounded 500-node server
projection and no more than 280 rich nodes; network/subnet/resource pages,
aggregate expansion and accumulated inventory paging are explicit. The UI
fetches native resource configuration only after selecting a resource and displays
readable network rule columns, with raw records behind Technical details.

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

Installed-package verification is reproducible with `examples/verify_installed_peaso.py`; see the [engine guide](peaso-engine.md#validation-and-maintenance). It blocks network connections while evaluating bundled fixtures. Saved-snapshot benchmarks are available through `examples/benchmark_peaso_saved_snapshot.py`; keep account data and generated measurements outside Git. These checks establish fixture behavior and local performance, not effective permissions or live reachability.
