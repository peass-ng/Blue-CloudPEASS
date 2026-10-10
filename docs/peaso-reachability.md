# Selected configuration reachability

The Network Map can answer one selected **configuration** question from an
immutable snapshot. `allowed` means the supported collected routing and policy
model admits the specified new flow; it does not prove an application is
listening, an endpoint is operating, a packet was delivered, or a live connection
exists. `blocked` requires a decisive applicable control or selected route;
`unknown` preserves missing facts and unsupported transformations. No evaluator
invokes cloud SDKs, sockets, subprocesses, network probes, or privileged writes.
No all-pairs computation, exploitation, or privilege-chain discovery is present.

## Contract

```python
from peaso.analysis import evaluate_reachability, network_snapshot

network_facts = network_snapshot(snapshot)
decision = evaluate_reachability(
    network_facts,
    source_resource_id=source_id,
    destination_resource_id=destination_id,
    protocol="tcp",
    destination_port=443,
    source_port=54321,
    address_family="ipv4",
)
```

Both IDs are normalized inventory `resource.id` values, not graph node IDs or
unqualified native names. The supported protocols are `tcp` and `udp`, with
integer destination/source ports from 1 through 65535 and `ipv4` or `ipv6`.
Source port is optional; a constrained stateless return rule or initial Azure
source-port selector can require it. The evaluator does not guess an operating
system's ephemeral port range. Invalid query values or an invalid snapshot
digest raise `ValueError`; missing endpoints and malformed native facts yield
explainable `unknown` states.

The result includes:

- `decision`, `provider`, `query`, and the selected private `endpoints`;
- `snapshot_id` identifying the original source, and `scoped_snapshot_id`
  identifying the verified derived network artifact;
- `routes`, `policy_decisions`, `translations`, `unresolved_dependencies`,
  `evidence_refs`, and `context_evidence`;
- `modeled_configuration: true`, `new_flow_only: true`, and
  `application_listening: unknown`.

Evidence names the bound source/artifact digests, global and native resource IDs,
scope, native field path, and collection status. Context evidence separately
records the evaluated metadata context path and its supplied source references.
Policy steps can contain a `candidate_decision` when a missing higher layer or
address transformation prevents that local rule from deciding the whole flow.
The overall decision is authoritative for this model; an inspector must show
the gaps alongside any candidate rule decision.

`REACHABILITY_TYPES` declares dependency inventories by provider and is included
in the network collection planner. `network_snapshot` validates and seals a
derived artifact containing entire native dependency collections with their
original statuses. It removes unrelated IAM/credential inventory and preserves
network context, identity-of-scope metadata, and the source snapshot reference.
It never trims individual routes, rules, or associations from a collection marked
complete. Original snapshots need not be read for each API query.

The tenant-authorized API owns `/api/scans/{id}/reachability` and scan lookup.
Its persisted source binding must match the scan's report snapshot ID; imported
`metadata.original_snapshot_id` is a provenance label, never authorization.
The dialog submits explicit source, destination, protocol, port, and family
choices and displays configuration allowance separately from application state.

## Supported native cases

### AWS

Selected instances or network interfaces require one unambiguous private address
in the requested family, exact subnet/VPC identity, and collected association
facts. Source SG egress and destination SG ingress are allow unions across attached
groups; return traffic uses stateful tracking. Referenced groups match observed
membership and the **security-group owner's** account, which may differ from
the ENI owner for shared groups. They do not copy the referenced group's rules.
CIDR rules and same-region referenced-group cases are supported. [AWS security
group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)

An explicitly associated subnet route table, or its VPC main table after complete
association enumeration, supplies forward and return routes. Longest-prefix
active local routes remain in the same scoped VPC. Active peering needs native
VPC, owner-account, and region matches and routes in both directions. A known
selected blackhole/drop is decisive; a peering edge alone is insufficient.
[AWS route priority](https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html),
[AWS peering routing](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html)

For different subnets, NACLs are ordered first-match stateless controls: source
egress, destination ingress, destination return egress, and source return ingress
are all evaluated. The return destination port is the initiating source port.
NACLs do not filter traffic within one subnet. IPv4/IPv6 entries are evaluated in
their own families, including separate implicit-deny entries. A restrictive
return-port rule requires the supplied source port; an all-port rule can prove
allowance without guessing it. [AWS NACL semantics](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)

### Azure

VMs resolve to one collected NIC; NIC address configuration resolves to an exact
ARM subnet/VNet. Source NIC then subnet outbound controls and destination subnet
then NIC inbound controls must all admit the new flow. NSGs use ordered native
priorities, custom rules, and immutable platform defaults. A matched five-tuple
allow uses stateful return behavior. [Azure NSG processing](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works),
[Azure NSG rules and defaults](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)

Higher security-admin policies can bypass or terminate NSG processing, including
`Always allow`. Their absence requires explicit evidence; even an NSG deny stays
a candidate when that context is missing. [Azure security-admin precedence](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#security-admin-rules)

The supported route model combines native UDRs and local/connected-peering system
routes only after complete system/BGP context verifies no BGP alternatives.
Longest prefix wins, with UDR precedence at the same prefix. A selected `None`
next hop is a drop. Other appliance, gateway, Internet, or NAT next hops remain
unknown. An inactive/access-disabled peering does not rule out unsupported
alternate routing. [Azure routing precedence](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview)

Address/port arrays and numeric port ranges are supported. `VirtualNetwork`
membership can be positively established from that NSG endpoint's observed VNet
prefixes. Other service tags, and membership outside those known prefixes, need
captured tag ranges; the evaluator does not equate a public/private-address
heuristic with a service tag. Application security groups remain unknown.

### GCP

VM primary private addresses use full project-qualified global network and
regional subnet references, including a shared host-project VPC. A numeric SDK
network ID is not substituted for its `selfLink`. Firewall/route completeness
must belong to the **host network project**; a service project's empty firewall
inventory cannot prove the host's implied deny.

Supported VPC rules retain enabled state, direction, priority, protocol/ports,
target tags/accounts, source ranges/tags/accounts, and destination ranges.
Source tag/account criteria apply only to interfaces in that VPC; range and
identity sources form a union. Highest priority wins, with deny at an equal
priority. Missing ingress sources or egress destinations default to IPv4 `/0`,
not IPv6. Matching responses are stateful. [GCP VPC firewall semantics](https://docs.cloud.google.com/firewall/docs/firewalls)

Hierarchical/global/regional policy context must explicitly prove no overriding
policies. An unobserved higher layer makes local VPC decisions candidates.
[GCP firewall policy precedence](https://docs.cloud.google.com/firewall/docs/firewall-policies-rule-details)

Within a global VPC, a native regular subnet route precedes ordinary custom static
routes after policy-based/dynamic context is verified. Supported cross-VPC
regular-private-subnet cases need active native peering in each direction and
IPv6 route exchange when applicable. Proxy/hybrid/service-connect subnets and
unmodeled static alternatives to inactive peering remain unknown.
[GCP route selection](https://docs.cloud.google.com/vpc/docs/routes),
[GCP subnet routes](https://docs.cloud.google.com/vpc/docs/subnets#subnet-routes)

### Kubernetes

Only direct pod endpoints are modeled. Standard ingress and egress isolation are
independent, and matching allow rules form an additive union. Each end must admit
the initial flow; reply traffic is implicitly admitted. A policy object by itself
does not establish an enforcing CNI. Namespace is an administrative selector
scope, never a subnet. [Kubernetes NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/)

Pod/namespace selectors support `matchLabels` and `In`, `NotIn`, `Exists`, and
`DoesNotExist`. Within one peer, pod and namespace selectors are conjunctive;
separate peers are alternatives. Numeric/named destination ports, port ranges,
and IP-block exceptions are supported when CNI range and preserved-pod-IP behavior
are evidenced. Named ports resolve from the destination pod specification.
[NetworkPolicy API fields](https://kubernetes.io/docs/reference/kubernetes-api/policy-resources/network-policy-v1/)

Host-network pods, Service/LB translation, node-source exceptions, and nonstandard
CNI policies need additional native enforcement/translation evidence and remain
outside this direct-pod model. CNI discovery by name alone is not proof of
enforcement; pod addresses, explicit cluster identity, and routing context are
also required.

## Explicit context gates

Collectors must populate these only after observing their stated coverage and
recording source references. An absent key, incomplete status, unsupported policy
presence, or missing evidence stays unknown. The evaluator does not turn a
collector's omission into a default allowance.

```yaml
metadata:
  network_context:
    azure:
      routing:
        status: collected
        complete: true
        bgp: none
        source_evidence: [{path: captured-system-and-bgp-route-context}]
      security_admin:
        status: collected
        complete: true
        policies: []
        source_evidence: [{path: captured-effective-admin-policy-context}]
    gcp:
      routing:
        status: collected
        complete: true
        policy_based_routes: none
        dynamic_routes: none
        source_evidence: [{path: captured-effective-routing-context}]
      firewall_hierarchy:
        status: collected
        complete: true
        policies: []
        source_evidence: [{path: captured-hierarchy-and-network-policy-context}]
    k8s:
      cni:
        status: collected
        enforces_network_policy: true
        supports_end_port: true
        ipblock_semantics: pod_ips_preserved
        source_evidence: [{path: captured-enforcing-cni-configuration}]
      routing:
        status: collected
        complete: true
        pod_network_connected: true
        source_evidence: [{path: captured-direct-pod-route-context}]
```

These are coverage contracts, not suggested hardcoded collector defaults. The
illustrated source paths are descriptive examples and do not constitute actual
proof. Current captures without those observations retain their missing-context
states. `effective_route` and additional policy/CNI inventories are retained in
the scoped artifact for evidence/future support; they do not automatically replace
these verified context gates.

## Decision and remaining unknown boundaries

A source egress denial can be decisive despite an allowance's missing route
context. A downstream source-CIDR denial cannot establish the selected flow is
blocked when an unknown NAT/appliance could rewrite that source. Scoped domain
inconsistency also prevents a candidate control from becoming a whole-flow proof.

| Remaining unknown class | Exact boundary |
| --- | --- |
| Endpoint ambiguity | Multiple interfaces/private addresses in the chosen family; missing IP, selected ID, or native domain; contradictory addresses or cluster identity |
| Native completeness | Missing/denied/partial collection; unresolved rule ordering, association, selector, prefix-list membership, or malformed native fields |
| AWS transformations | NAT, transit, Internet/VPN gateway, endpoint, appliance next hops, managed non-interface endpoint types, prefix lists; unjoined cross-account shared-VPC aliases |
| Azure effective context | BGP/combined effective routing, security-admin policies, ASGs, unresolved service tags, appliances/NAT/gateways and unsupported alternate peering paths |
| GCP effective context | Hierarchical/network policies, policy-based/dynamic routing, hybrid/proxy/PSC subnets, external IPv6, third-project account eligibility and unresolved numeric project aliases |
| Kubernetes enforcement | Unverified/unsupported CNI, custom CNI policy behavior, host network/node traffic exceptions, IP-block NAT ordering, unverified port-range support, Service/Ingress translation |
| Operational state | Application listening, endpoint operating/attachment, fragments, connection-tracking capacity/state, packets delivered, runtime firewall/host controls, and telemetry |

The supported transport model covers ordinary new TCP/UDP flows between declared
private endpoints. ICMP/SCTP, fragments, cross-family translation, policy chains,
and exhaustive paths are not inferred. Snapshot reads may occur at different
times; the model is bound to collected facts rather than a transactional live
cloud view. Scope IDs and provider-qualified references remain distinct when
names or CIDRs overlap. Structural graph relationships stay structural; a query
does not relabel an entire graph as reachable.

## Verification

```sh
python -m pytest -q tests/test_peaso_reachability.py
python -m pytest -q tests/test_peaso_reachability.py tests/test_peaso_analysis.py tests/test_peaso_api.py
```

The suite tests complete passing TCP/UDP paths across all four providers and both
families, ordered denies and uncertain earlier rules, stateful versus stateless
return, source-port requirements, native SG owner references, NSG intersection
and defaults, GCP tag/account/shared-host/numeric-ID joins, Kubernetes additive
unions and selector/port/IP-block behavior, unavailable collections, overlap,
cross-account active peering/owner/region mismatch, unsupported components,
artifact binding, strict query validation, and forbidden socket/subprocess calls.
Private capture checks skip honestly when their QA files are unavailable; they
never collect from a live account.

On this machine, a selected 5,010-resource AWS fixture returned allowance with
two routes and nine evidence references in 0.0939 seconds cold and 0.1103 seconds
warm. The benchmark includes snapshot validation, normalization/indexing, and one
flow; its size grows with inventory and selected rules, not endpoint pairs.
Timing is a measurement rather than a latency guarantee.

Saved private QA captures were also evaluated with no new cloud calls:

| Capture | Source digest | Network artifact | Selected result |
| --- | --- | --- | --- |
| AWS | `sha256:f2c6dd6946b865cf44b84a0acc9637f5b686c35b01bd828d4e46552597d30b5c` | 74 resources / 61,183 bytes versus 335,212-byte source | Modeled allowance, no gaps; application state remains unknown |
| Azure | `sha256:e15c49b6de86f3b0bc9c115d76073237c26be794fb9d7ef389afbd580f776667` | 0 supported endpoint resources / 1,370 bytes versus 6,181,591-byte source | Unknown: `endpoint_inventory_missing` |
| Kubernetes | `sha256:fc29a01b26b4eabcd0df9b342238ee852a2995cfd9b1afa174164beea953f14d` | 10 resources / 15,277 bytes versus 172,913-byte source | Unknown: captured pod has no address |

Artifact byte sizes use compact JSON and can change with additive metadata.
These are configuration model checks, not connection tests or proof that any
captured application accepts traffic. The fixture source files stay private;
only digests, counts, decisions, and gap classes are recorded here.
