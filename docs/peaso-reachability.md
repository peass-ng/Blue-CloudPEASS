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

Both IDs are normalized inventory `resource.id` values or derived IDs for
individual interfaces embedded in a collected GCP VM, never graph node IDs or
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

`REACHABILITY_TYPES` declares dependency inventories by provider. The network
collection planner requests the subset supported by the native collector. GCP
collects hierarchical and network firewall policies as `firewall_policy`;
`hierarchical_firewall_policy` and `network_firewall_policy` are accepted from
imported snapshots only. Kubernetes `cni_configuration` is also import-only:
the native collector cannot verify CNI enforcement or pod routing, so ordinary
Kubernetes captures cannot produce an `allowed` pod-flow result. These types
remain in `REACHABILITY_TYPES` so conflicting imported facts survive projection
and cannot be hidden by `network_snapshot`. `network_snapshot` validates and seals a
derived artifact containing entire native dependency collections with their
original statuses. It removes unrelated IAM/credential inventory and preserves
network context, identity-of-scope metadata, and the source snapshot reference.
It never trims individual routes, rules, or associations from a collection marked
complete. Original snapshots need not be read for each API query. Reachability
checks raw network collections for duplicate native identities before its index
can collapse them; a collision keeps the flow unknown because another route or
policy record could change the decision.
If a second collected AWS ENI in the same Region and VPC (including another
account participating in a shared VPC), Azure NIC in
the same VNet, GCP VM interface in the same host-project VPC, or Kubernetes Pod
in the same cluster claims either selected private IP, the named endpoint is
ambiguous and the decision remains unknown. A third resource in a separate
network with the same address does not create that collision. Batch, matrix,
and grid requests reuse each selected interface's collision search across
their independent pair decisions.

The tenant-authorized API owns `/api/scans/{id}/reachability` and scan lookup.
Its persisted source binding must match the scan's report snapshot ID; imported
`metadata.original_snapshot_id` is a provenance label, never authorization.
The dialog submits explicit source, destination, protocol, port, and family
choices and displays configuration allowance separately from application state.
The Network Map also accepts one source plus up to 24 loaded destination IDs
for the same protocol, port, and family through the tenant-owned
`/api/scans/{id}/reachability/batch` endpoint. Each result is a full independent
selected-flow decision bound to the same snapshot; one validated native-resource
index is reused within the request. Colored arrows identify
those exact endpoint pairs; an arrow anchored to a collapsed subnet or VPC
does not claim that every member of that group is reachable. The panel pages
through loaded endpoints in batches of 24 and lets users inspect or focus each
assessed pair. Results from successive pages accumulate as arrows on the map;
changing the source, protocol, address family, or port clears the old results.
Selecting “Assess connections from this resource” runs the first
batch immediately with the visible protocol and port (initially TCP/443), so
directional arrows appear without a second submission.
For a bounded automatic preview, the live map selects up to 12 loaded
endpoints from the current view and calls `/api/scans/{id}/reachability/matrix`
once for every ordered pair at IPv4 TCP/54321→443. The matrix reuses one
validated snapshot index, keeps each direction's decision independent, and
reports how many loaded endpoints were sampled. An AWS instance or Azure VM
with one attached interface is sampled once as the workload. With multiple
attached interfaces, their collected ENIs or NICs are sampled separately so
that endpoint identity and routing are unambiguous. GCP interfaces embedded in
each collected VM receive distinct, snapshot-derived selection IDs; a GCP VM
with multiple interfaces is sampled through those interfaces as well.
If an attached ENI or NIC is unresolved, the VM also remains selectable so the
missing endpoint evidence is visible as `unknown` rather than disappearing.
A pair whose endpoints project to the same collapsed VPC or subnet has no
drawable arrow between distinct nodes. The collapsed group shows the exact
number of assessed internal pairs and opens their individual results; opening
the group exposes arrows between the selected resources.
A larger loaded view can advance through 12-endpoint windows; the last window
borrows one adjacent endpoint when it otherwise contains only one. Windows do
not imply that cross-window pairs were evaluated. Selecting a second window
calls `/api/scans/{id}/reachability/grid` for both directions across the two
windows, at most 12 endpoints on each side. The borrowed endpoint is used only
for the singleton window's matrix; if the compared window contains that endpoint,
the grid omits it because its pair with the singleton was already assessed by
the matrix. The grid response uses
the same tenant-owned snapshot binding and independent flow decisions. The UI
also requires the grid and current matrix to report the same snapshot ID before
combining their arrows.
Before showing a manual decision or drawing batch, matrix, or grid arrows, the UI checks that the response
contains exactly the requested directed pairs, provider, snapshot, protocol,
address family, and ports. Incomplete or mismatched responses show an error
instead of a connectivity arrow.
A grouped arrow lists its named pairs and count. When those pairs have different
decisions, one purple mixed arrow shows the per-decision counts and opens each
underlying result; one colored verdict must not cover another verdict between
the same collapsed groups. The remainder of an inventory or other ports are
not inferred.

## Supported native cases

### AWS

Selected instances or network interfaces require one unambiguous private address
in the requested family, exact subnet/VPC identity, and collected association
facts. An instance also needs exactly one native interface entry; summarized
instance address fields cannot hide an unobserved second interface. Source SG
egress and destination SG ingress are allow unions across attached
groups; return traffic uses stateful tracking. Referenced groups match observed
membership and the **security-group owner's** account, which may differ from
the ENI owner for shared groups. They do not copy the referenced group's rules.
Missing, malformed, or contradictory ENI SG associations leave referenced-group
membership unknown; they cannot prove that a peer SG rule denies the flow. A
collected referenced SG whose VPC disagrees with the peer ENI also leaves its
membership unresolved.
An EC2 instance must be observed `running`. Its ENI must be separately collected,
`in-use`, attached to that instance, and named exactly once by the instance's
native interface list; subnet, VPC, and primary IP facts must agree in both
views. A selected ENI also requires that same running-instance proof. An
available, detached, or instance-less ENI cannot establish an endpoint path.
[AWS ENI status](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeNetworkInterfaces.html),
[EC2 instance states](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html).
CIDR rules, same-region referenced-group cases, and managed prefix-list rules
with complete version-pinned entries are supported. Missing, denied, changing,
or unversioned prefix-list entries keep the affected rule unknown. [AWS security
group rules](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
An SG reference to a peer VPC in a different Region cannot match; such peers
require CIDR rules. [AWS peering SG references](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-security-groups.html)
Permission and selector collections must have their native list shape; a
malformed empty object cannot be mistaken for an empty allow list or a deny.
A permission whose protocol and port apply but which has no source or
destination selector is unresolved; a complete, genuinely empty SG permission
list remains a deny. [AWS SG rule components](https://docs.aws.amazon.com/vpc/latest/userguide/security-group-rules.html)
A referenced-group selector without a usable group ID or with malformed account
or VPC identity cannot prove that no allow matches.
AWS protocol number `-1` matches every protocol. Other valid IP protocol
numbers are compared with the selected TCP/UDP protocol; unrelated numbers
cannot obscure a matching rule. Unsupported aliases such as `any`, `all`, and
`*` leave the affected SG or NACL rule unresolved rather than granting access.
[AWS SG protocol values](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html),
[AWS NACL protocol values](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_NetworkAclEntry.html)
The associated route table's `Routes` must likewise be a list of native route
objects; a malformed empty object cannot prove that no route exists.
Each route must have exactly one native destination selector. A selected local
or peering route with another next-hop field is unresolved instead of inheriting
the first target checked by the evaluator. [AWS route fields](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Route.html)
Its entries must include every associated IPv4 and IPv6 VPC CIDR destination;
their local targets can be replaced. An empty or truncated route list that
omits one of these mandatory destinations leaves the path unknown rather than
proving an implicit drop.
[AWS subnet route tables](https://docs.aws.amazon.com/vpc/latest/userguide/subnet-route-tables.html)

An explicitly associated subnet route table, or its VPC main table after complete
association enumeration, supplies forward and return routes. Longest-prefix
active local routes remain in the same scoped VPC. Active peering needs native
VPC, owner-account, and region matches and routes in both directions. A known
selected blackhole/drop is decisive; a peering edge alone is insufficient.
An association observed while associating, disassociating, or failed cannot
justify falling back to the main table; that route choice remains unknown.
Missing or malformed route-table association lists or entries also leave the selected
table unknown, even when a main table is present. An association must identify
exactly one of a subnet, the main table, a gateway, or a public IPv4 pool; an
empty or conflicting selector cannot justify falling back to the main table.
A route table that associates the selected subnet while declaring another VPC
also leaves the route choice unknown.
Secondary IPv4 and IPv6 VPC/subnet ranges count only when their native
association state is `associated`; a missing or disassociated state cannot prove
the selected address domain.
Version-pinned prefix-list route entries expand into destination CIDRs for
longest-prefix selection. A static CIDR route wins an equal-prefix tie over a
prefix-list route, which wins over a propagated route. Overlapping prefix-list
routes remain unknown when no more-specific CIDR route or equal-prefix static
CIDR route settles the selection; AWS can choose a different target even when
the matching prefix-list entries have different lengths. A VPC local route also wins over a more-specific overlapping
VPN/Direct Connect propagated route; static routes can still redirect the path.
A selected local or peering next hop is then checked like a
CIDR route; unsupported gateway and appliance targets remain unknown.
[AWS route priority](https://docs.aws.amazon.com/vpc/latest/userguide/route-tables-priority.html),
[AWS VPN route priority](https://docs.aws.amazon.com/vpn/latest/s2svpn/vpn-route-priority.html),
[AWS peering routing](https://docs.aws.amazon.com/vpc/latest/peering/vpc-peering-routing.html)

Transit Gateway route-table capture reads both static and propagated routes
and attachment associations, preserving partial or denied child reads on the
table. The collector also reads VPC attachment subnet IDs, state, and options.
The evaluator now admits a direct two-VPC Transit Gateway path when each
available VPC attachment has a collected subnet in its originating endpoint's
Availability Zone. With multiple attachment subnets, it selects the destination
attachment subnet in the source Availability Zone when appliance mode is
explicitly disabled; a sole destination subnet is also deterministic. It checks
both VPC subnet routes, both gateway
route-table associations, the longest-prefix gateway routes to the exact
destination attachments, local routes from both attachment subnets, and the
stateless NACL stages in both directions. Same-subnet instance/attachment
traffic follows AWS's special NACL direction rules. Missing or conflicting
gateway facts, a nondeterministic destination Availability Zone, other attachment types, and
cross-VPC security-group references without feature proof stay `unknown`.
An inbound cross-VPC security-group reference can be used only when the gateway
and both VPC attachments explicitly enable referencing, the selected route
uses that gateway, and the selected endpoint and attachment zones are supported.
Outbound references through Transit Gateway remain `unknown` because AWS does
not support them.
[AWS Transit Gateway route evaluation](https://docs.aws.amazon.com/vpc/latest/tgw/how-transit-gateways-work.html),
[Transit Gateway NACL stages](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-nacls.html),
[VPC attachment routing and SG reference requirements](https://docs.aws.amazon.com/vpc/latest/tgw/tgw-vpc-attachments.html)

For two selected hosts in the same native subnet, the direct subnet path does
not depend on the subnet route table. Security groups still decide the new flow;
NACLs do not filter it, and a source port is not needed for NACL return rules.
AWS does not route same-subnet host traffic through an appliance.
[AWS same-subnet routing](https://docs.aws.amazon.com/vpc/latest/userguide/route-table-options.html)
When both selected IDs resolve to one EC2 interface, the model leaves traffic
to its own private IP `unknown`: a guest-local path may bypass the VPC boundary,
so an SG or NACL rule cannot prove a network drop for that self-connection.

For different subnets, NACLs are ordered first-match stateless controls: source
egress, destination ingress, destination return egress, and source return ingress
are all evaluated. The return destination port is the initiating source port.
NACLs do not filter traffic within one subnet. IPv4/IPv6 entries are evaluated in
their own families, including separate implicit-deny entries. An entry with
both or neither CIDR family is unresolved rather than treated as a nonmatch.
User rules use `1..32766`; the native implicit-deny entry is `32767` for IPv4
and `32768` for IPv6. A missing or malformed family-specific implicit entry
leaves the captured rule list unknown.
[AWS native IPv4/IPv6 NACL entries](https://docs.aws.amazon.com/cli/latest/reference/ec2/describe-network-acls.html)
A missing or malformed NACL association list, including an association without a
nonempty subnet ID, cannot establish which ACL protects the subnet.
A NACL that associates the selected subnet while declaring another VPC likewise
leaves that policy stage unknown.
A restrictive return-port rule requires the supplied source port; an all-port rule can prove
allowance without guessing it. [AWS NACL semantics](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
If the return route passes through an unmodeled appliance, a source-subnet
return-ingress NACL decision remains a candidate: the appliance could change
the packet before that stage. A destination-subnet return-egress NACL deny can
still block once the forward path is proven, because it acts before the
uncertain return route.

### Azure

VMs resolve to one collected NIC; NIC address configuration resolves to an exact
ARM subnet/VNet. Source NIC then subnet outbound controls and destination subnet
then NIC inbound controls must all admit the new flow. NSGs use ordered native
priorities, custom rules, and immutable platform defaults. A matched five-tuple
allow uses stateful return behavior. [Azure NSG processing](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-group-how-it-works),
[Azure NSG rules and defaults](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview)
When both selected IDs resolve to one VM NIC, traffic to its own private IP
remains `unknown`; NSG and VNet routing rules cannot prove the guest-local path
is blocked.
The collector reads full NIC, VNet, subnet, and peering details. A selected NIC,
VNet, or subnet without full detail and explicit `Succeeded` provisioning state cannot
establish its address or NSG/route-table associations. A peering also needs
full detail and `Succeeded` state before it can establish a cross-VNet path.
[Azure subnet GET](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/subnets/get?view=rest-virtualnetwork-2025-05-01),
[Azure peering GET](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/virtual-network-peerings/get?view=rest-virtualnetwork-2025-05-01)
The collector reads full NSG detail. The attached NSG and each native custom
rule must explicitly report `provisioningState: Succeeded`; incomplete detail
or a transitioning rule leaves the result unknown.
[Azure NSG GET](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-security-groups/get?view=rest-virtualnetwork-2025-05-01)
A selected VM or NIC needs a complete full VM GET with `$expand=instanceView`,
`Succeeded` provisioning state, and exactly one `PowerState/running` status.
The NIC's attached-VM reference and the VM's native NIC list must agree in both
directions. An unattached NIC, a deallocated VM, or a missing runtime view
cannot establish a live endpoint. A duplicate IP configuration for the selected
address also leaves the endpoint unknown.
[Azure VM GET and instance view](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-compute-2023-09-01),
[Azure NIC attachment field](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/get?view=rest-virtualnetwork-2025-05-01)

NSG rules that name Application Security Groups match the selected NIC IP
configuration's collected ASG memberships. Positive matches require the ASG
endpoint and rule-owning VNet to be the same; mixed ASG and IP selectors or
malformed membership stay unknown. Plural address and port selectors must be
native string arrays; a malformed string cannot be evaluated as one selector
per character. Malformed NIC/subnet NSG associations and rule collections stay
unknown. An unrecognized rule direction remains an uncertain candidate
at its native priority. Only native NSG protocol values (`*`, `Tcp`, `Udp`,
`Icmp`, `Esp`, `Ah`) can decide a TCP/UDP flow; aliases and numeric strings
remain unresolved. Address and port wildcards require native `*`; `Any` is a UI
label, not a proven native selector. [Azure NSG rule fields](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/networksecuritygroups/securityrules),
[Azure ASG scope and membership](https://learn.microsoft.com/en-us/azure/virtual-network/application-security-groups)

The `VirtualNetwork` NSG service tag includes an access-enabled peered VNet.
The evaluator proves that positive membership only when a connected,
synchronized native peering and both the peering's remote address space and
the collected remote VNet contain the selected address. Gateway, BGP, and UDR
additions to the tag remain unresolved without effective tag evidence.
The peering's `peeringSyncLevel` must explicitly be `FullyInSync`; a missing
value cannot prove that the remote address space is current.
Declared peering routes require the selected destination in both the peering's
remote address space and the collected remote VNet; a missing field cannot be
filled from the VNet alone.
`peerCompleteVnets: false` is subnet peering, where route visibility can include
nonparticipating subnets. The selected route is admitted only when each peering
direction names its exact local and remote subnet in `localSubnetNames` and
`remoteSubnetNames`; missing or mismatched membership remains unknown. The
`VirtualNetwork` NSG tag uses the same selected subnet check for positive peer
membership. An IPv6-only peering cannot prove an IPv4 path.
[Azure subnet peering behavior](https://learn.microsoft.com/en-us/azure/virtual-network/how-to-configure-subnet-peering)
[Azure service tag membership](https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview),
[Azure peering access setting](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-network-manage-peering)

Higher security-admin policies can bypass or terminate NSG processing, including
`Always allow`. Their absence requires explicit evidence; even an NSG deny stays
a candidate when that context is missing. [Azure security-admin precedence](https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#security-admin-rules)
When the complete effective-rule inventory and each selected VNet query are
proven, a nonempty inventory consisting entirely of `Allow` rules leaves NSG
evaluation authoritative: those rules continue to NSGs. `Deny` and
`AlwaysAllow` still require effective priority/selector modeling and keep the
flow unknown. [Azure admin-rule actions](https://learn.microsoft.com/en-us/azure/virtual-network-manager/concept-security-admins)
The Azure collector now queries effective security-admin rules for every
collected VNet. Only complete empty responses across all selected subscription
scopes produce the `security_admin.policies: []` context proof. A failed or
partial query leaves this gate unknown. The evaluator also requires each selected
VNet's native query proof when the declared effective-rule inventory is empty;
metadata alone cannot establish absence. Query response digests must have the
native SHA-256 shape before they count as proof, both for admin rules and NIC
effective routes.

The supported route model combines native UDRs and local/connected-peering system
routes only after complete system/BGP context verifies no BGP alternatives.
An observed subnet `routeTable` association needs a nonempty native table ID;
malformed associations cannot be treated as the absence of a UDR.
The route-table collector uses full ARM GET detail with API `2025-07-01` to capture
`disablePeeringRoute` and route provisioning states. Declared-route reconstruction
requires that full-detail provenance; cross-VNet reconstruction also requires an
API version that exposes the peering setting. `All` suppresses
peering system routes; `None` permits them. A missing or unrecognized setting
on an associated cross-VNet table leaves the route unresolved. A route table
or child UDR without an explicit `Succeeded` provisioning state is also
unresolved. [Azure route-table change log](https://learn.microsoft.com/en-us/azure/templates/microsoft.network/change-log/routetables),
[Azure route-table GET](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/route-tables/get?view=rest-virtualnetwork-2026-01-01)
When per-NIC effective route tables are collected, they supersede this declared
route reconstruction: active longest-prefix routes are selected with native
source precedence, and local/peering system routes take precedence over BGP.
An effective peering route also needs the destination address in both the
peering's synchronized remote address space and the collected remote VNet's
address space; contradictory native facts leave the route unknown.
An active effective peering route that contradicts a fully collected, provisioned
associated route table with `disablePeeringRoute: All` stays unknown.
An active matching `VirtualNetworkServiceEndpoint` system route also takes
precedence over UDRs; it leaves direct NIC-to-NIC reachability unknown because
that service path is outside the selected endpoint model.
If no captured active route covers the destination, the effective response is
unresolved; a selected native `None` next hop is required to prove a route drop.
The collector keeps the exact NIC association, query status, and hashed native
response proof. Every response page for the selected NIC must have valid query
evidence, and its route row IDs must be unique. Each selected route row must
also carry the native operation and owning NIC identity; an anonymous or contradictory row leaves the route
unknown. A missing or partial effective table, or a table without its query
proof, cannot fall back to declared routes.
Longest prefix wins, with UDR precedence at the same prefix. A selected `None`
next hop is a drop. Other appliance, gateway, Internet, or NAT next hops remain
unknown. An inactive/access-disabled peering does not rule out unsupported
alternate routing. [Azure routing precedence](https://learn.microsoft.com/en-us/azure/virtual-network/virtual-networks-udr-overview)
Only Azure's permitted UDR next-hop types are accepted in declared and
effective tables. `VnetPeering` is a system route, and `VnetLocal` cannot
establish a path into a different VNet.
This route check also applies between two NICs in the same subnet: a subnet UDR
can override the local system path, including with a `None` drop next hop.

Address/port arrays and numeric port ranges are supported. `VirtualNetwork`
membership can be positively established from that NSG endpoint's observed VNet
prefixes and synchronized access-enabled peering. Its other dynamically included
ranges cannot be disproven by a subscription-wide service-tag list, so those
matches remain unknown. Other service tags need captured tag ranges; the evaluator does not equate a public/private-address
heuristic with a service tag. The collector now reads service-tag prefixes per
subscription from the native API, and membership is resolved only against the
selected endpoint's subscription.

### GCP

VM primary private addresses resolve project-qualified global network and
regional subnet references, including a shared host-project VPC. Same-project
partial interface and subnet-network URLs resolve against the owning VM or
subnet project; a service-project partial URL cannot join a same-named host
network. A numeric SDK network ID is not substituted for its `selfLink`. Firewall/route completeness
must belong to the **host network project**; a service project's empty firewall
inventory cannot prove the host's implied deny.
When the native network includes its `subnetworks` list, it must contain the
selected subnet as well as agreeing with the subnet's `network` reference;
contradictory inventories leave the endpoint unresolved.
An IPv6 endpoint also needs IPv6-capable stack types on both its interface and
subnet, plus internal IPv6 access on the subnet. An IPv4 endpoint cannot use an
IPv6-only interface or subnet. An omitted stack type has the API's IPv4-only
default, so a recorded IPv6 address alone cannot prove IPv6 capability.
[GCP VM interface fields](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances),
[GCP subnet fields](https://docs.cloud.google.com/compute/docs/reference/rest/v1/subnetworks).

For a VM selected as both endpoints, its own primary private address stays
inside the VM. VPC firewall policies and VPC routes do not gate that local
path; application listening remains unknown. [GCP always allowed traffic](https://docs.cloud.google.com/firewall/docs/firewalls).

Supported VPC rules retain enabled state, direction, priority, protocol/ports,
target tags/accounts, source ranges/tags/accounts, and destination ranges.
Source tag/account criteria apply only to interfaces in that VPC; range and
identity sources form a union. Highest priority wins, with deny at an equal
priority. Omitted or empty ingress source and egress destination lists use the
IPv4 `/0` defaults, not IPv6. Malformed tag, account, range, and protocol-port
lists remain unresolved at their native priority. Egress rules with source tags
or source service accounts, and port lists attached to non-TCP/UDP protocols, are likewise unresolved
instead of overriding another rule. Matching responses are stateful.
Valid numeric IP protocols that do not match the selected TCP/UDP flow are
nonmatches; generic wildcard spellings from other providers remain unresolved.
When `ports[]` is present, each GCP entry must be a numeric port or range;
`*` and `Any` cannot establish an allow or deny.
[GCP firewall API fields](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewalls),
[GCP VPC firewall semantics](https://docs.cloud.google.com/firewall/docs/firewalls).
An omitted native network reference resolves to that rule's project default
network. Malformed enabled-state, direction, or network references remain
uncertain candidates at their native priority instead of being discarded.

The collector proves absence of **applicable** hierarchical, global, and
regional policies separately for each VPC host project. It requires complete
project policy inventory with no attached network policies, known ancestry,
and empty policy associations at every ancestor. An unassociated policy or a
policy in another project cannot block a local VPC decision. Policies can be
created elsewhere in the organization and attached to an ancestor, so listing
policies owned by that ancestor alone is insufficient. The evaluator requires
this scoped inventory proof; an older unscoped `policies: []` assertion does
not establish absence. A denied, partial, or
missing read leaves that project's local decisions as candidates.
An imported split-type policy in the selected host project or one of its
ancestors also invalidates a scoped empty-policy assertion; it cannot be
silently ignored merely because the native collector uses `firewall_policy`.
The selected VPC's native `firewallPolicy` attachment is an independent
cross-check: if it names a policy while the policy inventory claims none is
applicable, collection cannot issue an empty-hierarchy proof and evaluation
stays unknown. [GCP Network resource](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks).
[GCP network policy associations](https://docs.cloud.google.com/firewall/docs/network-firewall-policies),
[hierarchical policy associations](https://docs.cloud.google.com/compute/docs/reference/rest/v1/firewallPolicies/listAssociations)
[GCP firewall policy precedence](https://docs.cloud.google.com/firewall/docs/firewall-policies-rule-details)

The collector also reads regional effective firewalls for every collected
network and subnet region. This response includes Google-managed
`SYSTEM_REGIONAL` policies, which project policy listings cannot rule out.
The evaluator requires a complete native regional response for both endpoints
before a classic VPC firewall decision is conclusive. A present regional policy,
denied or partial read, or missing response leaves the local decision unknown;
the response's read identifiers must also match its collection evidence.
regional policy rule evaluation is not yet modeled.
[GCP firewall policy evaluation order](https://docs.cloud.google.com/firewall/docs/firewall-policies-overview),
[regional effective firewalls API](https://docs.cloud.google.com/compute/docs/reference/rest/v1/regionNetworkFirewallPolicies/getEffectiveFirewalls).

The native GCP collector lists global policy-based routes through the Network
Connectivity API. A complete empty inventory with native list-request evidence
for each selected host project can prove their absence for regular local or
peering subnet paths. An unproven empty collection stays unknown. Observed
policy-based routes keep that path unknown. Cloud Router BGP peers do not
override regular subnet routes; hybrid subnets remain unresolved. An explicit
claim that dynamic routes are absent is treated as inconsistent if the same
snapshot contains observed BGP peers.
Policy-based routes precede regular subnet routes even for VM endpoints in the
same subnet. [GCP policy-based routing](https://docs.cloud.google.com/vpc/docs/policy-based-routes).

Within a global VPC, a native regular subnet route precedes ordinary custom static
and dynamic routes after policy-based routing is verified. The same precedence
applies to peering subnet routes. Supported cross-VPC
regular-subnet cases need active native peering in each direction and
IPv6 route exchange when applicable. Proxy/hybrid/service-connect subnets and
unmodeled static alternatives to inactive peering remain unknown.
The selected subnet prefixes must be present and nonoverlapping in the queried
IPv4 or internal IPv6 family. All collected primary, secondary, and IPv6 subnet
ranges of the two peered VPCs must also be mutually nonoverlapping; conflicting
peering facts leave the address domain unknown. [GCP peering subnet overlap](https://docs.cloud.google.com/vpc/docs/vpc-peering#subnet_ip_ranges_cant_overlap_across_peered_vpc_networks)
Native peering network URLs may be full or project-relative. A relative URL
resolves only within the VPC owner's project, so a same-named network in another
project cannot satisfy the route join.
Malformed peering inventories or effective status fields keep the selected
cross-VPC route unknown and identify the offending native peering field.
[GCP Network peering reference](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networks)
For private IPv4 subnet routes, a pending consensus update does not itself
remove the already effective peering route; GCP keeps the effective connection
settings until the peer acknowledges the update. IPv6 requires the effective
`connectionStatus.trafficConfiguration.stackType`; a requested stack type
alone cannot establish active IPv6 exchange, even without a reported pending
update.
[GCP peering connection status](https://docs.cloud.google.com/vpc/docs/about-peering-connections)
Subnets with `allowSubnetCidrRoutesOverlap: true` use hybrid subnet routing;
overlapping custom routes can change the destination path, so these are also
unknown until that path is modeled. [GCP hybrid subnet routing](https://cloud.google.com/vpc/docs/hybrid-subnets)
Private RFC 1918 and valid IPv4 special-use subnet routes are always exchanged
across active peering. A privately used public IPv4 subnet needs effective
public-range subnet-route import on the local peering and export on the peer.
The effective `trafficConfiguration` import and export flags must both prove
public-range exchange, including during a pending consensus update; requested
flags alone leave it unknown.
[GCP peering subnet-route exchange](https://docs.cloud.google.com/vpc/docs/vpc-peering#options-for-exchanging-subnet-routes),
[valid subnet ranges](https://docs.cloud.google.com/vpc/docs/subnets#valid-ipv4-ranges)
[GCP route selection](https://docs.cloud.google.com/vpc/docs/routes),
[GCP subnet routes](https://docs.cloud.google.com/vpc/docs/subnets#subnet-routes)

The selected GCP VM must have native `status: RUNNING` before an otherwise
allowed route and firewall combination can establish an endpoint path. A
stopped, transitioning, or status-less VM remains `unknown`; configured rules
alone do not establish a live interface.
An embedded interface is selected by a stable ID derived from its VM, scope,
and native interface index. The evaluator rechecks that exact native entry and
uses its own network, subnet, and address. Selecting the VM without an interface
is supported only when the VM has exactly one native interface; traffic between
two interfaces of the same VM remains `unknown` because it may stay inside the
guest. Address-collision checks are keyed by interface, so equal private IPs
in separate unpeered VPCs do not reuse each other's collision result.
[GCP instance status](https://docs.cloud.google.com/compute/docs/reference/rest/v1/instances)

### Kubernetes

Only direct pods observed in the `Running` phase without a deletion timestamp
are modeled as endpoints. A terminated, pending, or terminating pod can retain
an IP in API inventory, so its recorded address yields `unknown` rather than a
connection decision. If another observed active pod in the same cluster claims
either selected IP, endpoint identity is ambiguous and the flow stays `unknown`.
The native PodSpec must also contain the required normal
container list and a valid `hostNetwork` state; otherwise ordinary pod routing
cannot be assumed. [Kubernetes pod lifecycle](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/),
[PodSpec fields](https://kubernetes.io/docs/reference/kubernetes-api/core/pod-v1/)
Standard ingress and egress isolation are
independent, and matching allow rules form an additive union. Each end must admit
the initial flow; reply traffic is implicitly admitted. A policy object by itself
does not establish an enforcing CNI. Namespace is an administrative selector
scope, never a subnet. [Kubernetes NetworkPolicy semantics](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
Malformed `policyTypes` on a policy that might select the pod keeps that
direction unknown; a valid independent allow can still prove the additive
union. A policy selecting another pod does not affect the decision. When
`policyTypes` is omitted or empty, Kubernetes defaults to `Ingress` and adds
`Egress` only when at least one egress rule exists. An explicit `Egress` type
with an empty egress rule list isolates outbound traffic. Malformed rule, peer,
and port arrays leave the policy decision unknown;
unrecognized fields in a selected standard policy, rule, peer IP block, or
port likewise cannot be treated as an understood permission.
Valid empty peer and port arrays in a rule match all peers and ports. An IP-block
exception array must be a valid list of CIDRs; an omitted array means there are
no exceptions. An omitted `podSelector` defaults to the empty selector and therefore selects every pod
in the policy's namespace. A collected policy without its native namespace
cannot be silently discarded as unrelated when its pod selector might match;
it keeps the selected direction unknown unless an independent additive allow
already proves it.

Pod/namespace selectors support `matchLabels` and `In`, `NotIn`, `Exists`, and
`DoesNotExist`. Within one peer, pod and namespace selectors are conjunctive;
separate peers are alternatives. A namespace selector using
`kubernetes.io/metadata.name` needs that native
immutable label to agree with the Namespace name. A contradictory name label
invalidates the namespace identity; an absent label leaves a selector using it
unresolved. Numeric/named destination ports, port ranges,
and IP-block exceptions are supported when CNI range and preserved-pod-IP behavior
are evidenced. Named ports resolve from the destination pod specification.
If a rule contains `endPort`, its match remains unknown for every queried port,
including the start port, until the CNI's range support is proven.
Malformed `NetworkPolicyPort` combinations, including `endPort` without a
numeric start port, cannot become a match-all or a proven rule mismatch.
An absent or malformed destination container/port specification cannot prove
that a named port is missing; that policy decision stays unknown. A complete
pod specification with no matching named port can establish a rule mismatch.
An init container alone cannot prove a named NetworkPolicy port: ordinary init
containers finish before the pod runs, while restartable init sidecars may
persist, and the captured CNI context does not verify how their port names are
resolved. A matching port declared by both a regular and an init container is
accepted only when both declarations agree.
Ephemeral containers cannot declare ports in the Kubernetes API and cannot
supply a named NetworkPolicy port.
[NetworkPolicy API fields](https://kubernetes.io/docs/reference/kubernetes-api/policy-resources/network-policy-v1/)

Host-network pods, Service/LB translation, node-source exceptions, and nonstandard
CNI policies need additional native enforcement/translation evidence and remain
outside this direct-pod model. CNI discovery by name alone is not proof of
enforcement; pod addresses, explicit cluster identity, and routing context are
also required. Namespaced and cluster-wide Cilium and Calico policy inventories,
plus Admin, Baseline Admin, and ClusterNetworkPolicy inventories, must be
explicitly complete and empty; an omitted collection is unknown.
The Kubernetes collector uses API-group discovery to record an absent Cilium or
Calico API as an empty inventory, and lists namespaced, Cilium cluster-wide, and
Calico global policies when their APIs are served. It also discovers Network
Policy API admin and cluster policies. A denied or unsupported version stays
unknown. The discovery record is retained in the scoped network snapshot and
must be complete before empty policy inventories can prove absence. Its native
`GET /apis` provenance must match the selected cluster, and the advertised
groups must include `networking.k8s.io/v1` when standard NetworkPolicies are
being evaluated.
The CNI context must also prove that standard Kubernetes NetworkPolicy is its
only policy source. Cluster-wide Cilium policies, global Calico policies, and
policies imported directly into an agent cannot be ruled out by an empty
namespaced policy inventory alone.
The current Kubernetes API collector does not emit verified CNI enforcement or
direct pod-routing context, so its ordinary captures yield `unknown` for pod
reachability even when standard policy intent can be evaluated.
The selected pod inventory must also be complete; a partial pod LIST cannot
justify an `allowed` decision from retained pod rows alone. Each selected pod
must carry its own collected `provenance.cluster_id` matching the snapshot;
missing pod provenance cannot inherit cluster identity from metadata. Malformed
Pod metadata, status, or `podIPs` stay unknown.
Namespace labels and potentially selected NetworkPolicies likewise require
native provenance for the selected cluster; a policy's provenance namespace
must agree with `metadata.namespace`. Mixed-cluster objects cannot decide the
pod flow.
Malformed label selectors remain unresolved, including empty lists or
non-string label values; a missing policy `spec` is unresolved too. None can
turn into a match-all selector or silently remove isolation.
When `policyTypes` is omitted or empty, the policy includes Egress by default
only if the egress rule list is nonempty. An explicit `Egress` policy type with
an empty rule list isolates outbound traffic.
[Kubernetes NetworkPolicy API](https://kubernetes.io/docs/reference/kubernetes-api/networking/network-policy-v1/).

## Explicit context gates

Collectors must populate these only after observing their stated coverage and
recording source references. An absent key, incomplete status, unsupported policy
presence, or missing evidence stays unknown. The evaluator does not turn a
collector's omission into a default allowance.
An empty effective-policy or policy-route assertion also stays unknown if the
same snapshot contains observed or incomplete Azure security-admin rules, GCP
firewall policies, GCP policy-based routes, or Cloud Router BGP peers.

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
        policy_sources: standard_networkpolicy_only
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
context. A downstream source-CIDR or destination-port denial cannot establish
the selected flow is blocked when an unknown NAT/appliance could rewrite the
packet before that control. Scoped domain
inconsistency also prevents a candidate control from becoming a whole-flow proof.
Missing or contradictory selected endpoint identity, attachment, or runtime
state also keeps the whole-flow result `unknown`, even if a route or policy has
a `blocked` candidate. A denied path to an address cannot establish a verdict
for a pod, VM, or NIC whose identity is unresolved.

| Remaining unknown class | Exact boundary |
| --- | --- |
| Endpoint ambiguity | Multiple interfaces/private addresses in the chosen family; missing IP, selected ID, or native domain; contradictory addresses or cluster identity |
| Native completeness | Missing/denied/partial collection; unresolved rule ordering, association, selector, unavailable or changing prefix-list membership, or malformed native fields |
| AWS transformations | NAT, transit, Internet/VPN gateway, endpoint, appliance next hops, managed non-interface endpoint types, ambiguous equal-prefix routes; unjoined cross-account shared-VPC aliases |
| Azure effective context | BGP/combined effective routing, security-admin policies, malformed or unavailable ASG membership, unresolved service tags, appliances/NAT/gateways and unsupported alternate peering paths |
| GCP effective context | Hierarchical/network policies, policy-based routing, custom or dynamic routes outside regular subnet paths, hybrid/proxy/PSC subnets, external IPv6, third-project account eligibility and unresolved numeric project aliases |
| Kubernetes enforcement | Unverified/unsupported CNI, custom CNI policy behavior, host network/node traffic exceptions, IP-block NAT ordering, unverified port-range support, Service/Ingress translation |
| Operational state | Application listening, fragments, connection-tracking capacity/state, packets delivered, runtime firewall/host controls, and telemetry; selected VM/pod/attachment state is required where supported |

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
