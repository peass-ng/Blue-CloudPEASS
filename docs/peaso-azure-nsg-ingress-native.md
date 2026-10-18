# Azure native NSG ingress evidence

`nsg_effective_internet_path` supplies configured, world-source TCP/UDP backend destination-port evidence for `azure_nsg_world_ingress_approved_ports`. The collector reads Azure metadata; it does not send traffic, identify a listening service, or modify cloud resources. Its supported topology is deliberately narrow. Missing or unsupported topology remains UNKNOWN rather than becoming an empty exposure PASS.

## Native scope and supported topology

The selected subscription must have complete native inventories of all seven types: `nsg`, `nic`, `vnet`, `public_ip`, `vm`, `load_balancer`, and `application_gateway`. Native ListAll identity sets and full GET identities/ETags are checked before and after projection. Forward VM, public-IP and VNet references must belong to those complete lists before a cached object or GET can satisfy them. All VNet subnet lists, subnet IP-configuration references, NSG attachments and public-IP reverse/forward associations must resolve exactly.

An eligible path uses a directly assigned, globally routable native public IP and a standalone, single-NIC VM. Every NSG-associated NIC IP configuration requires its own proven public-IP binding. A private configuration without that binding is UNKNOWN, including possible IP-address-based load-balancer exposure. Unresolved public-IP bindings, missing native versions, nonempty selected-subscription load-balancer/application-gateway inventories, managed/delegated subnet references, VMSS, ASG, forwarding, peering or proxy ambiguity are unsupported. The collector never infers that absent NIC backend-pool references prove absent load balancers; Azure supports IP-based and cross-subscription backend configurations.

Native effective NSG groups must match the exact NIC/subnet parents. Explicit rules are evaluated in direction/priority order and NIC/subnet decisions are intersected. No default rule or successful terminal decision is invented. Effective security-admin results must be fully paginated empty and are reread. Any admin override is UNKNOWN. Routes must prove supported active system/default Internet routing; user/BGP/appliance routes and unresolved public source subsets are UNKNOWN.

This establishes configured backend-port decisions within the supported topology. It does not establish complete public frontend-port mappings, proxy reachability, delivered traffic, atomic provider snapshots or historical exposure. Before/after identities and ETags detect observed changes; they are not historical or atomic completeness guarantees.

## Read operations and permissions

The inventory reads require the corresponding resource `read` permissions: `Microsoft.Network/networkSecurityGroups/read`, `Microsoft.Network/networkInterfaces/read`, `Microsoft.Network/virtualNetworks/read`, `Microsoft.Network/virtualNetworks/subnets/read`, `Microsoft.Network/publicIPAddresses/read`, `Microsoft.Network/loadBalancers/read`, `Microsoft.Network/applicationGateways/read`, and `Microsoft.Compute/virtualMachines/read`. Network paths use API version `2025-05-01`; VM reads use `2024-07-01`.

Three additional ARM POST operations are semantic metadata queries, with no resource configuration writes:

| Resource and operation | Permission | Request |
| --- | --- | --- |
| NIC `/effectiveNetworkSecurityGroups` | `Microsoft.Network/networkInterfaces/effectiveNetworkSecurityGroups/action` | POST, no supplied payload |
| NIC `/effectiveRouteTable` | `Microsoft.Network/networkInterfaces/effectiveRouteTable/action` | POST, no supplied payload |
| VNet `/listNetworkManagerEffectiveSecurityAdminRules` | `Microsoft.Network/virtualNetworks/listNetworkManagerEffectiveSecurityAdminRules/read` | POST `{}`, followed only by bounded `skipToken` requests |

The query API version is `2025-05-01`. NIC query LRO results use GET only on exact selected-subscription NIC or already bound NSG `/operationResults/{UUID}` identities, with reviewed `2025-05-01`/`2025-07-01` continuation versions. Foreign origins, resources, redirects, ambiguous query parameters or unrecognized continuation shapes cannot acquire another token or satisfy evidence. The global Azure POST allowlist remains unchanged; the dedicated query transport accepts only these three operations.

Module-owned inventory and query reads limit each response to 8 MiB before JSON parsing and aggregate response bodies to 32 MiB. Each subscription capture has a 300-request budget, elapsed-time checks against 120 seconds before attempts/polls, and up to 20-second per-request socket timeouts. Semantic queries allow at most 32 pages (or the smaller selected page bound), 12 LRO polls, and bounded Retry-After waits. Inventory pages also honor the shared page/call/deadline budgets; inventory types cap at 1,000 resources each and projected paths cap at 4,096 rows. Partial pages, exhausted limits, changed generations or unreadable facts cannot yield a complete successful collection. Existing generic Azure discovery/enrichment transport is unchanged; the pre-parse body limits described here apply to this module's authoritative rereads.

No VM starts, policy/route/NSG changes, grants, secret reads or traffic probes are performed. Permissions are not created automatically. A denied read remains DENIED/UNKNOWN coverage and the signed control cannot pass from that incomplete collection.

Official contracts: [effective NSGs](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/list-effective-network-security-groups), [effective routes](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/get-effective-route-table), [effective security-admin rules](https://learn.microsoft.com/en-us/rest/api/networkmanager/list-network-manager-effective-security-admin-rules/list-network-manager-effective-security-admin-rules), [network permissions](https://learn.microsoft.com/en-us/azure/role-based-access-control/permissions/networking), [cross-subscription load balancing](https://learn.microsoft.com/en-us/azure/load-balancer/cross-subscription-overview), and [IP-based backend pools](https://learn.microsoft.com/en-us/azure/load-balancer/backend-pool-management).

## Operator criteria and freshness

Both local and Cognito connector intake accept this Azure-only namespace under `options.compliance_parameters`:

```json
{
  "azure_nsg_ingress": {
    "status": "collected",
    "scope": "/subscriptions/11111111-2222-3333-4444-555555555555",
    "observed_at": "2026-10-16T01:00:00Z",
    "max_age_seconds": 300,
    "approvedInternetPorts": [443]
  }
}
```

These are the exact allowed fields. Supply the actual review time with a timezone; the example timestamp is illustrative. Age must be an integer from 1 to 86,400 seconds. Ports must be unique non-boolean integers from 1 to 65,535, with at most 4,096 entries; an empty approved set is valid. This input supplies normative criteria, not native observations or externally verified approval identity.

Null/malformed declarations, extra observed paths/rules/coverage, and competing `options.compliance_policy.sw31` declarations are rejected before credentials. Collection also rejects wildcard selection or a selected subscription differing from the declared scope before constructing transport. Intake validates the declared identity; collection binds it to the actual selection.

The supplied review clock is preserved. A structurally valid stale or future declaration may be saved, but contributes no approved-port metadata at the snapshot clock, leaving the signed control UNKNOWN. The collector never refreshes approval time automatically. Fresh criteria become only `metadata.compliance_policy.sw31.approvedInternetPorts`; native facts are gathered independently.

The separate `azure.other.nsg_port_protocol_assignment` control additionally requires actual service measurements. This producer does not collect or invent them, and that control remains UNKNOWN without such evidence.

## Validation scope

Portable tests cover native metadata joins, strict scope/identity/ETag handling, default rules in both directions, denied/partial/unsupported outcomes, safe query/LRO/pagination/bounds, operator input, and actual public collection/evaluation with inert HTTP responses. The refreshed NSG is installed before ordinary diagnostics enrichment; the combined regression retains fresh NSG diagnostic settings and coverage, network-watcher flow logs and their coverage, and concrete child identities/parent bindings.

The retained evidence lineage is 97 core cases through V2, three new V3 membership cases, 28 intake/public-flow cases, and one new V4 enrichment regression. Results were accumulated in directed cohorts, not one final blanket rerun. Earlier failures, fixes and the disclosed accidental 95-case selection are retained in development receipts. These are local tests; they do not constitute live Azure permission/API validation, measured-service proof, certification or complete closure of the CSPM backlog.
