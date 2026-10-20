import type { Graph, GraphEdge, GraphNode } from "./types";

export const NETWORK_BUDGET = 280;
export const NETWORKS_PER_PAGE = 8;
export const AREAS_PER_PAGE = 24;
export const ASSETS_PER_PAGE = 16;
const networks = new Set(["vpc", "network", "vnet"]);
const areas = new Set(["subnet", "subnetwork", "namespace"]);
export const serviceTypes = new Set(["security_group", "network_acl", "network_firewall", "network_firewall_policy", "network_firewall_rule_group", "firewall", "firewall_policy", "nsg", "networkpolicy", "route_table", "transit_gateway_route_table", "route", "internet_gateway", "nat_gateway", "transit_gateway", "transit_gateway_attachment", "router", "load_balancer", "classic_load_balancer", "loadbalancer", "application_gateway", "ingress", "vpc_peering", "vnet_peering", "peering", "vpn_gateway", "vpn_connection", "vpn_tunnel", "ec2_client_vpn_endpoint", "forwarding_rule", "vpc_endpoint", "vpc_endpoint_service", "ec2_instance_connect_endpoint", "private_endpoint", "virtual_network_gateway", "elastic_ip", "ec2_eip", "address", "url_map", "backend_bucket", "health_check"]);
export const providerNames: Record<string, string> = { aws: "AWS", gcp: "Google Cloud", azure: "Azure", k8s: "Kubernetes" };
function firstReadable(...values: unknown[]) {
  const value = values.find((item) => typeof item === "string" && item || typeof item === "number" && Number.isFinite(item));
  return value === undefined ? "" : String(value);
}
export function kind(n: GraphNode) { return firstReadable(n.type, n.kind, n.service) || "resource"; }
export function label(n: GraphNode) { return firstReadable(n.label, n.name, n.native_id, n.id) || "Unnamed resource"; }
export function observed(n: GraphNode) {
  const evidence = n.evidence && typeof n.evidence === "object" ? n.evidence as Record<string, unknown> : {};
  return evidence.inventory_status !== "reference_only" && !n.outside_aggregate;
}
function clusterOf(n: GraphNode) {
  if (typeof n.cluster_id === "string" && n.cluster_id) return n.cluster_id;
  const evidence = n.evidence && typeof n.evidence === "object" ? n.evidence as Record<string,unknown> : {};
  if (typeof evidence.cluster_id === "string" && evidence.cluster_id) return evidence.cluster_id;
  const facets = n.facets && typeof n.facets === "object" ? n.facets as Record<string,unknown> : {};
  if (typeof facets.cluster_id === "string" && facets.cluster_id) return facets.cluster_id;
  const specific = n.provider_specific && typeof n.provider_specific === "object" ? n.provider_specific as Record<string,unknown> : {};
  if (typeof specific.cluster_id === "string" && specific.cluster_id) return specific.cluster_id;
  const resource = (n.evidence as Record<string,unknown> | undefined)?.native_resource;
  const data = resource && typeof resource === "object" ? (resource as Record<string,unknown>).data : undefined;
  const provenance = data && typeof data === "object" ? (data as Record<string,unknown>).provenance : undefined;
  if (provenance && typeof provenance === "object" && typeof (provenance as Record<string,unknown>).cluster_id === "string") return String((provenance as Record<string,unknown>).cluster_id);
  const native = String(n.native_id || "");
  if (native.startsWith("k8s://")) {
    try { const host = new URL(native).host; if (host) return decodeURIComponent(host); } catch { /* malformed native ID remains in its collected scope */ }
  }
  // Scope is administrative and may be a namespace. Keep it distinct without
  // claiming it is a verified cluster identity.
  return `unknown:${String(n.scope || "unspecified scope")}`;
}
function field(n: GraphNode, key: string): unknown {
  const native = (n.evidence as Record<string, unknown> | undefined)?.native_resource;
  const data = native && typeof native === "object" ? (native as Record<string, unknown>).data : undefined;
  const d = data && typeof data === "object" ? data as Record<string,unknown> : {};
  const properties = d.properties && typeof d.properties === "object" ? d.properties as Record<string,unknown> : {};
  return n[key] ?? d[key] ?? properties[key];
}
export function cidrs(n: GraphNode): string[] {
  const values = [field(n, "CidrBlock"), field(n, "cidrBlock"), field(n, "ipCidrRange"), field(n, "addressSpace"), field(n, "addressPrefix"), field(n, "addressPrefixes")];
  const out: string[] = [];
  const scan = (value: unknown) => {
    if (typeof value === "string" && /\//.test(value)) out.push(value);
    else if (Array.isArray(value)) value.forEach(scan);
    else if (value && typeof value === "object") Object.values(value).forEach(scan);
  };
  values.forEach(scan);
  return [...new Set(out)];
}
export type Group = { id: string; title: string; provider: string; root?: GraphNode; members: GraphNode[]; areas: GraphNode[]; count: number; observedCount: number; unresolvedCount: number };
export type NetworkModel = { providers: string[]; groups: Group[]; byId: Map<string, GraphNode>; edges: GraphEdge[]; owner: Map<string, string>; area: Map<string, string> };
export function networkModel(graph: Graph): NetworkModel {
  const byId = new Map(graph.nodes.map(n => [n.id, n]));
  const parents = new Map<string, string>();
  for (const n of graph.nodes) {
    const parent = typeof n.parent_id === "string" ? byId.get(n.parent_id) : undefined;
    if (parent && parent.provider === n.provider) parents.set(n.id, parent.id);
  }
  for (const e of graph.edges) {
    const source = byId.get(e.source), target = byId.get(e.target);
    if (!source || !target || source.provider !== target.provider) continue;
    if (e.type === "contains" && !parents.has(target.id)) parents.set(target.id, source.id);
    if (["associated_with", "contained_in_namespace", "namespace_membership", "load_balancer_subnet"].includes(String(e.type)) && (networks.has(kind(target)) || areas.has(kind(target))) && !parents.has(source.id)) parents.set(source.id, target.id);
  }
  const owner = new Map<string, string>(), area = new Map<string, string>();
  const find = (n: GraphNode, predicate: (item: GraphNode) => boolean) => {
    let current: GraphNode | undefined = n;
    const visited = new Set<string>();
    while (current && !visited.has(current.id)) {
      if (predicate(current)) return current.id;
      visited.add(current.id);
      current = byId.get(parents.get(current.id) || "");
    }
    return undefined;
  };
  const grouped = new Map<string, Group>();
  for (const n of graph.nodes) {
    const provider = String(n.provider || "unknown");
    const network = provider === "k8s" ? `cluster:${clusterOf(n)}` : find(n, x => networks.has(kind(x))) || `outside:${provider}:${String(n.scope || "unknown")}`;
    const areaId = find(n, x => areas.has(kind(x)));
    owner.set(n.id, network);
    if (areaId) area.set(n.id, areaId);
    let group = grouped.get(network);
    if (!group) {
      const root = byId.get(network);
      const title = provider === "k8s" ? (clusterOf(n).startsWith("unknown:") ? `Cluster unknown · scope ${String(n.scope || "unspecified")}` : `Cluster · ${clusterOf(n)}`) : root ? label(root) : `Shared / linked resources · ${String(n.scope || "unknown")}`;
      group = { id: network, title, provider, root, members: [], areas: [], count: 0, observedCount: 0, unresolvedCount: 0 };
      grouped.set(network, group);
    }
    group.members.push(n);
    group.count += Number(n.underlying_count || 1);
    group.observedCount += observed(n) ? Number(n.underlying_count || 1) : 0;
    group.unresolvedCount += observed(n) ? 0 : Number(n.underlying_count || 1);
    if (areas.has(kind(n))) group.areas.push(n);
  }
  const groups = [...grouped.values()].sort((a,b) => a.provider.localeCompare(b.provider) || Number(!!b.root)-Number(!!a.root) || a.title.localeCompare(b.title) || a.id.localeCompare(b.id));
  const providers = [...new Set(groups.filter(g => g.observedCount > 0).map(g => g.provider))].sort((a,b) => ["aws", "gcp", "azure", "k8s"].indexOf(a) - ["aws", "gcp", "azure", "k8s"].indexOf(b));
  return { providers, groups, byId, edges: graph.edges, owner, area };
}
export type VisibleItem = { id: string; title: string; subtitle: string; kind: string; parentId?: string; x?: number; y?: number; width: number; height: number; count: number; hidden: number; node?: GraphNode; group?: Group; aggregate?: boolean };
export type VisibleEdge = {
  id: string; source: string; target: string; type: string; count: number;
  // Indices refer to NetworkModel.edges. Store every loaded membership without
  // copying native evidence into each display group.
  recordIndices: number[];
  records: GraphEdge[]; // bounded preview only
  availableCount: number; // loaded, non-aggregate native relationship records
  unresolvedCount: number; // represented underlying records not loaded
  uncertain: boolean;
};
export type NetworkView = { items: VisibleItem[]; edges: VisibleEdge[]; hiddenNodes: number; hiddenEdges: number; matching: GraphNode[]; pageCount: number; pageLabel: string; visibleEdgeTotal: number };
function titleFor(n: GraphNode) { return label(n); }
export function networkView(model: NetworkModel, provider: string, selectedNetwork: string, selectedArea: string, search: string, page = 0, focusNetworks: string[] = [], focusAssets: string[] = [], expandedAreas: string[] = []): NetworkView {
  const providerGroups = model.groups.filter(g => g.provider === provider);
  const groupById = new Map(providerGroups.map(g => [g.id, g]));
  const linked = new Set<string>();
  if (selectedNetwork) {
    for (const edge of model.edges) {
      const from = model.owner.get(edge.source), to = model.owner.get(edge.target);
      if (from === selectedNetwork && to && to !== from) linked.add(to);
      if (to === selectedNetwork && from && to !== from) linked.add(from);
    }
    // A peering resource often lives outside either VPC. Keep its other VPC
    // endpoint visible with its native name and scope when one side is opened.
    const peerGroups = new Set([...linked].filter(id => id.startsWith("outside:")));
    for (const edge of model.edges) {
      if (edge.type !== "peering_endpoint") continue;
      const from = model.owner.get(edge.source), to = model.owner.get(edge.target);
      if (from && peerGroups.has(from) && to && to !== selectedNetwork) linked.add(to);
      if (to && peerGroups.has(to) && from && from !== selectedNetwork) linked.add(from);
    }
  }
  const groups = selectedNetwork
    ? [...providerGroups.filter(g => g.id === selectedNetwork),
        ...providerGroups.filter(g => g.id !== selectedNetwork && focusNetworks.includes(g.id))
          .sort((a,b) => focusNetworks.indexOf(a.id) - focusNetworks.indexOf(b.id)),
        ...providerGroups.filter(g => g.id !== selectedNetwork && linked.has(g.id) && !focusNetworks.includes(g.id)).slice(0, 12)]
    : focusNetworks.length ? providerGroups.filter(g => focusNetworks.includes(g.id))
        .sort((a,b) => focusNetworks.indexOf(a.id) - focusNetworks.indexOf(b.id)) : providerGroups;
  const term = search.trim().toLowerCase();
  const matches = (n: GraphNode) => `${label(n)} ${kind(n)} ${String(n.scope || "")} ${String(n.native_id || "")}`.toLowerCase().includes(term);
  const matching = groups.flatMap(g => g.members.filter(matches));
  const primary = groupById.get(selectedNetwork);
  const matchedAreas = new Set(primary?.members.filter(matches).map(n => model.area.get(n.id)).filter(Boolean));
  const focusRank = (n: GraphNode) => focusAssets.includes(n.id) ? -1 : 0;
  const focusAreas = focusAssets.map(id => model.area.get(id));
  const areaCandidates = (primary?.areas.filter(n => !term || matches(n) || matchedAreas.has(n.id)) || []).sort((a,b) => Number(!focusAreas.includes(a.id))-Number(!focusAreas.includes(b.id)));
  const assetCandidates = (primary?.members.filter(n => model.area.get(n.id) === selectedArea && n.id !== selectedArea && matches(n)) || []).sort((a,b) => focusRank(a)-focusRank(b));
  const phase = !selectedNetwork ? "network" : !selectedArea ? "area" : "asset";
  const directCandidates = primary?.members.filter(n => n.id !== primary.root?.id && !areas.has(kind(n)) && !model.area.has(n.id) && matches(n)) || [];
  const pageCount = Math.max(1, phase === "area" ? Math.max(Math.ceil(areaCandidates.length / AREAS_PER_PAGE), Math.ceil(directCandidates.length / 24)) : Math.ceil((phase === "network" ? groups.length : assetCandidates.length) / (phase === "network" ? NETWORKS_PER_PAGE : ASSETS_PER_PAGE)));
  const shownGroups = phase === "network" ? groups.slice(page * NETWORKS_PER_PAGE, (page + 1) * NETWORKS_PER_PAGE) : groups;
  const areaPage = phase === "asset" ? Math.floor(Math.max(0, areaCandidates.findIndex(n => n.id === selectedArea)) / AREAS_PER_PAGE) : page;
  const shownAreas = selectedNetwork ? areaCandidates.slice(areaPage * AREAS_PER_PAGE, (areaPage + 1) * AREAS_PER_PAGE) : [];
  const expandedAreaIds = new Set([...expandedAreas, ...(selectedArea ? [selectedArea] : [])]);
  // Keep the VPC's sibling subnets visible. Only the active subnet's resource page advances.
  const shownAssets = shownAreas.filter(area => expandedAreaIds.has(area.id))
    .sort((a,b) => Number(b.id === selectedArea) - Number(a.id === selectedArea))
    .flatMap(area => {
      const candidates = area.id === selectedArea ? assetCandidates : (primary?.members.filter(n => model.area.get(n.id) === area.id && n.id !== area.id && matches(n)) || []).sort((a,b) => focusRank(a)-focusRank(b));
      const offset = area.id === selectedArea ? page * ASSETS_PER_PAGE : 0;
      return candidates.slice(offset, offset + ASSETS_PER_PAGE);
    }).slice(0, Math.max(ASSETS_PER_PAGE, NETWORK_BUDGET - shownAreas.length - 25 - shownGroups.length * 9));
  const richOverview = phase === "network" && providerGroups.filter(g => !!g.root).length <= 3;
  const items: VisibleItem[] = [];
  const representative = new Map<string, string>();
  const displayed = new Set<string>();
  for (const group of shownGroups) {
    const rootId = `network:${group.id}`;
    const expanded = group.id === selectedNetwork;
    const focusedMembers = group.members.filter(n => focusAssets.includes(n.id) && !n.stub && !n.aggregate);
    const preview = (richOverview || focusedMembers.length > 0) && !expanded;
    const memberWeight = (node: GraphNode) => Number(node.underlying_count || 1);
    const areaWeights = new Map<string, number>();
    for (const member of group.members) {
      const areaId = model.area.get(member.id);
      if (areaId) areaWeights.set(areaId, (areaWeights.get(areaId) || 0) + memberWeight(member));
      representative.set(member.id, rootId);
    }
    const directAreas = expanded ? shownAreas : preview ? group.areas.slice(0, 4) : [];
    const ordinaryServices = (expanded || preview)
      ? group.members.filter(n => n.id !== group.root?.id && !areas.has(kind(n)) && !model.area.has(n.id) && (!term || matches(n))).slice(expanded && !selectedArea ? page * 24 : 0, expanded ? (!selectedArea ? page * 24 : 0) + 24 : 4)
      : [];
    const directServices = preview
      ? [...new Map([...focusedMembers, ...ordinaryServices].map(n => [n.id, n])).values()]
      : ordinaryServices;
    const assets = expanded ? shownAssets : [];
    const areaItems: VisibleItem[] = directAreas.map(area => {
      const areaAssets = assets.filter(n => model.area.get(n.id) === area.id);
      const count = areaWeights.get(area.id) || memberWeight(area);
      const width = areaAssets.length ? 180 : 144;
      const height = areaAssets.length ? 120 : 48;
      displayed.add(area.id);
      representative.set(area.id, `area:${area.id}`);
      return { id:`area:${area.id}`, title:label(area), subtitle:`${provider === "k8s" ? "Namespace · workload group" : "Subnet"} · ${count} resources`, kind:kind(area), parentId:rootId, width, height, count, hidden:Math.max(0,count-memberWeight(area)-areaAssets.reduce((sum,n)=>sum+memberWeight(n),0)), node:area, aggregate:!!area.aggregate };
    });
    for (const member of group.members) {
      const areaId = model.area.get(member.id);
      if (areaId && areaItems.some(item => item.node?.id === areaId)) representative.set(member.id, `area:${areaId}`);
    }
    const serviceItems: VisibleItem[] = directServices.map(n => {
      displayed.add(n.id);
      representative.set(n.id, `asset:${n.id}`);
      return { id:`asset:${n.id}`, title:label(n), subtitle:kind(n).replaceAll("_", " "), kind:kind(n), parentId:rootId, width:128, height:40, count:memberWeight(n), hidden:0, node:n, aggregate:!!n.aggregate };
    });
    const assetItems: VisibleItem[] = assets.map(n => {
      displayed.add(n.id);
      representative.set(n.id, `asset:${n.id}`);
      return { id:`asset:${n.id}`, title:label(n), subtitle:kind(n).replaceAll("_", " "), kind:kind(n), parentId:`area:${model.area.get(n.id)}`, width:128, height:40, count:memberWeight(n), hidden:0, node:n, aggregate:!!n.aggregate };
    });
    if (group.root) displayed.add(group.root.id);
    const direct = [...areaItems, ...serviceItems];
    const width = direct.length ? 200 : 144;
    const height = direct.length ? 120 : 48;
    const visibleWeight = group.members.filter(n => displayed.has(n.id)).reduce((sum,n)=>sum+memberWeight(n),0);
    items.push({ id:rootId, title:group.title, subtitle:`${group.count.toLocaleString()} resources · ${group.unresolvedCount} unresolved · ${group.root?.scope || group.members[0]?.scope || "scope unknown"}`, kind: provider === "k8s" ? "cluster" : kind(group.root || {id:"",type:"network"}), width, height, count:group.count, hidden:Math.max(0,group.count-visibleWeight), node:group.root, group });
    items.push(...areaItems,...serviceItems,...assetItems);
  }
  const edgeGroups = new Map<string, VisibleEdge>();
  let hiddenEdges = 0;
  const visibleById = new Map(items.map(item => [item.id,item]));
  for (const [index, edge] of model.edges.entries()) {
    if (model.byId.get(edge.source)?.provider !== provider && model.byId.get(edge.target)?.provider !== provider) continue;
    const source = representative.get(edge.source), target = representative.get(edge.target);
    const count = Number(edge.underlying_count || 1);
    if (!source || !target || source === target) { hiddenEdges += count; continue; }
    if (["associated_with","contains","contained_in_namespace","namespace_membership"].includes(String(edge.type)) &&
        (visibleById.get(source)?.parentId === target || visibleById.get(target)?.parentId === source)) {
      // Native containment is already shown by parentId geometry; its record
      // stays in the graph and inspector without crossing its own container.
      hiddenEdges += count;
      continue;
    }
    const type = String(edge.type || edge.label || "observed relationship");
    const key = JSON.stringify([source,target,type,edge.layer || "structural"]);
    const existing = edgeGroups.get(key);
    const available = edge.aggregate ? 0 : Math.min(1, count);
    if (existing) {
      existing.count += count;
      existing.availableCount += available;
      existing.unresolvedCount += Math.max(0, count - available);
      existing.recordIndices.push(index);
      if (existing.records.length < 20) existing.records.push(edge);
    } else edgeGroups.set(key,{id:key,source,target,type,count,recordIndices:[index],records:[edge],
      availableCount:available,unresolvedCount:Math.max(0,count-available),
      uncertain:edge.layer === "modeled_rule" || type === "rule_candidate"});
  }
  // A peering object is stored outside its two VPCs. Project its two
  // explicit endpoint references onto the VPC pair so the link is visible
  // in the overview. It remains a candidate until routes/policies are tested.
  {
    const peerLinks = new Map<string, { network: string; index: number }[]>();
    model.edges.forEach((edge, index) => {
      if (edge.type !== "peering_endpoint") return;
      const source = model.byId.get(edge.source), target = model.byId.get(edge.target);
      const peer = source && kind(source).includes("peering") ? source : target && kind(target).includes("peering") ? target : undefined;
      const network = peer?.id === edge.source ? target : peer?.id === edge.target ? source : undefined;
      if (!peer || !network || !networks.has(kind(network))) return;
      const list = peerLinks.get(peer.id) || [];
      list.push({ network: network.id, index });
      peerLinks.set(peer.id, list);
    });
    for (const [peerId, endpoints] of peerLinks) {
      const ids = [...new Set(endpoints.map(item => item.network))];
      if (ids.length !== 2) continue;
      const [source, target] = ids.map(id => `network:${id}`);
      if (!visibleById.has(source) || !visibleById.has(target)) continue;
      const indices = endpoints.map(item => item.index);
      const peer = model.byId.get(peerId);
      const key = `peering:${peerId}`;
      edgeGroups.set(key, { id:key, source, target,
        type:`Peering configured · ${peer ? label(peer) : peerId}`,
        count:1, recordIndices:indices, records:indices.map(index => model.edges[index]),
        availableCount:indices.filter(index => !model.edges[index].aggregate).length,
        unresolvedCount:indices.filter(index => !!model.edges[index].aggregate).length,
        uncertain:true });
    }
  }
  const ids = new Set(items.map(item => item.id));
  const visibleEdgeGroups = [...edgeGroups.values()].filter(edge => ids.has(edge.source) && ids.has(edge.target));
  const edges = visibleEdgeGroups.slice(0,400);
  hiddenEdges += visibleEdgeGroups.slice(400).reduce((sum,edge)=>sum+edge.count,0);
  const hiddenNodes = Math.max(0, groups.reduce((sum,g)=>sum+g.count,0) - [...displayed].reduce((sum,id)=>sum+Number(model.byId.get(id)?.underlying_count || 1),0));
  return { items, edges, matching, hiddenNodes, hiddenEdges, pageCount, pageLabel:phase === "network" ? "networks" : phase === "area" ? provider === "k8s" ? "namespace groups" : "subnets" : "resources", visibleEdgeTotal:visibleEdgeGroups.length };
}

export function nativeDetails(n: GraphNode): { name: string; value: string }[] {
  const scope = String(n.scope || "");
  const provider = String(n.provider || "");
  const scopeParts = scope.split("/");
  const native = (n.evidence as Record<string, unknown> | undefined)?.native_resource;
  const data = native && typeof native === "object" ? (native as Record<string, unknown>).data : undefined;
  const d = data && typeof data === "object" ? data as Record<string, unknown> : {};
  const scopeName = provider === "aws" ? "Account" : provider === "gcp" ? "Project" : provider === "azure" ? "Subscription" : provider === "k8s" ? "Collection scope" : "Scope";
  const arm = `${scope} ${String(n.native_id || "")}`;
  const scopeValue = provider === "aws" ? scopeParts[0] : provider === "gcp" && scopeParts[0] === "projects" ? scopeParts[1] : provider === "azure" ? arm.match(/(?:^|\/)subscriptions\/([^/\s]+)/i)?.[1] : scope;
  const region = n.region || n.location || d.location || (provider === "aws" ? scopeParts[1] : provider === "gcp" && kind(n) === "network" ? "Global" : undefined);
  const fields: [string, unknown][] = [["Name", label(n)], ["Type", kind(n).replaceAll("_", " ")], ["Native ID", n.native_id || "Unknown"], ["Resource ID", n.resource_id || "Unknown"], [scopeName, scopeValue || "Unknown"], ["Region", region || "Unknown"]];
  if (kind(n) !== "security_group" || cidrs(n).length) fields.push(["CIDR", cidrs(n).join(", ") || "Unknown"]);
  if (provider === "azure") fields.push(["Tenant", n.tenant_id || d.tenantId]);
  for (const [name,key] of [["Private IP", "PrivateIpAddress"], ["Public IP", "PublicIpAddress"], ["IP address", "ipAddress"], ["State", "State"], ["Description", "Description"], ["VPC", "VpcId"], ["Subnet", "SubnetId"], ["Interface", "NetworkInterfaceId"], ["Network", "network"], ["Subnetwork", "subnetwork"], ["Direction", "direction"], ["Priority", "priority"]]) fields.push([name, d[key]]);
  for (const [name,key] of [["Endpoint service", "ServiceName"], ["Endpoint type", "VpcEndpointType"], ["Transit gateway", "TransitGatewayId"], ["Transit route table", "TransitGatewayRouteTableId"], ["VPN gateway", "VpnGatewayId"], ["Customer gateway", "CustomerGatewayId"], ["Attachment resource", "ResourceId"], ["Attachment type", "ResourceType"], ["Endpoint DNS", "Endpoint"], ["Network firewall policy", "FirewallPolicyArn"], ["Public address", "PublicIp"], ["Address", "address"], ["Address type", "addressType"]]) fields.push([name, d[key]]);
  for (const [name,key] of [["Subnets", "SubnetIds"], ["Interfaces", "NetworkInterfaceIds"], ["Security groups", "SecurityGroupIds"], ["Route tables", "RouteTableIds"]]) if (Array.isArray(d[key])) fields.push([name, (d[key] as unknown[]).filter(x=>typeof x==="string").join(", ")]);
  const props = d.properties && typeof d.properties === "object" ? d.properties as Record<string,unknown> : {};
  for (const [name,key] of [["Private IP", "privateIPAddress"], ["Public IP", "publicIPAddress"], ["Address", "ipAddress"], ["Provisioning state", "provisioningState"]]) fields.push([name, props[key]]);
  if (Array.isArray(d.networkInterfaces)) for (const item of d.networkInterfaces.slice(0,8)) {
    if (!item || typeof item !== "object") continue;
    const iface = item as Record<string,unknown>;
    fields.push(["Interface IP", iface.networkIP]);
    if (Array.isArray(iface.accessConfigs)) for (const access of iface.accessConfigs.slice(0,4)) if (access && typeof access === "object") fields.push(["External IP", (access as Record<string,unknown>).natIP]);
  }
  if (Array.isArray(props.ipConfigurations)) for (const item of props.ipConfigurations.slice(0,8)) {
    const config = item && typeof item === "object" ? (item as Record<string,unknown>).properties : undefined;
    if (config && typeof config === "object") fields.push(["Private IP", (config as Record<string,unknown>).privateIPAddress]);
  }
  const firewall = d.Firewall && typeof d.Firewall === "object" ? d.Firewall as Record<string,unknown> : {};
  fields.push(["Firewall VPC", firewall.VpcId], ["Firewall policy", firewall.FirewallPolicyArn]);
  const cluster = d.Cluster && typeof d.Cluster === "object" ? (d.Cluster as Record<string,unknown>).cluster : undefined;
  if (cluster && typeof cluster === "object") {
    const c = cluster as Record<string,unknown>;
    fields.push(["Cluster endpoint", c.endpoint]);
    const attachment = c.resourcesVpcConfig && typeof c.resourcesVpcConfig === "object" ? c.resourcesVpcConfig as Record<string,unknown> : {};
    fields.push(["Cluster VPC", attachment.vpcId], ["Cluster subnets", Array.isArray(attachment.subnetIds) ? attachment.subnetIds.join(", ") : undefined]);
  }
  const placement = (n.evidence as Record<string,unknown> | undefined)?.placement_status;
  if (placement === "unknown") fields.push(["Network placement", "Unknown: native attachment or endpoint facts missing"]);
  const status = d.status && typeof d.status === "object" ? d.status as Record<string,unknown> : {};
  fields.push(["Pod IP", status.podIP], ["Host IP", status.hostIP]);
  fields.push(...attachmentDetails(d));
  const observed = Array.isArray(n.network_attributes) ? n.network_attributes : Array.isArray(d.NetworkAttributes) ? d.NetworkAttributes : [];
  for (const item of observed) {
    if (!item || typeof item !== "object") continue;
    const attribute = item as Record<string,unknown>;
    if (typeof attribute.name !== "string") continue;
    const value = attribute.value;
    if (!["string","number","boolean"].includes(typeof value) && !(Array.isArray(value) && value.every(v => ["string","number","boolean"].includes(typeof v)))) continue;
    const generic = /^(value|id|name|type|address|mode|enabled|status|state)$/i.test(attribute.name);
    const label = generic && typeof attribute.path === "string" ? attribute.path : attribute.name;
    const name = label.replace(/([a-z0-9])([A-Z])/g,"$1 $2").replaceAll("_"," ").replaceAll("."," / ");
    const text = Array.isArray(value) ? value.join(", ") : String(value);
    if (!fields.some(([label,existing]) => label.toLowerCase() === name.toLowerCase() && String(existing) === text)) fields.push([name,text]);
  }
  return fields.filter(([,v]) => typeof v === "string" && v || typeof v === "number").map(([name,value]) => ({ name, value: String(value) }));
}

function attachmentDetails(data: Record<string,unknown>): [string,string][] {
  const names: Record<string,string> = {
    VpcId:"VPC", vpcId:"VPC", SubnetId:"Subnet", subnetId:"Subnet", SubnetIds:"Subnets", subnetIds:"Subnets", subnets:"Subnets",
    SecurityGroups:"Security groups", SecurityGroupIds:"Security groups", securityGroups:"Security groups", securityGroupIds:"Security groups",
    network:"Network", subnetwork:"Subnetwork", privateNetwork:"Private network", authorizedNetwork:"Authorized network",
    FileSystemId:"EFS filesystem", MountTargetId:"Mount target", IpAddress:"IP address", Ipv6Address:"IPv6 address",
    VpcOriginId:"VPC origin", OriginEndpointArn:"Origin target", HTTPPort:"Origin HTTP port", HTTPSPort:"Origin HTTPS port",
    OriginProtocolPolicy:"Origin protocol", DomainName:"Origin hostname", clusterArn:"ECS cluster", serviceArn:"Service ARN", taskArn:"ECS task",
    connector:"VPC connector", vpcConnector:"VPC connector", egress:"VPC egress", ingress:"Ingress", networkEndpointType:"Endpoint type",
    pscTargetService:"PSC target", targetService:"Producer forwarding rule", pscServiceAttachmentLink:"PSC attachment", pscConnectionStatus:"PSC status",
    publicNetworkAccess:"Public network access", virtualNetworkSubnetId:"Integration subnet", vnetSubnetID:"Node subnet", podSubnetID:"Pod subnet",
    privateLinkServiceId:"Private Link target", groupIds:"Private Link subresources", provisioningState:"Provisioning state",
    volumeName:"Persistent volume", claimName:"Volume claim", volumeHandle:"Cloud storage handle", driver:"Storage driver", server:"NFS server",
    HostVPCId:"VPC", VpcConnectorArn:"App Runner connector", VpcEndpointId:"Private endpoint", SecurityGroupIdList:"Security groups",
    infrastructureSubnetId:"Environment subnet", environmentId:"App environment", managedEnvironmentId:"App environment",
    EndpointConfigName:"Endpoint configuration", DirectInternetAccess:"Direct Internet access", AppNetworkAccessType:"App network access",
    EnableNetworkIsolation:"Network isolation", gatewayClassName:"Gateway class", storageClassName:"Storage class",
    ResolverEndpointId:"DNS resolver endpoint", ResolverRuleId:"DNS resolver rule", networkUrl:"Network", targetNetwork:"DNS peer network",
    controllerName:"Gateway controller", externalName:"External service name", external:"External ingress", publicNetworkAccessForIngestion:"Public ingestion",
    containerPort:"Container port", hostPort:"Host port", hostNetwork:"Host networking", targetPort:"Target port", hostnames:"Route hostnames",
    vpcSubnetIds:"Subnets", vpcSecurityGroupIds:"Security groups", networkInterfaceIds:"Interfaces", subnet:"Subnetwork",
    serviceNetworkId:"Service network", serviceNetworkArn:"Service network", serviceId:"Service", resourceGatewayId:"Resource gateway",
    virtualNetworkSubnetResourceId:"Agent pool subnet", publiclyAccessible:"Public access", disableExecuteApiEndpoint:"Default API endpoint disabled",
    enablePrivateServiceConnect:"PSC enabled", dedicatedEndpointDns:"Dedicated endpoint DNS", DnsResolvers:"DNS resolvers",
    SubnetArns:"Subnets", SecurityGroupArns:"Security groups", GatewayARN:"Storage gateway", Ec2InstanceId:"Gateway instance",
    VpcEndpointService:"Endpoint service", PrivateLinkEndpoint:"Private Link endpoint", Ipv4Address:"IPv4 address",
    VPCId:"Associated VPC", VPCRegion:"Associated VPC region", PrivateZone:"Private DNS zone",
    ConnectionId:"VPC link", connectionId:"VPC link", ConnectionType:"Connection type", connectionType:"Connection type", IntegrationUri:"Integration target",
    LoadBalancerArn:"Load balancer", Port:"Port", Protocol:"Protocol", SslPolicy:"TLS policy", ServerName:"Endpoint server",
    fqdn:"Endpoint hostname", ipAddressRange:"Ingress IP range", transport:"Transport", allowInsecure:"Allow insecure ingress",
    DeploymentStatus:"Configuration deployment", vpcIdentifier:"VPC", resourceConfigurationId:"Resource configuration",
    targetGroupIdentifier:"Target group", listenerArn:"Lattice listener",
    meshes:"Meshes", gateways:"Gateways", serviceName:"Backend service", serverTlsPolicy:"Server TLS policy", clientTlsPolicy:"Client TLS policy",
    authorizationPolicy:"Authorization policy", interceptionPort:"Interception port", allowOpen:"Allow plaintext", rrdatas:"DNS addresses", ttl:"DNS TTL",
    wellKnownCACertificates:"CA trust", domainName:"Domain name", forwardingRuleState:"DNS forwarding state", targetDnsServers:"DNS forwarders",
    ipv4Address:"IPv4 address", ipv6Address:"IPv6 address", cname:"DNS alias", privateDnsZoneArmResourceId:"Private DNS zone",
    isolationMode:"Managed network isolation", serviceResourceId:"Outbound Private Link target", subresourceTarget:"Private Link subresource",
    linkedResourceId:"Linked monitor resource", ingestionAccessMode:"Ingestion access mode", queryAccessMode:"Query access mode",
    cidrs:"Service CIDRs", networkAttachment:"Network attachment", vpc:"Network", url:"Endpoint URL", CNAME:"Endpoint hostname", EndpointURL:"Endpoint URL",
    SecurityGroup:"Security group", EniId:"HSM interface", EniIp:"HSM IPv4 address", EniIpV6:"HSM IPv6 address", UriEndpoint:"Proxy endpoint",
    VerifiedAccessGroupId:"Verified Access group", VerifiedAccessInstanceId:"Verified Access instance", EndpointDomain:"Endpoint domain", ApplicationDomain:"Application domain",
    PolicyEnabled:"Policy enabled",
  };
  const containers = new Set(["properties","Config","DistributionConfig","Origins","Items","VpcOriginConfig","VpcOrigin","VpcOriginEndpointConfig",
    "networkConfiguration","awsvpcConfiguration","VpcConfig","DBSubnetGroup","DBSubnetGroupDetails","VpcSecurityGroups","Subnets","VpcOptions",
    "networkConfig","settings","ipConfiguration","pscConfig","template","vpcAccess","serviceConfig","networkInterfaces",
    "privateEndpointConnections","privateLinkServiceConnections","manualPrivateLinkServiceConnections","networkAcls","networkProfile","agentPoolProfiles",
    "spec","volumes","persistentVolumeClaim","csi","nfs","attachments","details","NetworkDetails","NetworkConfig","VpcConfiguration",
    "NetworkConfiguration","EgressConfiguration","IngressConfiguration","PhysicalConnectionRequirements","Configuration","projects","vpcConfig",
    "environment","workerPools","allocationPolicy","network","networkInterfaces","vnetConfiguration","configuration","ingress","jobTemplate",
    "endpointConfiguration","EndpointDetails","Server","vpcAccessConnector","privateVisibilityConfig","peeringConfig","networks","containers","ports","listeners","rules","backendRefs","parentRefs",
    "gcpConfig","accessConfig","networkConfigs","privateServiceConnectConfig","privateEndpoints","pscConfigs","pscConnections","endpoints","connections",
    "PrivateLinkConfig","GatewayNetworkInterfaces","VpcEndpoints","remoteAccess","resources","VPCs","NetworkIntegrations","NetworkResources","resourceMethods","methodIntegration",
    "GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS","ANY","HealthCheckConfig","MutualAuthentication","ipSecurityRestrictions","additionalPortMappings",
    "NetworkSettings","OptionSettings","config","NetworkTargets","target","defaultAction","forward","targetGroups","action","destinations","validation","targetRefs",
    "networkSettings","aRecords","aaaaRecords","cnameRecord","mxRecords","srvRecords","ptrRecords","targetDnsServers","currentDeployment","publicEndpoint","resourceConfigurationDefinition","dnsResource","ipResource",
    "managedNetwork","destination","accessModeSettings","configurationAccess","logsIngestion","metricsIngestion","vpcPeeringConfig","pscInterfaceConfig",
    "Hsms","NetworkInterfaceOptions","LoadBalancerOptions","CidrOptions","XksProxyConfiguration"]);
  const rows: [string,string][] = [];
  const seen = new Set<string>();
  const visit = (value: unknown, depth = 0) => {
    if (depth > 12 || rows.length >= 80 || !value || typeof value !== "object") return;
    if (Array.isArray(value)) { value.forEach(v => visit(v,depth + 1)); return; }
    const obj = value as Record<string,unknown>;
    const networkOptions: Record<string, Record<string,string>> = {
      "aws:ec2:vpc": {VPCId:"VPC",Subnets:"Subnets",ELBSubnets:"Load balancer subnets",DBSubnets:"Database subnets",AssociatePublicIpAddress:"Assign public IP",ELBScheme:"Load balancer scheme"},
      "aws:autoscaling:launchconfiguration": {SecurityGroups:"Security groups"},
      "aws:elb:loadbalancer": {SecurityGroups:"Security groups",ManagedSecurityGroup:"Managed security group"},
      "aws:elbv2:loadbalancer": {SecurityGroups:"Security groups",ManagedSecurityGroup:"Managed security group"},
    };
    const optionLabel = typeof obj.Namespace === "string" && typeof obj.OptionName === "string" ? networkOptions[obj.Namespace]?.[obj.OptionName] : undefined;
    if (optionLabel && typeof obj.Value === "string" && !seen.has(`${optionLabel}:${obj.Value}`)) {
      seen.add(`${optionLabel}:${obj.Value}`); rows.push([optionLabel,obj.Value]);
    }
    if ((obj.name === "networkInterfaceId" || obj.name === "subnetId") && typeof obj.value === "string") {
      const key = `${obj.name}:${obj.value}`;
      if (!seen.has(key)) { seen.add(key); rows.push([obj.name === "subnetId" ? "Subnet" : "Interface",obj.value]); }
    }
    for (const [key,item] of Object.entries(obj)) {
      const text = ["string","number","boolean"].includes(typeof item) ? String(item) : Array.isArray(item) && item.every(v => typeof v === "string") ? item.join(", ") : "";
      if (names[key] && text && !seen.has(`${key}:${text}`)) { seen.add(`${key}:${text}`); rows.push([names[key],text]); }
      if (key === "outboundRules" && item && typeof item === "object" && !Array.isArray(item)) Object.values(item).forEach(rule => visit(rule,depth + 1));
      if (key === "SubnetMapping" && item && typeof item === "object" && !Array.isArray(item)) {
        const subnets = Object.values(item).filter(subnet => typeof subnet === "string").join(", ");
        if (subnets) rows.push(["Subnets",subnets]);
      }
      if (containers.has(key)) visit(item,depth + 1);
    }
  };
  visit(data);
  return rows;
}
export function ruleRows(n: GraphNode): { order: string; direction: string; protocol: string; port: string; source: string; destination: string; action: string }[] {
  const native = (n.evidence as Record<string, unknown> | undefined)?.native_resource;
  const data = native && typeof native === "object" ? (native as Record<string, unknown>).data : undefined;
  const d = data && typeof data === "object" ? data as Record<string, unknown> : {};
  const rows: ReturnType<typeof ruleRows> = [];
  const malformed = (direction: string) => rows.push({order:"Unknown",direction,protocol:"Unknown",port:"Unknown",source:"Unknown",destination:"Unknown",action:"Malformed supplied rule"});
  const val = (x: unknown) => x === undefined || x === null || x === "" ? "Unknown" :
    typeof x === "string" || typeof x === "number" || typeof x === "boolean" ? String(x) : "Unknown (structured field)";
  const list = (x: unknown) => Array.isArray(x) ? x : [];
  const join = (x: unknown) => { const parts = list(x).flatMap((v: unknown) => v && typeof v === "object" ? Object.values(v as Record<string, unknown>).filter(y => typeof y === "string") : typeof v === "string" ? [v] : []); return parts.length ? parts.join(", ") : "Unknown"; };
  const securityGroupPeers = (r: Record<string,unknown>) => {
    const ids = [...list(r.IpRanges).map(x=>(x as Record<string,unknown>)?.CidrIp),
      ...list(r.Ipv6Ranges).map(x=>(x as Record<string,unknown>)?.CidrIpv6),
      ...list(r.UserIdGroupPairs).map(x=>(x as Record<string,unknown>)?.GroupId)]
      .filter(x=>typeof x==="string" && x);
    return ids.length ? ids.join(", ") : "Unknown";
  };
  if (kind(n) === "security_group") for (const [direction,key] of [["Inbound","IpPermissions"],["Outbound","IpPermissionsEgress"]]) for (const rule of list(d[key])) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) continue;
    const r = rule as Record<string, unknown>;
    const code = typeof r.IpProtocol === "string" || typeof r.IpProtocol === "number"
      ? String(r.IpProtocol).trim().toLowerCase() : "";
    const all = code === "-1";
    const icmp = ["icmp", "icmpv6", "1", "58"].includes(code);
    const protocol = all ? "All protocols" : code === "6" ? "TCP" : code === "17" ? "UDP"
      : code === "1" ? "ICMP" : code === "58" ? "ICMPv6" : val(r.IpProtocol);
    const port = all ? "All ports" : icmp
      ? `Type ${r.FromPort === undefined ? "Unknown" : String(r.FromPort) === "-1" ? "All" : val(r.FromPort)} · Code ${r.ToPort === undefined ? "Unknown" : String(r.ToPort) === "-1" ? "All" : val(r.ToPort)}`
      : r.FromPort === undefined ? "Unknown" : `${val(r.FromPort)}${r.ToPort !== r.FromPort ? `–${val(r.ToPort)}` : ""}`;
    rows.push({ order:"Unordered", direction, protocol, port, source: direction === "Inbound" ? securityGroupPeers(r) : "Attached resources", destination: direction === "Outbound" ? securityGroupPeers(r) : "Attached resources", action: "Allow rule" });
  }
  if (kind(n) === "network_acl") for (const rule of list(d.Entries)) {
    if (!rule || typeof rule !== "object") continue;
    const r = rule as Record<string,unknown>;
    const range = r.PortRange && typeof r.PortRange === "object" ? r.PortRange as Record<string,unknown> : {};
    const cidr = val(r.CidrBlock || r.Ipv6CidrBlock);
    const egress = r.Egress === true;
    rows.push({ order:val(r.RuleNumber), direction:egress?"Outbound":"Inbound", protocol:r.Protocol==="-1"?"All":val(r.Protocol), port:range.From===undefined?(r.Protocol==="-1"?"All":"Unknown"):`${val(range.From)}${range.To!==range.From?`–${val(range.To)}`:""}`, source:egress?"Associated subnet":cidr, destination:egress?cidr:"Associated subnet", action:val(r.RuleAction) });
  }
  if (kind(n) === "firewall") for (const [action,key] of [["Allow","allowed"],["Deny","denied"]]) for (const rule of list(d[key])) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) { malformed(val(d.direction)); continue; }
    const r = rule as Record<string, unknown>;
    rows.push({ order:val(d.priority), direction: val(d.direction), protocol: val(r.IPProtocol || r.ipProtocol), port: join(r.ports), source: join(d.sourceRanges || d.sourceTags || d.sourceServiceAccounts), destination: join(d.destinationRanges || d.targetTags || d.targetServiceAccounts), action });
  }
  if (kind(n) === "firewall_policy") for (const rule of list(d.rules)) {
    if (!rule || typeof rule !== "object") continue;
    const r=rule as Record<string,unknown>;
    const match=r.match && typeof r.match==="object" ? r.match as Record<string,unknown> : {};
    const configs=list(match.layer4Configs);
    for (const config of configs.length?configs:[{}]) {
      const c=config && typeof config==="object" ? config as Record<string,unknown> : {};
      rows.push({ order:val(r.priority), direction:val(r.direction), protocol:val(c.ipProtocol), port:join(c.ports), source:join(match.srcIpRanges || match.srcSecureTags), destination:join(match.destIpRanges || r.targetResources || r.targetSecureTags), action:val(r.action) });
    }
  }
  if (kind(n) === "nsg") for (const rule of [...list((d.properties as Record<string,unknown> | undefined)?.securityRules), ...list((d.properties as Record<string,unknown> | undefined)?.defaultSecurityRules)]) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) { malformed("Unknown"); continue; }
    const native = rule as Record<string,unknown>;
    const r = native.properties && typeof native.properties === "object" && !Array.isArray(native.properties)
      ? native.properties as Record<string,unknown> : native;
    rows.push({ order:val(r.priority), direction: val(r.direction), protocol: val(r.protocol), port: val(r.destinationPortRange || join(r.destinationPortRanges)), source: val(r.sourceAddressPrefix || join(r.sourceAddressPrefixes)), destination: val(r.destinationAddressPrefix || join(r.destinationAddressPrefixes)), action: val(r.access) });
  }
  if (kind(n) === "networkpolicy") for (const [direction,key] of [["Ingress","ingress"],["Egress","egress"]]) for (const rule of list((d.spec as Record<string,unknown> | undefined)?.[key])) {
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) { malformed(direction); continue; }
    const r = rule as Record<string,unknown>;
    const ports = list(r.ports).map(x => { const p=x && typeof x === "object" && !Array.isArray(x) ? x as Record<string,unknown> : {}; return `${val(p.protocol)}/${val(p.port)}`; }).join(", ") || "Unknown";
    const peers = (value: unknown) => list(value).map(x => {
      const peer = x && typeof x === "object" && !Array.isArray(x) ? x as Record<string,unknown> : {};
      const block = peer.ipBlock as Record<string,unknown> | undefined;
      if (block?.cidr) return `IP ${String(block.cidr)}${Array.isArray(block.except) ? ` except ${block.except.join(", ")}` : ""}`;
      if (peer.namespaceSelector || peer.podSelector) return "Namespace/pod selector";
      return "Unknown";
    }).join(", ") || "Unknown";
    rows.push({ order:"Unknown", direction, protocol: ports, port: ports, source: peers(r.from), destination: peers(r.to), action: "Policy allow candidate" });
  }
  return rows;
}
