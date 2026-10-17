import type { Graph, GraphNode, GraphEdge } from "../src/types";
const nodes: GraphNode[] = [];
const edges: GraphEdge[] = [];
function n(id: string, type: string, provider: string, scope: string, parent_id?: string, data?: Record<string, unknown>): GraphNode {
  const value: GraphNode = { id, type, provider, scope, label: id, native_id: id, resource_id: `resource:${id}`, ...(parent_id ? { parent_id } : {}), ...(data ? { evidence: { native_resource: { data } } } : {}) };
  nodes.push(value); return value;
}
function e(source: string, target: string, type: string, layer = "structural") { edges.push({ id:`${type}:${source}:${target}`, source, target, type, layer }); }
const a = "111111111111/us-east-1", b = "222222222222/us-east-1";
n("vpc-alpha", "vpc", "aws", a, undefined, { CidrBlock:"10.0.0.0/16" });
n("vpc-beta", "vpc", "aws", b, undefined, { CidrBlock:"10.0.0.0/16" });
n("subnet-a", "subnet", "aws", a, "vpc-alpha", { CidrBlock:"10.0.1.0/24" });
n("subnet-b", "subnet", "aws", b, "vpc-beta", { CidrBlock:"10.0.2.0/24" });
n("eni-a", "network_interface", "aws", a, "subnet-a", { PrivateIpAddress:"10.0.1.6", Groups:[{GroupId:"sg-a"}] });
n("instance-a", "instance", "aws", a, "subnet-a", { PrivateIpAddress:"10.0.1.6" });
n("sg-a", "security_group", "aws", a, "vpc-alpha", { IpPermissions:[{ IpProtocol:"tcp", FromPort:443, ToPort:443, IpRanges:[{CidrIp:"192.0.2.0/24"}] }] });
n("route-a", "route_table", "aws", a, "vpc-alpha", { Routes:[{DestinationCidrBlock:"10.0.0.0/16", VpcPeeringConnectionId:"peer-ab"}] });
n("peer-ab", "vpc_peering", "aws", a);
e("instance-a","eni-a","attached_interface"); e("eni-a","sg-a","protected_by"); e("route-a","subnet-a","route_association");
e("route-a","peer-ab","route_next_hop"); e("peer-ab","vpc-alpha","peering_endpoint"); e("peer-ab","vpc-beta","peering_endpoint");
// Explicit fixture reference between collected roots exercises ELK root routing;
// it is an observed record in this fixture, not a reachability conclusion.
e("vpc-alpha","vpc-beta","declared_network_reference");
const g = "projects/host-project";
n("gcp-net", "network", "gcp", g, undefined, { autoCreateSubnetworks:false });
n("gcp-sub", "subnetwork", "gcp", g, "gcp-net", { ipCidrRange:"10.8.0.0/24" });
n("gcp-vm", "instance", "gcp", g, "gcp-sub", { networkInterfaces:[{name:"nic0", network:"gcp-net"}] });
n("gcp-fw", "firewall", "gcp", g, "gcp-net", { direction:"INGRESS", sourceRanges:["198.51.100.0/24"], allowed:[{IPProtocol:"tcp",ports:["443"]}] });
n("gcp-share", "shared_vpc", "gcp", g, undefined, { relationshipType:"getXpnHost", id:"host-project" });
n("gcp-owner", "project_reference", "gcp", g); e("gcp-share","gcp-owner","shared_vpc_host");
const z = "/subscriptions/subscription-one/resourceGroups/rg-one";
n("vnet-one", "vnet", "azure", z, undefined, { location:"eastus", tenantId:"tenant-one", properties:{ addressSpace:{ addressPrefixes:["172.16.0.0/16"] } } });
n("azure-sub", "subnet", "azure", z, "vnet-one", { properties:{ addressPrefix:"172.16.1.0/24" } });
n("azure-vm", "vm", "azure", z, "azure-sub");
n("azure-nic", "nic", "azure", z, "azure-sub", { properties:{ privateIPAddress:"172.16.1.4" } });
n("azure-nsg", "nsg", "azure", z, "vnet-one", { properties:{securityRules:[{properties:{direction:"Inbound",protocol:"Tcp",destinationPortRange:"443",sourceAddressPrefix:"203.0.113.0/24",destinationAddressPrefix:"*",access:"Allow"}}]} });
for (const item of nodes.filter(n=>n.provider==="azure" && n.scope===z)) item.native_id = `${z}/providers/Microsoft.Network/${item.type}/${item.id}`;
e("azure-nic","azure-nsg","protected_by"); e("azure-vm","azure-nic","attached_interface");
const k = "cluster-prod";
n("ns-app", "namespace", "k8s", k);
n("pod-a", "pod", "k8s", k, "ns-app", { metadata:{namespace:"app"} });
n("policy-app", "networkpolicy", "k8s", k, "ns-app", {spec:{ingress:[{from:[{ipBlock:{cidr:"192.0.2.0/24"}}],ports:[{protocol:"TCP",port:8443}]}]}});
for (const item of nodes.filter(n=>n.provider==="k8s" && n.scope===k)) item.native_id = `k8s://${k}/${item.type}/${item.id}`;
e("policy-app","pod-a","policy_selects_pod","modeled_rule");
export const architectureFixture: Graph = { nodes, edges };

export function inventoryCoverageFixture(): Graph {
  const extraNodes: GraphNode[] = [
    {id:"vpce-extra",native_id:"vpce-extra",label:"Private S3 endpoint",type:"vpc_endpoint",provider:"aws",scope:a,parent_id:"subnet-a",resource_id:"resource:vpce-extra",evidence:{native_resource:{data:{VpcEndpointId:"vpce-extra",VpcId:"vpc-alpha",SubnetIds:["subnet-a"],NetworkInterfaceIds:["eni-a"],Groups:[{GroupId:"sg-a"}]}}}},
    {id:"acl-extra",native_id:"acl-extra",label:"Subnet traffic ACL",type:"network_acl",provider:"aws",scope:a,parent_id:"vpc-alpha",resource_id:"resource:acl-extra",evidence:{native_resource:{data:{NetworkAclId:"acl-extra",VpcId:"vpc-alpha",Associations:[{SubnetId:"subnet-a"}],Entries:[{RuleNumber:100,Egress:false,Protocol:"6",PortRange:{From:443,To:443},CidrBlock:"0.0.0.0/0",RuleAction:"deny"}]}}}},
    {id:"tgw-attach-extra",native_id:"tgw-attach-extra",label:"Transit attachment",type:"transit_gateway_attachment",provider:"aws",scope:a,parent_id:"vpc-alpha",resource_id:"resource:tgw-attach-extra",evidence:{native_resource:{data:{TransitGatewayAttachmentId:"tgw-attach-extra",TransitGatewayId:"tgw-extra",ResourceType:"vpc",ResourceId:"vpc-alpha"}}}},
    {id:"tgw-extra",native_id:"tgw-extra",label:"Transit gateway",type:"transit_gateway",provider:"aws",scope:a,resource_id:"resource:tgw-extra"},
    {id:"gcp-policy-extra",native_id:"organizations/42/firewallPolicies/1",label:"Hierarchy deny policy",type:"firewall_policy",provider:"gcp",scope:g,resource_id:"resource:gcp-policy-extra",evidence:{native_resource:{data:{rules:[{priority:100,direction:"INGRESS",action:"deny",match:{srcIpRanges:["0.0.0.0/0"],layer4Configs:[{ipProtocol:"tcp",ports:["443"]}]}}]}}}},
    {id:"azure-private-extra",native_id:`${z}/providers/Microsoft.Network/privateEndpoints/one`,label:"Storage private endpoint",type:"private_endpoint",provider:"azure",scope:z,parent_id:"azure-sub",resource_id:"resource:azure-private-extra",evidence:{native_resource:{data:{properties:{subnet:{id:"azure-sub"},ipConfigurations:[{properties:{privateIPAddress:"172.16.1.9"}}]}}}}},
    {id:"azure-vpn-extra",native_id:`${z}/providers/Microsoft.Network/virtualNetworkGateways/one`,label:"Azure VPN gateway",type:"virtual_network_gateway",provider:"azure",scope:z,parent_id:"vnet-one",resource_id:"resource:azure-vpn-extra"},
  ];
  const extraEdges: GraphEdge[] = [
    {id:"vpce-eni",source:"vpce-extra",target:"eni-a",type:"attached_interface"},
    {id:"vpce-sg",source:"vpce-extra",target:"sg-a",type:"protected_by"},
    {id:"acl-subnet",source:"acl-extra",target:"subnet-a",type:"route_association"},
    {id:"tgw-attachment",source:"tgw-attach-extra",target:"tgw-extra",type:"attachment_endpoint"},
    {id:"tgw-vpc",source:"tgw-attach-extra",target:"vpc-alpha",type:"attachment_endpoint"},
    {id:"policy-network",source:"gcp-policy-extra",target:"gcp-net",type:"policy_attachment"},
    {id:"private-subnet",source:"azure-private-extra",target:"azure-sub",type:"associated_with"},
  ];
  return {nodes:[...architectureFixture.nodes,...extraNodes],edges:[...architectureFixture.edges,...extraEdges]};
}

export function manySubnetsFixture(count = 131): Graph {
  const scope = "333333333333/us-west-2";
  const nodes: GraphNode[] = [{id:"vpc-many", label:"vpc-many", native_id:"vpc-many", type:"vpc", provider:"aws", scope, resource_id:"resource:vpc-many"}];
  const edges: GraphEdge[] = [];
  for (let i=0;i<count;i++) {
    const id = `subnet-${String(i).padStart(3,"0")}`;
    nodes.push({id,label:id,native_id:id,type:"subnet",provider:"aws",scope,parent_id:"vpc-many",resource_id:`resource:${id}`});
    const eni = `eni-${String(i).padStart(3,"0")}`;
    nodes.push({id:eni,label:eni,native_id:eni,type:"network_interface",provider:"aws",scope,parent_id:id,resource_id:`resource:${eni}`});
    edges.push({id:`contains:${id}`,source:id,target:"vpc-many",type:"associated_with"});
  }
  return {nodes,edges};
}

export function twoClustersFixture(): Graph {
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  for (const cluster of ["cluster-one","cluster-two"]) {
    for (const namespace of ["app","ops"]) {
      const id = `${cluster}:${namespace}`;
      nodes.push({id,label:namespace,native_id:`k8s://${cluster}/namespaces/${namespace}`,type:"namespace",provider:"k8s",scope:"administrative-scope",resource_id:`resource:${id}`});
      const pod = `${id}:pod`;
      nodes.push({id:pod,label:`${namespace}-pod`,native_id:`k8s://${cluster}/namespaces/${namespace}/pods/workload`,type:"pod",provider:"k8s",scope:"administrative-scope",parent_id:id,resource_id:`resource:${pod}`});
      edges.push({id:`membership:${pod}`,source:pod,target:id,type:"contained_in_namespace"});
    }
  }
  return {nodes,edges};
}
