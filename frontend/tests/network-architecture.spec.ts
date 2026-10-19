import { expect, test } from "@playwright/test";
import { architectureFixture, inventoryCoverageFixture, manySubnetsFixture, twoClustersFixture } from "./networkFixtures";
import { syntheticNetwork } from "./scaleFixtures";
import type { Graph } from "../src/types";
import { mkdirSync } from "node:fs";
import { cidrs, kind, label, nativeDetails, networkModel, networkView, ruleRows } from "../src/networkPresentation";

test("malformed native labels use a readable supplied identifier", () => {
  const malformed = { id: "eni-observed", label: { unexpected: "object" }, type: { unexpected: "object" } } as unknown as Graph["nodes"][number];
  expect(label(malformed)).toBe("eni-observed");
  expect(kind(malformed)).toBe("resource");
});

test("a foreign-provider parent cannot reassign a resource to another cloud network", () => {
  const graph: Graph = { nodes: [
    {id:"aws-vpc",type:"vpc",provider:"aws",scope:"111111111111/us-east-1"},
    {id:"azure-vm",type:"vm",provider:"azure",scope:"/subscriptions/example",parent_id:"aws-vpc"},
  ], edges:[] };
  const model = networkModel(graph);
  expect(model.owner.get("azure-vm")).toBe("outside:azure:/subscriptions/example");
  expect(model.groups.find(group => group.provider === "azure")?.root).toBeUndefined();
});

test("malformed supplied firewall, NSG and NetworkPolicy rules remain inspectable", () => {
  const row = (type: string, data: Record<string,unknown>) => ruleRows({
    id:type,type,provider:type === "networkpolicy" ? "k8s" : "azure",scope:"test",
    evidence:{native_resource:{data}},
  });
  expect(row("firewall",{direction:"INGRESS",allowed:[null,{IPProtocol:"tcp",ports:["443"]}]}).map(rule => rule.action))
    .toEqual(["Malformed supplied rule","Allow"]);
  expect(row("nsg",{properties:{securityRules:[null,{properties:{priority:100,access:"Allow"}}]}}).map(rule => rule.action))
    .toEqual(["Malformed supplied rule","Allow"]);
  const policy = row("networkpolicy",{spec:{ingress:[null,{ports:[null],from:[null]}]}});
  expect(policy.map(rule => rule.action)).toEqual(["Malformed supplied rule","Policy allow candidate"]);
  expect(policy[1]).toMatchObject({protocol:"Unknown/Unknown",source:"Unknown"});
});

test("AWS security group all-protocol, port, and ICMP display uses observed protocol facts", () => {
  const sg = inventoryCoverageFixture().nodes.find(n => n.id === "sg-a")!;
  const observed = {...sg, evidence: {native_resource: {data: {
    IpPermissions: [
      {IpProtocol: "-1", FromPort: 443, ToPort: 443, IpRanges: [{CidrIp: "0.0.0.0/0"}], Ipv6Ranges: [{CidrIpv6: "::/0"}]},
      {IpProtocol: -1, IpRanges: [{CidrIp: "192.0.2.0/24"}]},
      {IpProtocol: "tcp", FromPort: 443, ToPort: 8443, IpRanges: [{CidrIp: "192.0.2.0/24"}]},
      {IpProtocol: "17", FromPort: 53, ToPort: 53, Ipv6Ranges: [{CidrIpv6: "2001:db8::/32"}]},
      {IpProtocol: "icmp", FromPort: 8, ToPort: -1, IpRanges: [{CidrIp: "192.0.2.0/24"}]},
      {FromPort: 443, ToPort: 443, IpRanges: [{CidrIp: "192.0.2.0/24"}]},
      null,
    ],
  }}}};
  const rows = ruleRows(observed);
  expect(rows).toHaveLength(6);
  expect(rows[0]).toMatchObject({protocol: "All protocols", port: "All ports", source: "0.0.0.0/0, ::/0"});
  expect(rows[1]).toMatchObject({protocol: "All protocols", port: "All ports"});
  expect(rows[2]).toMatchObject({protocol: "tcp", port: "443–8443"});
  expect(rows[3]).toMatchObject({protocol: "UDP", port: "53", source: "2001:db8::/32"});
  expect(rows[4]).toMatchObject({protocol: "icmp", port: "Type 8 · Code All"});
  expect(rows[5]).toMatchObject({protocol: "Unknown", port: "443"});
});

test("new native controls keep endpoint links, boundary counts, and readable ordered rules", () => {
  const fixture = inventoryCoverageFixture();
  const model = networkModel(fixture);
  const view = networkView(model,"aws","vpc-alpha","subnet-a","");
  expect(view.items.some(x=>x.id==="asset:vpce-extra")).toBe(true);
  expect(view.edges.some(e=>e.type==="attached_interface" && e.source==="asset:vpce-extra" && e.target==="asset:eni-a")).toBe(true);
  expect(view.hiddenNodes).toBeGreaterThanOrEqual(0);
  const acl = fixture.nodes.find(n=>n.id==="acl-extra")!;
  expect(ruleRows(acl)).toMatchObject([{order:"100",direction:"Inbound",protocol:"6",port:"443",source:"0.0.0.0/0",action:"deny"}]);
  const sg = fixture.nodes.find(n=>n.id==="sg-a")!;
  const sgWithDescription = {...sg,evidence:{native_resource:{data:{IpPermissions:[{IpProtocol:"tcp",FromPort:443,ToPort:443,IpRanges:[{CidrIp:"192.0.2.0/24",Description:"owner note"}]}]}}}};
  expect(ruleRows(sgWithDescription)[0].source).toBe("192.0.2.0/24");
  expect(nativeDetails(fixture.nodes.find(n=>n.id==="vpce-extra")!).some(x=>x.name==="Interfaces" && x.value==="eni-a")).toBe(true);
  const gcp = fixture.nodes.find(n=>n.id==="gcp-policy-extra")!;
  expect(ruleRows(gcp)).toMatchObject([{order:"100",direction:"INGRESS",protocol:"tcp",port:"443",source:"0.0.0.0/0",action:"deny"}]);
  const azure = fixture.nodes.find(n=>n.id==="azure-private-extra")!;
  expect(nativeDetails(azure).some(x=>x.name==="Private IP" && x.value==="172.16.1.9")).toBe(true);
});

test("network ACL inspector shows ordered stateless deny, with raw facts collapsed", async ({page}) => {
  await serve(page,inventoryCoverageFixture());
  await page.getByRole("button",{name:/Table/}).click();
  await page.getByRole("button",{name:/Subnet traffic ACL/}).click();
  const dialog=page.getByRole("dialog");
  await expect(dialog).toContainText("Rule / priority");
  await expect(dialog).toContainText("100");
  await expect(dialog).toContainText("deny");
  await expect(dialog).toContainText("stateless");
  await expect(dialog.getByText("Collected technical fields")).toBeVisible();
  await dialog.getByText("Collected technical fields").click();
  await expect(dialog.locator("pre.network-raw")).toHaveCount(0);
});

test("collapsed boundary endpoints preserve supplied peering and attachment records", () => {
  const model = networkModel(architectureFixture);
  const overview = networkView(model, "aws", "", "", "");
  expect(overview.edges.some(e => e.source === "asset:peer-ab" && e.target === "network:vpc-alpha" && e.type === "peering_endpoint")).toBe(true);
  expect(overview.edges.some(e => e.source === "asset:peer-ab" && e.target === "network:vpc-beta" && e.type === "peering_endpoint")).toBe(true);
  expect(overview.edges.some(e => e.source === "network:vpc-alpha" && e.target === "network:vpc-beta" && e.type.startsWith("Peering configured"))).toBe(true);
  const network = networkView(model, "aws", "vpc-alpha", "", "");
  expect(network.items.find(x => x.id === "area:subnet-a")?.hidden).toBe(2);
  expect(network.items.some(x => x.id === "network:outside:aws:111111111111/us-east-1")).toBe(true);
  const area = networkView(model, "aws", "vpc-alpha", "subnet-a", "");
  expect(area.items.find(x => x.id === "area:subnet-a")?.hidden).toBe(0);
  expect(area.edges.some(e => e.source === "asset:eni-a" && e.target === "asset:sg-a" && e.type === "protected_by")).toBe(true);
});

test("assessed endpoints remain visible inside their VPCs when the overview has many networks", () => {
  const graph: Graph = structuredClone(architectureFixture);
  for (const name of ["gamma", "delta"]) {
    const vpc = `vpc-${name}`, subnet = `subnet-${name}`;
    graph.nodes.push({id:vpc,type:"vpc",label:vpc,provider:"aws",scope:`${name}/us-east-1`,resource_id:`resource:${vpc}`});
    graph.nodes.push({id:subnet,type:"subnet",label:subnet,provider:"aws",scope:`${name}/us-east-1`,parent_id:vpc,resource_id:`resource:${subnet}`});
  }
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  const model = networkModel(graph);
  expect(networkView(model,"aws","","","").items.some(item=>item.id==="asset:instance-a")).toBe(false);
  const focused = networkView(model,"aws","","", "",0,["vpc-alpha"],["instance-a","instance-c"]);
  expect(focused.items.filter(item=>item.id==="asset:instance-a" || item.id==="asset:instance-c").map(item=>item.parentId)).toEqual(["network:vpc-alpha","network:vpc-alpha"]);
});

test("an assessed remote VPC stays visible after opening the source VPC without a structural link", () => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"vpc-remote",type:"vpc",label:"vpc-remote",provider:"aws",scope:"333333333333/us-east-1",resource_id:"resource:vpc-remote"});
  graph.nodes.push({id:"subnet-remote",type:"subnet",label:"subnet-remote",provider:"aws",scope:"333333333333/us-east-1",parent_id:"vpc-remote",resource_id:"resource:subnet-remote"});
  graph.nodes.push({id:"instance-remote",type:"instance",label:"instance-remote",provider:"aws",scope:"333333333333/us-east-1",parent_id:"subnet-remote",resource_id:"resource:instance-remote"});
  const model = networkModel(graph);
  const view = networkView(model,"aws","vpc-alpha","","",0,["vpc-alpha","vpc-remote"],["instance-a","instance-remote"]);
  expect(view.items.some(item=>item.id==="network:vpc-remote")).toBe(true);
  expect(view.items.some(item=>item.id==="asset:instance-remote")).toBe(true);
});

test("automatic assessment selects both ENIs of a multi-interface instance", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"eni-secondary",type:"network_interface",label:"eni-secondary",provider:"aws",
    scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:eni-secondary"});
  graph.edges.push({id:"attached_interface:instance-a:eni-secondary",source:"instance-a",target:"eni-secondary",type:"attached_interface"});
  let selected: string[] = [];
  await serve(page,graph,body=>{selected = body.endpoint_resource_ids;return {snapshot_id:"synthetic",results:[]};});
  await expect.poll(()=>selected).toEqual(["resource:eni-a","resource:eni-secondary"]);
});

test("automatic assessment retains the instance when one attached ENI is unresolved", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"eni-unresolved",type:"network_interface",label:"eni-unresolved",provider:"aws",
    scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:eni-unresolved",stub:true});
  graph.edges.push({id:"attached_interface:instance-a:eni-unresolved",source:"instance-a",target:"eni-unresolved",type:"attached_interface"});
  let selected: string[] = [];
  await serve(page,graph,body=>{selected = body.endpoint_resource_ids;return {snapshot_id:"synthetic",results:[]};});
  await expect.poll(()=>selected).toEqual(["resource:eni-a","resource:instance-a"]);
});

test("automatic assessment selects each GCP interface of a multi-interface VM", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"gcp-second",type:"instance",label:"gcp-second",provider:"gcp",
    scope:"projects/host-project",parent_id:"gcp-sub",resource_id:"resource:gcp-second"});
  for (const [id, machine] of [["gcp-nic0","gcp-vm"],["gcp-nic1","gcp-vm"]] as const) {
    graph.nodes.push({id,type:"network_interface",label:id,provider:"gcp",scope:"projects/host-project",
      parent_id:"gcp-sub",resource_id:`resource:${id}`});
    graph.edges.push({id:`attached_interface:${machine}:${id}`,source:machine,target:id,type:"attached_interface"});
  }
  const selected: string[][] = [];
  await serve(page,graph,body=>{selected.push(body.endpoint_resource_ids);return {snapshot_id:"synthetic",results:[]};});
  await page.getByRole("tab",{name:/Google Cloud/}).click();
  await expect.poll(()=>selected.find(ids=>ids.includes("resource:gcp-nic0"))).toEqual([
    "resource:gcp-second","resource:gcp-nic0","resource:gcp-nic1"]);
});

test("live map automatically assesses directed pairs across networks and inside a subnet", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"instance-b",type:"instance",label:"instance-b",provider:"aws",scope:"222222222222/us-east-1",parent_id:"subnet-b",resource_id:"resource:instance-b"});
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  let requests = 0;
  await serve(page,graph,body => {
    requests += 1;
    expect(body).toMatchObject({protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"});
    expect(body.endpoint_resource_ids.length).toBeLessThanOrEqual(12);
    expect(body.endpoint_resource_ids).not.toContain("resource:eni-a");
    return {snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string) =>
      body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id).map((destination_resource_id:string)=>({
        decision:source_resource_id==="resource:instance-a" && destination_resource_id==="resource:instance-c" ? "blocked" : "allowed",
        query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},
        provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
      })))};
  });
  expect(requests).toBeGreaterThan(0);
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]').first()).toBeVisible();
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"] path.react-flow__edge-path').first()).toHaveAttribute("marker-end",/url\(/);
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="area:subnet-a"] .network-node-heading').click();
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).not.toHaveCount(0);
  await page.getByText(/Automatically assessed arrow groups ·/).click();
  await page.getByRole("region",{name:"Automatically assessed arrow groups"}).getByRole("button").first().click();
  await expect(page.getByRole("dialog")).toContainText("directed TCP/54321→443 IPv4");
});

test("automatic arrows reject mismatched route assessment responses", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",
    scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  let assessed = false;
  await serve(page,graph,body => {
    assessed = true;
    return {snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string) =>
      body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id)
        .map((destination_resource_id:string)=>({decision:"allowed",provider:"aws",snapshot_id:"synthetic",
          query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,
            destination_port:8443,address_family:"ipv4"},modeled_configuration:true,new_flow_only:true})))};
  });
  await expect.poll(()=>assessed).toBe(true);
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(0);
});

test("collapsed network arrow exposes mixed matrix decisions instead of overlapping verdicts", async ({page}) => {
  const graph: Graph = {nodes:[
    {id:"vpc-a",type:"vpc",provider:"aws",scope:"111111111111/us-east-1",resource_id:"resource:vpc-a"},
    {id:"subnet-a",type:"subnet",provider:"aws",scope:"111111111111/us-east-1",parent_id:"vpc-a",resource_id:"resource:subnet-a"},
    {id:"instance-a",type:"instance",label:"instance-a",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-a"},
    {id:"instance-c",type:"instance",label:"instance-c",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"},
    {id:"vpc-b",type:"vpc",provider:"aws",scope:"222222222222/us-east-1",resource_id:"resource:vpc-b"},
    {id:"subnet-b",type:"subnet",provider:"aws",scope:"222222222222/us-east-1",parent_id:"vpc-b",resource_id:"resource:subnet-b"},
    {id:"instance-b",type:"instance",label:"instance-b",provider:"aws",scope:"222222222222/us-east-1",parent_id:"subnet-b",resource_id:"resource:instance-b"},
  ],edges:[]};
  await serve(page,graph,body => ({snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string) =>
    body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id)
      .map((destination_resource_id:string)=>({decision:source_resource_id==="resource:instance-c" && destination_resource_id==="resource:instance-b" ? "blocked" : "allowed",
        query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},
        provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}))) }));
  const groups = page.getByRole("region",{name:"Automatically assessed arrow groups"});
  await page.getByText(/Automatically assessed arrow groups ·/).click();
  await expect(groups.getByRole("button",{name:/1 allowed · 1 blocked/})).toHaveCount(1);
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"][aria-label*="1 allowed · 1 blocked"]')).toHaveCount(1);
  await groups.getByRole("button",{name:/1 allowed · 1 blocked/}).click();
  await expect(page.getByRole("dialog")).toContainText("instance-a → instance-b · ALLOWED");
  await expect(page.getByRole("dialog")).toContainText("instance-c → instance-b · BLOCKED");
});

test("assessed paths inside a collapsed VPC remain visible and become arrows when expanded", async ({page}) => {
  const scope="111111111111/us-east-1";
  const graph: Graph = {nodes:[
    {id:"vpc-internal",type:"vpc",provider:"aws",scope,resource_id:"resource:vpc-internal"},
    {id:"subnet-internal",type:"subnet",provider:"aws",scope,parent_id:"vpc-internal",resource_id:"resource:subnet-internal"},
    {id:"instance-a",type:"instance",label:"instance-a",provider:"aws",scope,parent_id:"subnet-internal",resource_id:"resource:instance-a"},
    {id:"instance-b",type:"instance",label:"instance-b",provider:"aws",scope,parent_id:"subnet-internal",resource_id:"resource:instance-b"},
  ],edges:[]};
  await serve(page,graph,body => ({snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string) =>
    body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id)
      .map((destination_resource_id:string)=>({decision:source_resource_id==="resource:instance-a"?"allowed":"blocked",
        query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},
        provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}))) }));
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(0);
  await page.locator('.react-flow__node[data-id="area:subnet-internal"] .network-node-internal').click();
  await expect(page.getByRole("dialog")).toContainText("2 directed TCP/54321→443 IPv4 pairs");
  await expect(page.getByRole("dialog")).toContainText("instance-a → instance-b · ALLOWED");
  await expect(page.getByRole("dialog")).toContainText("instance-b → instance-a · BLOCKED");
  await page.getByRole("dialog").getByRole("button",{name:"Close inspector"}).click();
  await page.locator('.react-flow__node[data-id="network:vpc-internal"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="area:subnet-internal"] .network-node-internal')).toContainText("2 assessed internal pairs");
  await page.locator('.react-flow__node[data-id="area:subnet-internal"] .network-node-heading').click();
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(2);
});

test("automatic map windows reach a thirteenth loaded endpoint with a peer", async ({page}) => {
  const scope="333333333333/us-east-1";
  const graph: Graph = {nodes:[
    {id:"vpc-window",type:"vpc",provider:"aws",scope,resource_id:"resource:vpc-window"},
    {id:"subnet-window",type:"subnet",provider:"aws",scope,parent_id:"vpc-window",resource_id:"resource:subnet-window"},
    ...Array.from({length:13},(_,index)=>({id:`instance-${index}`,type:"instance",provider:"aws",scope,parent_id:"subnet-window",resource_id:`resource:instance-${index}`})),
  ],edges:[]};
  const requests:string[][]=[];
  const gridRequests:Array<{first_endpoint_resource_ids:string[];second_endpoint_resource_ids:string[]}>=[];
  await serve(page,graph,body => {
    requests.push(body.endpoint_resource_ids);
    return {snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string)=>
      body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id).map((destination_resource_id:string)=>({
        decision:"allowed",query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
      })))};
  },body => {
    gridRequests.push(body);
    const pairs=new Map<string,{source_resource_id:string;destination_resource_id:string}>();
    for (const source_resource_id of body.first_endpoint_resource_ids) for (const destination_resource_id of body.second_endpoint_resource_ids) {
      if (source_resource_id===destination_resource_id) continue;
      pairs.set(`${source_resource_id}:${destination_resource_id}`,{source_resource_id,destination_resource_id});
      pairs.set(`${destination_resource_id}:${source_resource_id}`,{source_resource_id:destination_resource_id,destination_resource_id:source_resource_id});
    }
    return {snapshot_id:"synthetic",results:[...pairs.values()].map(({source_resource_id,destination_resource_id})=>({
      decision:"allowed",query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
    }))};
  });
  await page.locator('.react-flow__node[data-id="network:vpc-window"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="area:subnet-window"] .network-node-heading').click();
  await expect(page.getByRole("button",{name:"Next 12 endpoints"})).toBeEnabled();
  await page.getByRole("button",{name:"Next 12 endpoints"}).click();
  expect(requests.at(-1)).toEqual(["resource:instance-11","resource:instance-12"]);
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(2);
  await page.getByLabel("Compare endpoint window").selectOption("0");
  await expect(page.getByRole("status").filter({hasText:"Cross-window IPv4 TCP/54321→443"})).toContainText("22 directed pairs evaluated");
  expect(gridRequests.at(-1)?.first_endpoint_resource_ids).toEqual(["resource:instance-12"]);
  expect(gridRequests.at(-1)?.second_endpoint_resource_ids).toHaveLength(11);
  expect(gridRequests.at(-1)?.second_endpoint_resource_ids).not.toContain("resource:instance-11");
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(24);
  await page.getByText("Cross-window assessed pairs · 22").click();
  await expect(page.getByRole("region",{name:"Cross-window assessed pairs"})).toContainText("instance-12 → instance-0");
});

test("cross-window arrows reject a different snapshot from the current matrix", async ({page}) => {
  const scope="333333333333/us-east-1";
  const graph: Graph = {nodes:[
    {id:"vpc-window",type:"vpc",provider:"aws",scope,resource_id:"resource:vpc-window"},
    {id:"subnet-window",type:"subnet",provider:"aws",scope,parent_id:"vpc-window",resource_id:"resource:subnet-window"},
    ...Array.from({length:13},(_,index)=>({id:`instance-${index}`,type:"instance",provider:"aws",scope,parent_id:"subnet-window",resource_id:`resource:instance-${index}`})),
  ],edges:[]};
  const decision = (source_resource_id:string,destination_resource_id:string,snapshot_id:string) => ({
    decision:"allowed",query:{source_resource_id,destination_resource_id,protocol:"tcp",source_port:54321,destination_port:443,address_family:"ipv4"},
    provider:"aws",snapshot_id,endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
  });
  await serve(page,graph,body => ({snapshot_id:"synthetic",results:body.endpoint_resource_ids.flatMap((source_resource_id:string) =>
    body.endpoint_resource_ids.filter((destination_resource_id:string)=>destination_resource_id!==source_resource_id)
      .map((destination_resource_id:string)=>decision(source_resource_id,destination_resource_id,"synthetic")))}),
  body => ({snapshot_id:"another-snapshot",results:body.first_endpoint_resource_ids.flatMap((first:string) =>
    body.second_endpoint_resource_ids.filter((second:string)=>second!==first)
      .flatMap((second:string)=>[decision(first,second,"another-snapshot"),decision(second,first,"another-snapshot")]))}));
  await page.locator('.react-flow__node[data-id="network:vpc-window"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="area:subnet-window"] .network-node-heading').click();
  await page.getByRole("button",{name:"Next 12 endpoints"}).click();
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(2);
  await page.getByLabel("Compare endpoint window").selectOption("0");
  await expect(page.getByRole("status").filter({hasText:"Cross-window IPv4 TCP/54321→443"})).toContainText("response incomplete or mismatched");
  await expect(page.locator('.react-flow__edge[data-id^="matrix:"]')).toHaveCount(2);
  await expect(page.getByText(/Cross-window assessed pairs ·/)).toHaveCount(0);
});

test("assessed flows draw directional arrows across VPCs and within a subnet", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.unshift({id:"placeholder-a",type:"instance",label:"placeholder-a",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-a",stub:true});
  graph.nodes.push({id:"instance-b",type:"instance",label:"instance-b",provider:"aws",scope:"222222222222/us-east-1",parent_id:"subnet-b",resource_id:"resource:instance-b"});
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  await serve(page,graph);
  await page.route("**/api/scans/**/reachability", async route => {
    const query = route.request().postDataJSON();
    await route.fulfill({json:{decision:query.destination_resource_id === "resource:instance-c" ? "blocked" : "allowed",query,provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}});
  });
  const assess = async (source:string,target:string,decision:string,sourcePort = "") => {
    await page.getByRole("button",{name:"Assess configuration path"}).click();
    const dialog=page.getByRole("dialog");
    await dialog.getByLabel("Source resource ID").fill(source);
    await dialog.getByLabel("Destination resource ID").fill(target);
    await dialog.getByLabel("Source port (optional)").fill(sourcePort);
    await dialog.getByRole("button",{name:"Assess configuration",exact:true}).click();
    await dialog.getByRole("button",{name:"Show path on map"}).click();
    const sourceName = source.split(":").at(-1);
    const targetName = target.split(":").at(-1);
    const arrow = page.locator(`.react-flow__edge g[data-relationship="${sourceName} → ${targetName} · IPv4 TCP/${sourcePort ? `${sourcePort}→` : ""}443 · ${decision}"] path.react-flow__edge-path`);
    await expect(arrow).toHaveAttribute("marker-end",/url\(/);
  };
  await assess("resource:instance-a","resource:instance-b","allowed","54321");
  await expect(page.locator('.react-flow__node[data-id="network:vpc-alpha"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="network:vpc-beta"]')).toBeVisible();
  await expect(page.locator(".network-flow-result")).toContainText("instance-a → instance-b");
  await assess("resource:instance-a","resource:instance-c","blocked");
  await expect(page.locator('.react-flow__node[data-id="asset:instance-a"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:instance-c"]')).toBeVisible();
});

test("editing an assessed flow clears its old decision before another arrow can be drawn", async ({page}) => {
  await serve(page,structuredClone(architectureFixture));
  await page.route("**/api/scans/**/reachability", async route => {
    const query = route.request().postDataJSON();
    await route.fulfill({json:{decision:"allowed",query,provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}});
  });
  await page.getByRole("button",{name:"Assess configuration path"}).click();
  const dialog=page.getByRole("dialog");
  await dialog.getByLabel("Source resource ID").fill("resource:instance-a");
  await dialog.getByLabel("Destination resource ID").fill("resource:instance-b");
  await dialog.getByRole("button",{name:"Assess configuration",exact:true}).click();
  await expect(dialog.getByRole("button",{name:"Show path on map"})).toBeVisible();
  await dialog.getByLabel("Destination port").fill("8443");
  await expect(dialog.getByRole("button",{name:"Show path on map"})).toHaveCount(0);
  await expect(dialog.getByRole("heading",{name:"Configuration decision",exact:true})).toHaveCount(0);
});

test("manual assessment rejects a response for another destination port", async ({page}) => {
  await serve(page,structuredClone(architectureFixture));
  await page.route("**/api/scans/**/reachability", async route => {
    const query = route.request().postDataJSON();
    await route.fulfill({json:{decision:"allowed",query:{...query,destination_port:8443},provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}});
  });
  await page.getByRole("button",{name:"Assess configuration path"}).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Source resource ID").fill("resource:instance-a");
  await dialog.getByLabel("Destination resource ID").fill("resource:instance-b");
  await dialog.getByRole("button",{name:"Assess configuration",exact:true}).click();
  await expect(dialog.getByText("Assessment response did not match the selected connection.")).toBeVisible();
  await expect(dialog.getByRole("button",{name:"Show path on map"})).toHaveCount(0);
  await expect(page.locator('.react-flow__edge g[data-relationship*="TCP/8443"]')).toHaveCount(0);
});

test("one source can show assessed arrows to loaded endpoints across and within VPCs", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"instance-b",type:"instance",label:"instance-b",provider:"aws",scope:"222222222222/us-east-1",parent_id:"subnet-b",resource_id:"resource:instance-b"});
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  await serve(page,graph);
  let submittedSourcePort: number | undefined;
  await page.route("**/api/scans/**/reachability/batch", async route => {
    const body = route.request().postDataJSON();
    submittedSourcePort = body.source_port;
    await route.fulfill({json:{snapshot_id:"synthetic",results:body.destination_resource_ids.map((destination_resource_id:string) => ({
      decision:destination_resource_id === "resource:instance-c" ? "blocked" : "allowed",
      query:{...body,destination_resource_id},provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
    }))}});
  });
  await page.getByRole("button",{name:/Table/}).click();
  await page.getByRole("button",{name:/instance-a/}).first().click();
  await page.getByRole("dialog").getByRole("button",{name:"Assess connections from this resource"}).click();
  await expect(page.getByRole("region",{name:"Connections from selected resource"})).toContainText("2 allowed · 1 blocked");
  await page.getByLabel("Source port (optional)").fill("54321");
  await expect(page.getByRole("region",{name:"Connections from selected resource"})).not.toContainText("2 allowed · 1 blocked");
  await page.getByRole("button",{name:"Assess loaded endpoints"}).click();
  await expect(page.getByRole("region",{name:"Connections from selected resource"})).toContainText("2 allowed · 1 blocked");
  expect(submittedSourcePort).toBe(54321);
  await page.getByRole("region",{name:"Connections from selected resource"}).getByLabel("Address family").selectOption("ipv6");
  await page.getByRole("button",{name:"Assess loaded endpoints"}).click();
  await expect(page.getByRole("region",{name:"Connections from selected resource"})).toContainText("2 allowed · 1 blocked");
  await page.getByRole("button",{name:"Map",exact:true}).click();
  await expect(page.locator('.react-flow__node[data-id="asset:instance-a"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:instance-c"]')).toBeVisible();
  await expect(page.locator('.react-flow__edge[data-id^="assessed-batch:"]')).toHaveCount(3);
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="area:subnet-a"] .network-node-heading').click();
  await expect(page.locator('.react-flow__edge[data-id^="assessed-batch:"]')).toHaveCount(3);
  await expect(page.locator('.react-flow__edge[data-id^="assessed-batch:"]').first()).toHaveAttribute("aria-label",/IPv6 TCP\/54321→443/);
  await page.getByRole("region",{name:"Connections from selected resource"}).getByText(/Results for/).click();
  await page.getByRole("region",{name:"Connections from selected resource"}).getByRole("button",{name:/instance-c/}).click();
  await expect(page.locator('.react-flow__edge[data-id="assessed-flow"]')).toHaveCount(1);
});

test("batch assessment rejects results for a different destination port", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  graph.nodes.push({id:"instance-c",type:"instance",label:"instance-c",provider:"aws",
    scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:"resource:instance-c"});
  await serve(page,graph);
  await page.route("**/api/scans/**/reachability/batch", route => {
    const body = route.request().postDataJSON();
    return route.fulfill({json:{snapshot_id:"synthetic",results:body.destination_resource_ids.map((destination_resource_id:string) => ({
      decision:"allowed",query:{...body,destination_resource_id,destination_port:8443},provider:"aws",
      snapshot_id:"synthetic",modeled_configuration:true,new_flow_only:true,
    }))}});
  });
  await page.getByRole("button",{name:/Table/}).click();
  await page.getByRole("button",{name:/instance-a/}).first().click();
  await page.getByRole("dialog").getByRole("button",{name:"Assess connections from this resource"}).click();
  await expect(page.getByRole("alert")).toContainText("did not match the selected connections");
  await expect(page.locator('.react-flow__edge[data-id^="assessed-batch:"]')).toHaveCount(0);
});

test("bounded connection pages can assess endpoints beyond the first 24", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  for (let index=0; index<25; index++) graph.nodes.push({id:`peer-${index}`,type:"instance",label:`peer-${index}`,provider:"aws",scope:"111111111111/us-east-1",parent_id:"subnet-a",resource_id:`resource:peer-${index}`});
  await serve(page,graph);
  await page.route("**/api/scans/**/reachability/batch", async route => {
    const body = route.request().postDataJSON();
    await route.fulfill({json:{snapshot_id:"synthetic",results:body.destination_resource_ids.map((destination_resource_id:string) => ({
      decision:"unknown",query:{...body,destination_resource_id},provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[{code:"route_collection_incomplete",message:"Source route table was not collected",evidence_refs:[]}],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true,
    }))}});
  });
  await page.getByRole("button",{name:"Table",exact:true}).click();
  await page.getByRole("button",{name:/instance-a/}).first().click();
  await page.getByRole("dialog").getByRole("button",{name:"Assess connections from this resource"}).click();
  const region = page.getByRole("region",{name:"Connections from selected resource"});
  await region.getByRole("button",{name:"Assess loaded endpoints"}).click();
  await expect(region).toContainText("Loaded endpoints 1–24 of 26");
  await region.getByText(/Results for/).click();
  await expect(region.getByText("Source route table was not collected")).toHaveCount(24);
  await region.getByRole("button",{name:"Next 24 endpoints"}).click();
  await expect(region).toContainText("Loaded endpoints 25–26 of 26");
  await expect(region).toContainText("Assessed 26 of 26");
  await region.getByRole("button",{name:"Previous 24 endpoints"}).click();
  await expect(region).toContainText("Assessed 26 of 26");
  await page.getByRole("button",{name:"Map",exact:true}).click();
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="area:subnet-a"] .network-node-heading').click();
  const arrows = page.locator('.react-flow__edge[data-id^="assessed-batch:"]');
  await expect(arrows).toHaveCount(16);
  expect(await arrows.evaluateAll(elements => elements.reduce((total,element) =>
    total + Number(element.getAttribute("aria-label")?.match(/(\d+) assessed pairs/)?.[1] || 0),0))).toBe(26);
  await region.getByLabel("Destination port").fill("8443");
  await expect(page.locator('.react-flow__edge[data-id^="assessed-batch:"]')).toHaveCount(0);
});

test("assessed flow outside loaded map names the missing evidence instead of claiming one group", async ({page}) => {
  await serve(page, architectureFixture);
  await page.route("**/api/scans/**/reachability", async route => {
    const query = route.request().postDataJSON();
    await route.fulfill({json:{decision:"unknown",query,provider:"aws",snapshot_id:"synthetic",endpoints:{},routes:[],policy_decisions:[],translations:[],unresolved_dependencies:[],evidence_refs:[],modeled_configuration:true,application_listening:"unknown",new_flow_only:true}});
  });
  await page.getByRole("button",{name:"Assess configuration path"}).click();
  const dialog = page.getByRole("dialog");
  await dialog.getByLabel("Source resource ID").fill("resource:instance-a");
  await dialog.getByLabel("Destination resource ID").fill("resource:not-loaded");
  await dialog.getByRole("button",{name:"Assess configuration",exact:true}).click();
  await dialog.getByRole("button",{name:"Show path on map"}).click();
  await expect(page.locator(".network-flow-result")).toContainText("outside the loaded map evidence");
  await expect(page.locator(".network-flow-result").getByRole("button",{name:"Load network inventory"})).toBeVisible();
  await expect(page.locator('.react-flow__edge[data-id="assessed-flow"]')).toHaveCount(0);
});

async function serve(page: import("@playwright/test").Page, graph: Graph, matrix?: (body: any) => unknown, grid?: (body: any) => unknown) {
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    const json = path.endsWith("/scans") ? { items:[{id:"network-scan",status:"completed",categories:["network"],created_at:"2026-01-01"}] }
      : path.endsWith("/summary") ? {resources:[],findings:[],coverage:[],graphs:{},stats:{}}
      : path.endsWith("/graphs/network") ? graph
      : path.endsWith("/reachability/matrix") ? matrix ? matrix(route.request().postDataJSON()) : {snapshot_id:"synthetic",results:[]}
      : path.endsWith("/reachability/grid") ? grid ? grid(route.request().postDataJSON()) : {snapshot_id:"synthetic",results:[]}
      : path.endsWith("/health") ? {status:"ok"}
      : path.endsWith("/me") ? {email:"tester@example.test",plan:"test"}
      : {items:[]};
    return route.fulfill({json});
  });
  await page.goto("/#Network%20Map");
  await expect(page.getByRole("tab", {name:/AWS/})).toBeVisible();
}

test("provider tabs, nested networks, boundary edges, service icons and human inspectors", async ({page}) => {
  const edgeWarnings:string[] = [];
  page.on("console",message=>{if (message.type()==="warning" && /edge type|networkLink/i.test(message.text())) edgeWarnings.push(message.text());});
  await serve(page, architectureFixture);
  for (const name of ["AWS", "Google Cloud", "Azure", "Kubernetes"]) await expect(page.getByRole("tab", {name:new RegExp(name)})).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="network:vpc-alpha"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="network:vpc-beta"]')).toBeVisible();
  await expect(page.getByText("Lines show resource links;",{exact:false})).toHaveCount(0);
  await expect(page.getByText("Automatic IPv4 TCP/54321→443 assessment:",{exact:false})).toHaveCount(0);
  await expect(page.locator('.react-flow__node[data-id="area:subnet-a"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:sg-a"]')).toBeVisible();
  mkdirSync("evidence", { recursive:true });
  await page.screenshot({path:"evidence/network-overview-multivpc-desktop.png",fullPage:true});
  await expect(page.locator('.react-flow__edge g[data-route="elk"] path.react-flow__edge-path').first()).toHaveAttribute("d",/^M /);
  await expect.poll(()=>page.locator('.react-flow__edge g[data-route="elk"]').count()).toBeGreaterThan(2);
  await expect(page.locator('.react-flow__edge g[data-route="elk"] path.react-flow__edge-path').first()).toHaveAttribute("d",/^M .+L /);
  // Peering metadata is a candidate relationship, not a measured path in either direction.
  await expect(page.locator('.react-flow__edge g[data-relationship^="Peering configured"] path.react-flow__edge-path')).not.toHaveAttribute("marker-end", /url\(/);
  await expect(page.locator('.react-flow__edge g[data-relationship^="Peering configured"] path.react-flow__edge-path')).not.toHaveAttribute("marker-start", /url\(/);
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="area:subnet-a"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:sg-a"] [aria-label="security group icon"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:route-a"] [aria-label="route table icon"]')).toBeVisible();
  expect(await page.locator('.react-flow__node[data-id="area:subnet-a"]').getAttribute("data-hidden")).not.toBe("0");
  await page.locator('.react-flow__node[data-id="area:subnet-a"] .network-node-heading').click();
  const eni = page.locator('.react-flow__node[data-id="asset:eni-a"]');
  await expect(eni).toBeVisible();
  await page.screenshot({ path:"evidence/network-aws-desktop.png", fullPage:true });
  const areaBox = await page.locator('.react-flow__node[data-id="area:subnet-a"]').boundingBox();
  const eniBox = await eni.boundingBox();
  expect(eniBox?.width).toBeLessThanOrEqual(152);
  expect(areaBox && eniBox && eniBox.x >= areaBox.x && eniBox.y >= areaBox.y && eniBox.x + eniBox.width <= areaBox.x + areaBox.width && eniBox.y + eniBox.height <= areaBox.y + areaBox.height).toBe(true);
  const instanceBox = await page.locator('.react-flow__node[data-id="asset:instance-a"]').boundingBox();
  const rootBox = await page.locator('.react-flow__node[data-id="network:vpc-alpha"]').boundingBox();
  const sgBox = await page.locator('.react-flow__node[data-id="asset:sg-a"]').boundingBox();
  const routeBox = await page.locator('.react-flow__node[data-id="asset:route-a"]').boundingBox();
  for (const child of [areaBox,sgBox,routeBox]) expect(rootBox && child && child.x>=rootBox.x && child.y>=rootBox.y && child.x+child.width<=rootBox.x+rootBox.width && child.y+child.height<=rootBox.y+rootBox.height).toBe(true);
  expect(areaBox && instanceBox && instanceBox.x>=areaBox.x && instanceBox.y>=areaBox.y && instanceBox.x+instanceBox.width<=areaBox.x+areaBox.width && instanceBox.y+instanceBox.height<=areaBox.y+areaBox.height).toBe(true);
  const overlaps = (a:NonNullable<typeof eniBox>,b:NonNullable<typeof eniBox>)=>a.x<b.x+b.width && a.x+a.width>b.x && a.y<b.y+b.height && a.y+a.height>b.y;
  expect(overlaps(eniBox!,instanceBox!)).toBe(false);
  expect(overlaps(sgBox!,routeBox!)).toBe(false);
  await eni.click();
  await expect(page.getByRole("dialog")).toContainText("10.0.1.6");
  await expect(page.getByRole("dialog")).toContainText("eni-a");
  await expect(page.getByRole("dialog").getByText("Collected technical fields")).toBeVisible();
  await page.getByRole("button", {name:"Close inspector"}).click();
  await page.locator('.react-flow__node[data-id="asset:sg-a"]').click();
  await expect(page.getByRole("dialog").getByRole("region", { name: "Collected network rules" }).getByRole("table")).toContainText("192.0.2.0/24");
  await page.screenshot({path:"evidence/network-sg-rule-inspector-desktop.png",fullPage:true});
  await page.getByRole("button", {name:"Close inspector"}).click();
  await page.getByRole("tab", {name:/Google Cloud/}).click();
  await expect(page.getByText(/GLOBAL \/ SHARED VPC CONTEXT/)).toHaveCount(0); // header appears after selecting a network
  await page.locator('.react-flow__node[data-id="network:gcp-net"] .network-node-heading').click();
  await expect(page.getByText("GLOBAL / SHARED VPC CONTEXT")).toBeVisible();
  await page.getByRole("tab", {name:/Azure/}).click();
  await page.locator('.react-flow__node[data-id="network:vnet-one"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="area:azure-sub"]')).toBeVisible();
  await page.getByRole("tab", {name:/Kubernetes/}).click();
  await page.locator('.react-flow__node[data-id="network:cluster:cluster-prod"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="area:ns-app"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="area:ns-app"] .network-node')).toHaveAttribute("title",/Namespace · workload group/);
  await page.locator('.react-flow__node[data-id="area:ns-app"] .network-node-heading').click();
  await expect(page.locator('.react-flow__node[data-id="asset:pod-a"]')).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="asset:policy-app"] [aria-label="networkpolicy icon"]')).toBeVisible();
  await page.setViewportSize({ width:390, height:844 });
  await page.screenshot({ path:"evidence/network-drill-mobile.png", fullPage:true });
  expect(edgeWarnings).toEqual([]);
});

test("escaped names remain text, and three thousand assets stay within the rich node budget", async ({page}) => {
  const large = syntheticNetwork(3100) as Graph;
  large.nodes[0].label = '<img src=x onerror=alert(1)> vpc';
  await serve(page, large);
  await expect(page.locator(".react-flow__node").first()).toBeVisible();
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(300);
  await expect(page.getByText(/resources folded or off page/)).toBeVisible();
  await page.getByRole("button", {name:"Table",exact:true}).click();
  await page.getByLabel("Search loaded network resources").fill("<img src=x");
  await expect(page.locator(".network-table-row")).toContainText("<img src=x");
  expect(await page.locator(".network-table-row img").count()).toBe(0);
});

test("reference-only providers do not appear as collected tabs and native rule detail loads lazily", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  const sg = graph.nodes.find(n => n.id === "sg-a")!;
  const vpc = graph.nodes.find(n => n.id === "vpc-alpha")!;
  sg.evidence = { native_resource_ref: sg.resource_id };
  vpc.evidence = { native_resource_ref: vpc.resource_id };
  for (const n of graph.nodes.filter(n => n.provider !== "aws")) { n.resource_id = null; n.evidence = { inventory_status:"reference_only" }; }
  let resourceReads = 0;
  await page.route("**/api/**", route => {
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/resources/")) { resourceReads++; return route.fulfill({json:decodeURIComponent(path).endsWith("resource:vpc-alpha") ? {id:"resource:vpc-alpha",data:{CidrBlock:"10.0.0.0/16"}} : {id:"resource:sg-a",data:{IpPermissions:[{IpProtocol:"tcp",FromPort:443,ToPort:443,IpRanges:[{CidrIp:"192.0.2.0/24"}]}]}}}); }
    const json = path.endsWith("/scans") ? {items:[{id:"network-scan",status:"completed",categories:["network"],created_at:"2026-01-01"}]}
      : path.endsWith("/summary") ? {resources:[],findings:[],coverage:[],graphs:{},stats:{}}
      : path.endsWith("/graphs/network") ? graph
      : path.endsWith("/health") ? {status:"ok"}
      : {items:[]};
    return route.fulfill({json});
  });
  await page.goto("/#Network%20Map");
  await expect(page.getByRole("tab", {name:/AWS/})).toBeVisible();
  await expect(page.getByRole("tab", {name:/Google Cloud/})).toHaveCount(0);
  expect(resourceReads).toBe(0);
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await expect(page.locator(".network-header-stats")).toContainText("10.0.0.0/16");
  await page.locator('.react-flow__node[data-id="asset:sg-a"]').click();
  await expect(page.getByRole("dialog").getByRole("region", { name: "Collected network rules" }).getByRole("table")).toContainText("192.0.2.0/24");
  expect(resourceReads).toBe(2);
});

test("rule table reaches every supplied rule page and resets for a different resource", async ({ page }) => {
  const graph: Graph = structuredClone(architectureFixture);
  const large = graph.nodes.find(node => node.id === "sg-a")!;
  large.evidence = { native_resource: { data: { IpPermissions: Array.from({ length: 125 }, (_, index) => ({
    IpProtocol: "tcp", FromPort: 443, ToPort: 443, IpRanges: [{ CidrIp: `198.51.100.${index}/32` }],
  })) } } };
  graph.nodes.push({ ...large, id: "sg-short", native_id: "sg-short", resource_id: "resource:sg-short",
    label: "sg-short", evidence: { native_resource: { data: { IpPermissions: [{
      IpProtocol: "tcp", FromPort: 8443, ToPort: 8443, IpRanges: [{ CidrIp: "203.0.113.8/32" }],
    }] } } } });
  await serve(page, graph);
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await page.locator('.react-flow__node[data-id="asset:sg-a"]').click();
  const dialog = page.getByRole("dialog");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table").locator("tbody tr")).toHaveCount(100);
  await expect(dialog).toContainText("Rules 1–100 of 125");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table")).toContainText("198.51.100.0/32");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table")).not.toContainText("198.51.100.100/32");
  await dialog.getByRole("button", { name: "Next rule page" }).click();
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table").locator("tbody tr")).toHaveCount(25);
  await expect(dialog).toContainText("Rules 101–125 of 125");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table")).toContainText("198.51.100.100/32");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table")).not.toContainText("198.51.100.0/32");
  await expect(dialog.getByRole("button", { name: "Next rule page" })).toBeDisabled();
  mkdirSync("evidence", { recursive: true });
  await page.screenshot({ path: "evidence/network-rule-page2-desktop.png", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await dialog.locator(".network-rule-pages").filter({ hasText: "Rules 101–125 of 125" }).scrollIntoViewIfNeeded();
  await page.screenshot({ path: "evidence/network-rule-page2-mobile.png", fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1080 });
  await dialog.getByRole("button", { name: "Previous rule page" }).click();
  await expect(dialog).toContainText("Rules 1–100 of 125");
  await page.getByRole("button", { name: "Close inspector" }).click();
  await page.locator('.react-flow__node[data-id="asset:sg-short"]').click();
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table").locator("tbody tr")).toHaveCount(1);
  await expect(dialog).toContainText("Rules 1–1 of 1");
  await expect(dialog.getByRole("region", { name: "Collected network rules" }).getByRole("table")).toContainText("203.0.113.8/32");
  await expect(dialog.getByRole("button", { name: "Next rule page" })).toHaveCount(0);
});

test("failed native configuration read keeps CIDR unknown", async ({page}) => {
  const graph: Graph = structuredClone(architectureFixture);
  const vpc = graph.nodes.find(n=>n.id==="vpc-alpha")!;
  vpc.evidence = {native_resource_ref:vpc.resource_id};
  await page.route("**/api/**",route=>{
    const path = new URL(route.request().url()).pathname;
    if (path.includes("/resources/")) return route.fulfill({status:503,json:{detail:"Unavailable"}});
    const json = path.endsWith("/scans") ? {items:[{id:"network-scan",status:"completed",categories:["network"],created_at:"2026-01-01"}]}
      : path.endsWith("/summary") ? {resources:[],findings:[],coverage:[],graphs:{},stats:{}}
      : path.endsWith("/graphs/network") ? graph
      : path.endsWith("/health") ? {status:"ok"} : {items:[]};
    return route.fulfill({json});
  });
  await page.goto("/#Network%20Map");
  await page.locator('.react-flow__node[data-id="network:vpc-alpha"] .network-node-heading').click();
  await expect(page.getByRole("alert").filter({hasText:"Native network configuration could not be loaded"})).toBeVisible();
  await expect(page.locator(".network-header-stats")).toContainText("Unknown CIDR");
});

test("every subnet beyond the initial area page is reachable from both pager and table", async ({page}) => {
  await serve(page, manySubnetsFixture(131));
  await page.locator('.react-flow__node[data-id="network:vpc-many"] .network-node-heading').click();
  await expect(page.getByText("Page 1 of 6")).toBeVisible();
  await expect(page.locator('.react-flow__node[data-id="area:subnet-130"]')).toHaveCount(0);
  for (let i=0;i<5;i++) await page.getByRole("button",{name:"Next subnets"}).click();
  await expect(page.locator('.react-flow__node[data-id="area:subnet-130"]')).toBeVisible();
  await page.getByRole("button",{name:"Table",exact:true}).click();
  await page.getByLabel("Search loaded network resources").fill("subnet-130");
  await expect(page.locator(".network-table-row")).toContainText("subnet-130");
  await page.locator(".network-table-row").getByRole("button",{name:"Open subnet"}).click();
  await expect(page.locator('.react-flow__node[data-id="asset:eni-130"]')).toBeVisible();
  expect(await page.locator(".react-flow__node").count()).toBeLessThanOrEqual(300);
});

test("clusters and repeated namespace names preserve native cluster identity", () => {
  const model = networkModel(twoClustersFixture());
  expect(model.groups.filter(g=>g.provider==="k8s").map(g=>g.id)).toEqual(["cluster:cluster-one","cluster:cluster-two"]);
  expect(model.area.get("cluster-one:app:pod")).toBe("cluster-one:app");
  expect(model.area.get("cluster-two:app:pod")).toBe("cluster-two:app");
  const overview = networkView(model,"k8s","","","");
  expect(overview.items.filter(x=>x.kind==="cluster")).toHaveLength(2);
  expect(overview.items.filter(x=>x.kind==="namespace")).toHaveLength(4);
  const unknown: Graph = {nodes:[{id:"orphan-namespace",type:"namespace",provider:"k8s",scope:"app",label:"app",resource_id:"resource:orphan"}],edges:[]};
  const unresolved=networkModel(unknown);
  expect(unresolved.groups[0].title).toContain("Cluster unknown");
  expect(unresolved.groups[0].id).toBe("cluster:unknown:app");
});

test("Azure native properties retain CIDR, account and region in readable details", () => {
  const vnet = architectureFixture.nodes.find(n=>n.id==="vnet-one")!;
  expect(cidrs(vnet)).toEqual(["172.16.0.0/16"]);
  expect(nativeDetails(vnet)).toEqual(expect.arrayContaining([
    {name:"Subscription",value:"subscription-one"},
    {name:"Tenant",value:"tenant-one"},
    {name:"Region",value:"eastus"},
    {name:"CIDR",value:"172.16.0.0/16"},
  ]));
});

test("edge-group ceiling includes omitted underlying relationship counts", () => {
  const graph: Graph = {nodes:[
    {id:"v1",type:"vpc",provider:"aws",scope:"one/us-east-1"},
    {id:"v2",type:"vpc",provider:"aws",scope:"two/us-east-1"},
  ],edges:Array.from({length:450},(_,i)=>({id:`edge-${i}`,source:"v1",target:"v2",type:`observed-${i}`,underlying_count:3}))};
  const view=networkView(networkModel(graph),"aws","","","");
  expect(view.edges).toHaveLength(400);
  expect(view.visibleEdgeTotal).toBe(450);
  expect(view.hiddenEdges).toBe(150);
});

test("inventory pages accumulate without dropping previous resources and stop at page count", async ({page}) => {
  let reads = 0;
  await page.route("**/api/**",route=>{
    const url = new URL(route.request().url()), path=url.pathname;
    if (path.endsWith("/graphs/network/page")) {
      reads++;
      const index=Number(url.searchParams.get("page"));
      const id=index===0?"instance-one":"instance-two";
      return route.fulfill({json:{page:index,page_count:2,total_nodes:3,nodes:[{id,label:id,type:"instance",provider:"aws",scope:"111/us-east-1",parent_id:"vpc-paged",resource_id:`resource:${id}`}],edges:[]}});
    }
    const json=path.endsWith("/graphs/network") ? {nodes:[{id:"vpc-paged",label:"vpc-paged",type:"vpc",provider:"aws",scope:"111/us-east-1",resource_id:"resource:vpc-paged"},{id:"aggregate-instances",label:"instance (2)",type:"instance",provider:"aws",scope:"111/us-east-1",parent_id:"vpc-paged",aggregate:true,underlying_count:2,node_refs:["instance-one","instance-two"]}],edges:[],projection:{collapsed:true,node_count:3,edge_count:0}}
      : path.endsWith("/scans") ? {items:[{id:"paged",status:"completed",categories:["network"],created_at:"2026-01-01"}]}
      : path.endsWith("/summary") ? {resources:[],findings:[],coverage:[],graphs:{},stats:{}}
      : path.endsWith("/health") ? {status:"ok"} : {items:[]};
    return route.fulfill({json});
  });
  await page.goto("/#Network%20Map");
  await page.getByRole("button",{name:"Load inventory page"}).click();
  await expect(page.getByRole("button",{name:"Load inventory page"})).toBeEnabled();
  await page.getByRole("button",{name:"Load inventory page"}).click();
  await expect(page.getByRole("button",{name:"All inventory pages loaded"})).toBeDisabled();
  await page.getByRole("button",{name:"Table",exact:true}).click();
  await expect(page.locator(".network-table-row",{hasText:"instance-one"})).toBeVisible();
  await expect(page.locator(".network-table-row",{hasText:"instance-two"})).toBeVisible();
  expect(reads).toBe(2);
});
