import { expect, test } from "@playwright/test";
import type { Graph } from "../src/types";
import { nativeDetails, networkModel, networkView } from "../src/networkPresentation";

test("inspectors display normalized native network fields from service wrappers", () => {
  const details = nativeDetails({id:"private-workload",type:"mwaa_environment",provider:"aws",network_attributes:[
    {path:"NetworkConfiguration.SubnetIds",name:"SubnetIds",value:["subnet-one","subnet-two"]},
    {path:"NetworkConfiguration.AssignPublicIp",name:"assignPublicIp",value:false},
    {path:"worker.endpoint",name:"endpoint",value:"https://private.example"},
  ]});
  expect(details).toContainEqual({name:"Subnet Ids",value:"subnet-one, subnet-two"});
  expect(details).toContainEqual({name:"assign Public Ip",value:"false"});
  expect(details).toContainEqual({name:"endpoint",value:"https://private.example"});
});

test("managed services without a single subnet remain visible and paginated", () => {
  const graph: Graph = { nodes: [
    {id:"vpc",type:"vpc",provider:"aws",scope:"111/us-east-1"},
    ...Array.from({length:27},(_,i)=>({id:`ecs-${i}`,type:"ecs_service",label:`ECS ${i}`,provider:"aws",scope:"111/us-east-1",parent_id:"vpc"})),
  ], edges:[] };
  const model = networkModel(graph);
  const first = networkView(model,"aws","vpc","","",0);
  const second = networkView(model,"aws","vpc","","",1);
  expect(first.pageCount).toBe(2);
  expect(first.items.some(n=>n.id==="asset:ecs-0")).toBe(true);
  expect(second.items.some(n=>n.id==="asset:ecs-26")).toBe(true);
  const outside: Graph = {nodes:[{id:"cloudfront",type:"cloudfront_distribution",provider:"aws",scope:"111/global",label:"Edge distribution"}],edges:[]};
  expect(networkView(networkModel(outside),"aws","","","").items.some(n=>n.id==="asset:cloudfront")).toBe(true);
});

test("inspectors explain managed attachments without exposing application settings", () => {
  const details = nativeDetails({id:"ecs",type:"ecs_service",provider:"aws",scope:"111/us-east-1",evidence:{native_resource:{data:{
    networkConfiguration:{awsvpcConfiguration:{subnets:["subnet-one"],securityGroups:["sg-one"]}},
    environment:[{name:"bad",value:"secret-sentinel"}],
  }}}});
  expect(details).toContainEqual({name:"Subnets",value:"subnet-one"});
  expect(details).toContainEqual({name:"Security groups",value:"sg-one"});
  expect(JSON.stringify(details)).not.toContain("secret-sentinel");
  const cloudfront = nativeDetails({id:"edge",type:"cloudfront_vpc_origin",provider:"aws",evidence:{native_resource:{data:{
    VpcOrigin:{VpcOriginEndpointConfig:{HTTPSPort:443,OriginProtocolPolicy:"https-only"}},
  }}}});
  expect(cloudfront).toContainEqual({name:"Origin HTTPS port",value:"443"});
  const volume = nativeDetails({id:"volume",type:"persistentvolume",provider:"k8s",evidence:{native_resource:{data:{
    spec:{csi:{driver:"efs.csi.aws.com",volumeHandle:"fs-one::fsap-one"}},
  }}}});
  expect(volume).toContainEqual({name:"Cloud storage handle",value:"fs-one::fsap-one"});
});

test("inspectors show modern private service and nested network attachments", () => {
  const kafka = nativeDetails({id:"kafka",type:"managed_kafka_cluster",provider:"gcp",evidence:{native_resource:{data:{
    gcpConfig:{accessConfig:{networkConfigs:[{subnet:"projects/host/regions/us-central1/subnetworks/private"}]}},
  }}}});
  expect(kafka).toContainEqual({name:"Subnetwork",value:"projects/host/regions/us-central1/subnetworks/private"});
  const gateway = nativeDetails({id:"gateway",type:"lattice_resource_gateway",provider:"aws",evidence:{native_resource:{data:{
    NetworkDetails:{vpcId:"vpc-one",subnetIds:["subnet-one"],securityGroupIds:["sg-one"]},
  }}}});
  expect(gateway).toContainEqual({name:"Subnets",value:"subnet-one"});
  expect(gateway).toContainEqual({name:"Security groups",value:"sg-one"});
});

test("inspectors retain Beanstalk, mesh, DNS and backend TLS details with application options excluded", () => {
  const beanstalk = nativeDetails({id:"beanstalk",type:"elastic_beanstalk_environment",provider:"aws",evidence:{native_resource:{data:{
    NetworkSettings:[{DeploymentStatus:"deployed",OptionSettings:[
      {Namespace:"aws:ec2:vpc",OptionName:"Subnets",Value:"subnet-one,subnet-two"},
      {Namespace:"aws:elasticbeanstalk:application:environment",OptionName:"Subnets",Value:"SECRET_SENTINEL"},
    ]}],
  }}}});
  expect(beanstalk).toContainEqual({name:"Subnets",value:"subnet-one,subnet-two"});
  expect(JSON.stringify(beanstalk)).not.toContain("SECRET_SENTINEL");
  const route = nativeDetails({id:"route",type:"mesh_http_route",provider:"gcp",evidence:{native_resource:{data:{
    meshes:["projects/p/locations/global/meshes/mesh"],rules:[{action:{destinations:[{serviceName:"backend"}]}}],
  }}}});
  expect(route).toContainEqual({name:"Meshes",value:"projects/p/locations/global/meshes/mesh"});
  expect(route).toContainEqual({name:"Backend service",value:"backend"});
  const tls = nativeDetails({id:"tls",type:"backendtlspolicy",provider:"k8s",evidence:{native_resource:{data:{
    spec:{validation:{hostname:"backend.internal",wellKnownCACertificates:"System"}},
  }}}});
  expect(tls).toContainEqual({name:"CA trust",value:"System"});
  const dns = nativeDetails({id:"dns",type:"private_dns_record_set",provider:"azure",evidence:{native_resource:{data:{
    properties:{aRecords:[{ipv4Address:"10.0.0.4"}]},
  }}}});
  expect(dns).toContainEqual({name:"IPv4 address",value:"10.0.0.4"});
});

test("generic native leaves retain their network context in inspector labels", () => {
  const details = nativeDetails({id:"vpc",type:"vpc",provider:"aws",network_attributes:[
    {path:"EnableDnsSupport.Value",name:"Value",value:true},
    {path:"EnableDnsHostnames.Value",name:"Value",value:false},
  ]} as any);
  expect(details).toContainEqual({name:"Enable Dns Support / Value",value:"true"});
  expect(details).toContainEqual({name:"Enable Dns Hostnames / Value",value:"false"});
});
