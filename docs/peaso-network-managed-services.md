# Managed services in the Network Map and network AI context

The network collection plan, graph and AI resource projection share the service
catalog in `peaso/analysis/network_services.py` and the audited families in
`peaso/analysis/network_catalog.py`. Collecting these services for a
different category is no longer required. Network scans request their native
metadata alongside VPC/VNet, subnet, interface and policy inventories.

| Provider | Managed network inventory |
| --- | --- |
| AWS | ECS clusters, services, task sets, tasks and container instances; EFS filesystems and mount targets; CloudFront distributions and VPC origins; ElastiCache, MemoryDB and subnet groups; Redshift and subnet groups; FSx, RDS/proxies, DocumentDB, Neptune, DMS, OpenSearch, MQ, MSK, Lambda and EKS. Generic VPC endpoints retain service names and join owned endpoint services when their observed service names match unambiguously. |
| Azure | Private Endpoints and Private Link services; storage, vaults/HSMs, SQL, Cosmos, Redis, App Service, AKS, registry/container groups, data/analytics/AI services and messaging services listed in the catalog. Private Link target ARM IDs resolve to collected services across subscriptions; uncollected targets retain their native type and unresolved status. Subnet integration and service-endpoint rules remain different relationships. |
| GCP | PSC service attachments, NEGs (including global NEGs), network attachments, VPC connectors, Cloud SQL, Cloud Run services/jobs, Functions, Filestore, Redis and the other managed compute/database services in the catalog. Explicit serverless NEG targets link to collected services. Project-qualified references retain the owning project. |
| Kubernetes | Pods, Services, nodes, policies and ingress plus PVC/PV bindings. Pod → PVC → PV → CSI handle/NFS server relationships preserve cluster and namespace identity. Node provider IDs and Service load-balancer addresses remain external references. |

The second audit also includes these native inventories and their declared
network attachments:

| Provider | Additional families |
| --- | --- |
| AWS | App Runner ingress/egress and connectors; Batch, Auto Scaling, Beanstalk, WorkSpaces/AppStream and Directory Service; EKS node groups/Fargate profiles; EMR/EMR Serverless, SageMaker, Glue, DAX, Redshift Serverless, MSK Connect, Grafana, CodeBuild and Firehose; ElastiCache Serverless, OpenSearch Serverless VPC endpoints, OpenSearch Ingestion, Timestream InfluxDB and QuickSight VPC connections; API Gateway VPC links/private API endpoints, S3 access points, Transfer, DataSync agents, Storage Gateway/file shares, Global Accelerator and VPC Lattice; Resolver endpoint IPs/rules/associations, DHCP, DNS zones/records, customer gateways and Direct Connect gateways/interfaces/associations. |
| Azure | Container Apps/environments/jobs, registry agent pools, VM scale sets, Service Fabric, Spring and integration environments; additional database/data platforms and NetApp volumes; private/public DNS, private resolver endpoints/rulesets, Bastion, ExpressRoute, VPN connections/sites, Virtual WAN/hubs and their child connections. WAF policies are included as network controls. |
| GCP | App Engine version network metadata, Dataflow worker networking, Batch allocation networking, instance templates/groups/autoscalers; Managed Kafka, Memorystore/Redis clusters, NetApp, Vertex endpoints and Cloud Run worker pools; Service Networking connections, service connection policies, Network Connectivity Center hubs/spokes, Interconnect/attachments, private DNS/forwarding/peering and network security policies. Existing Cloud Build private pools, Composer, Dataproc and other cataloged service networks remain included. |
| Kubernetes | Workload controllers and UID-qualified owner relationships; legacy Endpoints and EndpointSlices; IngressClass; GatewayClass/Gateway/HTTP/gRPC/TLS/TCP/UDP routes and ReferenceGrants; StorageClass, CSI drivers/nodes and VolumeAttachments; installed Cilium, Calico and administrative policy inventories. Gateway API list versions are negotiated from API discovery. |

The follow-up audit also covers native configuration and service families that
were not established by the original list responses:

| Provider | Additional collection and relationships |
| --- | --- |
| AWS | Beanstalk's actual VPC/subnet/security-group options and deployed/draft configuration state; Lightsail instances, databases, load balancers and container endpoints; AppSync API endpoints; Lattice listeners, default actions, rules, target groups and registered targets, resource configurations and resource associations; CloudHSM subnet/ENI/security-group attachments, KMS custom-store proxy configuration and Verified Access endpoints/groups/instances. Resource/Service Network VPC endpoint ARNs retain their explicit Lattice target. Application settings, deployment variables and header match literals are excluded from these new configuration responses before the shared cache. Verified Access topology does not establish a policy decision. |
| Azure | Private DNS record sets, resolver forwarding rules and ruleset VNet links; ML compute and managed-network outbound destinations; Data Factory managed VNets and their managed private endpoints, including parent discovery for an endpoint-only request; Azure Monitor Private Link scopes, linked monitor resources and Data Collection Endpoints; Automation, IoT provisioning, File Sync and Log Analytics clusters as Private Link targets. Denied ancestors remain gaps in downstream inventory. |
| GCP | Service Mesh meshes, gateways, endpoint policies, HTTP/gRPC/TCP/TLS routes and backend references; native TLS/authorization policy enumeration, including unreferenced policies; Datastream and Database Migration VPC/PSC private connections; public/private DNS record identities and address records. TXT and other arbitrary DNS bodies are not requested by the new `dns_record_set` collector. It first enumerates identities, then requests address values by exact name/type. |
| Kubernetes | BackendTLSPolicy, including served `v1alpha3` and `v1` versions, linked to its declared backend Service; native `networking.k8s.io/v1` ServiceCIDR and IPAddress inventories, with explicit address allocation owners. API resources unavailable on older clusters remain coverage gaps. |

Mesh route enumeration requests network-only response fields; application
headers and direct-response bodies are omitted. Declared routes, TLS policies,
private endpoint approvals and ML outbound destinations do not establish live
traffic or controller enforcement. GCP locations denied by organization policy
remain partial/denied coverage, even when another location was readable.

Generic VPC endpoints preserve the observed provider service name even when the
target is a provider-managed API with no customer-owned network resource.
API Gateway private integrations retain their VPC link IDs and HTTP API listener
targets; embedded request templates/parameters are excluded before caching.
Private Route 53 zone associations retain VPC IDs and regions; `GetHostedZone`
does not establish the associated VPC's account owner, so that owner stays
unverified rather than being inferred from the DNS zone's account.
Controller templates and route references are declarations, not running
workloads or proof that a controller accepted a route. Kubernetes ownership
joins require cluster, namespace, name and matching observed UIDs.

Services with several subnet attachments remain visible without selecting a
single subnet as their parent. Direct resources are paginated in the map, and
the inspector shows native attachment fields. Edges retain their source paths.
The AI receives the same graph, service counts, collection coverage and a positive
projection of native network fields. Application settings, environment values,
origin custom headers and CSI credential references are not included.

Missing/denied collection and incomplete native fields remain gaps. Reference
nodes are not observations of remote resources. CSI handles, provider IDs and
load-balancer hostnames do not establish cross-snapshot cloud membership. These
structural associations do not extend the selected-flow evaluator or prove
traffic, DNS resolution, application listening, policy approval or reachability.

## Capturing the new inventory

Run a new network scan; old immutable snapshots cannot supply facts that were
not collected. Explicit inventory selections still limit what can be captured.

The generated AWS customer role includes the metadata reads for CloudFront VPC
origins, MemoryDB subnet groups and EFS mount-target security groups (including
the required `ec2:DescribeNetworkInterfaceAttribute` companion permission).
It also includes the reviewed metadata reads for the additional families above,
with API Gateway GET restricted to the required resource paths. The generator
splits the documents within IAM size and attachment limits. Existing deployed
roles need the updated template before their next scan.

Azure requires read access to `Microsoft.Network/privateLinkServices` and
the additional ARM resource families. Kubernetes needs list access to storage,
workload, endpoint and routing inventories; the updated read-only RBAC example
is in [the collector guide](peaso-azure-k8s-collectors.md#read-only-rbac-for-the-collecting-identity).
Absent Gateway APIs are recorded as absent; denied discovery remains unknown.

GCP readers need `compute.serviceAttachments.list`,
`compute.networkEndpointGroups.list`, `compute.networkAttachments.list`,
`vpcaccess.connectors.list`, `file.instances.list`, `redis.instances.list` and
service location discovery permissions when locations are not supplied.
The new regional options are `vpcaccess_locations`, `filestore_locations` and
`redis_locations`, each falling back to `regions`. Filestore locations can be
zones as well as regions. These three collectors do not request resource IAM
policies. Existing Cloud Run, SQL, Function and other collectors retain their
usual metadata permissions.

The additional GCP regional collectors accept `<service>_network_locations`,
fall back to `regions`, and otherwise discover the service's locations. Service
names are `redis`, `netapp`, `networkconnectivity`, `batch`, `managedkafka`,
`memorystore`, `aiplatform`, `run`, `networkservices`, `networksecurity`,
`datastream` and `datamigration`. Network Services/Security discovery always
includes `global` as well as selected/discovered regions. Readers need the corresponding service
list permissions and location discovery access. Dataflow additionally needs
`dataflow.jobs.get`: the collector uses a network-only response field mask;
Batch excludes task payloads and App Engine excludes deployment contents.
Service Networking connections require Compute network enumeration and
`servicenetworking.services.connections.list`. API disablement, denied reads,
partial pages and missing locations remain collection coverage gaps.

The follow-up needs `networkservices.*.list` for the listed mesh resource types,
`networksecurity.serverTlsPolicies.list`, `networksecurity.clientTlsPolicies.list`,
`networksecurity.authorizationPolicies.list`, the two migration/streaming
`privateConnections.list` permissions, and `dns.managedZones.list` /
`dns.resourceRecordSets.list`. Azure readers need the corresponding Monitor,
Data Factory managed-network/endpoint, DNS resolver child and private DNS
record-set read permissions. The AWS role generator includes the additional
Beanstalk, Lightsail and Lattice metadata operations.

## Audit guards

Regression tests require every catalog member to be supported by its collector,
selected by a network scan, present in the graph and retained in AI inventory.
Additional tests compare the AWS SDK's native output schemas for network fields
against graph coverage; backup/history aliases and derived evidence have
explicit exclusion reasons. All native Azure `Microsoft.Network` endpoint
kinds and Kubernetes network endpoint registrations must also have map coverage.
Representative native attachment fixtures verify relationships and positive
field projection, including cross-account/project targets and omitted secrets.

## API references

- [CloudFront VPC origin list](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_ListVpcOrigins.html) and [detail](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_GetVpcOrigin.html).
- [EFS mount-target security groups and required permissions](https://docs.aws.amazon.com/efs/latest/APIReference/API_DescribeMountTargetSecurityGroups.html).
- [MemoryDB subnet groups](https://docs.aws.amazon.com/memorydb/latest/APIReference/API_DescribeSubnetGroups.html).
- [GCP PSC service attachments](https://docs.cloud.google.com/compute/docs/reference/rest/v1/serviceAttachments/aggregatedList), [NEGs](https://docs.cloud.google.com/compute/docs/reference/rest/v1/networkEndpointGroups/aggregatedList), and [VPC connectors](https://docs.cloud.google.com/vpc/docs/reference/vpcaccess/rest/v1/projects.locations.connectors/list).
- [DataSync private network configuration](https://docs.aws.amazon.com/datasync/latest/apireference/API_DescribeAgent.html), [QuickSight VPC connections](https://docs.aws.amazon.com/quicksight/latest/APIReference/API_ListVPCConnections.html), [OpenSearch Ingestion private access](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/pipeline-security.html), and [Timestream InfluxDB reads](https://docs.aws.amazon.com/service-authorization/latest/reference/list_timestream-influxdb.html).
- [Cloud Run worker pools](https://docs.cloud.google.com/run/docs/reference/rest/v2/projects.locations.workerPools/list) and [Gateway API versions](https://gateway-api.sigs.k8s.io/concepts/versioning/).
- [Beanstalk VPC options](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html), [Lattice metadata actions](https://docs.aws.amazon.com/service-authorization/latest/reference/list_vpc-lattice.html), and [Azure managed private endpoints](https://learn.microsoft.com/en-us/rest/api/datafactory/managed-private-endpoints/list-by-factory?view=rest-datafactory-2018-06-01).
- [Cloud Service Mesh network APIs](https://docs.cloud.google.com/service-mesh/docs/reference/network-services/rest), [Datastream private connections](https://docs.cloud.google.com/datastream/docs/reference/rest/v1/projects.locations.privateConnections), and [Cloud DNS record filtering](https://docs.cloud.google.com/dns/docs/reference/rest/v1/resourceRecordSets/list).
- [BackendTLSPolicy](https://gateway-api.sigs.k8s.io/reference/api-types/policy/backendtlspolicy/) and [Kubernetes ServiceCIDR](https://kubernetes.io/docs/reference/kubernetes-api/networking/service-cidr-v1/).

## Independent provider API audit

`scripts/audit_network_service_inventory.py` scans every installed AWS service's
read API outputs and the preferred Google API discovery documents independently
of the registered collector catalog. The checked-in candidate reports are in
`docs/network-audit/`. A candidate includes aliases, history, planning, logical
networks and non-Cloud products, so a candidate is not automatically a live asset.
The review is ongoing; catalog membership alone does not prove exhaustive coverage.

The additional AWS plans are declared in
`peaso/collectors/aws_network_inventory.json`. They include managed Airflow,
Flink, Comprehend, AgentCore, Bedrock workloads, EventBridge private connections
and targets, schedules, CodeConnections hosts, DocumentDB Elastic, Prometheus
scrapers, Synthetics, Deadline fleets, PCS, image-building infrastructure,
mainframe environments, media networking, Oracle Database networks, migration
services, directory replicas, iSCSI storage, additional SageMaker workloads,
private database endpoints, traffic mirrors, route servers and network monitors.
Each plan declares the actual list/detail operations, argument sources, parent
discovery, response roots, identities and fallback pagination tokens. Denied
parents and detail reads preserve explicit incomplete coverage and available rows.
AWS SDK dictionary properties, application settings, scripts and credential
branches cannot become network evidence by using a network-looking field name.

`aws_network_inventory_iam.json` records exact read/list actions verified against
AWS's current service authorization reference, including differing API/IAM
prefixes. Regenerate the customer role after changing the plans. The current
role remains within managed-policy size and attachment limits; no role is
modified in a customer account by generation.

The additional Azure resource types and reviewed API versions are declared in
`azure_network_private_services.json`. They cover missing Private Link targets
and dedicated VNet deployments, including domain services, managed Service
Fabric, VMware, OpenShift, Cassandra, Grafana, HSMs, Lustre, managed developer
pools and Elastic SAN. Parent-scoped child discovery includes Cassandra data
centers, Grafana managed private endpoints, Elastic SAN volume groups, Virtual
Hub BGP/routes/maps and VPN/ExpressRoute connections.

`gcp_network_private_services.json` records native response field masks and
source discovery documents for additional private services, including Apigee,
Looker, Memcached, Cloud IDS, TPU, Lustre, Backup/DR, Data Fusion, VMware Engine,
Workstations, integration endpoints and Vertex workloads. Apigee organization
reads are bound to the selected project's native organization mapping.

`k8s_network_extensions.json` declares reviewed CNI, MetalLB, Antrea and Istio
resources. Served API versions and namespace scope are verified at discovery;
Calico supports the aggregated API and native CRD groups. Absent APIs are
explicitly absent, while denied discovery remains unknown. Multus attachment
and status annotations are parsed into native names, interfaces and IP addresses;
CNI arguments and plugin credentials are omitted. Pod links require the exact
cluster and namespace of the NetworkAttachmentDefinition.

Network attributes retain native paths through service-specific wrappers. They
are available in map inspectors and in the agent's resource evidence, including
a repeated export of an already projected resource. Endpoint URLs lose user
information and query/fragment material. Network declarations, old job states,
peering, private access and service API endpoints do not establish active traffic.


## Independent provider audit

The audit compares the application with 114 AWS SDK service candidates, 85
Google discovery candidates from 316 preferred public APIs, Microsoft's 71
Private Link resource types, and 65 reviewed Kubernetes extension resources.
The machine-readable reconciliation is
[service-dispositions.json](network-audit/service-dispositions.json). It distinguishes
native resources from API aliases, historical/finding records, logical device
networks and products requiring a separate SaaS identity. It is a service-family
review, not a claim that every provider GET or every future CRD is collected.

The additional manifests now contain 188 AWS native collection plans, 106 Google
resource plans and 51 Azure root resource plans. Existing core collectors remain
part of the network inventory. Azure includes Event Grid namespaces, Fabric
private links, standalone managed file shares, Arc private link scopes, Monitor
workspaces, healthcare workspaces/services and Application Gateway for Containers
subnet associations/frontends. DPS network configuration uses `iot_dps_network`;
the separate compliance observation deliberately retains only DPS identities.

AWS includes managed ECS capacity providers/Express Gateway services, EKS
capabilities, DMS serverless resources, MediaConnect routing, DataSync managed-file
locations, Cloud WAN peers, Client VPN routes and target networks, endpoint/Lattice
associations and native QuickSight network restrictions. OpenSearch Serverless
network-policy JSON and QuickSight rule-map keys are projected before caching;
free-text policy descriptions and rule-map values are omitted. VPC DNS support
and hostname settings are read independently and retain individual coverage gaps.
The generated customer role contains 1075 reviewed metadata actions in seven
managed policies within IAM limits. Existing customer roles need redeployment.

Google includes zonal TPU/IDS/firewall resources, Metastore, Parallelstore,
Managed AD, BeyondCorp, BigQuery private connections, FTP, Contact Center,
Oracle Database, managed Kafka Connect, Eventarc, Dataproc serverless workloads,
Vertex/Agent Engine, nested Service Directory/Workstations/VMware inventories,
Cloud Run revisions and GKE on-premises clusters. It uses documented regional
hosts, actual zone discovery, native metadata GETs/FULL views where needed,
positive response field masks and independent CRM proof for numeric project
aliases. Region selections expand through Compute Zones List for zonal APIs;
`<service>_network_locations` supplies explicit service locations. An empty or
unavailable location set is a coverage gap. Cloud Storage native bucket IP
filters and managed NFS export-policy clients reach the map and agent.

Synapse managed private endpoints use the workspace's native `dev` endpoint and
`https://dev.azuresynapse.net` audience. Load Testing network definitions use the
ARM-bound `dataPlaneURI` and `https://cnt-prod.loadtesting.azure.com` audience.
Both enumerate read-only network metadata; no script or artifact downloads are
performed. An ARM-only token cannot mint these audiences: those collections
remain unavailable until the connector identity can acquire the correct token
and has the corresponding data-plane metadata read role. A Load Test Reader
and a Synapse role granting managed-endpoint reads are sufficient for their
respective metadata surfaces; Azure subscription Reader alone does not imply
those grants.

Kubernetes version/scope discovery covers Cilium, Calico, MetalLB, Antrea,
Multus and Istio, plus Traefik, Contour, NGINX, Linkerd, Envoy Gateway and
OpenShift/OVN routes and network declarations. The additional ingress/mesh
resources have a separate registry from the existing admitted CNI/Multus router.
The original router manifest/matcher and selected-content admission contracts
remain unchanged. The collector guide contains the exact optional read-only
RBAC groups/plurals. Arbitrary installed CRDs and SaaS account APIs outside the
four native connector identity domains are not silently treated as collected.

Network declarations and policy references remain distinct from observed
traffic. Cross-account endpoint ownership and native API resource types are
preserved; missing targets remain references. All endpoint URL projections,
including arrays, remove embedded user information and query/fragment material.
The agent receives lossless network resource detail through `context.sqlite`;
its compact overview and the map's paginated views do not drop that evidence.
A fresh network scan is required because existing snapshots are immutable.
