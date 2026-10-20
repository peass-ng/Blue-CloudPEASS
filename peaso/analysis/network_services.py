"""Native managed-service network facts shared by topology and AI projection.

Links describe configuration, never observed traffic. Only explicit resource
references establish attachments; DNS names and CSI handles remain references.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit
from .network_catalog import NETWORK_SERVICE_GROUPS, NETWORK_FIELDS


SERVICE_TYPES = {
    "aws": {
        "bucket", "ecs_cluster", "ecs_service", "ecs_task", "ecs_task_set", "ecs_container_instance",
        "efs_file_system", "efs_mount_target", "cloudfront_distribution", "cloudfront_vpc_origin",
        "elasticache_cluster", "elasticache_replication_group", "elasticache_subnet_group",
        "memorydb_cluster", "memorydb_subnet_group", "redshift_cluster", "redshift_subnet_group", "fsx_file_system",
        "rds_proxy", "rds_db_subnet_group", "docdb_instance", "docdb_cluster", "neptune_cluster", "dms_replication_instance",
        "opensearch_domain", "mq_broker", "msk_cluster", "rds_instance", "rds_cluster",
        "lambda_function", "eks_cluster",
    },
    "azure": {
        "storage_account", "vault", "managed_hsm", "sql_server", "cosmos_account", "redis_cache",
        "app_service", "app_service_environment", "aks_cluster", "container_group", "container_registry",
        "cognitive_account", "app_configuration", "data_factory", "api_management", "search_service",
        "purview_account", "mongo_cluster", "databricks_workspace", "kusto_cluster", "ml_workspace",
        "mysql_flexible_server", "postgresql_flexible_server", "mssql_managed_instance",
        "servicebus_namespace", "eventhub_namespace", "eventgrid_topic", "eventgrid_domain",
        "synapse_workspace", "signalr_service", "web_pubsub", "batch_account", "recovery_vault",
        "frontdoor", "cdn_profile", "azure_firewall", "private_link_service",
    },
    "gcp": {
        "bucket", "gke_cluster", "sql_instance", "cloudrun_service", "cloudrun_job", "function",
        "service_attachment", "network_endpoint_group", "network_attachment", "vpc_access_connector",
        "filestore_instance", "redis_instance", "alloydb_cluster", "alloydb_instance",
        "composer_environment", "workbench_instance", "dataproc_cluster", "worker_pool",
    },
    "k8s": {"persistentvolume", "persistentvolumeclaim"},
}
for _provider, _groups in NETWORK_SERVICE_GROUPS.items():
    SERVICE_TYPES[_provider].update(set().union(*_groups.values()))

# A positive field projection, rather than copying arbitrary application
# configuration. Container environment, origin headers, CSI credentials, IAM,
# database users and configuration values are deliberately not admitted.
_SCALARS = set("""
id name type location arn ARN Arn status Status state State endpoint Endpoint address Address
host port Port protocol Protocol ipAddress IpAddress Ipv6Address DNSName domainName DomainName
VpcId VpcID SubnetId SubnetIds SecurityGroupIds GroupId NetworkInterfaceId NetworkInterfaceIds
FileSystemId FileSystemArn MountTargetId clusterArn serviceArn taskArn containerInstanceArn
ec2InstanceId taskDefinitionArn DBInstanceIdentifier DBClusterIdentifier PubliclyAccessible
CacheClusterId CacheSubnetGroupName ReplicationGroupId SubnetGroupName ClusterIdentifier
DBSubnetGroupName SubnetIdentifier VpcSecurityGroupId VpcSecurityGroupIds VpcSubnetIds SecurityGroupId LifeCycleState
AvailabilityZoneName AvailabilityZoneId NetworkType NetworkEndpointType networkEndpointType
network subnetwork networkIP privateIpAddress publicIpAddress privateNetwork authorizedNetwork
vpcConnector vpcConnectorEgressSettings vpcConnectorEgressSetting vpcAccessConnector vpcAccessEgress
connector egress ingress internalIpOnly enablePrivateEndpoint enablePrivateNodes privateEndpoint
publicEndpoint endpointPublicAccess endpointPrivateAccess endpointPrivateAccessOnly
clusterSecurityGroupId vpcId subnetIds securityGroupIds endpointWithId consumerNetwork targetService
target serviceAttachment pscTargetService pscConnectionStatus pscConnectionId serviceClass
connectionPreference enableProxyProtocol natSubnets subnet subnetName networkName projectId
vnetSubnetID podSubnetID virtualNetworkSubnetId subnetResourceId delegatedSubnetResourceId
privateEndpointNetworkPolicies privateLinkServiceNetworkPolicies publicNetworkAccess
virtualNetworkType virtualNetworkId privateLinkServiceId groupIds customDnsConfigs
privateIPAddress privateIPAllocationMethod fqdn provisioningState connectionStatus
server serverName hostname path volumeHandle driver volumeName claimName namespace uid
providerID loadBalancerClass externalTrafficPolicy internalTrafficPolicy clusterIP clusterIPs
externalIPs loadBalancerIP loadBalancerSourceRanges allocateLoadBalancerNodePorts ipFamilies
serviceName readOnly bindCompleted apiVersion kind
Id Name VpcOriginId OriginEndpointArn HTTPPort HTTPSPort OriginProtocolPolicy OriginSslProtocols
assignPublicIp desiredStatus lastStatus launchType platformVersion connectivity
networkMode networkInterfaceId privateIpv4Address subnetId securityGroups subnets
cacheClusterId cacheNodeId CacheClusterId DBInstanceArn DBClusterArn CacheSubnetGroupName
ClusterSubnetGroupName SubnetGroupName subnetGroupName ipCidrRange cidr ipCidr ipv4CidrBlock
privateIpGoogleAccess privateIpv6GoogleAccess enablePscGlobalAccess dnsName dnsNames
dnsSupport dnsHostnames publicAccess cidrBlocks clusterIpv4Cidr servicesIpv4Cidr serviceIpv4Cidr
privateEndpointIpAddress publicEndpointIpAddress enablePublicEndpoint privateIpv6Access
pscServiceAttachmentLink clusterIpv4CidrBlock servicesIpv4CidrBlock masterIpv4CidrBlock
defaultAction bypass action virtualNetworkSubnetId ignoreMissingVnetServiceEndpoint endpointService
privateLinkResourceId privateLinkLocation requestMessage statusCode vnetResourceId
hostNetwork nodeName podCIDR podCIDRs dnsPolicy nodeSelector podIP podIPs hostIP
ip serverPort targetPort nodePort appProtocol networkAttachment blockOwnerDeletion
pscEnabled enablePrivateServiceConnect service cloudRunService cloudFunctionUrl clusterName
serviceArn serviceName group
function region zone uri Ipv6AllowedForDualStack IpAddressType Scheme EndpointType Identifier
enablePrivateCluster podCidr serviceCidr dnsServiceIP outboundType networkPlugin networkPolicy
""".split())
_CONTAINERS = set("""
properties networkProfile networkAcls virtualNetworkRules ipRules privateEndpointConnections
privateEndpoint privateLinkServiceConnections manualPrivateLinkServiceConnections
privateLinkServiceConnectionState networkInterfaces ipConfigurations publicIPAddress
virtualNetwork networkSecurityGroup networkConfiguration awsvpcConfiguration attachments details
VpcConfig NetworkConfiguration VpcSecurityGroups DBSubnetGroup DBSubnetGroupDetails Subnets
SecurityGroups SecurityGroupIds SubnetIds SubnetMappings AvailabilityZones resourcesVpcConfig
Configuration clusters Cluster cluster vnetConnections agentPoolProfiles apiServerAccessProfile
vnetConfiguration virtualNetworkConfiguration subnetIds virtualNetworkSubnetId networkRuleSet
networkRules networkRuleBypassOptions networkConfig privateClusterConfig ipAllocationPolicy
masterAuthorizedNetworksConfig controlPlaneEndpointsConfig settings ipConfiguration ipAddresses
pscConfig pscServiceAttachmentLink allowedConsumerProjects connectedEndpoints natSubnets
vpcAccess networkInterfaces template templateConfig serviceConfig buildConfig config
gceClusterConfig virtualClusterConfig environmentConfig softwareConfig nodeConfig
VpcOptions BrokerNodeGroupInfo BrokerNodeGroupInfoList ClientSubnets SecurityGroupIds
CacheSubnetGroup ReplicationSubnetGroup VpcSecurityGroups SubnetGroup ClusterSubnetGroup
VpcOriginEndpointConfig VpcOriginConfig Origins Items Config DistributionConfig VpcOrigin
loadBalancers targetGroupArn loadBalancerName containerName containerPort
spec metadata status nfs csi claimRef volumeClaimTemplates volumes persistentVolumeClaim
loadBalancer ingress ports endpoints addresses cloudRun cloudFunction appEngine pscData
networks authorizedNetworks networkAttachments pscConnections consumerForwardingRule
VpcOptions vpcOptions BrokerNodeGroupInfo brokerNodeGroupInfo serverless provisioned
Serverless Provisioned VpcConfigs VpcConfig vpcConfig SecurityGroupIds SecurityGroups
subnets securityGroups vpcSecurityGroups subnetGroup securityGroupIds awsVpcConfiguration
subnetIds vpcSubnets securityGroups Configuration Cluster cluster clusters ResourcesVpcConfig
loadBalancerArn subnetConfigurations ipConfiguration ipv4Enabled requireSsl sslMode
enablePrivatePathForGoogleCloudServices resourceName customNetworkConfig
userAssignedNATGateway vnetConfiguration subnetResourceId serviceEndpoints
networkAcls networkRuleSet virtualNetworkRules ipRules privateLinkResources
frontendIPConfigurations backendAddressPools loadBalancerFrontendIpConfigurations
networkInterfaces privateEndpoints privateEndpointConnection networkInterface
loadBalancerOrigin originGroups origins afdEndpoints FrontDoorConfig
sharedPrivateLinkResource privateLink
spec volumes persistentVolumeClaim claimRef nfs csi
Domain DomainStatus Broker BrokerInstances Endpoints NetworkConfiguration VpcOriginEndpointConfig
Detail ClusterInfo
""".split())
_CONTAINERS |= NETWORK_FIELDS | {"projects", "endpointConfiguration", "PhysicalConnectionRequirements", "Server"}


def project_network_data(data):
    """Retain native paths used for network attachments, dropping other fields."""
    if isinstance(data, list):
        return [project_network_data(x) for x in data]
    if not isinstance(data, dict):
        if isinstance(data, str):
            from .network_observations import safe_url
            return safe_url(data)
        return data
    out = {}
    for key, value in data.items():
        if key in {"_coverage", "_provenance", "_evidence"}:
            out[key] = value
        elif key == "NetworkAttributes":
            from .network_observations import network_observations
            out[key] = network_observations({key: value})
        elif key == "environment":
            # Dataflow uses this name for worker networking. Other services use
            # it for application variables, even variables named "network".
            if isinstance(value, dict) and isinstance(value.get("workerPools"), list):
                out[key] = {"workerPools": [{k: v for k, v in pool.items()
                    if k in {"network", "subnetwork", "ipConfiguration"} and isinstance(v, str)}
                    for pool in value["workerPools"] if isinstance(pool, dict)]}
        elif key == "details" and isinstance(value, list):
            out[key] = [{"name": d["name"], "value": d.get("value")} for d in value
                        if isinstance(d, dict) and d.get("name") in
                        {"subnetId", "networkInterfaceId", "privateIPv4Address", "ipv6Address", "privateDnsName"}]
        elif key in {"nodeSelector", "matchLabels"} and isinstance(value, dict):
            out[key] = {k: v for k, v in value.items() if isinstance(v, str)}
        elif key == "metadata" and isinstance(value, dict):
            out[key] = {k: v for k, v in value.items() if k in {"name", "namespace", "uid", "labels", "ownerReferences"}}
        elif key == "resourceMethods" and isinstance(value, dict):
            out[key] = {method: project_network_data(config) for method, config in value.items()
                        if method in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY"}}
        elif key == "outboundRules" and isinstance(value, dict):
            out[key] = {name: project_network_data(rule) for name, rule in value.items() if isinstance(rule, dict)}
        elif key == "publicDomainNames" and isinstance(value, dict):
            out[key] = {name: [host for host in hosts if isinstance(host, str)] for name, hosts in value.items() if isinstance(hosts, list)}
        elif key == "SubnetMapping" and isinstance(value, dict):
            out[key] = {zone: subnet for zone, subnet in value.items() if isinstance(subnet, str) and subnet.startswith("subnet-")}
        elif key == "OptionSettings" and isinstance(value, list):
            permitted = {
                "aws:ec2:vpc": {"VPCId", "Subnets", "ELBSubnets", "DBSubnets", "AssociatePublicIpAddress", "ELBScheme"},
                "aws:autoscaling:launchconfiguration": {"SecurityGroups"},
                "aws:elb:loadbalancer": {"SecurityGroups", "ManagedSecurityGroup"},
                "aws:elbv2:loadbalancer": {"SecurityGroups", "ManagedSecurityGroup"},
            }
            out[key] = [{k: option[k] for k in ("Namespace", "OptionName", "Value") if k in option}
                        for option in value if isinstance(option, dict) and
                        option.get("OptionName") in permitted.get(option.get("Namespace"), set()) and
                        isinstance(option.get("Value"), str)]
        elif key in {"uri", "IntegrationUri", "url", "EndpointURL", "UriEndpoint"} and isinstance(value, str) and value.startswith(("https://", "http://")):
            parsed = urlsplit(value)
            out[key] = parsed._replace(netloc=parsed.netloc.rsplit("@", 1)[-1], query="", fragment="").geturl()
        elif key in _SCALARS or key in _CONTAINERS:
            out[key] = project_network_data(value)
    return out


def walk(value, path=""):
    if isinstance(value, dict):
        for key, item in value.items():
            current = f"{path}.{key}" if path else key
            yield current, key, item
            if isinstance(item, (dict, list)):
                yield from walk(item, current)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from walk(item, f"{path}[{i}]")


def aws_scope(rid, fallback, *, global_resource=False):
    parts = rid.split(":", 5)
    if len(parts) == 6 and parts[0] == "arn" and parts[4]:
        return f"{parts[4]}/{'global' if global_resource else parts[3] or 'global'}"
    return fallback


def gcp_ref(value, kind, resource):
    """Normalize Compute URLs/relative names while retaining project identity."""
    if not isinstance(value, str) or not value:
        return None
    path = urlsplit(value).path
    path = path[path.index("projects/"):] if "projects/" in path else path
    project = str(resource["scope"]).removeprefix("projects/")
    if path.startswith("projects/"):
        project = path.split("/")[1]
    elif kind == "network" and "/" not in path:
        path = f"projects/{project}/global/networks/{path}"
    else:
        return None
    if kind in {"vpc_access_connector", "gke_cluster"}:
        return path, f"projects/{project}"
    return "https://www.googleapis.com/compute/v1/" + path, f"projects/{project}"


def azure_kind(rid):
    # Resource type is part of the ARM ID, not a guessed service name.
    from peaso.collectors.azure import ENDPOINTS
    from peaso.collectors.azure_network_catalog import CHILDREN
    parts = rid.strip('/').split('/')
    providers = [i for i, part in enumerate(parts) if part.casefold() == 'providers']
    if not providers:
        return 'private_link_service_reference'
    native = parts[providers[-1] + 1:]
    if len(native) < 3 or len(native) % 2 != 1:
        return 'private_link_service_reference'
    expected_type = (native[0] + '/' + '/'.join(native[1::2])).casefold()
    for kind, (resource_type, _) in ENDPOINTS.items():
        if resource_type.casefold() == expected_type:
            return kind
    for kind in CHILDREN:
        segments, root = [], kind
        while root in CHILDREN:
            parent, segment, _ = CHILDREN[root]
            segments.insert(0, segment)
            root = parent
        if root in ENDPOINTS and (ENDPOINTS[root][0] + '/' + '/'.join(segments)).casefold() == expected_type:
            return kind
    return "private_link_service_reference"


def service_references(resource):
    data, provider, kind = resource["data"], resource["provider"], resource["type"]
    if provider == "aws":
        if kind == "vpc_endpoint" and isinstance(data.get("ServiceName"), str) and data["ServiceName"]:
            yield "ServiceName", "endpoint_service_reference", data["ServiceName"], None, "endpoint_service"
        # Applied to supported managed services only, not arbitrary payloads.
        if kind not in SERVICE_TYPES[provider]:
            return
        fields = {"VpcId": "vpc", "VpcID": "vpc", "vpcId": "vpc", "SubnetId": "subnet",
                  "SubnetIdentifier": "subnet", "subnetId": "subnet", "GroupId": "security_group",
                  "SecurityGroupId": "security_group", "VpcSecurityGroupId": "security_group",
                  "NetworkInterfaceId": "network_interface", "ec2InstanceId": "instance",
                  "clusterArn": "ecs_cluster", "serviceArn": "ecs_service", "containerInstanceArn": "ecs_container_instance",
                  "targetGroupArn": "target_group", "FileSystemId": "fsx_file_system" if kind.startswith('fsx_') else "efs_file_system"}
        lists = {"SubnetIds": "subnet", "VpcSubnetIds": "subnet", "subnetIds": "subnet", "subnets": "subnet", "ClientSubnets": "subnet",
                 "SecurityGroupIds": "security_group", "securityGroups": "security_group",
                 "securityGroupIds": "security_group", "SecurityGroups": "security_group"}
        # ECS lower-case configuration is native, including attachment details.
        for path, key, val in walk(project_network_data(data)):
            if key in fields and isinstance(val, str) and val:
                target = fields[key]
                if key == "serviceArn" and kind.startswith("lattice_"):
                    target = "lattice_service"
                if key == "targetGroupArn" and kind.startswith("lattice_"):
                    target = "lattice_target_group"
                if path == key and key in {"VpcId", "SubnetId", "NetworkInterfaceId"}:
                    continue  # The generic AWS reader already emits this field.
                target_scope = aws_scope(val, resource["scope"])
                owner = data.get("vpcOwnerId")
                if kind == "lattice_vpc_association" and isinstance(owner, str) and owner.isdigit() and len(owner) == 12 and target in {"vpc", "security_group"}:
                    target_scope = f"{owner}/{resource['scope'].split('/')[-1]}"
                yield path, target, val, target_scope, "protected_by" if target == "security_group" else "associated_with" if target in {"vpc", "subnet"} else "service_attachment"
            if key in lists and isinstance(val, list):
                for i, rid in enumerate(val):
                    if isinstance(rid, str) and rid:
                        target = lists[key]
                        owner = data.get("vpcOwnerId")
                        scope = f"{owner}/{resource['scope'].split('/')[-1]}" if kind == "lattice_vpc_association" and isinstance(owner, str) and owner.isdigit() and len(owner) == 12 else None
                        yield f"{path}[{i}]", target, rid, scope, "protected_by" if target == "security_group" else "associated_with"
            if kind == "memorydb_subnet_group" and key == "Identifier" and ".Subnets[" in "." + path and isinstance(val, str):
                yield path, "subnet", val, None, "associated_with"
            if key == "details" and isinstance(val, list) and ".attachments[" in "." + path:
                for i, detail in enumerate(val):
                    if isinstance(detail, dict) and detail.get("name") in {"subnetId", "networkInterfaceId"} and isinstance(detail.get("value"), str):
                        target = "subnet" if detail["name"] == "subnetId" else "network_interface"
                        yield f"{path}[{i}].value", target, detail["value"], None, "associated_with" if target == "subnet" else "attached_interface"
            if key == "VpcOriginId" and isinstance(val, str) and val:
                account = str(resource["scope"]).split("/")[0]
                yield path, "cloudfront_vpc_origin", val, f"{account}/global", "vpc_origin"
            if kind == "cloudfront_distribution" and key == "DomainName" and "Origins.Items[" in path and isinstance(val, str) and val:
                yield path, "external_endpoint_reference", val, None, "origin_hostname"
            if (key == "Arn" and "VpcOriginEndpointConfig" in path or key == "OriginEndpointArn") and isinstance(val, str):
                target = "load_balancer" if ":elasticloadbalancing:" in val else "instance" if ":ec2:" in val and ":instance/" in val else None
                if target:
                    rid = val.rsplit("/", 1)[-1] if target == "instance" else val
                    yield path, target, rid, aws_scope(val, resource["scope"]), "origin_target"
        # Names refer to explicitly collected subnet groups, never to subnets.
        for key, target in (("CacheSubnetGroupName", "elasticache_subnet_group"),
                            ("ClusterSubnetGroupName", "redshift_subnet_group"),
                            ("SubnetGroupName", "memorydb_subnet_group")):
            if isinstance(data.get(key), str) and data[key]:
                yield key, target, data[key], None, "subnet_group"
    elif provider == "gcp":
        mapping = {"privateNetwork": "network", "authorizedNetwork": "network", "network": "network",
                   "subnetwork": "subnetwork", "subnet": "subnetwork", "connector": "vpc_access_connector", "vpcConnector": "vpc_access_connector",
                   "vpcAccessConnector": "vpc_access_connector", "pscServiceAttachmentLink": "service_attachment",
                   "serviceAttachment": "service_attachment", "pscTargetService": "service_attachment",
                   "consumerNetwork": "network", "targetService": "forwarding_rule"}
        for path, key, value in walk(project_network_data(data)):
            target = mapping.get(key)
            if key in {"network", "subnetwork"} and (kind not in SERVICE_TYPES["gcp"] or "peerings[" in path):
                target = None
            if target and (ref := gcp_ref(value, target, resource)):
                relation = ("psc_consumer_network" if key == "consumerNetwork" else
                            "associated_with" if target in {"network", "subnetwork"} else "service_attachment")
                yield path, target, ref[0], ref[1], relation
            if key in {"natSubnets", "subnetworks"} and isinstance(value, list):
                for i, rid in enumerate(value):
                    if ref := gcp_ref(rid, "subnetwork", resource):
                        yield f"{path}[{i}]", "subnetwork", ref[0], ref[1], "contains" if kind == "network" else "associated_with"
            if key == "subnetwork" and isinstance(value, str) and "/" not in value:
                name_parts = str(data.get("name", "")).split("/")
                if "locations" in name_parts:
                    region = name_parts[name_parts.index("locations") + 1]
                    rid = f"{resource['scope']}/regions/{region}/subnetworks/{value}"
                    ref = gcp_ref(rid, "subnetwork", resource)
                    yield path, "subnetwork", ref[0], ref[1], "associated_with"
        if kind == "vpc_access_connector":
            subnet = data.get("subnet")
            name = data.get("name", "").split("/")
            if isinstance(subnet, dict) and isinstance(subnet.get("name"), str) and "/" not in subnet["name"] and "locations" in name:
                region = name[name.index("locations") + 1]
                project = subnet.get("projectId") or str(resource["scope"]).removeprefix("projects/")
                rid = f"projects/{project}/regions/{region}/subnetworks/{subnet['name']}"
                if ref := gcp_ref(rid, "subnetwork", resource):
                    yield "subnet.name", "subnetwork", ref[0], ref[1], "associated_with"
        if kind == "network_endpoint_group":
            identity = data.get("selfLink") or resource.get("native_id") or data.get("name", "")
            region = re.search(r"/regions/([^/]+)/", str(identity))
            if region:
                for key, field, target_kind, segment in (("cloudRun", "service", "cloudrun_service", "services"),
                        ("cloudFunction", "function", "function", "functions")):
                    config = data.get(key)
                    service = config.get(field) if isinstance(config, dict) else None
                    if isinstance(service, str) and service and "/" not in service:
                        rid = f"{resource['scope']}/locations/{region[1]}/{segment}/{service}"
                        yield f"{key}.{field}", target_kind, rid, resource["scope"], "serverless_backend"
    elif provider == "azure":
        for path, key, val in walk(project_network_data(data)):
            if key == "id" and path.endswith(".subnet.id") and isinstance(val, str) and "/subnets/" in val.lower():
                yield path, "subnet", val, azure_scope(val, resource["scope"]), "associated_with"
            if key == "id" and path.endswith(".virtualNetwork.id") and isinstance(val, str) and "/virtualnetworks/" in val.lower():
                target = "subnet" if "/subnets/" in val.lower() else "vnet"
                yield path, target, val, azure_scope(val, resource["scope"]), "associated_with"
            if key in {"virtualNetworkSubnetId", "virtualNetworkSubnetResourceId", "subnetId", "subnetResourceId", "delegatedSubnetResourceId", "vnetSubnetID", "podSubnetID"}:
                if isinstance(val, str) and "/subnets/" in val.lower():
                    yield path, "subnet", val, azure_scope(val, resource["scope"]), "associated_with"
            if key == "id" and isinstance(val, str) and ".virtualNetworkRules[" in "." + path and "/subnets/" in val.lower():
                yield path, "subnet", val, azure_scope(val, resource["scope"]), "service_endpoint_rule"
            if key == "privateEndpoint" and isinstance(val, dict) and isinstance(val.get("id"), str):
                rid = val["id"]
                yield path + ".id", "private_endpoint", rid, azure_scope(rid, resource["scope"]), "private_endpoint_connection"
            if key == "privateLinkResourceId" and isinstance(val, str) and val:
                yield path, azure_kind(val), val, azure_scope(val, resource["scope"]), "private_link_target"
            if key == "privateLink" and "sharedPrivateLinkResource" in path and isinstance(val, dict) and isinstance(val.get("id"), str):
                rid = val["id"]
                yield path + ".id", azure_kind(rid), rid, azure_scope(rid, resource["scope"]), "private_link_target"
            if key == "vnetResourceId" and isinstance(val, str):
                yield path, "vnet", val, azure_scope(val, resource["scope"]), "associated_with"
            if key == "service" and "serviceEndpoints[" in path and isinstance(val, str) and val:
                yield path, "azure_service_reference", val, None, "service_endpoint"
    elif provider == "k8s":
        # Preserve cloud resource IDs and storage endpoints without fabricating
        # account/project context or claiming a cross-snapshot cloud join.
        for path, key, val in walk(data):
            if ((key == "providerID" or key == "volumeHandle" and ".csi." in "." + path
                 or key == "server" and ".nfs." in "." + path)
                    and isinstance(val, str) and val):
                yield path, "external_service_reference", val, None, "external_service"
            if kind == "service" and key in {"hostname", "ip"} and path.startswith("status.loadBalancer.") and isinstance(val, str) and val:
                yield path, "external_endpoint_reference", val, None, "load_balancer_endpoint"


def azure_scope(rid, fallback):
    match = re.search(r"/subscriptions/([^/]+)", rid, re.I)
    if match:
        return (f"/subscriptions/{match[1]}" if fallback.lower().startswith("/subscriptions/")
                else f"subscription:{match[1]}")
    return fallback
