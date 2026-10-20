"""Extra explicit service, DNS and transit references; no reachability inference."""
import re
from .network_services import project_network_data, walk, aws_scope, gcp_ref, azure_scope, azure_kind


def references(resource):
    provider, kind = resource["provider"], resource["type"]
    data = project_network_data(resource["data"])
    if provider == "aws":
        if kind == 'vpc_endpoint_connection' and isinstance(resource['data'].get('ServiceId'), str):
            yield 'ServiceId', 'vpc_endpoint_service', resource['data']['ServiceId'], resource['scope'], 'private_endpoint_service'
        if kind == 'vpc_public_access_exclusion':
            from .network_observations import aws_attachment
            for path, target, identity in aws_attachment({'path': 'ResourceArn', 'name': 'ResourceArn', 'value': resource['data'].get('ResourceArn')}):
                yield path, target, identity.rsplit('/', 1)[-1], aws_scope(identity, resource['scope']), 'public_access_exclusion'
        fields = {"HostVPCId": "vpc", "VPCId": "vpc", "Ec2SubnetId": "subnet", "securityGroupId": "security_group", "SecurityGroupIdentifier": "security_group",
            "VpcEndpointId": "vpc_endpoint", "VpcConnectorArn": "app_runner_vpc_connector",
            "ServiceArn": "app_runner_service", "ResolverEndpointId": "resolver_endpoint", "ResolverRuleId": "resolver_rule",
            "DhcpOptionsId": "dhcp_options", "directConnectGatewayId": "directconnect_gateway",
            "virtualGatewayId": "vpn_gateway", "connectionId": "directconnect_connection",
            "AcceleratorArn": "globalaccelerator_accelerator", "ListenerArn": "globalaccelerator_listener"}
        fields.update({"EndpointConfigName": "sagemaker_endpoint_config", "ModelName": "sagemaker_model"})
        fields.update({"serviceNetworkId": "lattice_service_network", "serviceNetworkArn": "lattice_service_network"})
        lists = {"Subnets": "subnet", "SecurityGroupIdList": "security_group", "VpcSecurityGroupIds": "security_group",
            "RequestedEc2SubnetIds": "subnet", "AdditionalMasterSecurityGroups": "security_group", "AdditionalSlaveSecurityGroups": "security_group",
            "vpcEndpointIds": "vpc_endpoint", "VpcEndpointIds": "vpc_endpoint", "targetArns": "load_balancer"}
        lists["networkInterfaceIds"] = "network_interface"
        lists.update({"vpcSubnetIds": "subnet", "vpcSecurityGroupIds": "security_group", "sourceSecurityGroups": "security_group",
                      "SubnetArns": "subnet", "SecurityGroupArns": "security_group"})
        fields.update({"GatewayARN": "storagegateway_gateway", "Ec2InstanceId": "instance"})
        fields["LoadBalancerArn"] = "load_balancer"
        fields.update({"resourceConfigurationId": "lattice_resource_configuration", "resourceConfigurationArn": "lattice_resource_configuration",
            "ResourceConfigurationArn": "lattice_resource_configuration", "resourceGatewayId": "lattice_resource_gateway",
            "ServiceNetworkArn": "lattice_service_network", "vpcIdentifier": "vpc", "targetGroupId": "lattice_target_group",
            "targetGroupIdentifier": "lattice_target_group", "listenerArn": "lattice_listener"})
        lists["serviceArns"] = "lattice_service"
        fields.update({"SecurityGroup": "security_group", "EniId": "network_interface", "CloudHsmClusterId": "cloudhsm_cluster",
            "VerifiedAccessGroupId": "verified_access_group", "VerifiedAccessInstanceId": "verified_access_instance",
            "VpcEndpointServiceName": "endpoint_service_reference"})
        fields.update({'ReplicationSubnetGroupId': 'dms_replication_subnet_group', 'SubnetGroupIdentifier': 'dms_replication_subnet_group'})
        fields['ClientVpnEndpointId'] = 'ec2_client_vpn_endpoint'
        fields.update(dict.fromkeys({"EmrManagedMasterSecurityGroup", "EmrManagedSlaveSecurityGroup", "ServiceAccessSecurityGroup"}, "security_group"))
        for path, key, value in walk(data):
            if key == 'NetworkInterfaceArn' and kind in {'mediaconnect_router_input', 'mediaconnect_router_output'} and isinstance(value, str):
                yield path, 'mediaconnect_router_interface', value, aws_scope(value, resource['scope']), 'declared_router_interface'
            if key == 'VpcConnectionArn' and kind == 'msk_client_vpc_connection' and isinstance(value, str):
                yield path, 'msk_vpc_connection', value, aws_scope(value, resource['scope']), 'client_vpc_connection'
            if key == 'PrefixListId' and isinstance(value, str) and kind != 'managed_prefix_list':
                yield path, 'managed_prefix_list', value, resource['scope'], 'prefix_list_reference'
            if kind == 'flow_log' and key == 'ResourceId' and isinstance(value, str):
                target = 'vpc' if value.startswith('vpc-') else 'subnet' if value.startswith('subnet-') else 'network_interface' if value.startswith('eni-') else None
                if target:
                    yield path, target, value, resource['scope'], 'flow_log_configuration'
            if kind in {'events_network_target', 'scheduler_network_schedule'} and key == 'Arn' and isinstance(value, str) and ':ecs:' in value and ':cluster/' in value:
                yield path, 'ecs_cluster', value, aws_scope(value, resource['scope']), 'configured_workload_target'
            if kind == "cloudhsm_cluster" and key == "SubnetMapping" and isinstance(value, dict):
                for zone, subnet in value.items():
                    yield f"{path}.{zone}", "subnet", subnet, None, "associated_with"
            if kind in {"lightsail_container_service", "elastic_beanstalk_environment", "appsync_graphql_api"} and key in {"url", "CNAME", "EndpointURL", "GRAPHQL", "REALTIME"} and isinstance(value, str):
                yield path, "external_endpoint_reference", value, None, "service_endpoint"
            if kind == "lightsail_load_balancer" and key == "instanceName" and isinstance(value, str):
                yield path, "lightsail_instance", value, None, "load_balancer_backend"
            if kind == "lattice_resource_configuration" and key in {"arn", "domainName", "ipAddress"} and "resourceConfigurationDefinition." in path and isinstance(value, str):
                target = "rds_instance" if ":rds:" in value and ":db:" in value else "rds_cluster" if ":rds:" in value and ":cluster:" in value else "external_endpoint_reference"
                yield path, target, value, aws_scope(value, resource["scope"]), "resource_configuration_target"
            if key == "OptionSettings" and kind == "elastic_beanstalk_environment" and isinstance(value, list):
                for i, option in enumerate(value):
                    target = {"VPCId": "vpc", "Subnets": "subnet", "ELBSubnets": "subnet", "DBSubnets": "subnet",
                              "SecurityGroups": "security_group", "ManagedSecurityGroup": "security_group"}.get(option.get("OptionName"))
                    for rid in option.get("Value", "").split(","):
                        if target and rid.strip():
                            yield f"{path}[{i}].Value", target, rid.strip(), None, "protected_by" if target == "security_group" else "associated_with"
            if key in fields and isinstance(value, str) and value and (key != "connectionId" or kind == "directconnect_virtual_interface"):
                target = fields[key]
                if kind == "route53_zone" and key == "VPCId" and ".VPCs[" in "." + path:
                    continue  # Region is carried by the containing association.
                if key == "ServiceArn" and kind != "app_runner_vpc_ingress_connection":
                    continue
                scope = resource['scope']
                if target == 'vpc_endpoint':
                    owner = resource['data'].get('VpcEndpointOwner') or resource['data'].get('vpcEndpointOwner') or resource['data'].get('vpcEndpointOwnerId')
                    if isinstance(owner, str) and re.fullmatch(r'\d{12}', owner):
                        scope = owner + '/' + scope.split('/')[-1]
                    region = resource['data'].get('VpcEndpointRegion')
                    if isinstance(region, str):
                        scope = scope.split('/')[0] + '/' + region
                yield path, target, value, aws_scope(value, scope), "associated_with" if target in {"vpc", "subnet"} else "protected_by" if target == "security_group" else "service_reference"
            if key in lists and isinstance(value, list):
                for i, rid in enumerate(value):
                    if isinstance(rid, str) and rid:
                        target = lists[key]
                        target_id = rid.rsplit("/", 1)[-1] if key in {"SubnetArns", "SecurityGroupArns"} and rid.startswith("arn:") else rid
                        yield f"{path}[{i}]", target, target_id, aws_scope(rid, resource["scope"]), "associated_with" if target == "subnet" else "protected_by" if target == "security_group" else "service_reference"
            if key == "clusterName" and kind in {"eks_nodegroup", "eks_fargate_profile"} and isinstance(value, str):
                yield path, "eks_cluster", value, resource["scope"], "cluster_membership"
            if kind == "route53_zone" and key == "VPCs" and isinstance(value, list):
                for i, vpc in enumerate(value):
                    if isinstance(vpc, dict) and isinstance(vpc.get("VPCId"), str) and isinstance(vpc.get("VPCRegion"), str):
                        # GetHostedZone does not identify the VPC owner; private zones
                        # may be associated with another account's VPC.
                        yield f"{path}[{i}].VPCId", "vpc", vpc["VPCId"], "owner-unverified/" + vpc["VPCRegion"], "dns_vpc_association"
            if key == "VpcLinkId" and kind != "apigatewayv2_vpc_link" and isinstance(value, str):
                yield path, "apigatewayv2_vpc_link", value, None, "private_integration"
            if key in {"connectionId", "ConnectionId"} and kind in {"rest_api", "http_api"} and isinstance(value, str):
                target = "apigateway_vpc_link" if kind == "rest_api" else "apigatewayv2_vpc_link"
                yield path, target, value, None, "private_integration"
            if key == "IntegrationUri" and kind == "http_api" and isinstance(value, str):
                target = "lambda_function" if value.startswith("arn:") and ":lambda:" in value else "elbv2_listener" if ":elasticloadbalancing:" in value and ":listener/" in value else "external_endpoint_reference"
                yield path, target, value, aws_scope(value, resource["scope"]), "integration_target"
            if key == "VPCZoneIdentifier" and isinstance(value, str):
                for i, subnet in enumerate(value.split(",")):
                    if re.fullmatch(r"subnet-[A-Za-z0-9]+", subnet.strip()):
                        yield path, "subnet", subnet.strip(), None, "associated_with"
            if key == "EndpointId" and kind == "globalaccelerator_endpoint_group" and isinstance(value, str):
                target = "load_balancer" if ":elasticloadbalancing:" in value else "instance" if value.startswith("i-") else "elastic_ip" if value.startswith("eipalloc-") else "external_endpoint_reference"
                scope = aws_scope(value, f"{resource['scope'].split('/')[0]}/{resource['data'].get('EndpointGroupRegion', 'unknown-region')}")
                yield path, target, value, scope, "accelerator_endpoint"
            if key == "SubnetGroupName" and kind == "dax_cluster" and isinstance(value, str):
                yield path, "dax_subnet_group", value, None, "subnet_group"
            if kind == "lattice_target_group" and key == "id" and re.search(r"(?:^|\.)NetworkTargets\[\d+\]\.id$", path) and isinstance(value, str):
                target = "instance" if value.startswith("i-") else "lambda_function" if ":lambda:" in value else "load_balancer" if ":elasticloadbalancing:" in value else "external_endpoint_reference"
                yield path, target, value, aws_scope(value, resource["scope"]), "registered_target"
            if key == "associatedGateway" and isinstance(value, dict) and kind == "directconnect_gateway_association":
                rid = value.get("id")
                target = {"transitGateway": "transit_gateway", "virtualPrivateGateway": "vpn_gateway"}.get(value.get("type"))
                owner, region = value.get("ownerAccount"), value.get("region")
                if target and isinstance(rid, str):
                    scope = f"{owner}/{region}" if isinstance(owner, str) and isinstance(region, str) else resource["scope"] + "/owner-unverified"
                    yield path + ".id", target, rid, scope, "gateway_association"
    elif provider == "azure":
        if kind == 'flow_log':
            for path, key, value in walk(resource['data']):
                if key == 'targetResourceId' and isinstance(value, str) and value.startswith('/subscriptions/'):
                    yield path, azure_kind(value), value, azure_scope(value, resource['scope']), 'flow_log_configuration'
        if kind == 'synapse_managed_private_endpoint':
            rid = resource.get('native_id', '')
            if isinstance(rid, str) and '/managedVirtualNetworks/' in rid:
                parent = rid.split('/managedVirtualNetworks/', 1)[0]
                yield 'networkDataPlaneParent', 'synapse_workspace', parent, azure_scope(parent, resource['scope']), 'service_parent'
        if kind == 'powerplatform_enterprise_policy':
            injection = resource['data'].get('properties', {}).get('networkInjection', {})
            for index, native in enumerate(injection.get('virtualNetworks', [])):
                if not isinstance(native, dict):
                    continue
                network, subnet = native.get('id'), native.get('subnet', {}).get('name')
                if isinstance(network, str) and isinstance(subnet, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', subnet):
                    rid = network.rstrip('/') + '/subnets/' + subnet
                    yield f'properties.networkInjection.virtualNetworks[{index}].subnet.name', 'subnet', rid, azure_scope(rid, resource['scope']), 'associated_with'
        targets = {"infrastructureSubnetId": "subnet", "delegatedSubnetId": "subnet", "managedEnvironmentId": "container_app_environment",
            "environmentId": "container_app_environment", "poolId": "netapp_capacity_pool",
            "privateDnsZoneArmResourceId": "private_dns_zone", "privateDnsZoneId": "private_dns_zone"}
        native_maps = {"virtualHub": "virtual_hub", "virtualWan": "virtual_wan", "localNetworkGateway1": "local_network_gateway",
            "localNetworkGateway2": "local_network_gateway", "virtualNetworkGateway1": "virtual_network_gateway",
            "virtualNetworkGateway2": "virtual_network_gateway", "dnsResolver": "dns_resolver", "outboundEndpoint": "dns_outbound_endpoint"}
        native_maps["integrationServiceEnvironment"] = "integration_service_environment"
        for path, key, value in walk(data):
            if key == "serviceResourceId" and isinstance(value, str) and value.startswith("/"):
                yield path, azure_kind(value), value, azure_scope(value, resource["scope"]), "declared_private_link_destination"
            if key == "linkedResourceId" and kind == "monitor_scoped_resource" and isinstance(value, str) and value.startswith("/"):
                yield path, azure_kind(value), value, azure_scope(value, resource["scope"]), "monitor_private_link_resource"
            if key == "id" and ".dnsResolverOutboundEndpoints[" in "." + path and isinstance(value, str):
                yield path, "dns_outbound_endpoint", value, azure_scope(value, resource["scope"]), "resolver_outbound_endpoint"
            target = targets.get(key)
            if key in native_maps and isinstance(value, dict):
                target, value = native_maps[key], value.get("id")
                path += ".id"
            if key == "firewallPolicy" and isinstance(value, dict) and isinstance(value.get("id"), str):
                target, value = azure_kind(value["id"]), value["id"]
                path += ".id"
            if target and isinstance(value, str) and value.startswith("/"):
                yield path, target, value, azure_scope(value, resource["scope"]), "associated_with" if target == "subnet" else "service_reference"
        # ARM child resources have an explicit parent in their resource ID.
        parent_kind = {"hub_vnet_connection": ("hubVirtualNetworkConnections", "virtual_hub"),
            'traffic_controller_association': ('associations', 'traffic_controller'),
            'traffic_controller_frontend': ('frontends', 'traffic_controller'),
            'healthcare_fhir_service_v2': ('fhirservices', 'healthcare_workspace'),
            'healthcare_dicom_service': ('dicomservices', 'healthcare_workspace'),
            'healthcare_iot_connector': ('iotconnectors', 'healthcare_workspace'),
            'kusto_managed_private_endpoint': ('managedPrivateEndpoints', 'kusto_cluster'),
            'load_test_network_test': ('tests', 'load_test_resource'),
            'cassandra_data_center': ('dataCenters', 'cassandra_cluster'),
            'grafana_managed_private_endpoint': ('managedPrivateEndpoints', 'managed_grafana'),
            'elastic_san_volume_group': ('volumeGroups', 'elastic_san'),
            'hub_bgp_connection': ('bgpConnections', 'virtual_hub'),
            'hub_route_table': ('hubRouteTables', 'virtual_hub'),
            'hub_route_map': ('routeMaps', 'virtual_hub'),
            'hub_vpn_connection': ('vpnConnections', 'hub_vpn_gateway'),
            'hub_vpn_link_connection': ('vpnLinkConnections', 'hub_vpn_connection'),
            'hub_expressroute_connection': ('expressRouteConnections', 'hub_expressroute_gateway'),
            "monitor_scoped_resource": ("scopedResources", "monitor_private_link_scope"),
            "datafactory_managed_vnet": ("managedVirtualNetworks", "data_factory"),
            "datafactory_managed_private_endpoint": ("managedPrivateEndpoints", "datafactory_managed_vnet"),
            "dns_forwarding_rule": ("forwardingRules", "dns_forwarding_ruleset"),
            "dns_forwarding_vnet_link": ("virtualNetworkLinks", "dns_forwarding_ruleset"),
            "ml_compute": ("computes", "ml_workspace"),
            "registry_agent_pool": ("agentPools", "container_registry"),
            "dns_inbound_endpoint": ("inboundEndpoints", "dns_resolver"), "dns_outbound_endpoint": ("outboundEndpoints", "dns_resolver"),
            "netapp_volume": ("volumes", "netapp_capacity_pool"), "netapp_capacity_pool": ("capacityPools", "netapp_account")}
        rid = resource.get("native_id", "")
        if kind in {"dns_record", "private_dns_record_set"} and isinstance(rid, str):
            match = re.search(r"(/providers/Microsoft\.Network/(?:privateDnsZones|dnsZones)/[^/]+)/[^/]+/[^/]+$", rid, re.I)
            if match:
                parent = rid[:match.end(1)]
                target = "private_dns_zone" if kind == "private_dns_record_set" else "dns_zone"
                yield "id", target, parent, azure_scope(parent, resource["scope"]), "dns_zone_record"
        if kind in parent_kind and isinstance(rid, str):
            segment, target = parent_kind[kind]
            match = re.search(r"/" + segment + r"/[^/]+$", rid, re.I)
            if match:
                parent = rid[:match.start()]
                yield "id", target, parent, azure_scope(parent, resource["scope"]), "service_parent"
    elif provider == "gcp":
        yield from _gcp_native_service_links(resource)
        if kind == 'cloudrun_revision':
            native = resource.get('native_id', '')
            if isinstance(native, str) and '/revisions/' in native:
                parent = native.rsplit('/revisions/', 1)[0]
                yield 'name', 'cloudrun_service', parent, '/'.join(parent.split('/')[:2]), 'service_parent'
        if kind == "forwarding_rule" and isinstance(data.get("target"), str) and data["target"] in {"all-apis", "vpc-sc"}:
            yield "target", "google_api_bundle_reference", data["target"], None, "private_google_api_endpoint"
        fields = {"networkUrl": "network", "targetNetwork": "network", "peeredNetwork": "network", "interconnect": "interconnect",
            "router": "router", "instanceTemplate": "instance_template", "hub": "network_connectivity_hub",
            "vpc": "network", "networkAttachment": "network_attachment"}
        mesh_refs = {"serverTlsPolicy": "server_tls_policy", "clientTlsPolicy": "client_tls_policy", "authorizationPolicy": "authorization_policy"}
        for path, key, value in walk(data):
            if key == 'workerPool' and isinstance(value, str) and re.fullmatch(r'projects/[^/]+/locations/[^/]+/workerPools/[^/]+', value):
                yield path, 'worker_pool', value, '/'.join(value.split('/')[:2]), 'declared_execution_pool'
            if kind == 'fleet_membership' and key == 'resourceLink' and isinstance(value, str):
                native = value.removeprefix('//container.googleapis.com/')
                if re.fullmatch(r'projects/[^/]+/locations/[^/]+/clusters/[^/]+', native):
                    yield path, 'gke_cluster', native, '/'.join(native.split('/')[:2]), 'fleet_membership'
            if kind == "dns_record_set" and key == "managedZone" and isinstance(value, str):
                yield path, "dns_managed_zone", value, resource["scope"], "dns_zone_record"
            if kind == "dns_record_set" and key == "rrdatas" and isinstance(value, list) and data.get("type") in {"A", "AAAA", "CNAME", "NS", "PTR", "MX", "SRV"}:
                for i, address in enumerate(value):
                    if isinstance(address, str) and address:
                        target = address.split()[-1].rstrip(".")
                        yield f"{path}[{i}]", "external_endpoint_reference", target, None, "dns_record_value"
            if key in mesh_refs and isinstance(value, str) and re.fullmatch(r"projects/[^/]+/locations/[^/]+/[^/]+/[^/]+", value):
                yield path, mesh_refs[key], value, "projects/" + value.split("/")[1], "security_policy_reference"
            if key in {"meshes", "gateways"} and isinstance(value, list):
                target = "service_mesh" if key == "meshes" else "mesh_gateway"
                for i, rid in enumerate(value):
                    if isinstance(rid, str) and re.fullmatch(r"projects/[^/]+/locations/[^/]+/[^/]+/[^/]+", rid):
                        yield f"{path}[{i}]", target, rid, "projects/" + rid.split("/")[1], "declared_route_parent"
            if key == "serviceName" and kind.startswith("mesh_") and isinstance(value, str) and "/backendServices/" in value:
                if ref := gcp_ref(value, "backend_service", resource):
                    yield path, "backend_service", ref[0], ref[1], "declared_route_backend"
            target = fields.get(key)
            if target and isinstance(value, str) and value:
                if target == "network_connectivity_hub":
                    yield path, target, value, "projects/" + value.split("/")[1] if value.startswith("projects/") else None, "transit_hub"
                elif ref := gcp_ref(value, target, resource):
                    yield path, target, ref[0], ref[1], "policy_network" if key == "targetNetwork" else "associated_with" if key == "networkUrl" else "service_reference"
            if key == "uris" and isinstance(value, list):
                target = "vpn_tunnel" if "linkedVpnTunnels" in path else "interconnect_attachment" if "linkedInterconnectAttachments" in path else None
                if target:
                    for i, rid in enumerate(value):
                        if ref := gcp_ref(rid, target, resource):
                            yield f"{path}[{i}]", target, ref[0], ref[1], "transit_spoke"
            if key in {"ipv4Address", "ipv6Address"} and "targetNameServers" in path and isinstance(value, str):
                yield path, "external_endpoint_reference", value, None, "dns_forwarder"
            if key == "storagePool" and isinstance(value, str) and value.startswith("projects/"):
                yield path, "netapp_storage_pool", value, "projects/" + value.split("/")[1], "service_parent"
        if kind == "app_engine_network_version":
            network = data.get("network")
            if isinstance(network, dict) and (ref := gcp_ref(network.get("name"), "network", resource)):
                yield "network.name", "network", ref[0], ref[1], "associated_with"
            connector = data.get("vpcAccessConnector")
            if isinstance(connector, dict) and isinstance(connector.get("name"), str):
                rid = connector["name"]
                if rid.startswith("projects/"):
                    yield "vpcAccessConnector.name", "vpc_access_connector", rid, "projects/" + rid.split("/")[1], "service_reference"
            name = resource["data"].get("name", "")
            if isinstance(name, str) and "/versions/" in name:
                yield "name", "app_engine_service", name.rsplit("/versions/", 1)[0], None, "service_parent"


def _gcp_native_service_links(resource):
    """Explicit API resource names, including nested private-service parents."""
    from .network_catalog import _GCP_PRIVATE_SERVICES as plans
    from .network_observations import network_observations
    plan = plans.get(resource['type'])
    if not plan:
        return
    fields = {
        'firewallEndpoint': ('ngfw_endpoint', 'ngfw_organization_endpoint'),
        'odbNetwork': ('oracle_network',), 'odbSubnet': ('oracle_subnet',), 'backupOdbSubnet': ('oracle_subnet',),
        'interceptEndpointGroup': ('ngfw_intercept_endpoint_group',),
        'mirroringEndpointGroup': ('ngfw_mirroring_endpoint_group',),
        'interceptDeploymentGroup': ('ngfw_intercept_deployment_group',),
        'mirroringDeploymentGroup': ('ngfw_mirroring_deployment_group',),
        'appGateway': ('beyondcorp_gateway',), 'connectors': ('beyondcorp_connector',),
    }
    def pattern(spec):
        value = spec.get('scope_kind', 'projects') + r'/[^/?#%]+'
        if not spec.get('project_wide'):
            value += r'/locations/[^/?#%]+'
        for parent in spec.get('parents', []):
            value += '/' + re.escape(parent['segment']) + r'/[^/?#%]+'
        return value + '/' + re.escape(spec['segment']) + r'/[^/?#%]+'
    for fact in network_observations(resource['data']):
        values = fact['value'] if isinstance(fact['value'], list) else [fact['value']]
        for value in values:
            for target in fields.get(fact['name'], ()):
                if isinstance(value, str) and target in plans and re.fullmatch(pattern(plans[target]), value):
                    yield fact.get('evidence_path', fact['path']), target, value, '/'.join(value.split('/')[:2]), 'declared_service_reference'
    native = resource.get('native_id', '')
    if isinstance(native, str) and plan.get('parents'):
        parent_id = native.rsplit('/' + plan['segment'] + '/', 1)[0]
        parent_segments = [p['segment'] for p in plan['parents']]
        for target, spec in plans.items():
            if (spec['service'] == plan['service'] and spec.get('segment') == parent_segments[-1]
                    and [p['segment'] for p in spec.get('parents', [])] == parent_segments[:-1]
                    and re.fullmatch(pattern(spec), parent_id)):
                yield 'name', target, parent_id, '/'.join(parent_id.split('/')[:2]), 'service_parent'
