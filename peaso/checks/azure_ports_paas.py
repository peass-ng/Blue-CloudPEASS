"""Reviewed PaaS setting predicates with explicit native fields and source branches."""
from . import register, result, unknown
from .facts import get, field_check, list_of_objects, Unavailable
from .fixtures import CASES, nest
from .azure_ports_services import _approved, _enum, _nullable_string

CHECK_IDS = []
SOURCE_QUERIES = {}
SCALARS = [
    ("container_registry_encrypted_with_cmk", "container_registry", "properties.encryption.status", "enabled", "disabled", "Container Registry enables its CMK encryption configuration"),
    ("container_registry_restrict_public_access", "container_registry", "properties.networkRuleSet.defaultAction", "Deny", "Allow", "Container Registry network rules default to Deny"),
    ("container_registry_admin_user_disabled", "container_registry", "properties.adminUserEnabled", False, True, "Container Registry disables the administrator user"),
    ("container_registry_quarantine_policy_enabled", "container_registry", "properties.policies.quarantinePolicy.status", "enabled", "disabled", "Container Registry declares quarantine policy enabled"),
    ("container_registry_retention_policy_enabled", "container_registry", "properties.policies.retentionPolicy.status", "enabled", "disabled", "Container Registry declares retention policy enabled"),
    ("container_registry_public_network_access_disabled", "container_registry", "properties.publicNetworkAccess", "Disabled", "Enabled", "Container Registry disables public networking"),
    ("container_registry_trust_policy_enabled", "container_registry", "properties.policies.trustPolicy.status", "enabled", "disabled", "Container Registry declares image trust policy enabled"),
    ("cosmosdb_account_key_based_metadata_write_access_disabled", "cosmos_account", "properties.disableKeyBasedMetadataWriteAccess", True, False, "Cosmos DB disables key-based metadata writes"),
    ("cosmosdb_account_uses_aad_and_rbac", "cosmos_account", "properties.disableLocalAuth", True, False, "Cosmos DB disables local key authentication"),
    ("databricks_workspace_no_public_ip_enabled", "databricks_workspace", "properties.parameters.enableNoPublicIp.value", True, False, "Databricks workspace configures no public IP"),
    ("databricks_workspace_public_network_access_disabled", "databricks_workspace", "properties.publicNetworkAccess", "Disabled", "Enabled", "Databricks workspace disables public networking"),
    ("kusto_cluster_disk_encryption_enabled", "kusto_cluster", "properties.enableDiskEncryption", True, False, "Kusto cluster enables disk encryption"),
    ("kusto_cluster_double_encryption_enabled", "kusto_cluster", "properties.enableDoubleEncryption", True, False, "Kusto cluster enables double encryption"),
    ("kubernetes_cluster_network_plugin_azure", "aks_cluster", "properties.networkProfile.networkPlugin", "azure", "kubenet", "AKS configures Azure networking"),
    ("kubernetes_cluster_add_on_azure_policy_enabled", "aks_cluster", "properties.addonProfiles.azurepolicy.enabled", True, False, "AKS enables the Azure Policy add-on"),
]
for query, kind, path, good, bad, title in SCALARS:
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    field_check(cid, "azure", kind, path, good, bad, title, expected=type(good))


def port(query, kind, title, dependencies=None):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    return register(cid, "azure", "hardening", kind, title, "medium", "CM-6",
                    "Review the collected configuration and service applicability; runtime access and effective protection are separate.",
                    dependencies=dependencies or [kind])


def _private(query, kind, title):
    @port(query, kind, title)
    def evaluate(item, index):
        _, states = _approved(item)
        return result("Approved" not in states, approval_states=states, semantics="Approval configuration only; no network reachability inference")
    cid = SOURCE_QUERIES[query]
    CASES[cid] = {"pass": {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}},
                  "fail": {"properties": {"privateEndpointConnections": []}}}


_private("container_registry_uses_private_link", "container_registry", "Container Registry has an approved private endpoint")
_private("cosmosdb_account_uses_private_link", "cosmos_account", "Cosmos DB has an approved private endpoint")
_private("databricks_workspace_uses_private_endpoint", "databricks_workspace", "Databricks workspace has an approved private endpoint")


@port("cosmosdb_account_encryption_at_rest_using_cmk", "cosmos_account", "Cosmos DB declares a Key Vault CMK URI")
def cosmos_cmk(item, index):
    uri = _nullable_string(item, "properties.keyVaultKeyUri")
    return result(uri is None, cmk_uri=uri, semantics="Key metadata only; no key value read and no claim platform encryption is disabled")
CASES[SOURCE_QUERIES["cosmosdb_account_encryption_at_rest_using_cmk"]] = {"pass": nest("properties.keyVaultKeyUri", "https://vault/keys/key"), "fail": nest("properties.keyVaultKeyUri", None)}


@port("cosmosdb_account_virtual_network_filter_enabled", "cosmos_account", "Cosmos DB disables public networking or enables its VNet filter")
def cosmos_vnet_filter(item, index):
    public = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    if public == "Disabled":
        return result(False, public_network_access=public)
    enabled = get(item, "properties.isVirtualNetworkFilterEnabled", bool)
    return result(not enabled, public_network_access=public, vnet_filter_enabled=enabled)
CASES[SOURCE_QUERIES["cosmosdb_account_virtual_network_filter_enabled"]] = {"pass": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": True}}, "fail": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": False}}}


@port("cosmosdb_account_with_firewall_rules", "cosmos_account", "Cosmos DB public access has a VNet filter or IP rules")
def cosmos_firewall(item, index):
    public = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    if public == "Disabled":
        return result(False, public_network_access=public)
    enabled = get(item, "properties.isVirtualNetworkFilterEnabled", bool)
    rules = list_of_objects(get(item, "properties.ipRules", list))
    for rule in rules:
        get(rule, "ipAddressOrRange", str)
    return result(not enabled and len(rules) == 0, vnet_filter_enabled=enabled, ip_rule_count=len(rules),
                  semantics="Presence of source-required rules, not rule safety or reachability")
CASES[SOURCE_QUERIES["cosmosdb_account_with_firewall_rules"]] = {"pass": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": False, "ipRules": [{"ipAddressOrRange": "10.0.0.1"}]}}, "fail": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": False, "ipRules": []}}}


@port("cosmosdb_use_virtual_service_endpoint", "cosmos_account", "Cosmos DB declares at least one virtual network rule")
def cosmos_endpoint(item, index):
    rules = list_of_objects(get(item, "properties.virtualNetworkRules", list))
    for rule in rules:
        get(rule, "id", str)
    return result(not rules, virtual_network_rule_count=len(rules), semantics="Declared rule membership; endpoint routing is not verified")
CASES[SOURCE_QUERIES["cosmosdb_use_virtual_service_endpoint"]] = {"pass": nest("properties.virtualNetworkRules", [{"id": "/subnets/subnet"}]), "fail": nest("properties.virtualNetworkRules", [])}


@port("databricks_workspace_deployed_in_custom_vnet", "databricks_workspace", "Databricks workspace declares a custom virtual-network parameter")
def databricks_vnet(item, index):
    parameter = get(item, "properties.parameters.customVirtualNetworkId")
    if parameter is not None and not isinstance(parameter, dict):
        return unknown("Malformed custom virtual-network parameter")
    return result(parameter is None, parameter_declared=parameter is not None, semantics="Preserves source parameter-object presence, not a resolved subnet/route claim")
CASES[SOURCE_QUERIES["databricks_workspace_deployed_in_custom_vnet"]] = {"pass": nest("properties.parameters.customVirtualNetworkId", {"value": "/virtualNetworks/network"}), "fail": nest("properties.parameters.customVirtualNetworkId", None)}


@port("kusto_cluster_encrypted_at_rest_with_cmk", "kusto_cluster", "Kusto declares CMK key name, vault URI and version")
def kusto_cmk(item, index):
    props = get(item, "properties.keyVaultProperties", dict)
    values = {field: _nullable_string(props, field) for field in ("keyName", "keyVaultUri", "keyVersion")}
    return result(any(value is None for value in values.values()), key_metadata=values, semantics="Source key-reference completeness; no cryptographic key value read")
CASES[SOURCE_QUERIES["kusto_cluster_encrypted_at_rest_with_cmk"]] = {"pass": nest("properties.keyVaultProperties", {"keyName": "key", "keyVaultUri": "https://vault", "keyVersion": "version"}), "fail": nest("properties.keyVaultProperties", {"keyName": "key", "keyVaultUri": "https://vault", "keyVersion": None})}


@port("kubernetes_cluster_os_and_data_disks_encrypted_with_cmk", "aks_cluster", "AKS declares a disk encryption set")
def aks_disk_cmk(item, index):
    identity = _nullable_string(item, "properties.diskEncryptionSetID")
    return result(identity is None, disk_encryption_set_id=identity, semantics="Control-plane reference only; node/data-disk encryption runtime is separate")
CASES[SOURCE_QUERIES["kubernetes_cluster_os_and_data_disks_encrypted_with_cmk"]] = {"pass": nest("properties.diskEncryptionSetID", "/diskEncryptionSets/set"), "fail": nest("properties.diskEncryptionSetID", None)}


@port("search_replica_minimum_for_index_updates", "search_service", "Paid Search service has at least three replicas for the index-update SLA")
def search_replicas(item, index):
    sku = _enum(item, "sku.name", ("free", "basic", "standard", "standard2", "standard3", "storage_optimized_l1", "storage_optimized_l2"))
    if sku == "free":
        return "NOT_APPLICABLE", {"reason": "Free tier has no SLA"}
    count = get(item, "properties.replicaCount", int)
    if count < 1:
        return unknown("Invalid replica count")
    return result(count < 3, replica_count=count, semantics="Current declared read-write SLA requirement; actual availability and throughput are not measured")
CASES[SOURCE_QUERIES["search_replica_minimum_for_index_updates"]] = {"pass": {"sku": {"name": "basic"}, "properties": {"replicaCount": 3}}, "fail": {"sku": {"name": "basic"}, "properties": {"replicaCount": 2}}}
