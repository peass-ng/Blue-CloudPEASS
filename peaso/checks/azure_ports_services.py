"""Reviewed Azure service predicates, preserving each source's actual conditions."""
from . import register, result, unknown
from .facts import get, list_of_objects, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {}


def port(query, kind, title, *, severity="medium", control="CM-6", dependencies=None):
    cid = "azure.port." + query
    CHECK_IDS.append(cid)
    SOURCE_QUERIES[query] = cid
    decorate = register(cid, "azure", "hardening", kind, title, severity, control,
                        "Review the declared configuration for the intended workload; collected settings do not establish runtime enforcement.",
                        dependencies=dependencies or [kind])
    return decorate


def _enum(item, path, values):
    value = get(item, path, str)
    if value not in values:
        raise Unavailable("unrecognized provider enum: " + path)
    return value


def _nullable_string(item, path):
    value = get(item, path)
    if value is not None and (not isinstance(value, str) or not value):
        raise Unavailable("malformed nullable provider identifier: " + path)
    return value


def _capabilities(item):
    capabilities = list_of_objects(get(item, "properties.capabilities", list))
    return {get(capability, "name", str) for capability in capabilities}


def _approved(item):
    connections = list_of_objects(get(item, "properties.privateEndpointConnections", list))
    statuses = [get(connection, "properties.privateLinkServiceConnectionState.status", str) for connection in connections]
    if any(status not in ("Approved", "Pending", "Rejected", "Disconnected") for status in statuses):
        raise Unavailable("unrecognized private connection status")
    return connections, statuses


@port("redis_cache_ssl_enabled", "redis_cache", "Redis disables the unencrypted connection port", control="SC-8")
def redis_ssl(item, index):
    enabled = get(item, "properties.enableNonSslPort", bool)
    return result(enabled, non_ssl_port_enabled=enabled)
CASES[SOURCE_QUERIES["redis_cache_ssl_enabled"]] = {"pass": {"properties": {"enableNonSslPort": False}}, "fail": {"properties": {"enableNonSslPort": True}}}


@port("redis_cache_min_tls_1_2", "redis_cache", "Redis explicitly requires minimum TLS 1.2", control="SC-8")
def redis_tls(item, index):
    value = _enum(item, "properties.minimumTlsVersion", ("1.0", "1.1", "1.2"))
    return result(value != "1.2", minimum_tls=value, source_predicate="exact TLS 1.2 in the reviewed API version")
CASES[SOURCE_QUERIES["redis_cache_min_tls_1_2"]] = {"pass": {"properties": {"minimumTlsVersion": "1.2"}}, "fail": {"properties": {"minimumTlsVersion": "1.1"}}}


@port("redis_cache_no_basic_sku", "redis_cache", "Redis uses a reviewed SKU above Basic")
def redis_sku(item, index):
    value = _enum(item, "properties.sku.name", ("Basic", "Standard", "Premium"))
    return result(value == "Basic", sku=value, semantics="Declared service tier; availability/SLA is not measured")
CASES[SOURCE_QUERIES["redis_cache_no_basic_sku"]] = {"pass": {"properties": {"sku": {"name": "Standard"}}}, "fail": {"properties": {"sku": {"name": "Basic"}}}}


@port("redis_cache_in_virtual_network", "redis_cache", "Redis declares a virtual-network subnet", control="SC-7")
def redis_vnet(item, index):
    subnet = _nullable_string(item, "properties.subnetId")
    return result(subnet is None, subnet_id=subnet, semantics="Declared network attachment; routing and access remain separate")
CASES[SOURCE_QUERIES["redis_cache_in_virtual_network"]] = {"pass": {"properties": {"subnetId": "/subscriptions/s/resourceGroups/g/providers/Microsoft.Network/virtualNetworks/v/subnets/n"}}, "fail": {"properties": {"subnetId": None}}}


@port("redis_cache_uses_private_link", "redis_cache", "Redis has an approved private endpoint", control="SC-7")
def redis_private(item, index):
    _, statuses = _approved(item)
    return result("Approved" not in statuses, approval_states=statuses, semantics="Connection approval only; public access and DNS are separate")
CASES[SOURCE_QUERIES["redis_cache_uses_private_link"]] = {"pass": {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"properties": {"privateEndpointConnections": []}}}


@port("cognitive_service_local_auth_disabled", "cognitive_account", "Cognitive Services disables local key authentication", control="AC-3")
def cognitive_local(item, index):
    disabled = get(item, "properties.disableLocalAuth", bool)
    return result(not disabled, local_auth_disabled=disabled, source_note="Upstream reason strings reverse enabled/disabled; its boolean status condition is retained")
CASES[SOURCE_QUERIES["cognitive_service_local_auth_disabled"]] = {"pass": {"properties": {"disableLocalAuth": True}}, "fail": {"properties": {"disableLocalAuth": False}}}


@port("cognitive_account_public_network_access_disabled", "cognitive_account", "Cognitive Services public network mode is disabled", control="SC-7")
def cognitive_public(item, index):
    value = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    return result(value == "Enabled", public_network_access=value)
CASES[SOURCE_QUERIES["cognitive_account_public_network_access_disabled"]] = {"pass": {"properties": {"publicNetworkAccess": "Disabled"}}, "fail": {"properties": {"publicNetworkAccess": "Enabled"}}}


@port("cognitive_account_restrict_public_access", "cognitive_account", "Cognitive Services with VirtualNetworks capability defaults network ACLs to Deny", control="SC-7")
def cognitive_acl(item, index):
    capabilities = _capabilities(item)
    if "VirtualNetworks" not in capabilities:
        return result(False, source_predicate="VirtualNetworks capability is absent; upstream does not alarm this resource", capabilities=sorted(capabilities))
    value = _enum(item, "properties.networkAcls.defaultAction", ("Allow", "Deny"))
    return result(value != "Deny", default_action=value, capabilities=sorted(capabilities), semantics="Capability-gated ACL declaration; no runtime access claim")
CASES[SOURCE_QUERIES["cognitive_account_restrict_public_access"]] = {"pass": {"properties": {"capabilities": [{"name": "VirtualNetworks"}], "networkAcls": {"defaultAction": "Deny"}}}, "fail": {"properties": {"capabilities": [{"name": "VirtualNetworks"}], "networkAcls": {"defaultAction": "Allow"}}}}


@port("cognitive_account_encrypted_with_cmk", "cognitive_account", "Cognitive Services with CMK capability selects the Key Vault key source", control="SC-28")
def cognitive_cmk(item, index):
    capabilities = _capabilities(item)
    if "CustomerManagedKey" not in capabilities:
        return result(False, source_predicate="CustomerManagedKey capability is absent; upstream does not alarm this resource", capabilities=sorted(capabilities))
    value = _enum(item, "properties.encryption.keySource", ("Microsoft.CognitiveServices", "Microsoft.KeyVault"))
    return result(value != "Microsoft.KeyVault", key_source=value, capabilities=sorted(capabilities))
CASES[SOURCE_QUERIES["cognitive_account_encrypted_with_cmk"]] = {"pass": {"properties": {"capabilities": [{"name": "CustomerManagedKey"}], "encryption": {"keySource": "Microsoft.KeyVault"}}}, "fail": {"properties": {"capabilities": [{"name": "CustomerManagedKey"}], "encryption": {"keySource": "Microsoft.CognitiveServices"}}}}


@port("cognitive_account_private_link_used", "cognitive_account", "Cognitive Services supports virtual networking and has an approved private link", control="SC-7")
def cognitive_private(item, index):
    connections, statuses = _approved(item)
    if not connections:
        return "MANUAL", {"reason": "Upstream reports INFO when no private endpoint connection exists; no successful configuration inferred"}
    capabilities = _capabilities(item)
    return result("VirtualNetworks" not in capabilities or "Approved" not in statuses, capabilities=sorted(capabilities), approval_states=statuses)
CASES[SOURCE_QUERIES["cognitive_account_private_link_used"]] = {"pass": {"properties": {"capabilities": [{"name": "VirtualNetworks"}], "privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"properties": {"capabilities": [], "privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "manual": {"properties": {"privateEndpointConnections": []}}}


@port("app_configuration_private_link_used", "app_configuration", "Paid App Configuration has an approved private endpoint", control="SC-7")
def appconfig_private(item, index):
    sku = _enum(item, "sku.name", ("free", "standard"))
    if sku == "free":
        return "NOT_APPLICABLE", {"reason": "Pinned upstream excludes Free SKU", "sku": sku}
    _, statuses = _approved(item)
    return result("Approved" not in statuses, sku=sku, approval_states=statuses)
CASES[SOURCE_QUERIES["app_configuration_private_link_used"]] = {"pass": {"sku": {"name": "standard"}, "properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"sku": {"name": "standard"}, "properties": {"privateEndpointConnections": []}}}


@port("app_configuration_sku_standard", "app_configuration", "App Configuration declares Standard SKU")
def appconfig_sku(item, index):
    sku = _enum(item, "sku.name", ("free", "standard"))
    return result(sku != "standard", sku=sku, semantics="Reviewed service-tier baseline; no SLA assertion")
CASES[SOURCE_QUERIES["app_configuration_sku_standard"]] = {"pass": {"sku": {"name": "standard"}}, "fail": {"sku": {"name": "free"}}}


@port("app_configuration_encryption_enabled", "app_configuration", "App Configuration declares a customer-managed encryption key", control="SC-28")
def appconfig_cmk(item, index):
    value = _nullable_string(item, "properties.encryption.keyVaultProperties.keyIdentifier")
    return result(value is None, key_identifier=value, semantics="CMK declaration; platform-managed at-rest encryption is not claimed disabled")
CASES[SOURCE_QUERIES["app_configuration_encryption_enabled"]] = {"pass": {"properties": {"encryption": {"keyVaultProperties": {"keyIdentifier": "https://vault.vault.azure.net/keys/key/version"}}}}, "fail": {"properties": {"encryption": {"keyVaultProperties": {"keyIdentifier": None}}}}}


@port("data_factory_public_network_access_disabled", "data_factory", "Data Factory disables public network access", control="SC-7")
def datafactory_public(item, index):
    value = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    return result(value == "Enabled", public_network_access=value)
CASES[SOURCE_QUERIES["data_factory_public_network_access_disabled"]] = {"pass": {"properties": {"publicNetworkAccess": "Disabled"}}, "fail": {"properties": {"publicNetworkAccess": "Enabled"}}}


@port("data_factory_encrypted_with_cmk", "data_factory", "Data Factory declares a CMK vault URL", control="SC-28")
def datafactory_cmk(item, index):
    value = _nullable_string(item, "properties.encryption.vaultBaseUrl")
    return result(value is None, vault_base_url=value, semantics="Metadata configuration; no key value, linked-service secret or factory parameter value read")
CASES[SOURCE_QUERIES["data_factory_encrypted_with_cmk"]] = {"pass": {"properties": {"encryption": {"vaultBaseUrl": "https://vault.vault.azure.net"}}}, "fail": {"properties": {"encryption": {"vaultBaseUrl": None}}}}


@port("data_factory_uses_git_repository", "data_factory", "Data Factory declares a source-control repository")
def datafactory_repo(item, index):
    value = _nullable_string(item, "properties.repoConfiguration.repositoryName")
    return result(value is None, repository_name=value, semantics="Source-control configuration; repository access or contents were not read")
CASES[SOURCE_QUERIES["data_factory_uses_git_repository"]] = {"pass": {"properties": {"repoConfiguration": {"repositoryName": "factory-config"}}}, "fail": {"properties": {"repoConfiguration": {"repositoryName": None}}}}


@port("data_factory_uses_private_link", "data_factory", "Data Factory has an approved private endpoint", control="SC-7")
def datafactory_private(item, index):
    _, statuses = _approved(item)
    return result("Approved" not in statuses, approval_states=statuses)
CASES[SOURCE_QUERIES["data_factory_uses_private_link"]] = {"pass": {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"properties": {"privateEndpointConnections": []}}}


@port("apimanagement_service_with_virtual_network", "api_management", "API Management declares Internal or External virtual networking", control="SC-7")
def apim_vnet(item, index):
    mode = _enum(item, "properties.virtualNetworkType", ("None", "Internal", "External"))
    return result(mode == "None", virtual_network_type=mode, semantics="External VNet mode does not imply an internal-only gateway")
CASES[SOURCE_QUERIES["apimanagement_service_with_virtual_network"]] = {"pass": {"properties": {"virtualNetworkType": "External"}}, "fail": {"properties": {"virtualNetworkType": "None"}}}


@port("search_service_public_network_access_disabled", "search_service", "Search service public networking is disabled", control="SC-7")
def search_public(item, index):
    mode = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    return result(mode == "Enabled", public_network_access=mode)
CASES[SOURCE_QUERIES["search_service_public_network_access_disabled"]] = {"pass": {"properties": {"publicNetworkAccess": "Disabled"}}, "fail": {"properties": {"publicNetworkAccess": "Enabled"}}}


@port("search_service_uses_private_link", "search_service", "Search service has an approved private endpoint", control="SC-7")
def search_private(item, index):
    _, statuses = _approved(item)
    return result("Approved" not in statuses, approval_states=statuses)
CASES[SOURCE_QUERIES["search_service_uses_private_link"]] = {"pass": {"properties": {"privateEndpointConnections": [{"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}]}}, "fail": {"properties": {"privateEndpointConnections": []}}}


@port("search_service_uses_managed_identity", "search_service", "Search service declares precisely SystemAssigned identity", control="IA-5")
def search_identity(item, index):
    mode = _enum(item, "identity.type", ("None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"))
    return result(mode != "SystemAssigned", identity_type=mode, source_predicate="Exact SystemAssigned comparison; combined/user-assigned modes are distinct")
CASES[SOURCE_QUERIES["search_service_uses_managed_identity"]] = {"pass": {"identity": {"type": "SystemAssigned"}}, "fail": {"identity": {"type": "SystemAssigned, UserAssigned"}}}


@port("search_service_uses_sku_supporting_private_link", "search_service", "Search declares a reviewed non-Free SKU", control="SC-7")
def search_sku(item, index):
    sku = _enum(item, "sku.name", ("free", "basic", "standard", "standard2", "standard3", "storage_optimized_l1", "storage_optimized_l2"))
    return result(sku == "free", sku=sku, source_predicate="Pinned source alarms Free SKU only; no actual endpoint availability inferred")
CASES[SOURCE_QUERIES["search_service_uses_sku_supporting_private_link"]] = {"pass": {"sku": {"name": "basic"}}, "fail": {"sku": {"name": "free"}}}
