"""Reviewed PaaS setting predicates with explicit native fields and source branches."""
from . import register, result, unknown
from .facts import get, field_check, list_of_objects, Unavailable, optional
from .fixtures import CASES, nest
from .azure_ports_services import _approved, _enum, _nullable_string

CHECK_IDS = []
SOURCE_QUERIES = {}
SCALARS = [
    ("databricks_workspace_no_public_ip_enabled", "databricks_workspace", "properties.parameters.enableNoPublicIp.value", True, False, "Databricks workspace configures no public IP"),
    ("databricks_workspace_public_network_access_disabled", "databricks_workspace", "properties.publicNetworkAccess", "Disabled", "Enabled", "Databricks workspace disables public networking"),
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


_private("cosmosdb_account_uses_private_link", "cosmos_account", "Cosmos DB has an approved private endpoint")
_private("databricks_workspace_uses_private_endpoint", "databricks_workspace", "Databricks workspace has an approved private endpoint")





@port("cosmosdb_account_virtual_network_filter_enabled", "cosmos_account", "Cosmos DB disables public networking or enables its VNet filter")
def cosmos_vnet_filter(item, index):
    public = _enum(item, "properties.publicNetworkAccess", ("Enabled", "Disabled"))
    if public == "Disabled":
        return result(False, public_network_access=public)
    enabled = get(item, "properties.isVirtualNetworkFilterEnabled", bool)
    return result(not enabled, public_network_access=public, vnet_filter_enabled=enabled)
CASES[SOURCE_QUERIES["cosmosdb_account_virtual_network_filter_enabled"]] = {"pass": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": True}}, "fail": {"properties": {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": False}}}








@port("databricks_workspace_deployed_in_custom_vnet", "databricks_workspace", "Databricks workspace declares a custom virtual-network parameter")
def databricks_vnet(item, index):
    parameters = get(item, "properties.parameters", dict)
    parameter = optional(parameters, "customVirtualNetworkId", None)
    if "customVirtualNetworkId" in parameters and not isinstance(parameter, dict):
        return unknown("Malformed custom virtual-network parameter")
    return result(parameter is None, parameter_declared=parameter is not None, semantics="Preserves source parameter-object presence, not a resolved subnet/route claim")
CASES[SOURCE_QUERIES["databricks_workspace_deployed_in_custom_vnet"]] = {"pass": nest("properties.parameters.customVirtualNetworkId", {"value": "/virtualNetworks/network"}), "fail": nest("properties.parameters", {})}








