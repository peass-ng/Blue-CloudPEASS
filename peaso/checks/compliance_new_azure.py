"""Source-bound Azure compliance checks over existing complete scalar facts.

Only explicitly reviewed IDs are registered; the remaining signed proposals
stay pending until their resource kind, child inventory, or policy input exists.
"""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, get, list_of_objects
from .fixtures import CASES

IDS = []


def _register(check_id, kind, title, evaluate, *, category="hardening", severity="medium", remediation, passing, failing):
    register(check_id, "azure", category, kind, title, severity, "CM-6", remediation,
             dependencies=[kind])(evaluate)
    IDS.append(check_id)
    CASES[check_id] = {"pass": passing, "fail": failing, "missing": {}, "malformed": None}


def _postgres_public_network(item, index):
    value = get(item, "properties.network.publicNetworkAccess", str)
    if value not in ("Enabled", "Disabled"):
        return unknown("unrecognized PostgreSQL Flexible Server public network setting", observed=value)
    return result(value == "Enabled", public_network_access=value,
                  semantics="Flexible Server public-network declaration; no endpoint reachability is inferred")


_register("azure.cis.public_network_access_should_postgresql_servers", "postgresql_flexible_server",
          "PostgreSQL Flexible Server public network access is disabled", _postgres_public_network,
          category="network", severity="high", remediation="Inspect the server's application dependencies and private connectivity; if approved, set network.publicNetworkAccess to Disabled in the owning IaC or Azure configuration and test clients before rollout.",
          passing={"properties": {"network": {"publicNetworkAccess": "Disabled"}}},
          failing={"properties": {"network": {"publicNetworkAccess": "Enabled"}}})


def _mysql_public_network(item, index):
    value = get(item, "properties.network.publicNetworkAccess", str)
    if value not in ("Enabled", "Disabled"):
        return unknown("unrecognized MySQL Flexible Server public network setting", observed=value)
    return result(value == "Enabled", public_network_access=value,
                  semantics="Flexible Server public-network declaration; firewall rules and endpoint reachability are separate")


_register("azure.cis.public_network_access_should_mysql_servers", "mysql_flexible_server",
          "MySQL Flexible Server public network access is disabled", _mysql_public_network,
          category="network", severity="high",
          remediation="With the server and network owners, verify a private connectivity path and dependent clients before disabling publicNetworkAccess in the owning IaC or Azure configuration; test the cutover and retain a rollback plan.",
          passing={"properties": {"network": {"publicNetworkAccess": "Disabled"}}},
          failing={"properties": {"network": {"publicNetworkAccess": "Enabled"}}})


def _postgres_log_duration(item, index):
    rows = list_of_objects(get(item, "configurations", list))
    matches = [row for row in rows if get(row, "name", str) == "log_duration"]
    if len(matches) != 1:
        return unknown("PostgreSQL log_duration configuration absent or duplicated", observed_matches=len(matches))
    value = get(matches[0], "properties.value", str)
    if value not in ("on", "off"):
        return unknown("unrecognized PostgreSQL log_duration value", observed=value)
    return result(value == "off", parameter="log_duration", configured=value,
                  semantics="Observed server parameter; delivery and retention of logs are separate")


_register("azure.gap.postgres_db_server_log_duration_on", "postgresql_flexible_server",
          "PostgreSQL Flexible Server log_duration parameter is on", _postgres_log_duration,
          remediation="Review logging volume and retention with the database owner, set the log_duration server parameter to on through the owning IaC or Azure configuration, and verify emitted logs and workload impact after rollout.",
          passing={"configurations": [{"name": "log_duration", "properties": {"value": "on"}}]},
          failing={"configurations": [{"name": "log_duration", "properties": {"value": "off"}}]})


def _search_cmk(item, index):
    cmk = get(item, "properties.encryptionWithCmk", dict)
    enforcement = get(cmk, "enforcement", str)
    compliance = get(cmk, "encryptionComplianceStatus", str)
    if enforcement not in ("Enabled", "Disabled", "Unspecified"):
        return unknown("unrecognized Search CMK enforcement", observed=enforcement)
    if compliance not in ("Compliant", "NonCompliant"):
        return unknown("unrecognized Search CMK compliance", observed=compliance)
    return result(enforcement != "Enabled" or compliance != "Compliant",
                  enforcement=enforcement, encryption_compliance_status=compliance,
                  semantics="Search service CMK enforcement, not basic service-managed encryption")


_register("azure_search_service_3_5_1_19_a3c75c0", "search_service",
          "Azure AI Search enforces customer-managed keys with compliant objects", _search_cmk,
          remediation="Review Search service CMK capability, dependent keys and any noncompliant objects with the service owner; set encryptionWithCmk.enforcement to Enabled in the owning configuration only after a migration and rollback plan.",
          passing={"properties": {"encryptionWithCmk": {"enforcement": "Enabled", "encryptionComplianceStatus": "Compliant"}}},
          failing={"properties": {"encryptionWithCmk": {"enforcement": "Enabled", "encryptionComplianceStatus": "NonCompliant"}}})


_SUBSCRIPTION = r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
_ARM_ID = re.compile(r"^/subscriptions/" + _SUBSCRIPTION + r"/resourcegroups/[^/]+/providers/microsoft\.managedidentity/userassignedidentities/[^/]+$", re.I)


def _vm_identity(item, index):
    # ARM can omit the whole identity object when none is configured. Without a
    # complete-representation proof that omission is collection uncertainty.
    if "identity" not in item:
        return unknown("VM identity absent from collected representation; completeness not proved")
    identity = get(item, "identity", dict)
    identity_type = get(identity, "type", str)
    allowed = {"None", "SystemAssigned", "UserAssigned", "SystemAssigned, UserAssigned"}
    if identity_type not in allowed:
        return unknown("unrecognized VM identity type", observed=identity_type)
    if identity_type == "None":
        return result(True, identity_type=identity_type)
    system = "SystemAssigned" in identity_type
    user = "UserAssigned" in identity_type
    system_state = False
    if system:
        try:
            system_state = bool(get(identity, "principalId", str).strip())
        except Unavailable:
            system_state = None
    user_state = False
    if user:
        try:
            associations = get(identity, "userAssignedIdentities", dict)
        except Unavailable:
            user_state = None
        else:
            if any(not isinstance(key, str) or not _ARM_ID.fullmatch(key) or (value is not None and not isinstance(value, dict))
                   for key, value in associations.items()):
                user_state = None
            else:
                user_state = bool(associations)
    if system_state or user_state:
        return result(False, identity_type=identity_type, observed_system_principal=system_state is True,
                      observed_user_associations=len(associations) if user_state is True else 0,
                      semantics="VM identity declaration; granted permissions and token use are separate")
    if system_state is None or user_state is None:
        return unknown("VM managed-identity reference incomplete or malformed", identity_type=identity_type)
    return result(True, identity_type=identity_type, observed_system_principal=False,
                  observed_user_associations=0,
                  semantics="VM identity declaration; granted permissions and token use are separate")


_register("azure_vm_app_function_identity_is_configured_bdb10d4", "vm",
          "Virtual machine has an observed managed identity reference", _vm_identity,
          remediation="With the VM owner, choose a system- or user-assigned managed identity that fits the workload; configure it through the owning IaC, migrate callers from stored credentials, and verify access before retiring old credentials.",
          passing={"identity": {"type": "SystemAssigned", "principalId": "a3b98610-e245-4cee-9d08-d61261ee5d39"}},
          failing={"identity": {"type": "None"}})


_NSG_ASSOCIATION = re.compile(r"^/subscriptions/" + _SUBSCRIPTION + r"/resourcegroups/[^/]+/providers/microsoft\.network/(?:virtualnetworks/[^/]+/subnets/[^/]+|networkinterfaces/[^/]+)$", re.I)


def _nsg_association(item, index):
    subnets = get(item, "properties.subnets", list)
    interfaces = get(item, "properties.networkInterfaces", list)
    if any(not isinstance(row, dict) for row in subnets + interfaces):
        return unknown("malformed NSG association collection")
    references = []
    for row in subnets + interfaces:
        ref = get(row, "id", str)
        if not _NSG_ASSOCIATION.fullmatch(ref):
            return unknown("malformed NSG association ARM ID", observed_id=ref)
        references.append(ref)
    return result(not references, association_ids=references,
                  semantics="Observed NSG subnet/NIC association; rule effectiveness and reachability are separate")


_register("azure_pci_1_2_8_39", "nsg", "Network security group has a subnet or NIC association",
          _nsg_association, category="network", remediation="Confirm whether the NSG is intended for a subnet or NIC with the network owner; attach it through the owning IaC only after reviewing existing rules and testing workload traffic, or document the unused NSG disposition.",
          passing={"properties": {"subnets": [], "networkInterfaces": [{"id": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic1"}]}},
          failing={"properties": {"subnets": [], "networkInterfaces": []}})


_KEY_VAULT_KEY = re.compile(r"^https://[a-z0-9-]+\.vault\.(?:azure\.net|usgovcloudapi\.net|azure\.cn)/keys/[A-Za-z0-9-]+(?:/[A-Za-z0-9]+)?$", re.I)


def _mysql_flexible_cmk(item, index):
    encryption = get(item, "properties.dataEncryption", dict)
    key_type = get(encryption, "type", str)
    if key_type == "SystemManaged":
        return result(True, encryption_type=key_type,
                      semantics="MySQL Flexible Server encryption configuration; key availability is separate")
    if key_type != "AzureKeyVault":
        return unknown("unrecognized MySQL Flexible Server encryption type", observed=key_type)
    key_uri = get(encryption, "primaryKeyURI", str)
    identity = get(encryption, "primaryUserAssignedIdentityId", str)
    if key_uri and not _KEY_VAULT_KEY.fullmatch(key_uri):
        return unknown("unrecognized Key Vault key URI", observed_key_uri=key_uri)
    if identity and not _ARM_ID.fullmatch(identity):
        return unknown("malformed user-assigned identity ARM ID", observed_id=identity)
    return result(not (key_uri and identity), encryption_type=key_type,
                  key_uri_present=bool(key_uri), user_identity_present=bool(identity),
                  semantics="CMK configuration only; Key Vault authorization and key availability are separate")


_register("azure.cis.mysql_flexible_cmk", "mysql_flexible_server",
          "MySQL Flexible Server declares Key Vault CMK and user-assigned identity", _mysql_flexible_cmk,
          severity="high", remediation="With the database and Key Vault owners, verify CMK support, key access and recovery; configure dataEncryption.type=AzureKeyVault, a reviewed primaryKeyURI and user-assigned identity in the owning IaC, then test database access and rollback before changing production.",
          passing={"properties": {"dataEncryption": {"type": "AzureKeyVault", "primaryKeyURI": "https://keys.vault.azure.net/keys/mysql-key/0123456789abcdef", "primaryUserAssignedIdentityId": "/subscriptions/00000000-1111-2222-3333-444444444444/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mysql"}}},
          failing={"properties": {"dataEncryption": {"type": "SystemManaged"}}})
