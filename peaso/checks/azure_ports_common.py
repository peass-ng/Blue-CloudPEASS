"""Reviewed common predicates; logical conjunctions remain their own check."""
from . import register, result, unknown
from .facts import get
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {}


@register("azure.port.keyvault_vault_recoverable", "azure", "hardening", "vault", "Key Vault enables both soft delete and purge protection", "medium", "CP-9",
          "Enable soft delete and purge protection; recovery configuration does not prove successful restore testing.")
def vault_recoverable(item, index):
    soft = get(item, "properties.enableSoftDelete", bool)
    purge = get(item, "properties.enablePurgeProtection", bool)
    return result(not (soft and purge), soft_delete_enabled=soft, purge_protection_enabled=purge)
CHECK_IDS.append("azure.port.keyvault_vault_recoverable")
SOURCE_QUERIES["keyvault_vault_recoverable"] = CHECK_IDS[-1]
CASES[CHECK_IDS[-1]] = {"pass": {"properties": {"enableSoftDelete": True, "enablePurgeProtection": True}}, "fail": {"properties": {"enableSoftDelete": True, "enablePurgeProtection": False}}}


@register("azure.port.storage_account_trusted_microsoft_services_enabled", "azure", "hardening", "storage_account", "Storage network bypass declares trusted Azure services", "medium", "SC-7",
          "Review AzureServices bypass against the workload trust policy; it does not authorize every Azure tenant or prove effective access.")
def trusted_azure_services(item, index):
    value = get(item, "properties.networkAcls.bypass", str)
    if not value or any(part.strip() not in ("None", "Logging", "Metrics", "AzureServices") for part in value.split(",")):
        return unknown("Unrecognized storage network bypass declaration")
    return result("AzureServices" not in value, configured_bypass=value, semantics="Pinned source substring condition on recognized native enum values; authorization and data-plane access remain separate")
CHECK_IDS.append("azure.port.storage_account_trusted_microsoft_services_enabled")
SOURCE_QUERIES["storage_account_trusted_microsoft_services_enabled"] = CHECK_IDS[-1]
CASES[CHECK_IDS[-1]] = {"pass": {"properties": {"networkAcls": {"bypass": "Logging,AzureServices"}}}, "fail": {"properties": {"networkAcls": {"bypass": "Logging,Metrics"}}}}
