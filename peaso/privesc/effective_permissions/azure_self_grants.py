"""Typed review boundary for Azure permissions explicitly granted to the caller.

These records describe a completed policy or ACL change, not just possession of
the write action. Importers must verify both the previous denial and the newly
effective permission on the named resource before marking a record verified.
"""
from __future__ import annotations

import re

from . import items


CONTRACT = {
    "azure-purview-policy-self-grant": (
        "Microsoft.Purview/policyElements/write",
        frozenset({"governed_sql_read", "governed_storage_read", "governed_storage_write"}),
    ),
    "azure-storage-adls-acl-self-grant": (
        "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/modifyPermissions/action",
        frozenset({"blob_read", "blob_write", "blob_execute"}),
    ),
    "azure-storage-files-acl-self-grant": (
        "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action",
        frozenset({"file_read", "file_write", "file_execute"}),
    ),
}


ADLS_PATH = re.compile(
    r"(?P<account>/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.storage/storageaccounts/[^/]+)/blobservices/default/"
    r"containers/[^/]+(?:/blobs/[^/]+(?:/[^/]+)*)?", re.I)

AZURE_FILE_PATH = re.compile(
    r"(?P<share>/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"microsoft\.storage/storageaccounts/[^/]+/fileservices/default/fileshares/[^/]+)"
    r"/files(?P<path>/[^/]+(?:/[^/]+)*)?", re.I)

PURVIEW_ACCOUNT = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.purview/accounts/[^/]+", re.I)
STORAGE_SOURCE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.storage/storageaccounts/[^/]+"
    r"(?:/blobservices/default/containers/[^/]+(?:/blobs/.+)?)?", re.I)
SQL_SOURCE = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/"
    r"(?:microsoft\.sql/(?:servers|managedinstances)/[^/]+(?:/databases/[^/]+)?|"
    r"microsoft\.hybridcompute/machines/[^/]+/providers/microsoft\.azurearcdata/sqlserverinstances/[^/]+)", re.I)


def _adls_hns(snapshot, fact, resource):
    match = ADLS_PATH.fullmatch(resource)
    if match is None or "#" in resource or any(segment in (".", "..") for segment in resource.split("/")):
        return False
    account = match.group("account").casefold()
    native = [row for _, row in items(snapshot, "storage_account")
              if str(row.get("id", "")).casefold() == account
              and str(row.get("type", "")).casefold() == "microsoft.storage/storageaccounts"]
    if len(native) == 1:
        enabled = (native[0].get("properties") or {}).get("isHnsEnabled")
        if type(enabled) is bool:
            return enabled
    return (fact.get("HierarchicalNamespaceVerified") is True
            and isinstance(fact.get("StorageAccountEvidenceRef"), str)
            and bool(fact["StorageAccountEvidenceRef"].strip()))


def valid(technique, fact, source_id, granted_resource_id, action_resource_id, snapshot=None):
    """Accept only an exact self-grant with an observed before/after access change."""
    spec = CONTRACT.get(technique)
    if spec is None or not isinstance(fact, dict):
        return False
    action, permissions = spec
    if not all(isinstance(value, str) and value.startswith("/subscriptions/") and
               "/providers/" in value and "*" not in value and "?" not in value
               for value in (granted_resource_id, action_resource_id)):
        return False
    if fact.get("TechniqueId") != technique or fact.get("EffectType") != "self_permission_grant":
        return False
    if fact.get("Status") != "verified" or fact.get("VerifiedPreconditions") is not True:
        return False
    if not isinstance(fact.get("EvidenceRef"), str) or not fact["EvidenceRef"].strip():
        return False
    if not all(isinstance(fact.get(key), str) and fact[key].strip()
               for key in ("PriorAccessEvidenceRef", "MutationEvidenceRef", "PostGrantEvidenceRef")):
        return False
    if technique == "azure-storage-adls-acl-self-grant" and granted_resource_id.casefold() != action_resource_id.casefold():
        return False
    if technique == "azure-storage-files-acl-self-grant":
        match = AZURE_FILE_PATH.fullmatch(granted_resource_id)
        if (match is None or match.group("share").casefold() != action_resource_id.casefold()
                or fact.get("TargetPathKind") not in ("file", "directory")
                or (not match.group("path") and fact.get("TargetPathKind") != "directory")
                or "#" in granted_resource_id
                or any(part in (".", "..") for part in granted_resource_id.split("/"))):
            return False
    if technique == "azure-storage-adls-acl-self-grant" and not _adls_hns(
            snapshot or {}, fact, granted_resource_id):
        return False
    if (technique == "azure-storage-adls-acl-self-grant"
            and fact.get("GrantedPermission") == "blob_execute"
            and fact.get("TargetPathKind") != "directory"):
        return False
    if technique == "azure-purview-policy-self-grant":
        permission = fact.get("GrantedPermission")
        governed = (STORAGE_SOURCE if permission in ("governed_storage_read", "governed_storage_write")
                    else SQL_SOURCE if permission == "governed_sql_read" else None)
        if (not PURVIEW_ACCOUNT.fullmatch(action_resource_id)
                or governed is None or not governed.fullmatch(granted_resource_id)
                or "#" in granted_resource_id or any(part in (".", "..") for part in granted_resource_id.split("/"))
                or not all(fact.get(key) is True for key in (
                    "PolicyAuthorVerified", "DataPolicyEnforcementVerified", "PolicyPublishedVerified",
                    "PolicyTargetsGrantedResourceVerified"))
                or not all(isinstance(fact.get(key), str) and fact[key].strip() for key in (
                    "PolicyAuthorEvidenceRef", "PolicyElementId", "PolicyTargetEvidenceRef"))):
            return False
    return (fact.get("SourceId") == source_id == fact.get("GrantedPrincipalId")
            and fact.get("TargetKind") == "azure_verified_authority"
            and fact.get("TargetId") == granted_resource_id == fact.get("GrantedResourceId")
            and fact.get("TargetScope") == action_resource_id == fact.get("ActionResourceId")
            and fact.get("SourceAction", "").casefold() == action.casefold()
            and fact.get("GrantedPermission") in permissions
            and fact.get("PriorAccessDenied") is True
            and fact.get("GrantApplied") is True
            and fact.get("PostGrantAccessVerified") is True)
