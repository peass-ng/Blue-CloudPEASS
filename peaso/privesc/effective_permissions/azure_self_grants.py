"""Typed review boundary for Azure permissions explicitly granted to the caller.

These records describe a completed policy or ACL change, not just possession of
the write action. Importers must verify both the previous denial and the newly
effective permission on the named resource before marking a record verified.
"""
from __future__ import annotations


CONTRACT = {
    "azure-purview-policy-self-grant": (
        "Microsoft.Purview/policyElements/write",
        frozenset({"governed_sql_read", "governed_sql_write", "governed_storage_read", "governed_storage_write"}),
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


def valid(technique, fact, source_id, granted_resource_id, action_resource_id):
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
    if technique.startswith("azure-storage-") and granted_resource_id.casefold() != action_resource_id.casefold():
        return False
    if technique == "azure-purview-policy-self-grant" and not all(
            fact.get(key) is True for key in ("PolicyAuthorVerified", "DataPolicyEnforcementVerified",
                                              "PolicyPublishedVerified")):
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
