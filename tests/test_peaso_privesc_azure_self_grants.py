"""Azure policy and ACL self-grants need a proven permission gain on one resource."""
from __future__ import annotations

import copy

import pytest

from peaso import privesc
from peaso.privesc.schema import load_catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, az


CASES = (
    ("azure-purview-policy-self-grant", "Microsoft.Purview/policyElements/write", "governed_sql_read", True),
    ("azure-storage-adls-acl-self-grant",
     "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/modifyPermissions/action", "blob_read", True),
    ("azure-storage-files-acl-self-grant",
     "Microsoft.Storage/storageAccounts/fileServices/fileshares/files/modifypermissions/action", "file_read", True),
)


def _case(technique, action, permission, data_action):
    entry = next(e for e in load_catalog()["entries"] if e["id"] == technique)
    resource = f"{RG}/providers/Microsoft.Storage/storageAccounts/a/fileServices/default/shares/s"
    if technique.startswith("azure-purview"):
        resource = f"{RG}/providers/Microsoft.Purview/accounts/a/policyElements/p"
    fact = {
        "TechniqueId": technique, "SourceId": "u-alice", "TargetKind": "azure_verified_authority",
        "TargetId": resource, "TargetScope": resource, "Status": "verified",
        "VerifiedPreconditions": True, "EvidenceRef": "reviewed-policy-or-acl-change-1",
        "EffectType": "self_permission_grant", "GrantedPrincipalId": "u-alice",
        "GrantedResourceId": resource, "ActionResourceId": resource,
        "SourceAction": action, "GrantedPermission": permission,
        "PriorAccessDenied": True, "GrantApplied": True, "PostGrantAccessVerified": True,
        "PriorAccessEvidenceRef": "prior-denial-1", "MutationEvidenceRef": "policy-or-acl-change-1",
        "PostGrantEvidenceRef": "successful-access-1",
    }
    if technique == "azure-purview-policy-self-grant":
        fact.update(PolicyAuthorVerified=True, DataPolicyEnforcementVerified=True,
                    PolicyPublishedVerified=True)
    roles = {ROLE_ID: ([], [action]) if data_action else ([action], [])}
    # A resource-scoped role assignment permits this mutation without making the
    # source an administrator of its subscription before the self-grant.
    snap = az(assignments=[("u-alice", "User", resource, ROLE_ID)], roles=roles,
              extra=[("azure_privesc_challenge_evidence", resource, [fact])])
    return entry, snap, fact


@pytest.mark.parametrize("technique,action,permission,data_action", CASES)
def test_exact_self_grant_requires_effective_new_permission(technique, action, permission, data_action):
    entry, snap, fact = _case(technique, action, permission, data_action)
    targets = reached(privesc.analyze(snap, entries=[entry]), "u-alice", technique)
    assert len(targets) == 1 and set(targets.values()) == {"conditional"}
    assert next(iter(targets)).startswith(f"exact:{technique}:")

    invalid = [("PriorAccessDenied", False), ("PriorAccessEvidenceRef", ""),
                         ("GrantedPrincipalId", "u-other"),
                         ("PostGrantAccessVerified", False), ("GrantedPermission", "unrelated"),
                         ("ActionResourceId", f"{RG}/providers/Microsoft.Storage/storageAccounts/other")]
    if technique == "azure-purview-policy-self-grant":
        invalid.append(("PolicyPublishedVerified", False))
    for field, value in invalid:
        bad = copy.deepcopy(snap)
        next(c for c in bad["collections"] if c["type"] == "azure_privesc_challenge_evidence")["items"][0][field] = value
        assert all(conf == "unknown" for conf in reached(privesc.analyze(bad, entries=[entry]), "u-alice", technique).values()), field

    no_action = copy.deepcopy(snap)
    next(c for c in no_action["collections"] if c["type"] == "role_definition")["items"][0]["properties"]["permissions"] = [
        {"actions": ["Microsoft.Resources/deployments/read"], "dataActions": []}]
    assert not any(conf in ("conditional", "derived") for conf in
                   reached(privesc.analyze(no_action, entries=[entry]), "u-alice", technique).values())


def test_generic_review_flag_cannot_create_self_grant():
    technique, action, permission, data_action = CASES[0]
    entry, snap, fact = _case(technique, action, permission, data_action)
    for key in ("EffectType", "GrantedPrincipalId", "PriorAccessDenied", "PostGrantAccessVerified"):
        fact.pop(key)
    assert all(conf == "unknown" for conf in reached(privesc.analyze(snap, entries=[entry]), "u-alice", technique).values())
