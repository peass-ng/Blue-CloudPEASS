"""Partner Tier1 and incident roles reset only eligible non-admin passwords."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-password-partner-tier1")


def _case(*, role="Partner Tier1 Support", target_role=None, source_scope="/",
          restricted=False, owner=False, federated=False, synced=False,
          target_enabled=True, app=False):
    snap = az(users=("u-target",) if app else ("u-source", "u-target"),
              sps=("sp-source",) if app else (), groups=[("g-protected", "protected")],
              members={"g-protected": []}, extra=[
                  ("directory_administrative_unit", T, [{"id": "au-1", "memberIds": ["u-target"],
                      "isMemberManagementRestricted": restricted}], "collected"),
                  ("directory_domain", T, [{"id": "t.com", "authenticationType":
                      "Federated" if federated else "Managed"}], "collected"),
                  ("directory_owner", f"{T}/groups/g-protected", [{"id": "g-protected",
                      "objectId": "g-protected", "objectType": "group",
                      "ownerIds": ["u-target"] if owner else []}], "collected")])
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    for row in users["items"]:
        row["accountEnabled"] = target_enabled if row["id"] == "u-target" else True
        row["onPremisesSyncEnabled"] = synced if row["id"] == "u-target" else False
    group = next(c for c in snap["collections"] if c["type"] == "directory_group")
    group["items"][0]["isAssignableToRole"] = True
    if app:
        next(c for c in snap["collections"] if c["type"] == "directory_service_principal")["items"][0]["accountEnabled"] = True
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="collected", items=[{"id": "source-role", "displayName": role,
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/password/update",
            *(["microsoft.directory/users/enable"] if role == "Security Operator" else [])]}]},
        *([{"id": "target-role", "displayName": target_role,
            "rolePermissions": [{"allowedResourceActions": []}]}] if target_role else [])])
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignments.update(status="collected", items=[{"id": "role-assignment",
        "principalId": "sp-source" if app else "u-source", "roleDefinitionId": "source-role",
        "directoryScopeId": source_scope}, *([{"id": "target-role-assignment",
        "principalId": "u-target", "roleDefinitionId": "target-role", "directoryScopeId": "/"}]
        if target_role else [])])
    return snap


def _targets(snap, *, app=False):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source" if app else "u-source", ENTRY["id"])


def test_only_enabled_non_admin_users_and_unprotected_owners():
    assert validate_entry(ENTRY)[0] == []
    for role in ("Partner Tier1 Support", "Security Operator", "Entra SOC Identity Responder"):
        assert "u-target" in _targets(_case(role=role))
        assert "u-target" not in _targets(_case(role=role, target_role="Directory Readers"))
    assert "u-target" not in _targets(_case(owner=True))
    assert "u-target" not in _targets(_case(app=True), app=True)


def test_restricted_unit_requires_matching_scoped_role():
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(restricted=True,
        source_scope="/administrativeUnits/au-1", target_role="Directory Readers"))


def test_password_origin_and_disabled_account():
    assert "u-target" not in _targets(_case(federated=True))
    assert _targets(_case(synced=True))["u-target"] == "conditional"
    assert "u-target" not in _targets(_case(target_enabled=False))
    assert _targets(_case(role="Security Operator", target_enabled=False))["u-target"] == "conditional"


def test_missing_group_owner_evidence_is_conditional():
    snap = _case()
    next(c for c in snap["collections"] if c["type"] == "directory_owner")["status"] = "partial"
    assert _targets(snap)["u-target"] == "conditional"
