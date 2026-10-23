"""Helpdesk reset follows the documented role matrix and directory boundaries."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-password-helpdesk-admin")


def _case(*, target_role=None, source_scope="/", restricted=False, owner=False,
          federated=False, synced=False, app=False):
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
        row["accountEnabled"] = True
        row["onPremisesSyncEnabled"] = synced if row["id"] == "u-target" else False
    group = next(c for c in snap["collections"] if c["type"] == "directory_group")
    group["items"][0]["isAssignableToRole"] = True
    if app:
        next(c for c in snap["collections"] if c["type"] == "directory_service_principal")["items"][0]["accountEnabled"] = True
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions.update(status="collected", items=[{"id": "source-role", "displayName": "Helpdesk Administrator",
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/password/update"]}]},
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


def test_helpdesk_matrix_and_protected_owner():
    assert validate_entry(ENTRY)[0] == []
    assert "u-target" in _targets(_case())
    assert "u-target" in _targets(_case(target_role="User Experience Success Manager"))
    assert "u-target" not in _targets(_case(target_role="Global Reader"))
    assert "u-target" not in _targets(_case(owner=True))


def test_helpdesk_au_and_restricted_unit_scope():
    assert "u-target" in _targets(_case(source_scope="/administrativeUnits/au-1"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-1",
                                            target_role="Helpdesk Administrator"))
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))


def test_federated_password_and_synced_password_writeback():
    assert "u-target" not in _targets(_case(federated=True))
    assert _targets(_case(synced=True))["u-target"] == "conditional"
    assert "u-target" not in _targets(_case(app=True), app=True)


def test_incomplete_owner_and_au_membership_are_conditional():
    snap = _case()
    next(c for c in snap["collections"] if c["type"] == "directory_owner")["status"] = "partial"
    assert _targets(snap)["u-target"] == "conditional"
    snap = _case()
    unit = next(c for c in snap["collections"] if c["type"] == "directory_administrative_unit")
    unit["items"][0].pop("memberIds")
    assert _targets(snap)["u-target"] == "conditional"
