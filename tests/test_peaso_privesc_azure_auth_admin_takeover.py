"""Authentication Administrator takeover follows the documented target and AU matrix."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-reset-credentials-authentication-admin")


def _case(*, target_role=None, source_scope="/", restricted=False, owner=False,
          federated=False, tap_enabled=True):
    snap = az(users=("u-source", "u-target"), groups=[("g-protected", "protected")], members={
        "g-protected": []}, extra=[
        ("directory_administrative_unit", T, [{"id": "au-1",
            "isMemberManagementRestricted": restricted, "memberIds": ["u-target"]}], "collected"),
        ("directory_domain", T, [{"id": "t.com",
            "authenticationType": "Federated" if federated else "Managed"}], "collected"),
        ("temporary_access_pass_policy", T, [{"id": "TemporaryAccessPass",
            "state": "enabled" if tap_enabled else "disabled",
            "includeTargets": [{"targetType": "group", "id": "all_users"}],
            "excludeTargets": []}], "collected"),
        ("directory_owner", f"{T}/groups/g-protected", [{"id": "g-protected",
            "objectId": "g-protected", "objectType": "group",
            "ownerIds": ["u-target"] if owner else []}], "collected")])
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    for row in users["items"]:
        row["accountEnabled"] = True
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0]["isAssignableToRole"] = True
    defs = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    defs.update(status="collected", items=[{"id": "auth-role", "displayName": "Authentication Administrator",
        "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/password/update"]}]},
        *([{"id": "target-role", "displayName": target_role,
           "rolePermissions": [{"allowedResourceActions": []}]}] if target_role else [])])
    assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignments.update(status="collected", items=[{"id": "source-role", "principalId": "u-source",
        "roleDefinitionId": "auth-role", "directoryScopeId": source_scope},
        *([{"id": "target-role-assignment", "principalId": "u-target",
            "roleDefinitionId": "target-role", "directoryScopeId": "/"}] if target_role else [])])
    return snap


def _targets(snap):
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-source", ENTRY["id"])


def test_target_role_matrix_and_protected_owner():
    assert validate_entry(ENTRY)[0] == []
    assert "u-target" in _targets(_case())
    assert "u-target" in _targets(_case(target_role="User Experience Success Manager"))
    assert "u-target" not in _targets(_case(target_role="Global Reader"))
    assert "u-target" not in _targets(_case(target_role="Helpdesk Administrator"))
    assert "u-target" not in _targets(_case(owner=True))


def test_missing_target_role_definition_is_conditional():
    snap = _case(target_role="Global Reader")
    definitions = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    definitions["items"] = [row for row in definitions["items"] if row["id"] != "target-role"]
    assert _targets(snap)["u-target"] == "conditional"


def test_au_scope_and_restricted_unit_must_match():
    assert "u-target" in _targets(_case(source_scope="/administrativeUnits/au-1"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-2"))
    assert "u-target" not in _targets(_case(source_scope="/administrativeUnits/au-1",
                                            target_role="User Experience Success Manager"))
    assert "u-target" not in _targets(_case(restricted=True))
    assert "u-target" in _targets(_case(restricted=True, source_scope="/administrativeUnits/au-1"))


def test_federated_user_needs_a_viable_authentication_route():
    assert "u-target" in _targets(_case(federated=True, tap_enabled=True))
    assert "u-target" not in _targets(_case(federated=True, tap_enabled=False))


def test_incomplete_tap_group_membership_stays_conditional():
    snap = _case(federated=True)
    policy = next(c for c in snap["collections"] if c["type"] == "temporary_access_pass_policy")
    policy["items"][0]["includeTargets"] = [{"targetType": "group", "id": "g-protected"}]
    membership = next(c for c in snap["collections"] if c["type"] == "directory_membership")
    membership["status"] = "partial"
    assert _targets(snap)["u-target"] == "conditional"
