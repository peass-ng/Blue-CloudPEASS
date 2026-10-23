"""Directory PIM activation requires live eligibility and no self-approval blocker."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-pim-eligible-role-activation")
ROLE = "role-one"
TARGET = f"entra_role:{ROLE}"


def _case(*, source="u-alice", principal="u-alice", approval=False, policy=True,
          active=False, role_enabled=True, group_assignable=True, eligibility_scope="/",
          user_enabled=True, expired=False):
    snap = az(users=("u-alice",), sps=("sp-source",), groups=[("g-eligible", "eligible")],
              members={"g-eligible": ["u-alice"]}, extra=[
        ("directory_role_eligibility_schedule", T, [{"id": "schedule", "principalId": principal,
            "roleDefinitionId": ROLE, "directoryScopeId": eligibility_scope, "status": "Provisioned"}], "collected"),
        ("directory_role_eligibility_instance", T, [{"id": "instance", "principalId": principal,
            "roleDefinitionId": ROLE, "directoryScopeId": eligibility_scope}], "collected"),
        ("directory_role_pim_policy", T, ([{"id": "policy-assignment", "scopeId": "/",
            "scopeType": "DirectoryRole", "roleDefinitionId": ROLE,
            "policy": {"rules": [{"id": "Approval_EndUser_Assignment",
                "setting": {"isApprovalRequired": approval}}]}}] if policy else []),
            "collected" if policy else "access_denied")])
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = user_enabled
    sps = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    sps["items"][0]["accountEnabled"] = True
    groups = next(c for c in snap["collections"] if c["type"] == "directory_group")
    groups["items"][0]["isAssignableToRole"] = group_assignable
    roles = next(c for c in snap["collections"] if c["type"] == "directory_role_definition")
    roles.update(status="collected", items=[{"id": ROLE, "displayName": "Example role",
        "isEnabled": role_enabled, "rolePermissions": [{"allowedResourceActions": ["microsoft.directory/users/read"]}]}])
    if expired:
        instances = next(c for c in snap["collections"] if c["type"] == "directory_role_eligibility_instance")
        instances["items"][0]["endDateTime"] = "2020-01-01T00:00:00Z"
    if active:
        assignments = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
        assignments.update(status="collected", items=[{"id": "active-role", "principalId": source,
            "roleDefinitionId": ROLE, "directoryScopeId": eligibility_scope}])
    return snap


def _targets(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_direct_eligibility_activates_only_without_approval_or_existing_role():
    assert validate_entry(ENTRY)[0] == []
    assert _targets(_case()).get(TARGET) == "conditional"
    assert TARGET not in _targets(_case(approval=True))
    assert TARGET not in _targets(_case(active=True))
    assert TARGET not in _targets(_case(role_enabled=False))
    assert TARGET not in _targets(_case(user_enabled=False))
    assert TARGET not in _targets(_case(expired=True))
    assert _targets(_case(policy=False)).get(TARGET) == "conditional"


def test_group_eligibility_requires_role_assignable_group_and_user_source():
    assert _targets(_case(principal="g-eligible")).get(TARGET) == "conditional"
    assert TARGET not in _targets(_case(principal="g-eligible", group_assignable=False))
    assert TARGET not in _targets(_case(source="sp-source", principal="sp-source"), "sp-source")


def test_scoped_eligibility_is_kept_as_conditional():
    assert _targets(_case(eligibility_scope="/administrativeUnits/au-1")).get(TARGET) == "conditional"
