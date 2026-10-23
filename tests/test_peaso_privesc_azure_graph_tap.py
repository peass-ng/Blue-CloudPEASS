"""Graph TAP issuance is bound to an enabled policy and eligible user."""
from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T, az


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_roles.yaml").read_text())
    if row["id"] == "azure-entraid-graph-userauthenticationmethod-tap")
GRAPH = "00000003-0000-0000-c000-000000000000"


def _targets(*, grant="UserAuthenticationMethod.ReadWrite.All", policy_state="enabled",
             included="all_users", excluded=(), source_enabled=True, user_enabled=True,
             creation_type=None, policy_write=False, policy_complete=True,
             membership_complete=True, restricted=False):
    groups = [("g-in", "included"), ("g-out", "excluded"), ("g-elsewhere", "elsewhere")]
    snap = az(users=("u-victim",), sps=("sp-source", "sp-graph"), groups=groups,
              members={"g-in": ["u-victim"], "g-out": ["u-victim"], "g-elsewhere": []}, extra=[
        ("directory_app_role_assignment", T,
         ([{"id": "tap-grant", "principalId": "sp-source", "resourceId": "sp-graph",
            "appRoleValue": grant, "appRoleEnabled": True}] if grant else []) +
         ([{"id": "policy-grant", "principalId": "sp-source", "resourceId": "sp-graph",
            "appRoleValue": "Policy.ReadWrite.AuthenticationMethod", "appRoleEnabled": True}] if policy_write else [])),
        ("directory_administrative_unit", T, [{"id": "au-1", "isMemberManagementRestricted": True,
                                               "memberIds": ["u-victim"] if restricted else []}])])
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    for row in principals["items"]:
        row.update(accountEnabled=source_enabled if row["id"] == "sp-source" else True,
                   appId=GRAPH if row["id"] == "sp-graph" else "source-app")
    user = next(c for c in snap["collections"] if c["type"] == "directory_user")
    user["items"][0].update(accountEnabled=user_enabled, creationType=creation_type,
                            identities=[{"issuer": "contoso.onmicrosoft.com"}])
    if not membership_complete:
        next(c for c in snap["collections"] if c["type"] == "directory_membership")["status"] = "partial"
    policy = {"id": "TemporaryAccessPass", "state": policy_state,
              "includeTargets": [{"targetType": "group", "id": included}] if included else [],
              "excludeTargets": [{"targetType": "group", "id": group} for group in excluded]}
    snap["collections"].append({"type": "temporary_access_pass_policy", "scope": T,
                                "service": "Microsoft.Graph", "status": "collected" if policy_complete else "denied",
                                "items": [policy] if policy_complete else []})
    return reached(privesc.analyze(snap, entries=[ENTRY]), "sp-source", ENTRY["id"])


def test_tap_policy_all_users_or_included_group_reaches_user():
    assert validate_entry(ENTRY)[0] == []
    assert _targets().get("u-victim") == "conditional"
    assert _targets(included="g-in").get("u-victim") == "conditional"
    assert _targets(grant="UserAuthMethod-TAP.ReadWrite.All").get("u-victim") == "conditional"


def test_tap_excludes_disabled_external_outside_policy_and_restricted_users():
    for variant in ({"grant": ""}, {"source_enabled": False}, {"user_enabled": False},
                    {"creation_type": "Invitation"}, {"policy_state": "disabled"},
                    {"included": "g-elsewhere"}, {"excluded": ("g-out",)}, {"restricted": True}):
        assert "u-victim" not in _targets(**variant), variant


def test_tap_policy_write_and_incomplete_evidence_stay_conditional():
    assert _targets(policy_state="disabled", policy_write=True).get("u-victim") == "conditional"
    assert _targets(excluded=("g-out",), policy_write=True).get("u-victim") == "conditional"
    assert _targets(policy_complete=False).get("u-victim") == "conditional"
    assert _targets(included="g-in", membership_complete=False).get("u-victim") == "conditional"
