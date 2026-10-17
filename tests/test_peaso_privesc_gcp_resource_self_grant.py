"""A resource IAM self-grant reaches only its reviewed new permission."""
from __future__ import annotations

import copy

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached, snapshot

SOURCE = "user:alice@corp.com"
SCOPE = "projects/p1"
RESOURCE = "projects/p1/secrets/s1"
GRANTED_RESOURCE = RESOURCE + "/versions/7"
ACTION = "secretmanager.secrets.setIamPolicy"
GRANTED = "secretmanager.versions.access"
ID = "gcp-test-secret-self-grant"
ENTRY = {
    "id": ID, "provider": "gcp", "service": "secretmanager", "title": "Grant self secret access",
    "source": "src/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-secretmanager-privesc.md#secretmanagersecretssetiampolicy",
    "summary": "The source grants itself a named new permission on one Secret.",
    "requires": {"all_of": [{"action": ACTION, "resource": "{target.policy_resource}"}]},
    "target": {"kind": "gcp_verified_authority", "selector": {"gcp_resource_self_grant": True},
               "scope": "same_project", "outcome": "permission_grant", "grants": [GRANTED]},
    "conditions": [], "blockers": [], "confidence": "conditional", "severity": "high",
    "mitigation": "Restrict Secret IAM policy writes.",
}


def proof():
    return {"TechniqueId": ID, "SourceId": SOURCE, "TargetScope": SCOPE,
            "TargetResource": RESOURCE, "GrantedResource": GRANTED_RESOURCE,
            "AccessPermission": ACTION,
            "GrantedPrincipalId": SOURCE, "GrantedPermissions": [GRANTED],
            "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
            "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
            "Status": "verified", "EvidenceRef": "reviewed-secret-policy-1"}


def case(records=None, *, status="collected", write_permission=True, permissions=None):
    role = {"name": "projects/p1/roles/policyWriter", "includedPermissions":
            ([ACTION] if write_permission else []) if permissions is None else permissions}
    return snapshot("gcp", [
        ("project", SCOPE, [{"projectId": "p1", "name": "projects/123", "_ancestry": []}]),
        ("iam_policy", SCOPE, [{"name": SCOPE, "bindings": [
            {"role": role["name"], "members": [SOURCE]}]}]),
        ("iam_role", SCOPE, [role]), ("service_account", SCOPE, []),
        ("iam_deny_policy", SCOPE, [], "empty"),
        ("gcp_resource_self_grant_evidence", SCOPE, [proof()] if records is None else records, status),
    ])


def paths(snap, entry=ENTRY):
    result = privesc.analyze(snap, entries=[entry])
    return {target: confidence for target, confidence in reached(result, SOURCE, entry["id"]).items()
            if not target.startswith(("unknown:", "unresolved:"))}


def test_unique_reviewed_self_grant_reaches_bounded_new_permission():
    assert validate_entry(ENTRY)[0] == []
    got = paths(case())
    assert len(got) == 1
    assert next(iter(got)).startswith("gcp_verified_authority:self-grant:")
    assert set(got.values()) == {"conditional"}
    result = privesc.analyze(case(), entries=[ENTRY])
    target = next(iter(got))
    node = next(node for node in result["graph"]["nodes"] if node["id"] == target)
    assert node["label"].endswith(f"{GRANTED} on {GRANTED_RESOURCE}")


def test_missing_partial_conflicting_or_mismatched_review_has_no_path():
    wrong = copy.deepcopy(proof())
    wrong["GrantedPermissions"] = ["secretmanager.secrets.delete"]
    for snap in (case([]), case(status="partial"), case([proof(), proof()]),
                 case([proof(), wrong]), case([wrong]), case(write_permission=False)):
        assert paths(snap) == {}
    for field, value in (("GrantedPrincipalId", "user:bob@corp.com"),
                         ("PriorPermissionAbsent", False), ("AfterPermissionAllowed", False),
                         ("PolicyMutationAccepted", False), ("EvidenceRef", ""),
                         ("AccessPermission", "secretmanager.secrets.get"),
                         ("GrantedResource", ""),
                         ("GrantedResource", "projects/p1/secrets/s2/versions/7"),
                         ("GrantedResource", "projects/p2/secrets/s1/versions/7")):
        altered = copy.deepcopy(proof())
        altered[field] = value
        assert paths(case([altered])) == {}, (field, value)


def test_direct_resource_permission_and_distinct_child_grants():
    direct = copy.deepcopy(proof())
    direct["GrantedResource"] = RESOURCE
    assert len(paths(case([direct]))) == 1
    other_child = copy.deepcopy(proof())
    other_child["GrantedResource"] = RESOURCE + "/versions/8"
    assert len(paths(case([proof(), other_child]))) == 2


def test_reviewed_access_action_must_be_named_in_yaml_requirements():
    entry = copy.deepcopy(ENTRY)
    entry["requires"]["all_of"][0]["action"] = "secretmanager.secrets.get"
    assert paths(case(), entry) == {}


def test_bigquery_row_policy_requires_all_ddl_permissions_and_exact_self_grant():
    import yaml
    from pathlib import Path

    entry = yaml.safe_load((Path(__file__).resolve().parents[1] / "peaso/privesc/catalog/gcp/bigquery_row_policy.yaml").read_text())[0]
    assert validate_entry(entry)[0] == []
    actions = [req["action"] for req in entry["requires"]["all_of"]]
    table = "projects/p1/datasets/d1/tables/t1"
    evidence = {**proof(), "TechniqueId": entry["id"], "TargetResource": table,
                "GrantedResource": table, "AccessPermission": actions[0],
                "GrantedPermissions": entry["target"]["grants"]}
    assert len(paths(case([evidence], permissions=actions), entry)) == 1
    for missing in actions:
        assert paths(case([evidence], permissions=[a for a in actions if a != missing]), entry) == {}
    wrong = {**evidence, "GrantedPrincipalId": "user:bob@corp.com"}
    assert paths(case([wrong], permissions=actions), entry) == {}
    assert paths(case([], permissions=actions), entry) == {}
