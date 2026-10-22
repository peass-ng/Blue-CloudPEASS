"""Address-group policy self-grants need a named resource and new update access."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.effective_permissions.gcp_resource_self_grant import (
    _valid, networksecurity_address_group_candidates, select,
)
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
ADDRESS_GROUP = PROJECT + "/locations/us-central1/addressGroups/trusted"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/addressGroupPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-networksecurity-addressgroups-setiampolicy-address-group-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions": [
            "networksecurity.addressGroups.setIamPolicy",
            "networksecurity.addressGroups.getIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("network_security_address_group", [{"name": ADDRESS_GROUP,
            "iamPolicy": {"bindings": []},
            "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def selected(snapshot):
    model = GcpModel(snapshot)
    model.current_entry = ENTRY
    return select(model, networksecurity_address_group_candidates(model),
                  model.principals[SOURCE])


def reached(snapshot):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if not target.startswith(("unknown:", "unresolved:"))]


def test_exact_regional_and_global_address_group_writers_gain_update():
    assert reached(case())[0][1] == "conditional"
    snapshot = case()
    snapshot["collections"][7]["items"][0]["name"] = ADDRESS_GROUP.replace(
        "us-central1", "global")
    assert reached(snapshot)[0][1] == "conditional"


def test_prior_update_or_no_policy_write_is_not_an_escalation():
    snapshot = case()
    snapshot["collections"][7]["items"][0]["iamPolicy"]["bindings"].append({
        "role": "roles/networksecurity.editor", "members": [SOURCE]})
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][2]["items"][0]["bindings"].append({
        "role": "roles/networksecurity.editor", "members": [SOURCE]})
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][1]["items"][0]["includedPermissions"].remove(
        "networksecurity.addressGroups.setIamPolicy")
    assert reached(snapshot) == []


def test_exact_condition_and_missing_policies():
    snapshot = case()
    snapshot["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + ADDRESS_GROUP + "'"}
    assert reached(snapshot)[0][1] == "conditional"
    snapshot["collections"][2]["items"][0]["bindings"][0]["condition"] = {
        "expression": "resource.name == '" + ADDRESS_GROUP + "-other'"}
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][7]["items"][0]["_coverage"]["iamPolicy"]["status"] = "denied"
    assert next(iter(selected(snapshot).values()))[0] == "unknown"
    snapshot = case()
    snapshot["collections"][1]["items"][0]["includedPermissions"].remove(
        "networksecurity.addressGroups.getIamPolicy")
    assert next(iter(selected(snapshot).values()))[0] == "unknown"


def test_other_project_or_duplicate_resource_is_not_a_definite_path():
    snapshot = case()
    snapshot["collections"][7]["items"][0]["name"] = ADDRESS_GROUP.replace(
        "demo-project1", "other-project")
    assert reached(snapshot) == []
    snapshot = case()
    snapshot["collections"][7]["items"].append(deepcopy(
        snapshot["collections"][7]["items"][0]))
    assert reached(snapshot) == []


def test_reviewed_mutation_cannot_claim_an_organization_resource_without_setter():
    record = {"TechniqueId": ENTRY["id"], "SourceId": SOURCE,
              "TargetScope": PROJECT, "TargetResource": ADDRESS_GROUP,
              "GrantedResource": ADDRESS_GROUP,
              "AccessPermission": "networksecurity.addressGroups.setIamPolicy",
              "GrantedPrincipalId": SOURCE,
              "GrantedPermissions": ["networksecurity.addressGroups.update"],
              "PriorPermissionAbsent": True, "PolicyMutationAuthorized": True,
              "PolicyMutationAccepted": True, "AfterPermissionAllowed": True,
              "Status": "verified", "EvidenceRef": "accepted-address-group-policy"}
    assert _valid(record, PROJECT, case())
    org = "organizations/123/locations/global/addressGroups/trusted"
    record.update(TargetScope="organizations/123", TargetResource=org,
                  GrantedResource=org)
    assert not _valid(record, "organizations/123", case())
