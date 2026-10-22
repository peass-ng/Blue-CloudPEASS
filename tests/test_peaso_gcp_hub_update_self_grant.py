"""Hub update access needs a reviewed effective hub-level grant."""
from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
HUB = PROJECT + "/locations/global/hubs/core"
SOURCE = "user:operator@example.com"
WRITER = PROJECT + "/roles/hubPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-networkconnectivity-hubs-setiampolicy-hub-self-grant")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def proof():
    return {"TechniqueId": ENTRY["id"], "SourceId": SOURCE,
            "TargetScope": PROJECT, "TargetResource": HUB,
            "GrantedResource": HUB,
            "AccessPermission": "networkconnectivity.hubs.setIamPolicy",
            "GrantedPrincipalId": SOURCE,
            "GrantedPermissions": ["networkconnectivity.hubs.update"],
            "PriorPermissionAbsent": True,
            "PolicyMutationAuthorized": True, "PolicyMutationAccepted": True,
            "AfterPermissionAllowed": True, "Status": "verified",
            "EvidenceRef": "reviewed-hub-policy-grant"}


def case(records=None, *, role_permissions=None):
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": WRITER, "includedPermissions":
            role_permissions if role_permissions is not None else [
                "networkconnectivity.hubs.setIamPolicy"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": WRITER, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []),
        envelope("gcp_resource_self_grant_evidence",
                 [proof()] if records is None else records),
    ]}


def reached(snapshot):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snapshot), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()
            if not target.startswith(("unknown:", "unresolved:"))]


def test_accepted_exact_hub_update_grant_remains_available():
    assert len(reached(case())) == 1
    assert reached(case())[0][1] == "conditional"


def test_hub_policy_write_alone_does_not_imply_hub_update():
    assert reached(case(records=[])) == []
    assert reached(case(role_permissions=[])) == []
    wrong = deepcopy(proof())
    wrong["GrantedPermissions"] = ["networkconnectivity.groups.use"]
    assert reached(case(records=[wrong])) == []
    wrong = deepcopy(proof())
    wrong["PolicyMutationAccepted"] = False
    assert reached(case(records=[wrong])) == []
    wrong = deepcopy(proof())
    wrong["TargetResource"] = HUB.replace("/hubs/core", "/hubs/other")
    assert reached(case(records=[wrong])) == []
