"""Log view self-grants require an existing exact view and new read access."""

from copy import deepcopy
import json

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
VIEW = PROJECT + "/locations/global/buckets/_Default/views/custom"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/viewPolicyWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-logging-views-setiampolicy-self-grant")


def envelope(kind, rows):
    return {"type": kind, "scope": PROJECT,
            "status": "collected" if rows else "empty", "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": ["logging.views.setIamPolicy"]}]),
        envelope("iam_role_builtin", [{"name": "roles/logging.viewAccessor",
                                      "includedPermissions": ["logging.views.access"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("logging_view", [{"name": VIEW, "filter": "severity>=ERROR",
            "iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy": {"status": "collected"}}}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_view_with_new_access_is_conditional():
    assert reached(case()) == [(
        "gcp_verified_authority:possible-logging-view-self-grant:" + VIEW,
        "conditional")]


def test_existing_access_or_no_policy_writer_is_not_an_escalation():
    snap = case()
    snap["collections"][-1]["items"][0]["iamPolicy"]["bindings"] = [
        {"role": "roles/logging.viewAccessor", "members": [SOURCE]}]
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"] = []
    assert reached(snap) == []


def test_missing_or_conflicting_view_evidence_is_not_definite():
    for mutate in (
        lambda s: s["collections"][-1]["items"][0]["_coverage"]["iamPolicy"].update(
            {"status": "denied"}),
        lambda s: s["collections"][-1]["items"].append(
            deepcopy(s["collections"][-1]["items"][0])),
        lambda s: s["collections"][-1]["items"][0].update(
            {"name": VIEW.replace("demo-project1", "foreign-project")}),
        lambda s: s["collections"][-1]["items"][0]["iamPolicy"].update(
            {"bindings": [{"role": "roles/logging.viewAccessor", "members": [None]}]}),
    ):
        snap = case(); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_condition_must_cover_the_same_view_and_role_must_grant_access():
    snap = case()
    snap["collections"][3]["items"][0]["bindings"][0]["condition"] = {
        "expression": 'resource.name == "' + VIEW.replace("custom", "other") + '"'}
    assert reached(snap) == []
    snap = case()
    snap["collections"][2]["items"][0]["includedPermissions"] = []
    assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_organization_owned_view_is_not_lost():
    scope = "organizations/123456"
    snap = json.loads(json.dumps(case()).replace(PROJECT, scope))
    snap["collections"][0]["type"] = "organization"
    snap["collections"][0]["items"][0].pop("projectId", None)
    assert ("gcp_verified_authority:possible-logging-view-self-grant:"
            + VIEW.replace(PROJECT, scope), "conditional") in reached(snap)
