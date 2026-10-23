"""Infra Manager create needs a real location and configured run-as SA."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
LOCATION = PROJECT + "/locations/us-central1"
SOURCE = "user:operator@example.com"
EMAIL = "terraform@demo-project1.iam.gserviceaccount.com"
TARGET = "serviceAccount:" + EMAIL
ROLE = PROJECT + "/roles/deploymentCreator"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-inframanager-deployments-create-actas")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": [
            "config.deployments.create"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [
            {"role": ROLE, "members": [SOURCE]},
            {"role": "roles/iam.serviceAccountUser", "members": [SOURCE]},
            {"role": "roles/config.agent", "members": [TARGET]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("service_account", [{"email": EMAIL, "projectId": "demo-project1",
                                      "disabled": False}]),
        envelope("inframanager_location", [{"name": LOCATION}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def cross_project_case():
    snap = case()
    sa_project = "projects/other-project"
    email = "terraform@other-project.iam.gserviceaccount.com"
    snap["collections"][0]["items"][0]["name"] = "projects/123"
    snap["collections"][0]["items"].append(
        {"name": "projects/456", "projectId": "other-project"})
    snap["collections"][2]["items"][0]["bindings"][2]["members"] = [
        "serviceAccount:" + email]
    snap["collections"][7]["items"] = []
    snap["collections"][7]["status"] = "empty"
    snap["collections"].extend([
        {"type": "service_account", "scope": sa_project, "status": "collected",
         "items": [{"email": email, "projectId": "other-project", "disabled": False}]},
        {"type": "iam_policy", "scope": sa_project, "status": "collected", "items": [
            {"name": sa_project, "bindings": [
                {"role": "roles/iam.serviceAccountUser", "members": [SOURCE,
                    "serviceAccount:service-123@gcp-sa-config.iam.gserviceaccount.com"]},
                {"role": "roles/iam.serviceAccountTokenCreator", "members": [
                    "serviceAccount:service-123@gcp-sa-cloudbuild.iam.gserviceaccount.com"]}]}]},
        {"type": "iam_deny_policy", "scope": sa_project, "status": "empty", "items": []},
        {"type": "org_policy_effective", "scope": sa_project, "status": "collected",
         "items": [{"constraint": "iam.disableCrossProjectServiceAccountUsage",
                    "spec": {"rules": [{"enforce": False}]}}]},
        {"type": "inframanager_location", "scope": sa_project,
         "status": "empty", "items": []},
    ])
    return snap, "serviceAccount:" + email


def test_exact_location_with_agent_and_actas_gives_conditional_route():
    assert reached(case()) == [(TARGET, "conditional")]


def test_missing_agent_actas_or_location_blocks_definite_route():
    for mutate in (
        lambda s: s["collections"][2]["items"][0]["bindings"].pop(2),
        lambda s: s["collections"][2]["items"][0]["bindings"].pop(1),
        lambda s: s["collections"][-1]["items"].clear(),
        lambda s: s["collections"][-2]["items"][0].update({"disabled": True}),
    ):
        snap = deepcopy(case()); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_create_iam_condition_must_match_listed_location():
    snap = case()
    binding = snap["collections"][2]["items"][0]["bindings"][0]
    binding["condition"] = {"expression": 'resource.name == "' + LOCATION + '"'}
    assert reached(snap)[0][1] == "conditional"
    binding["condition"] = {"expression": 'resource.name == "' +
                            LOCATION.replace("us-central1", "europe-west1") + '"'}
    assert reached(snap) == []


def test_conditional_agent_binding_is_not_a_definite_run_as_route():
    snap = case()
    snap["collections"][2]["items"][0]["bindings"][2]["condition"] = {
        "expression": 'resource.name == "' + PROJECT + '"'}
    assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_cross_project_sa_requires_both_service_agents_and_allowing_policy():
    snap, target = cross_project_case()
    assert reached(snap) == [(target, "conditional")]
    for change in ("org_enforced", "missing_config_agent", "missing_build_agent"):
        snap, _ = cross_project_case()
        if change == "org_enforced":
            snap["collections"][-2]["items"][0]["spec"]["rules"][0]["enforce"] = True
        elif change == "missing_config_agent":
            snap["collections"][-4]["items"][0]["bindings"][0]["members"].remove(
                "serviceAccount:service-123@gcp-sa-config.iam.gserviceaccount.com")
        else:
            snap["collections"][-4]["items"][0]["bindings"].pop(1)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))
    snap, _ = cross_project_case()
    host_binding = snap["collections"][2]["items"][0]["bindings"].pop(2)
    snap["collections"][-4]["items"][0]["bindings"].append(host_binding)
    assert not any(confidence == "conditional" for _, confidence in reached(snap))
