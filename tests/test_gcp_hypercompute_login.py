"""A Cluster Director login-node edge needs an exact running VM and its SA."""

from copy import deepcopy

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/compute"
VM = PROJECT + "/zones/us-central1-a/instances/login1"
EMAIL = "login@demo-project1.iam.gserviceaccount.com"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/clusterWriter"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-hypercomputecluster-login-node-startup-actas")


def envelope(kind, rows, status=None):
    return {"type": kind, "scope": PROJECT,
            "status": status or ("collected" if rows else "empty"), "items": rows}


def case():
    return {"provider": "gcp", "metadata": {}, "collections": [
        envelope("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        envelope("iam_role", [{"name": ROLE, "includedPermissions": [
            "hypercomputecluster.clusters.update", "iam.serviceAccounts.actAs"]}]),
        envelope("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE,
            "members": [SOURCE]}]}]),
        envelope("iam_deny_policy", []), envelope("org_policy_effective", []),
        envelope("group", []), envelope("group_membership", []),
        envelope("service_account", [{"email": EMAIL, "projectId": "demo-project1",
                                      "disabled": False}]),
        envelope("hypercompute_cluster", [{"name": CLUSTER, "reconciling": False,
            "orchestrator": {"slurm": {"loginNodes": {"count": "1",
                "zone": "us-central1-a", "instances": [{"instance": VM}]}}}}]),
        envelope("instance", [{"name": "login1", "status": "RUNNING",
            "selfLink": "https://www.googleapis.com/compute/v1/" + VM,
            "serviceAccounts": [{"email": EMAIL,
                "scopes": ["https://www.googleapis.com/auth/cloud-platform"]}]}]),
    ]}


def reached(snap):
    return [(target, grant.confidence) for edge in
            Evaluator(GcpModel(snap), [ENTRY], include_unknown=True,
                      admin_scopes={}).run() if edge.source.id == SOURCE
            for target, grant in edge.targets.items()]


def test_exact_login_vm_and_service_account_make_conditional_path():
    assert reached(case()) == [("serviceAccount:" + EMAIL, "conditional")]


def test_missing_or_different_login_vm_is_not_a_definite_path():
    for mutate in (
        lambda s: s["collections"][-2]["items"][0]["orchestrator"]["slurm"]["loginNodes"].update(
            {"instances": [{"instance": VM.replace("login1", "other")}] }),
        lambda s: s["collections"][-1]["items"][0].update({"status": "TERMINATED"}),
        lambda s: s["collections"][-1]["items"][0]["serviceAccounts"][0].update(
            {"scopes": ["https://www.googleapis.com/auth/devstorage.read_only"]}),
        lambda s: s["collections"][-1]["items"][0]["serviceAccounts"][0].update(
            {"email": "other@demo-project1.iam.gserviceaccount.com"}),
        lambda s: s["collections"][-2]["items"][0].update({"reconciling": True}),
    ):
        snap = deepcopy(case()); mutate(snap)
        assert not any(confidence == "conditional" for _, confidence in reached(snap))


def test_no_login_nodes_or_no_update_grant_has_no_path():
    snap = case()
    snap["collections"][-2]["items"][0]["orchestrator"]["slurm"]["loginNodes"] = {"count": "0"}
    assert reached(snap) == []
    snap = case()
    snap["collections"][1]["items"][0]["includedPermissions"].remove(
        "hypercomputecluster.clusters.update")
    assert reached(snap) == []
