"""GKE impersonation needs a usable Standard cluster, not just an IAM grant."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/impersonator"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-clusters-impersonate")


def row(kind, records):
    return {"type": kind, "scope": PROJECT, "status": "collected" if records else "empty",
            "items": records}


def case(*, impersonate=True, get=True, autopilot=False, policy=False,
         status="RUNNING", private=False, authorized=False, endpoint=True):
    permissions = []
    if impersonate:
        permissions.append("container.clusters.impersonate")
    if get:
        permissions.append("container.clusters.get")
    cluster = {"name": "primary", "location": "us-central1", "status": status,
               "autopilot": {"enabled": autopilot,
                             "clusterPolicyConfig": {"noSystemImpersonation": policy}},
               "privateClusterConfig": {"enablePrivateEndpoint": private},
               "masterAuthorizedNetworksConfig": {"enabled": authorized}}
    if endpoint:
        cluster["endpoint"] = "203.0.113.10"
    snapshot = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE,
                                                          "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [cluster]),
    ]}
    model = GcpModel(snapshot)
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_standard_cluster_system_impersonation_path():
    assert case() == [("k8s_cluster_admin:" + CLUSTER, "conditional")]
    assert case(impersonate=False) == []


def test_cluster_policy_and_access_gaps_do_not_claim_admin():
    for options in ({"autopilot": True}, {"policy": True}, {"status": "ERROR"},
                    {"private": True}, {"authorized": True}, {"endpoint": False},
                    {"get": False}):
        result = case(**options)
        assert not any(confidence in ("derived", "conditional") for _, confidence in result)
