"""GKE TokenRequest reaches only an existing exact KSA on an accessible cluster."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/tokenMinter"
TARGET = "k8s:" + CLUSTER + ":sa:work:app"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-serviceaccounts-createtoken")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, create=True, get=True, joined=True, private=False,
         deleting=False, uid="uid-app", sa_status=None, cluster_status="RUNNING"):
    permissions = ((["container.serviceAccounts.createToken"] if create else []) +
                   (["container.clusters.get"] if get else []))
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1",
                             "status": cluster_status, "endpoint": "203.0.113.10",
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    metadata = {"name": "app", "namespace": "work", "uid": uid}
    if deleting:
        metadata["deletionTimestamp"] = "2026-01-01T00:00:00Z"
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": metadata}], "*", sa_status),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_exact_existing_ksa_token_request_path():
    assert case() == [(TARGET, "conditional")]
    assert case(create=False) == []
    assert case(get=False) == []
    assert case(deleting=True)[0][1] == "unknown"
    assert case(uid="")[0][1] == "unknown"


def test_missing_cluster_join_or_access_stays_unresolved():
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(sa_status="denied")[0][1] == "unknown"
    assert case(cluster_status="STOPPING")[0][1] == "unknown"
