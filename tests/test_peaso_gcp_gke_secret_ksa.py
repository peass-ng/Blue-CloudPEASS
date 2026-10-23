"""GKE Secret reads reach only a current, usable KSA token Secret."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/secretReader"
TARGET = "k8s:" + CLUSTER + ":sa:work:app"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-secrets-read-ksa-token-secret")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, list_secret=True, get_secret=False, list_sa=False, list_pod=False,
         sa_ref=False, pod_ref=False, secret_uid="uid-app", invalid=False,
         get=True, joined=True, private=False, secret_status=None, sa_status=None):
    permissions = ((["container.secrets.list"] if list_secret else []) +
                   (["container.secrets.get"] if get_secret else []) +
                   (["container.serviceAccounts.list"] if list_sa else []) +
                   (["container.pods.list"] if list_pod else []) +
                   (["container.clusters.get"] if get else []))
    gcp = {"provider": "gcp", "metadata": {}, "collections": [
        row("project", [{"name": PROJECT, "projectId": "demo-project1"}]),
        row("iam_role", [{"name": ROLE, "includedPermissions": permissions}]),
        row("iam_policy", [{"name": PROJECT, "bindings": [{"role": ROLE, "members": [SOURCE]}]}]),
        row("iam_deny_policy", []),
        row("gke_cluster", [{"name": "primary", "location": "us-central1", "status": "RUNNING",
                             "endpoint": "203.0.113.10",
                             "privateClusterConfig": {"enablePrivateEndpoint": private},
                             "masterAuthorizedNetworksConfig": {"enabled": False}}]),
    ]}
    sa = {"metadata": {"name": "app", "namespace": "work", "uid": "uid-app"},
          "secrets": [{"name": "app-token"}] if sa_ref else []}
    secret = {"metadata": {"name": "app-token", "namespace": "work",
                           "annotations": {"kubernetes.io/service-account.name": "app",
                                           "kubernetes.io/service-account.uid": secret_uid},
                           "labels": {"kubernetes.io/legacy-token-invalid-since": "2026-01-01"}
                           if invalid else {}},
              "type": "kubernetes.io/service-account-token"}
    pod = {"metadata": {"name": "app", "namespace": "work"},
           "spec": {"volumes": [{"name": "token", "secret": {"secretName": "app-token"}}]}}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [sa], "*", sa_status),
        row("secret_metadata", [secret], "*", secret_status),
        row("pod", [pod] if pod_ref else [], "*"),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [ENTRY], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_list_or_discoverable_get_reaches_current_ksa_token():
    assert case() == [(TARGET, "conditional")]
    assert case(list_secret=False, get_secret=True, list_sa=True, sa_ref=True) == [(TARGET, "conditional")]
    assert case(list_secret=False, get_secret=True, list_pod=True, pod_ref=True) == [(TARGET, "conditional")]
    assert case(list_secret=False, get_secret=True)[0][1] == "unknown"
    assert case(list_secret=False, get_secret=False) == []


def test_stale_or_unresolved_token_does_not_claim_ksa():
    assert case(secret_uid="old-uid") == []
    assert case(secret_uid="")[0][1] == "unknown"
    assert case(invalid=True) == []
    assert case(get=False) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(secret_status="denied")[0][1] == "unknown"
    assert case(sa_status="denied")[0][1] == "unknown"
