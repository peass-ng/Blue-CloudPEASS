"""GKE exec reaches a KSA only through a token mounted in a running container."""
from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator

PROJECT = "projects/demo-project1"
CLUSTER = PROJECT + "/locations/us-central1/clusters/primary"
SOURCE = "user:operator@example.com"
ROLE = PROJECT + "/roles/podExec"
TARGET = "k8s:" + CLUSTER + ":sa:work:app"
ENTRY = next(row for row in privesc.catalog()["entries"] if row["id"] ==
             "gcp-container-pods-exec-running-ksa")


def row(kind, records, scope=PROJECT, status=None):
    return {"type": kind, "scope": scope, "status": status or ("collected" if records else "empty"),
            "items": records}


def case(*, token=True, audience=None, mount=True, running=True, get=True,
         exec_permission=True, joined=True, private=False, pod_status=None,
         sa_status=None, legacy=False, legacy_uid="uid-app", wrong_sa=False,
         action="container.pods.exec", entry=ENTRY, image="app:1"):
    permissions = (([action] if exec_permission else []) +
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
    volume = {"name": "token", "secret": {"secretName": "legacy-token"}} if legacy else {
        "name": "token", "projected": {"sources": [{"serviceAccountToken": {
            "path": "token", **({"audience": audience} if audience else {})}}]}}
    spec = {"serviceAccountName": "other" if wrong_sa else "app",
            "automountServiceAccountToken": False,
            "containers": [{"name": "app", "image": image, "volumeMounts": [
                {"name": "token", "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"}]
                if mount else []}],
            "volumes": [volume] if token else []}
    pod = {"metadata": {"name": "app-1", "namespace": "work"}, "spec": spec,
           "status": {"phase": "Running" if running else "Pending",
                      "containerStatuses": [{"name": "app", "state": {
                          "running": {"startedAt": "2026-01-01T00:00:00Z"}}}]}}
    secret = {"metadata": {"name": "legacy-token", "namespace": "work",
                           "annotations": {"kubernetes.io/service-account.name": "app",
                                           "kubernetes.io/service-account.uid": legacy_uid}},
              "type": "kubernetes.io/service-account-token"}
    k8s = {"provider": "k8s", "metadata": {"cluster_id": CLUSTER}, "collections": [
        row("serviceaccount", [{"metadata": {"name": "app", "namespace": "work",
                                            "uid": "uid-app"}}], "*", sa_status),
        row("pod", [pod], "*", pod_status),
        row("secret_metadata", [secret] if legacy else [], "*"),
    ]}
    model = GcpModel(gcp)
    if joined:
        model.set_related([k8s])
    return [(target, grant.confidence) for reach in
            Evaluator(model, [entry], include_unknown=True, admin_scopes={}).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()]


def test_mounted_api_token_in_running_container_reaches_exact_ksa():
    assert case() == [(TARGET, "conditional")]
    assert case(legacy=True) == [(TARGET, "conditional")]
    assert case(legacy=True, legacy_uid="old-uid") == []
    assert case(token=False) == []
    assert case(mount=False) == []
    assert case(running=False) == []
    assert case(wrong_sa=True) == []
    assert case(audience="other-service")[0][1] == "unknown"


def test_missing_authority_or_inventory_does_not_claim_ksa():
    assert case(exec_permission=False) == []
    assert case(get=False) == []
    assert case(joined=False)[0][1] == "unknown"
    assert case(private=True)[0][1] == "unknown"
    assert case(pod_status="denied")[0][1] == "unknown"
    assert case(sa_status="denied")[0][1] == "unknown"
