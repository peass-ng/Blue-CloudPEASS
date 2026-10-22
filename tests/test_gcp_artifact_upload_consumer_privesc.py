"""Artifact upload must reach the exact mutable image and runtime identity."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
CONSUMER = "projects/p2"
TARGET = "runtime@p2.iam.gserviceaccount.com"
REPO = PROJECT + "/locations/us-central1/repositories/app"
TECHNIQUE = "gcp-artifactregistry-upload-artifacts"


def snapshot(*, image="us-central1-docker.pkg.dev/p1/app/web:latest",
             upload=True, repo_binding=False, immutable=False,
             mode="STANDARD_REPOSITORY", binary_authorization=None,
             repo_status="collected", kind="cloudrun_service"):
    def row(name, scope, records, status="collected"):
        return {"type": name, "scope": scope, "service": name, "status": status,
                "items": records, "error": None}
    role = PROJECT + "/roles/uploader"
    binding = {"role": role, "members": ["user:source@example.com"]}
    resource_type = {"cloudrun_service": "services", "cloudrun_job": "jobs",
                     "cloudrun_worker_pool": "workerPools"}[kind]
    workload = {"name": CONSUMER + "/locations/us-central1/" + resource_type + "/web",
                "template": {"serviceAccount": TARGET,
                             "containers": [{"image": image}]}}
    if kind == "cloudrun_job":
        workload["template"] = {"template": workload["template"]}
    if binary_authorization is not None:
        workload["binaryAuthorization"] = binary_authorization
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT, CONSUMER],
            "metadata": {}, "collections": [
                row("project", PROJECT, [{"projectId": "p1", "name": "projects/111"}]),
                row("project", CONSUMER, [{"projectId": "p2", "name": "projects/222"}]),
                row("iam_role", PROJECT, [{"name": role, "includedPermissions":
                    ["artifactregistry.repositories.uploadArtifacts"] if upload else []}]),
                row("iam_policy", PROJECT, [{"name": PROJECT,
                    "bindings": [] if repo_binding else [binding]}]),
                row("service_account", CONSUMER, [{"email": TARGET, "projectId": "p2",
                    "iamPolicy": {"bindings": []}}]),
                row("artifact_repository", PROJECT, [{"name": REPO, "format": "DOCKER",
                    "mode": mode, "dockerConfig": {"immutableTags": immutable},
                    "iamPolicy": {"bindings": [binding] if repo_binding else []},
                    "_coverage": {"iamPolicy": {"status": "collected"}}}], repo_status),
                row(kind, CONSUMER, [workload]),
                row("iam_deny_policy", PROJECT, [], "empty"),
            ]}


def outcome(snap, related=()):
    model = GcpModel(snap)
    if related:
        model.set_related(related)
    source = model.principals["user:source@example.com"]
    target = model.sas["serviceAccount:" + TARGET]
    direct = model.selector("gcp_artifact_upload_consumer_path", True,
                            {target.id: target}, source)
    entry, = [row for row in privesc.catalog()["entries"] if row["id"] == TECHNIQUE]
    reaches = [reach for reach in Evaluator(model, [entry]).run()
               if reach.source.id == source.id]
    return direct.get(target.id), reaches


def test_tagged_service_in_exact_repository_is_conditional():
    verdict, reaches = outcome(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_repository_scoped_upload_and_job_consumer_are_not_missed():
    verdict, reaches = outcome(snapshot(repo_binding=True, kind="cloudrun_job"))
    assert verdict[0] == "conditional"
    assert reaches


def test_worker_pool_image_and_runtime_account_are_joined():
    verdict, reaches = outcome(snapshot(kind="cloudrun_worker_pool"))
    assert verdict[0] == "conditional"
    assert reaches


def test_inline_cloud_build_step_uses_trigger_account():
    snap = snapshot()
    snap["collections"] = [row for row in snap["collections"]
                           if row["type"] != "cloudrun_service"]
    snap["collections"].append({"type": "cloudbuild_trigger", "scope": CONSUMER,
        "service": "cloudbuild_trigger", "status": "collected", "error": None,
        "items": [{"resourceName": CONSUMER + "/locations/us-central1/triggers/build",
                   "serviceAccount": CONSUMER + "/serviceAccounts/" + TARGET,
                   "build": {"steps": [{"name": "us-central1-docker.pkg.dev/p1/app/builder:latest"}]}}]})
    verdict, reaches = outcome(snap)
    assert verdict[0] == "conditional"
    assert reaches
    snap["collections"][-1]["items"][0]["build"]["steps"][0]["name"] = \
        "us-central1-docker.pkg.dev/p1/other/builder:latest"
    assert outcome(snap)[1] == []
    snap["collections"][-1]["items"][0]["build"]["steps"][0]["name"] = \
        "us-central1-docker.pkg.dev/p1/app/builder:latest"
    snap["collections"][-1]["items"][0]["disabled"] = True
    assert outcome(snap)[1] == []


def test_joined_gke_pod_requires_workload_identity_binding_and_enabled_node_pool():
    snap = snapshot()
    snap["collections"] = [row for row in snap["collections"]
                           if row["type"] != "cloudrun_service"]
    cluster = CONSUMER + "/locations/us-central1/clusters/cluster"
    snap["collections"].append({"type": "gke_cluster", "scope": CONSUMER,
        "service": "gke_cluster", "status": "collected", "error": None,
        "items": [{"name": "cluster", "location": "us-central1",
                   "workloadIdentityConfig": {"workloadPool": "p2.svc.id.goog"},
                   "nodePools": [{"name": "workers", "config": {
                       "workloadMetadataConfig": {"mode": "GKE_METADATA"}}}]}]})
    sa_item = snap["collections"][4]["items"][0]
    sa_item["iamPolicy"]["bindings"] = [{"role": "roles/iam.workloadIdentityUser",
        "members": ["serviceAccount:p2.svc.id.goog[team/app]"]}]
    def row(kind, items):
        return {"type": kind, "scope": cluster, "service": kind,
                "status": "collected", "items": items, "error": None}
    k8s = {"schema_version": 1, "provider": "k8s", "metadata": {"cluster_id": cluster},
        "collections": [
            row("serviceaccount", [{"metadata": {"namespace": "team", "name": "app",
                "annotations": {"iam.gke.io/gcp-service-account": TARGET}}}]),
            row("node", [{"metadata": {"name": "n1", "labels": {
                "cloud.google.com/gke-nodepool": "workers"}}}]),
            row("pod", [{"metadata": {"namespace": "team", "name": "web"},
                "status": {"phase": "Running"}, "spec": {"serviceAccountName": "app",
                    "nodeName": "n1", "containers": [{"name": "web",
                        "image": "us-central1-docker.pkg.dev/p1/app/web:latest",
                        "imagePullPolicy": "Always"}]}}]),
        ]}
    verdict, reaches = outcome(snap, [k8s])
    assert verdict[0] == "conditional"
    assert reaches
    k8s["collections"][-1]["items"][0]["spec"]["containers"][0]["imagePullPolicy"] = "IfNotPresent"
    assert outcome(snap, [k8s])[1]
    k8s["collections"][-1]["items"][0]["spec"]["containers"][0]["imagePullPolicy"] = "Never"
    assert outcome(snap, [k8s])[1] == []
    k8s["collections"][-1]["items"][0]["spec"]["containers"][0]["imagePullPolicy"] = "Always"
    k8s["collections"][-1]["items"][0]["spec"]["automountServiceAccountToken"] = False
    assert outcome(snap, [k8s])[1] == []
    k8s["collections"][-1]["items"][0]["spec"]["volumes"] = [{"name": "token",
        "projected": {"sources": [{"serviceAccountToken": {"path": "token"}}]}}]
    k8s["collections"][-1]["items"][0]["spec"]["containers"][0]["volumeMounts"] = [
        {"name": "token", "mountPath": "/var/run/secrets/tokens"}]
    assert outcome(snap, [k8s])[1]
    k8s["collections"][-1]["items"][0]["spec"].pop("automountServiceAccountToken")
    snap["collections"][-1]["items"][0]["binaryAuthorization"] = {"enabled": True}
    assert outcome(snap, [k8s])[0][0] == "unknown"
    snap["collections"][-1]["items"][0]["binaryAuthorization"] = {"enabled": False}
    assert outcome(snap, [k8s])[1]
    sa_item["iamPolicy"]["bindings"] = []
    assert outcome(snap, [k8s])[1] == []
    sa_item["iamPolicy"]["bindings"] = [{"role": "roles/iam.workloadIdentityUser",
        "members": ["serviceAccount:p2.svc.id.goog[team/app]"]}]
    snap["collections"][-1]["items"][0]["nodePools"][0]["config"]["workloadMetadataConfig"]["mode"] = "GCE_METADATA"
    assert outcome(snap, [k8s])[1] == []
    snap["collections"][-1]["items"][0]["autopilot"] = {"enabled": True}
    k8s["collections"] = [row for row in k8s["collections"] if row["type"] != "node"]
    assert outcome(snap, [k8s])[1]


def test_missing_upload_or_unrelated_repository_has_no_edge():
    assert outcome(snapshot(upload=False))[1] == []
    assert outcome(snapshot(image="us-central1-docker.pkg.dev/p1/other/web:latest"))[1] == []


def test_digest_immutable_and_remote_repository_have_no_edge():
    assert outcome(snapshot(image="us-central1-docker.pkg.dev/p1/app/web@sha256:" + "a" * 64))[1] == []
    assert outcome(snapshot(image="us-central1-docker.pkg.dev/p1/app/web:"))[1] == []
    assert outcome(snapshot(immutable=True))[1] == []
    assert outcome(snapshot(mode="REMOTE_REPOSITORY"))[1] == []


def test_binary_authorization_and_unreadable_repository_stay_unresolved():
    assert outcome(snapshot(binary_authorization={"useDefault": True}))[0][0] == "unknown"
    assert outcome(snapshot(binary_authorization={"useDefault": False}))[1]
    assert outcome(snapshot(repo_status="denied"))[0][0] == "unknown"


def test_legacy_gcr_host_requires_redirected_registry():
    snap = snapshot(image="gcr.io/p1/web:latest")
    snap["collections"][5]["items"][0]["name"] = PROJECT + "/locations/us/repositories/gcr.io"
    assert outcome(snap)[0][0] == "unknown"
    snap["collections"].append({"type": "gcp_v4_workload_facts", "scope": PROJECT,
        "service": "gcp_v4_workload_facts", "status": "collected", "error": None,
        "items": [{"name": PROJECT, "scope": PROJECT, "artifact_registry":
            {"settings_status": "collected", "redirection_state":
             "REDIRECTION_FROM_GCR_IO_ENABLED"}}]})
    assert outcome(snap)[1]
    snap["collections"][-1]["items"].append(snap["collections"][-1]["items"][0].copy())
    assert outcome(snap)[0][0] == "unknown"
