"""Direct Dataflow Flex launches require usable worker and staging paths."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SOURCE = "user:source@example.com"
WORKER = "worker@p1.iam.gserviceaccount.com"
DATAFLOW_AGENT = "serviceAccount:service-123@dataflow-service-producer-prod.iam.gserviceaccount.com"
COMPUTE_AGENT = "serviceAccount:service-123@compute-system.iam.gserviceaccount.com"
TECHNIQUE = "gcp-dataflow-jobs-create-actas"


def snapshot(*, api="ENABLED", agent=True, bucket=True, worker_storage=True,
             source_project_read=True, source_actas=True):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}

    source_permissions = ["dataflow.jobs.create", "storage.buckets.get"]
    if source_project_read:
        source_permissions.append("resourcemanager.projects.get")
    if source_actas:
        source_permissions.append("iam.serviceAccounts.actAs")
    bindings = [
        {"role": PROJECT + "/roles/source", "members": [SOURCE]},
        {"role": PROJECT + "/roles/worker", "members": ["serviceAccount:" + WORKER]},
    ]
    if agent:
        bindings.extend([
            {"role": "roles/iam.serviceAccountUser", "members": [DATAFLOW_AGENT, COMPUTE_AGENT]},
            {"role": "roles/iam.serviceAccountTokenCreator", "members": [DATAFLOW_AGENT, COMPUTE_AGENT]},
            {"role": PROJECT + "/roles/agent", "members": [DATAFLOW_AGENT]},
        ])
    bucket_bindings = ([{"role": PROJECT + "/roles/storage", "members": ["serviceAccount:" + WORKER]}]
                       if worker_storage else [])
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [
                row("project", [{"projectId": "p1", "name": "projects/123"}]),
                row("iam_role", [
                    {"name": PROJECT + "/roles/source", "includedPermissions": source_permissions},
                    {"name": PROJECT + "/roles/worker", "includedPermissions": ["dataflow.workItems.lease"]},
                    {"name": PROJECT + "/roles/storage", "includedPermissions":
                     ["storage.objects.get", "storage.objects.create"]},
                    {"name": PROJECT + "/roles/agent", "includedPermissions": ["compute.instances.create"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": bindings}]),
                row("service_account", [{"email": WORKER, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
                row("service_usage", [{"name": PROJECT + "/services/dataflow.googleapis.com", "state": api}]),
                row("bucket", ([{"name": "stage-p1", "_representation": "full",
                                 "iamPolicy": {"bindings": bucket_bindings},
                                 "_coverage": {"iamPolicy": {"status": "collected"}}}]
                               if bucket else [])),
                row("iam_deny_policy", [], "empty"),
            ]}


def evaluate(snap):
    model = GcpModel(snap)
    source = model.principals[SOURCE]
    worker = model.sas["serviceAccount:" + WORKER]
    verdict = model.selector("gcp_dataflow_flex_launch_path", True, {worker.id: worker}, source).get(worker.id)
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = [reach for reach in Evaluator(model, [entry]).run() if reach.source.id == SOURCE]
    return verdict, reaches


def test_complete_direct_launch_path_is_conditional():
    verdict, reaches = evaluate(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_disabled_api_and_no_actas_do_not_reach_worker():
    assert evaluate(snapshot(api="DISABLED")) == (None, [])
    assert evaluate(snapshot(source_actas=False))[1] == []


def test_missing_agent_bucket_worker_storage_or_project_read_is_unresolved():
    for change in ({"agent": False}, {"bucket": False},
                   {"worker_storage": False}, {"source_project_read": False}):
        verdict, reaches = evaluate(snapshot(**change))
        assert verdict[0] == "unknown"
        assert reaches


def test_denied_api_inventory_is_unresolved():
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "service_usage")["status"] = "denied"
    assert evaluate(snap)[0][0] == "unknown"
