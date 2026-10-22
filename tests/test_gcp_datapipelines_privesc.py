"""A scheduled Data Pipeline needs more than creator and worker actAs grants."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SOURCE = "user:creator@example.com"
WORKER = "worker@p1.iam.gserviceaccount.com"
SCHEDULER = "scheduler@p1.iam.gserviceaccount.com"
NUMBER = "123"
PIPELINE_AGENT = f"serviceAccount:service-{NUMBER}@gcp-sa-datapipelines.iam.gserviceaccount.com"
DATAFLOW_AGENT = f"serviceAccount:service-{NUMBER}@dataflow-service-producer-prod.iam.gserviceaccount.com"
TECHNIQUE = "gcp-dataflow-datapipelines-create-actas"


def snapshot(*, api_state="ENABLED", app_location="us-central", pipeline_agent=True,
             scheduler_actas=True, worker_role=True, source_actas=True):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}

    source_permissions = ["datapipelines.pipelines.create"]
    if source_actas:
        source_permissions.append("iam.serviceAccounts.actAs")
    project_bindings = [
        {"role": PROJECT + "/roles/source", "members": [SOURCE]},
        {"role": "roles/iam.serviceAccountUser", "members": [DATAFLOW_AGENT]},
        {"role": "roles/iam.serviceAccountTokenCreator", "members": [DATAFLOW_AGENT]},
    ]
    if worker_role:
        project_bindings.append({"role": PROJECT + "/roles/worker", "members": ["serviceAccount:" + WORKER]})
    if pipeline_agent:
        project_bindings.append({"role": "roles/datapipelines.serviceAgent", "members": [PIPELINE_AGENT]})
    worker_bindings = ([{"role": "roles/iam.serviceAccountUser", "members": ["serviceAccount:" + SCHEDULER]}]
                       if scheduler_actas else [])
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [
                row("project", [{"projectId": "p1", "name": "projects/" + NUMBER}]),
                row("iam_role", [
                    {"name": PROJECT + "/roles/source", "includedPermissions": source_permissions},
                    {"name": PROJECT + "/roles/worker", "includedPermissions": ["dataflow.workItems.lease"]},
                    {"name": "roles/datapipelines.serviceAgent",
                     "includedPermissions": ["dataflow.jobs.create", "cloudscheduler.jobs.create"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": project_bindings}]),
                row("service_account", [
                    {"email": WORKER, "projectId": "p1", "iamPolicy": {"bindings": worker_bindings}},
                    {"email": SCHEDULER, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
                row("service_usage", [{"name": PROJECT + "/services/" + api,
                                       "state": api_state if api == "datapipelines.googleapis.com" else "ENABLED"}
                                      for api in ("datapipelines.googleapis.com", "dataflow.googleapis.com",
                                                  "cloudscheduler.googleapis.com")]),
                row("app_engine_application", [{"id": "p1", "locationId": app_location}]),
                row("iam_deny_policy", [], "empty"),
            ]}


def evaluate(snap):
    model = GcpModel(snap)
    worker = model.sas["serviceAccount:" + WORKER]
    source = model.principals[SOURCE]
    direct = model.selector("gcp_datapipelines_scheduled_template_path", True, {worker.id: worker}, source)
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = [reach for reach in Evaluator(model, [entry]).run() if reach.source.id == SOURCE]
    return direct.get(worker.id), reaches


def test_complete_identity_and_service_path_is_conditional():
    verdict, reaches = evaluate(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_disabled_api_and_missing_creator_actas_do_not_reach_worker():
    assert evaluate(snapshot(api_state="DISABLED")) == (None, [])
    assert evaluate(snapshot(source_actas=False))[1] == []


def test_missing_agent_scheduler_and_worker_grants_stay_unresolved():
    for change in ({"pipeline_agent": False}, {"scheduler_actas": False},
                   {"worker_role": False}):
        verdict, reaches = evaluate(snapshot(**change))
        assert verdict[0] == "unknown"
        assert reaches


def test_missing_app_engine_region_stays_unresolved():
    verdict, reaches = evaluate(snapshot(app_location=""))
    assert verdict[0] == "unknown"
    assert reaches


def test_missing_api_inventory_and_dataflow_agent_stay_unresolved():
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "service_usage")["status"] = "denied"
    assert evaluate(snap)[0][0] == "unknown"

    snap = snapshot()
    policy = next(row for row in snap["collections"] if row["type"] == "iam_policy")
    policy["items"][0]["bindings"] = [
        binding for binding in policy["items"][0]["bindings"]
        if DATAFLOW_AGENT not in binding["members"]]
    assert evaluate(snap)[0][0] == "unknown"
