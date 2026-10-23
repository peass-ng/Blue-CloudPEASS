"""The code object, writer grants, and worker identity must all match."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
SOURCE = "user:writer@example.com"
WORKER = "worker@p1.iam.gserviceaccount.com"
TECHNIQUE = "gcp-dataflow-udf-template-bucket-write"


def snapshot(*, checksum=None, hold=False, retention=None, metadata_status="collected",
             source_create=True, source_delete=True, worker_read=True, job_status="collected"):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}

    source_permissions = []
    if source_create:
        source_permissions.append("storage.objects.create")
    if source_delete:
        source_permissions.append("storage.objects.delete")
    bindings = [{"role": PROJECT + "/roles/source", "members": [SOURCE]}]
    if worker_read:
        bindings.append({"role": PROJECT + "/roles/reader", "members": ["serviceAccount:" + WORKER]})
    artifact = {"kind": "worker_package", "bucket": "code-bucket", "object": "workflow.py",
                "sha256": checksum, "metadataStatus": metadata_status,
                "metadata": {"generation": "123", "temporaryHold": hold,
                             "eventBasedHold": False, "retentionExpirationTime": retention,
                             "retainUntilTime": None}}
    job = {"name": PROJECT + "/locations/us-central1/jobs/job_1", "projectId": "p1",
           "location": "us-central1", "id": "job_1", "currentState": "JOB_STATE_RUNNING",
           "workerServiceAccountEmail": WORKER, "codeObjects": [artifact],
           "_representation": "privesc_code_references"}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT], "metadata": {},
            "collections": [
                row("project", [{"projectId": "p1", "name": "projects/123"}]),
                row("iam_role", [
                    {"name": PROJECT + "/roles/source", "includedPermissions": source_permissions},
                    {"name": PROJECT + "/roles/reader", "includedPermissions": ["storage.objects.get"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": bindings}]),
                row("service_account", [{"email": WORKER, "projectId": "p1", "iamPolicy": {"bindings": []}}]),
                row("bucket", [{"name": "code-bucket", "_representation": "full",
                                "iamPolicy": {"bindings": []},
                                "_coverage": {"iamPolicy": {"status": "collected"}}}]),
                row("dataflow_privesc_job", [job], job_status),
                row("dataflow_privesc_pipeline", [], "empty"),
                row("iam_deny_policy", [], "empty"),
            ]}


def evaluate(snap):
    model = GcpModel(snap)
    source = model.principals[SOURCE]
    target = model.sas["serviceAccount:" + WORKER]
    verdict = model.selector("gcp_dataflow_artifact_overwrite_path", True,
                             {target.id: target}, source).get(target.id)
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = [reach for reach in Evaluator(model, [entry]).run() if reach.source.id == SOURCE]
    return verdict, reaches


def test_active_unpinned_package_with_exact_rights_is_conditional():
    verdict, reaches = evaluate(snapshot())
    assert verdict[0] == "conditional"
    assert reaches


def test_checksum_and_hold_block_named_path():
    assert evaluate(snapshot(checksum="a" * 64))[0][0] == "unknown"
    assert evaluate(snapshot(hold=True))[0] is None


def test_active_retention_blocks_named_path():
    assert evaluate(snapshot(retention="2099-01-01T00:00:00Z"))[0] is None


def test_missing_metadata_stays_unresolved():
    verdict, reaches = evaluate(snapshot(metadata_status="unavailable"))
    assert verdict[0] == "unknown"
    assert reaches


def test_missing_writer_or_worker_grant_has_no_named_positive():
    assert evaluate(snapshot(source_create=False))[1] == []
    assert evaluate(snapshot(source_delete=False))[1] == []
    assert evaluate(snapshot(worker_read=False))[0][0] == "unknown"


def test_denied_job_inventory_stays_unresolved():
    verdict, reaches = evaluate(snapshot(job_status="denied"))
    assert verdict[0] == "unknown"
    assert reaches


def test_active_batch_template_without_running_job_stays_visible_as_unresolved():
    snap = snapshot()
    for collection in snap["collections"]:
        if collection["type"] == "dataflow_privesc_job":
            collection["items"] = []
            collection["status"] = "empty"
        if collection["type"] == "dataflow_privesc_pipeline":
            collection["items"] = [{
                "name": PROJECT + "/locations/us-central1/pipelines/daily",
                "projectId": "p1", "jobProjectId": "p1",
                "workerServiceAccountEmail": WORKER,
                "templateObject": {"kind": "standard_template", "bucket": "code-bucket",
                                   "object": "workflow.py"},
                "_representation": "batch_template_reference"}]
            collection["status"] = "collected"
    verdict, reaches = evaluate(snap)
    assert verdict[0] == "unknown"
    assert reaches


def test_denied_pipeline_inventory_keeps_possible_route_unresolved():
    snap = snapshot()
    for collection in snap["collections"]:
        if collection["type"] == "dataflow_privesc_job":
            collection["items"] = []
            collection["status"] = "empty"
        if collection["type"] == "dataflow_privesc_pipeline":
            collection["status"] = "denied"
    verdict, reaches = evaluate(snap)
    assert verdict[0] == "unknown"
    assert reaches


def test_create_and_delete_on_different_buckets_do_not_join():
    snap = snapshot()
    for collection in snap["collections"]:
        if collection["type"] == "iam_policy":
            collection["items"][0]["bindings"] = [
                binding for binding in collection["items"][0]["bindings"]
                if SOURCE not in binding["members"]]
        if collection["type"] == "iam_role":
            collection["items"][0]["includedPermissions"] = ["storage.objects.create"]
            collection["items"].append({
                "name": PROJECT + "/roles/delete", "includedPermissions": ["storage.objects.delete"]})
        if collection["type"] == "bucket":
            collection["items"][0]["iamPolicy"]["bindings"] = [
                {"role": PROJECT + "/roles/source", "members": [SOURCE]}]
            collection["items"].append({
                "name": "other-bucket", "_representation": "full",
                "iamPolicy": {"bindings": [
                    {"role": PROJECT + "/roles/delete", "members": [SOURCE]}]},
                "_coverage": {"iamPolicy": {"status": "collected"}}})
    verdict, reaches = evaluate(snap)
    assert verdict[0] == "unknown"
    assert all(reach.targets[target.id].confidence == "unknown"
               for reach in reaches for target in [GcpModel(snap).sas["serviceAccount:" + WORKER]]
               if target.id in reach.targets)
