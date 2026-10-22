"""Dataset ACL self-grant needs a concrete table with previously absent access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
DATASET = PROJECT + "/datasets/private"
TABLE = DATASET + "/tables/records"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigquery-datasets-setiampolicy-dataset-iam-self-grant"


def snapshot(*, write=True, acl=None, table_bindings=None, dataset_status="collected",
             table_policy="collected", table_status="collected", table_type="TABLE"):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    writer = PROJECT + "/roles/datasetPolicyWriter"
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": writer, "includedPermissions":
                    ["bigquery.datasets.setIamPolicy"] if write else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings":
                    [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigquery_dataset", [{"name": DATASET,
                    "access": [] if acl is None else acl,
                    "_coverage": {"datasetDetails": {"status": dataset_status}}}]),
                row("bigquery_table", [{"name": TABLE, "type": table_type,
                    "iamPolicy": {"bindings": [] if table_bindings is None else table_bindings},
                    "_coverage": {"iamPolicy": {"status": table_policy}}}], table_status),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-bigquery-dataset-self-grant:")}


def test_exact_dataset_write_and_unreadable_table_yields_conditional_path():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigquery-dataset-self-grant:" + TABLE: "conditional"}


def test_no_write_or_prior_dataset_acl_access_yields_no_new_path():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(acl=[{"role": "READER", "userByEmail": "editor@example.com"}]))


def test_table_iam_grant_and_incomplete_evidence_do_not_claim_new_access():
    snap = snapshot(table_bindings=[{"role": "roles/bigquery.dataViewer", "members": [SOURCE]}])
    assert not targets(snap)
    assert "conditional" not in targets(snapshot(dataset_status="denied")).values()
    assert "conditional" not in targets(snapshot(table_policy="denied")).values()
    assert "conditional" not in targets(snapshot(table_status="denied")).values()
    assert not targets(snapshot(table_type="VIEW"))


def test_unrecognized_dataset_acl_remains_unresolved():
    assert "conditional" not in targets(snapshot(acl=[{
        "role": "READER", "specialGroup": "unknownGroup"}])).values()


def test_default_project_reader_acl_does_not_hide_custom_writer_path():
    assert "conditional" in targets(snapshot(acl=[
        {"role": "READER", "specialGroup": "projectReaders"},
        {"role": "WRITER", "specialGroup": "projectWriters"},
        {"role": "OWNER", "specialGroup": "projectOwners"},
    ])).values()
