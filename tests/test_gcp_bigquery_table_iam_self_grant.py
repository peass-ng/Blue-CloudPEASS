"""Table-level IAM self-grants require a real new table read permission."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
DATASET = PROJECT + "/datasets/private"
TABLE = DATASET + "/tables/records"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigquery-tables-setiampolicy-table-self-grant"


def snapshot(*, write=True, table_bindings=None, dataset_acl=None, table_policy="collected",
             dataset_status="collected", table_status="collected", table_type="TABLE",
             org_policy=None):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    writer = PROJECT + "/roles/tablePolicyWriter"
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": writer, "includedPermissions":
                    ["bigquery.tables.setIamPolicy"] if write else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings":
                    [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", org_policy or [], "collected" if org_policy else "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigquery_dataset", [{"name": DATASET,
                    "access": [] if dataset_acl is None else dataset_acl,
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
            if target.startswith("gcp_verified_authority:possible-bigquery-table-self-grant:")}


def test_exact_table_policy_write_and_missing_read_yield_conditional_path():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigquery-table-self-grant:" + TABLE: "conditional"}
    no_bindings = snapshot()
    next(row for row in no_bindings["collections"] if row["type"] == "bigquery_table")[
        "items"][0]["iamPolicy"] = {}
    assert "conditional" in targets(no_bindings).values()


def test_missing_write_or_existing_table_or_dataset_read_is_not_a_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(table_bindings=[{
        "role": "roles/bigquery.dataViewer", "members": [SOURCE]}]))
    assert not targets(snapshot(dataset_acl=[{
        "role": "READER", "userByEmail": "editor@example.com"}]))


def test_incomplete_policies_or_non_table_never_claim_a_definite_gain():
    assert "conditional" not in targets(snapshot(table_policy="denied")).values()
    assert "conditional" not in targets(snapshot(dataset_status="denied")).values()
    assert "conditional" not in targets(snapshot(table_status="denied")).values()
    assert "conditional" not in targets(snapshot(table_bindings=[{
        "role": "roles/bigquery.dataViewer", "members": "allUsers"}])).values()
    assert not targets(snapshot(table_type="VIEW"))
    assert "conditional" not in targets(snapshot(dataset_acl=[{
        "role": "READER", "specialGroup": "unknownGroup"}])).values()


def test_member_restriction_keeps_prospective_policy_grant_unresolved():
    assert "conditional" not in targets(snapshot(org_policy=[{
        "constraint": "iam.allowedPolicyMemberDomains",
        "name": PROJECT + "/policies/allowedPolicyMemberDomains"}])).values()
