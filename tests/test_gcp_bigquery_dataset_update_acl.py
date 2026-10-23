"""Legacy dataset ACL mutation must respect the effective enforcement mode."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
DATASET = PROJECT + "/datasets/private"
TABLE = DATASET + "/tables/records"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigquery-datasets-update-dataset-acl-self-grant"


def snapshot(*, update=True, mode=False, prior_access=False, table_policy=True):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    role = PROJECT + "/roles/datasetUpdater"
    dataset = {"name": DATASET, "location": "US", "access": ([{"role": "READER", "userByEmail":
        "editor@example.com"}] if prior_access else []),
        "_coverage": {"datasetDetails": {"status": "collected"}}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": role, "includedPermissions":
                    ["bigquery.datasets.update"] if update else []}]),
                row("iam_policy", [{"name": PROJECT, "bindings":
                    [{"role": role, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigquery_dataset", [dataset]),
                row("bigquery_acl_mode", ([{"name": PROJECT + "/locations/US/bigqueryAclMode",
                    "location": "US", "enabled": mode}] if mode is not None else []),
                    "collected" if mode is not None else "empty"),
                row("bigquery_table", [{"name": TABLE, "type": "TABLE",
                    "iamPolicy": {"bindings": []}, "_coverage": {"iamPolicy":
                        {"status": "collected" if table_policy else "denied"}}}]),
            ]}


def reaches(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    return {grant.confidence for reach in Evaluator(GcpModel(snap), [entry]).run()
            if reach.source.id == SOURCE for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-bigquery-dataset-self-grant:update:")}


def test_disabled_mode_with_update_and_new_table_access_is_conditional():
    assert reaches(snapshot()) == {"conditional"}


def test_enabled_mode_does_not_accept_update_alone():
    assert not reaches(snapshot(mode=True))


def test_missing_mode_cannot_claim_working_acl_update():
    assert "conditional" not in reaches(snapshot(mode=None))


def test_no_update_or_no_new_access_or_incomplete_table_policy():
    assert not reaches(snapshot(update=False))
    assert not reaches(snapshot(prior_access=True))
    assert "conditional" not in reaches(snapshot(table_policy=False))
