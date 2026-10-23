"""Table policy self-grants require a new row permission on an exact ready table."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
TABLE = INSTANCE + "/tables/t1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigtable-tables-setiampolicy-table-self-grant"


def snapshot(*, write=True, prior=None, ready=True, details=True, denied=None, wrong_table=False):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}
    writer = PROJECT + "/roles/tablePolicyWriter"
    reader = PROJECT + "/roles/tableReader"
    def resource(name):
        return {"name": name,
                "iamPolicy": {"bindings": [{"role": reader, "members": [SOURCE]}] if name == prior else []},
                "_coverage": {"iamPolicy": {"status": "denied" if name == denied else "collected"}}}
    instance = resource(INSTANCE)
    instance["state"] = "READY"
    table = resource(TABLE + "/child" if wrong_table else TABLE)
    table["clusterStates"] = {"c1": {"replicationState": "READY" if ready else "INITIALIZING"}}
    table["_coverage"]["details"] = {"status": "collected" if details else "denied"}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [
                    {"name": writer, "includedPermissions":
                     ["bigtable.tables.setIamPolicy"] if write else []},
                    {"name": reader, "includedPermissions": ["bigtable.tables.readRows"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigtable_instance", [instance]),
                row("bigtable_table", [table]),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-table-self-grant:")}


def test_exact_new_table_read_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigtable-table-self-grant:" + TABLE: "conditional"}


def test_missing_write_or_prior_read_has_no_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=TABLE))
    assert not targets(snapshot(prior=INSTANCE))


def test_incomplete_or_not_ready_is_never_conditional():
    assert not targets(snapshot(wrong_table=True))
    for snap in (snapshot(ready=False), snapshot(details=False),
                 snapshot(denied=INSTANCE), snapshot(denied=TABLE)):
        assert "conditional" not in targets(snap).values()
