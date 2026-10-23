"""Materialized-view self-grants require an exact, ready view and prior-access proof."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
VIEW = INSTANCE + "/materializedViews/v1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigtable-materializedviews-setiampolicy-materialized-view-self-grant"


def snapshot(*, write=True, prior=False, ready=True, denied=None, details=True, wrong_view=False):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}

    writer = PROJECT + "/roles/viewPolicyWriter"
    reader = PROJECT + "/roles/viewReader"

    def resource(name):
        bindings = [{"role": reader, "members": [SOURCE]}] if prior and name == VIEW else []
        status = "denied" if name == denied else "collected"
        return {"name": name, "iamPolicy": {"bindings": bindings},
                "_coverage": {"iamPolicy": {"status": status}}}

    view = resource(VIEW + "/child" if wrong_view else VIEW)
    view.update({"query": "SELECT COUNT(*) FROM t1",
                 "clusterStates": {"c1": {"replicationState": "READY" if ready else "INITIALIZING"}}})
    view["_coverage"]["details"] = {"status": "collected" if details else "denied"}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [
                    {"name": writer, "includedPermissions":
                     ["bigtable.materializedViews.setIamPolicy"] if write else []},
                    {"name": reader, "includedPermissions":
                     ["bigtable.materializedViews.readRows"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigtable_instance", [resource(INSTANCE)]),
                row("bigtable_materialized_view", [view]),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-materialized-view-self-grant:")}


def test_exact_ready_view_has_conditional_gain():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigtable-materialized-view-self-grant:" + VIEW: "conditional"}


def test_no_policy_write_or_prior_read_has_no_new_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=True))


def test_wrong_view_and_incomplete_state_are_never_conditional():
    assert not targets(snapshot(wrong_view=True))
    for snap in (snapshot(ready=False), snapshot(denied=INSTANCE),
                 snapshot(denied=VIEW), snapshot(details=False)):
        assert "conditional" not in targets(snap).values()
