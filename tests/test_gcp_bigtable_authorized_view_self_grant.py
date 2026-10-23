"""Authorized-view self-grants need exact view and inherited policy evidence."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
TABLE = INSTANCE + "/tables/t1"
VIEW = TABLE + "/authorizedViews/v1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigtable-authorizedviews-setiampolicy-authorized-view-self-grant"


def snapshot(*, write=True, prior=None, denied=None, wrong_view=False):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}

    writer = PROJECT + "/roles/viewPolicyWriter"
    reader = PROJECT + "/roles/viewReader"
    base_reader = PROJECT + "/roles/baseReader"

    def resource(name):
        role = base_reader if name == prior and prior == TABLE else reader
        bindings = [{"role": role, "members": [SOURCE]}] if name == prior else []
        status = "denied" if name == denied else "collected"
        return {"name": name, "iamPolicy": {"bindings": bindings},
                "_coverage": {"iamPolicy": {"status": status}}}

    view = VIEW + "/child" if wrong_view else VIEW
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [
                    {"name": writer, "includedPermissions":
                     ["bigtable.authorizedViews.setIamPolicy"] if write else []},
                    {"name": reader, "includedPermissions":
                     ["bigtable.authorizedViews.readRows"]},
                    {"name": base_reader, "includedPermissions":
                     ["bigtable.tables.readRows"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigtable_instance", [resource(INSTANCE)]),
                row("bigtable_table", [resource(TABLE)]),
                row("bigtable_authorized_view", [resource(view)]),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-authorized-view-self-grant:")}


def test_exact_new_view_read_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigtable-authorized-view-self-grant:" + VIEW: "conditional"}


def test_no_policy_write_or_prior_view_or_base_table_read_is_not_new_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior=VIEW))
    assert not targets(snapshot(prior=TABLE))
    assert not targets(snapshot(prior=INSTANCE))


def test_bad_view_and_missing_parent_policy_never_claim_conditional():
    assert not targets(snapshot(wrong_view=True))
    for resource in (INSTANCE, TABLE, VIEW):
        assert "conditional" not in targets(snapshot(denied=resource)).values()
