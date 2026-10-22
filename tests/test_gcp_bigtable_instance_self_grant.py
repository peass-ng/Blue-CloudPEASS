"""An instance IAM write grants a new read only on an exact child table."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
INSTANCE = PROJECT + "/instances/i1"
TABLE = INSTANCE + "/tables/private"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-bigtable-instances-setiampolicy-instance-self-grant"
ADMIN_TECHNIQUE = "gcp-bigtable-instances-setiampolicy-instance-admin-self-grant"


def snapshot(*, write=True, prior=None, ready=True, instance_policy="collected",
             table_policy="collected", table_inventory="collected"):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind,
                "status": status, "items": records, "error": None}
    writer = PROJECT + "/roles/instancePolicyWriter"
    reader = PROJECT + "/roles/tableReader"

    def bindings(name):
        return ([{"role": reader, "members": [SOURCE]}] if prior == name else [])

    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [
                    {"name": writer, "includedPermissions":
                     ["bigtable.instances.setIamPolicy"] if write else []},
                    {"name": reader, "includedPermissions": ["bigtable.tables.readRows"]}]),
                row("iam_policy", [{"name": PROJECT, "bindings": [
                    {"role": writer, "members": [SOURCE]}, *bindings(PROJECT)]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("bigtable_instance", [{"name": INSTANCE,
                    "state": "READY" if ready else "CREATING",
                    "iamPolicy": {"bindings": bindings(INSTANCE)},
                    "_coverage": {"iamPolicy": {"status": instance_policy}}}]),
                row("bigtable_table", [{"name": TABLE,
                    "iamPolicy": {"bindings": bindings(TABLE)},
                    "_coverage": {"iamPolicy": {"status": table_policy}}}],
                    table_inventory),
            ]}


def targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-instance-self-grant:")}


def test_new_exact_table_read_from_instance_policy_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-bigtable-instance-self-grant:" + TABLE: "conditional"}


def test_no_write_or_existing_project_instance_or_table_read_is_not_new_gain():
    assert not targets(snapshot(write=False))
    for parent in (PROJECT, INSTANCE, TABLE):
        assert not targets(snapshot(prior=parent))


def test_unready_instance_and_incomplete_policies_cannot_make_confirmed_path():
    for kwargs in ({"ready": False}, {"instance_policy": "denied"},
                   {"table_policy": "denied"}, {"table_inventory": "denied"}):
        assert "conditional" not in targets(snapshot(**kwargs)).values()


def test_uncertain_existing_read_is_retained_as_unknown():
    snap = snapshot()
    policy = next(row for row in snap["collections"] if row["type"] == "bigtable_table")
    policy["items"][0]["iamPolicy"]["bindings"] = [{
        "role": PROJECT + "/roles/tableReader", "members": [SOURCE],
        "condition": {"expression": "resource.matchTag('123/key', 'value')"}}]
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    assert any(reach.source.id == SOURCE and any(
        target.startswith("unresolved:gcp_verified_authority:")
        for target in reach.targets) for reach in reaches)


def test_missing_table_inventory_keeps_an_unresolved_scope():
    snap = snapshot(table_inventory="denied")
    table_row = next(row for row in snap["collections"] if row["type"] == "bigtable_table")
    table_row["items"] = []
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    assert any(reach.source.id == SOURCE and any(
        target.startswith("unknown:gcp_verified_authority:")
        for target in reach.targets) for reach in reaches)


def admin_targets(snap):
    entry = next(e for e in privesc.catalog()["entries"] if e["id"] == ADMIN_TECHNIQUE)
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {tid: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for tid, grant in reach.targets.items()
            if tid.startswith("gcp_verified_authority:possible-bigtable-instance-admin-self-grant:")}


def test_instance_admin_gain_exists_even_without_tables():
    snap = snapshot()
    next(row for row in snap["collections"] if row["type"] == "bigtable_table")["items"] = []
    assert admin_targets(snap) == {
        "gcp_verified_authority:possible-bigtable-instance-admin-self-grant:" + INSTANCE: "conditional"}


def test_existing_instance_update_or_missing_policy_cannot_claim_new_admin_gain():
    snap = snapshot()
    roles = next(row for row in snap["collections"] if row["type"] == "iam_role")
    roles["items"].append({"name": PROJECT + "/roles/instanceUpdater",
                           "includedPermissions": ["bigtable.instances.update"]})
    instance = next(row for row in snap["collections"] if row["type"] == "bigtable_instance")
    instance["items"][0]["iamPolicy"]["bindings"] = [{
        "role": PROJECT + "/roles/instanceUpdater", "members": [SOURCE]}]
    assert not admin_targets(snap)
    assert "conditional" not in admin_targets(snapshot(instance_policy="denied")).values()
