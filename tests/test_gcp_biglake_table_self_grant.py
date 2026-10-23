"""Table self-grant respects catalog and namespace inherited access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/c1"
NAMESPACE = CATALOG + "/namespaces/private"
TABLE = NAMESPACE + "/tables/t1"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-biglake-tables-setiampolicy-table-self-grant"


def snapshot(*, write=True, prior_parent=None, table_policy="collected",
             namespace_policy="collected", catalog_policy="collected", inventory="collected",
             resource=TABLE):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}
    writer = PROJECT + "/roles/tablePolicyWriter"
    reader = PROJECT + "/roles/tableReader"
    roles = [{"name": writer, "includedPermissions":
              ["biglake.tables.setIamPolicy"] if write else []},
             {"name": reader, "includedPermissions": ["biglake.tables.get"]}]
    def policy(name, status):
        bindings = ([{"role": reader, "members": [SOURCE]}]
                    if name == prior_parent else [])
        return {"name": name, "iamPolicy": {"bindings": bindings},
                "_coverage": {"iamPolicy": {"status": status}}}
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", roles),
                row("iam_policy", [{"name": PROJECT,
                    "bindings": [{"role": writer, "members": [SOURCE]}]}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("biglake_catalog", [policy(CATALOG, catalog_policy)]),
                row("biglake_namespace", [policy(NAMESPACE, namespace_policy)]),
                row("biglake_table", [policy(resource, table_policy)], inventory),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-biglake-table-self-grant:")}


def test_exact_table_policy_write_and_new_get_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-biglake-table-self-grant:" + TABLE: "conditional"}


def test_no_write_or_inherited_table_read_is_not_new_access():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(prior_parent=CATALOG))
    assert not targets(snapshot(prior_parent=NAMESPACE))


def test_wrong_table_and_incomplete_policies_are_not_confirmed():
    assert not targets(snapshot(resource=TABLE + "/credentials"))
    assert "conditional" not in targets(snapshot(table_policy="denied")).values()
    assert "conditional" not in targets(snapshot(namespace_policy="denied")).values()
    assert "conditional" not in targets(snapshot(catalog_policy="denied")).values()
    assert "conditional" not in targets(snapshot(inventory="denied")).values()
