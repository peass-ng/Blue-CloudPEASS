"""Namespace self-grant joins exact namespace and inherited catalog IAM."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/c1"
NAMESPACE = CATALOG + "/namespaces/private"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-biglake-namespaces-setiampolicy-namespace-self-grant"


def snapshot(*, write=True, inherited_get=False, namespace_policy="collected",
             catalog_policy="collected", inventory="collected", resource=NAMESPACE):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}
    writer = PROJECT + "/roles/namespacePolicyWriter"
    roles = [{"name": writer, "includedPermissions":
              ["biglake.namespaces.setIamPolicy"] if write else []}]
    bindings = [{"role": writer, "members": [SOURCE]}]
    if inherited_get:
        roles.append({"name": PROJECT + "/roles/namespaceReader",
                      "includedPermissions": ["biglake.namespaces.get"]})
        bindings.append({"role": roles[-1]["name"], "members": [SOURCE]})
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", roles),
                row("iam_policy", [{"name": PROJECT, "bindings": bindings}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("biglake_catalog", [{"name": CATALOG, "iamPolicy": {"bindings": []},
                    "_coverage": {"iamPolicy": {"status": catalog_policy}}}]),
                row("biglake_namespace", [{"name": resource, "iamPolicy": {"bindings": []},
                    "_coverage": {"iamPolicy": {"status": namespace_policy}}}], inventory),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-biglake-namespace-self-grant:")}


def test_exact_namespace_write_with_new_access_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-biglake-namespace-self-grant:" + NAMESPACE: "conditional"}


def test_missing_write_or_inherited_get_is_not_new_access():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(inherited_get=True))


def test_wrong_namespace_and_incomplete_policies_are_not_confirmed():
    assert not targets(snapshot(resource=NAMESPACE + "/tables/t1"))
    assert "conditional" not in targets(snapshot(namespace_policy="denied")).values()
    assert "conditional" not in targets(snapshot(catalog_policy="denied")).values()
    assert "conditional" not in targets(snapshot(inventory="denied")).values()
