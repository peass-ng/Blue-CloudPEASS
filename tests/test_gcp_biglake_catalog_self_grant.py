"""BigLake catalog self-grant needs a real catalog and new effective access."""

from peaso import privesc
from peaso.privesc.effective_permissions.gcp import GcpModel
from peaso.privesc.evaluator import Evaluator


PROJECT = "projects/p1"
CATALOG = PROJECT + "/catalogs/private"
SOURCE = "user:editor@example.com"
TECHNIQUE = "gcp-biglake-catalogs-setiampolicy-catalog-self-grant"


def snapshot(*, write=True, already=False, policy_status="collected", catalog=CATALOG,
             role_scope=PROJECT, inventory_status="collected"):
    def row(kind, records, status="collected"):
        return {"type": kind, "scope": PROJECT, "service": kind, "status": status,
                "items": records, "error": None}
    role = PROJECT + "/roles/catalogPolicyWriter"
    permissions = (["biglake.catalogs.setIamPolicy"] if write else []) + \
                  (["biglake.catalogs.get"] if already else [])
    return {"schema_version": 1, "provider": "gcp", "scopes": [PROJECT],
            "metadata": {}, "collections": [
                row("project", [{"projectId": "p1", "name": "projects/111"}]),
                row("iam_role", [{"name": role, "includedPermissions": permissions}]),
                row("iam_policy", [{"name": PROJECT, "bindings":
                    [{"role": role, "members": [SOURCE]}] if role_scope == PROJECT else []}]),
                row("service_account", [], "empty"),
                row("iam_deny_policy", [], "empty"),
                row("org_policy_effective", [], "empty"),
                row("group", [], "empty"),
                row("group_membership", [], "empty"),
                row("biglake_catalog", [{"name": catalog,
                    "iamPolicy": {"bindings": [{"role": role, "members": [SOURCE]}]
                                  if role_scope == CATALOG else []},
                    "_coverage": {"iamPolicy": {"status": policy_status}}}],
                    inventory_status),
            ]}


def targets(snap):
    entry, = [entry for entry in privesc.catalog()["entries"] if entry["id"] == TECHNIQUE]
    reaches = Evaluator(GcpModel(snap), [entry]).run()
    return {target: grant.confidence for reach in reaches if reach.source.id == SOURCE
            for target, grant in reach.targets.items()
            if target.startswith("gcp_verified_authority:possible-biglake-catalog-self-grant:")}


def test_exact_catalog_policy_write_and_new_get_permission_is_conditional():
    assert targets(snapshot()) == {
        "gcp_verified_authority:possible-biglake-catalog-self-grant:" + CATALOG: "conditional"}


def test_repository_scoped_policy_write_is_not_missed():
    assert targets(snapshot(role_scope=CATALOG))


def test_no_write_or_existing_catalog_access_is_not_new_gain():
    assert not targets(snapshot(write=False))
    assert not targets(snapshot(already=True))


def test_wrong_resource_or_incomplete_policy_stays_unproved():
    assert not targets(snapshot(catalog=CATALOG + "/namespaces/child"))
    assert "conditional" not in targets(snapshot(policy_status="denied")).values()
    assert "conditional" not in targets(snapshot(inventory_status="denied")).values()
