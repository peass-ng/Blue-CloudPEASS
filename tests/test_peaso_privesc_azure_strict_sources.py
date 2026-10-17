"""A prose-only source condition must not turn into an Azure escalation edge."""

from peaso import privesc
from peaso.privesc.schema import load_catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, T, az


def test_databricks_admin_requires_collected_member_user():
    entries = {e["id"]: e for e in load_catalog()["entries"] if e["provider"] == "azure"}
    entry = entries["azure-databricks-assign-workspace-admin"]
    workspace = f"{RG}/providers/Microsoft.Databricks/workspaces/w"
    actions = ["Microsoft.Databricks/workspaces/assignWorkspaceAdmin/action",
               "Microsoft.Databricks/workspaces/read"]
    snap = az(assignments=[(p, kind, workspace, ROLE_ID) for p, kind in
                           (("u-member", "User"), ("u-guest", "User"), ("sp-a", "ServicePrincipal"))],
              roles={ROLE_ID: (actions, [])}, users=("u-member", "u-guest"), sps=("sp-a",),
              graph=({"id": workspace, "type": "Microsoft.Databricks/workspaces"},))
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")["items"]
    next(u for u in users if u["id"] == "u-guest")["userType"] = "Guest"
    result = privesc.analyze(snap, entries=[entry])
    assert any(k.startswith("azure_dataplane_admin:") for k in reached(result, "u-member", entry["id"]))
    assert not reached(result, "u-guest", entry["id"])
    assert not reached(result, "sp-a", entry["id"])


def test_aks_group_graft_is_inactive_without_verified_membership_and_kubeconfig():
    ids = {e["id"] for e in load_catalog()["entries"] if e["provider"] == "azure"}
    assert "azure-aks-managedclusters-write-admin-group" not in ids
