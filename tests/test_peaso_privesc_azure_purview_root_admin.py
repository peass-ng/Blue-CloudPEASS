"""Purview root collection admin action applies only to exact Purview accounts."""
from __future__ import annotations

from peaso import privesc
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, SUB, az


TECHNIQUE = "azure-purview-add-root-collection-admin"
ACTION = "Microsoft.Purview/accounts/addrootcollectionadmin/action"
PURVIEW = RG + "/providers/Microsoft.Purview/accounts/catalog"
VM = RG + "/providers/Microsoft.Compute/virtualMachines/worker"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TECHNIQUE)


def _run(scope, *, native=True, graph=()):
    purview = {"id": PURVIEW, "type": "Microsoft.Purview/accounts", "name": "catalog"}
    extra = [("purview_account", SUB, [purview], "collected")] if native else []
    snap = az([("u-alice", "User", scope, ROLE_ID)], roles={ROLE_ID: ([ACTION], [])},
              graph=list(graph), extra=extra)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TECHNIQUE)


def test_native_purview_account_is_named_and_other_resource_is_not():
    result = _run(SUB, graph=[{"id": VM, "type": "Microsoft.Compute/virtualMachines"}])
    assert result == {"azure_dataplane_admin:" + PURVIEW.lower(): "conditional"}


def test_resource_graph_purview_account_is_supported_without_native_collection():
    result = _run(SUB, native=False, graph=[{"id": PURVIEW, "type": "Microsoft.Purview/accounts"}])
    assert result == {"azure_dataplane_admin:" + PURVIEW.lower(): "conditional"}


def test_unrelated_resource_scope_or_missing_purview_account_does_not_reach():
    assert _run(VM) == {}
    assert _run(SUB, native=False, graph=[{"id": VM, "type": "Microsoft.Compute/virtualMachines"}]) == {}
