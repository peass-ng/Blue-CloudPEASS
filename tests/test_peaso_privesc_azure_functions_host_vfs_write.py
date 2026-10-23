"""Hostruntime VFS write requires the exact writable Function App host."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_functions_write import APP, OTHER, _snapshot


TID = "azure-functions-hostruntime-vfs-write"
ENTRY = next({k: v for k, v in row.items() if not k.startswith("_")}
             for row in privesc.load_catalog()["entries"] if row["id"] == TID)
ACTION = "Microsoft.Web/sites/hostruntime/vfs/write"


def _reached(**kwargs):
    snap = _snapshot(action=ACTION, **kwargs)
    return reached(privesc.analyze(snap, entries=[ENTRY]), "u-alice", TID)


def test_exact_host_vfs_write_is_conditional():
    assert validate_entry(ENTRY)[0] == []
    assert _reached() == {"mi-app": "conditional"}
    assert _reached(grant=OTHER) == {}
    assert _reached(grant=APP + "/config/web") == {}


def test_package_flex_container_and_wrong_identity_host_excluded():
    assert _reached(package="1") == {}
    assert _reached(package="https://example.com/code.zip") == {}
    assert _reached(sku="FC1") == {}
    assert _reached(function_config=True) == {}
    assert _reached(kind="functionapp,container,linux") == {}
    assert _reached(other_identity=True) == {}


def test_missing_plan_and_non_function_site_do_not_claim_vfs_execution():
    assert _reached(plan=False) == {}
    assert _reached(kind="app,linux") == {}
