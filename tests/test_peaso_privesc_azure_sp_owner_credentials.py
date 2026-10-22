"""An SP owner can add credentials only to the owned, usable service principal."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory
from tests.test_peaso_privesc_schema_ext_azure import T


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-sp-owner-credentials")


def _snapshot(*, owner="u-alice", status="collected"):
    snap = _inventory()
    snap["collections"].append({"type": "directory_owner", "scope": T + "/servicePrincipals/sp-a",
        "status": status, "items": [{"id": "sp-a", "objectId": "sp-a", "objectType": "servicePrincipal",
                                    "ownerIds": [owner]}] if status == "collected" else []})
    snap["collections"].append({"type": "directory_owner", "scope": T + "/servicePrincipals/sp-b",
        "status": "empty", "items": []})
    snap["collections"].append({"type": "directory_owner", "scope": T + "/servicePrincipals/sp-external",
        "status": "empty", "items": []})
    return snap


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_owner_reaches_only_exact_service_principal():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_snapshot()) == {"sp-a": "conditional"}
    assert _reached(_snapshot(owner="u-other")) == {}


def test_disabled_identity_or_credential_lock_blocks_owner():
    snap = _snapshot()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _snapshot()
    app = next(c for c in snap["collections"] if c["type"] == "directory_application")
    app["items"][0]["servicePrincipalLockConfiguration"] = {
        "isEnabled": True, "allProperties": True}
    assert _reached(snap) == {}


def test_app_owner_needs_graph_credential_write_permission():
    snap = _snapshot(owner="sp-b")
    snap["collections"].append({"type": "directory_app_role_assignment", "scope": T,
                                "status": "empty", "items": []})
    assert _reached(snap, "sp-b") == {}
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    sp["items"].append({"id": "graph-sp", "appId": "00000003-0000-0000-c000-000000000000",
                        "servicePrincipalType": "Application", "accountEnabled": True})
    grant = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grant.update(status="collected", items=[{"id": "grant-1", "principalId": "sp-b",
        "resourceId": "graph-sp", "appRoleValue": "Application.ReadWrite.OwnedBy", "appRoleEnabled": True}])
    assert _reached(snap, "sp-b") == {"sp-a": "conditional"}


def test_missing_owner_listing_preserves_unknown_instead_of_a_negative():
    snap = _snapshot(status="not_collected")
    result = privesc.analyze(snap, entries=[ENTRY], include_unknown=True)
    assert any(row["status"] == "UNKNOWN" for row in result["findings"])
    assert any(row["kind"] == "selector" and "directory_owner" in row["impact"]
               for row in result["coverage"])


def test_unrelated_missing_owner_listing_does_not_downgrade_recorded_owner():
    snap = _snapshot()
    other = next(c for c in snap["collections"] if c["type"] == "directory_owner"
                 and c["scope"].endswith("/sp-b"))
    other["status"] = "not_collected"
    assert _reached(snap) == {"sp-a": "conditional"}
