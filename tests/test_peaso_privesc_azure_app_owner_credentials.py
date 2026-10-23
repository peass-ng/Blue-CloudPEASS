"""Application owners reach only the usable SP of the exact owned registration."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import T
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-app-owner-credentials")


def _owned(*, owner="u-alice", object_id="app-a", status="collected",
           permission="Application.ReadWrite.OwnedBy", resource="sp-graph"):
    snap = _inventory()
    snap["collections"].append({"type": "directory_owner", "scope": f"{T}/applications/{object_id}",
        "service": "Microsoft.Graph", "status": status, "items": [{"id": object_id,
            "objectId": object_id, "objectType": "application", "ownerIds": [owner]}]})
    if owner != "u-alice":
        sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
        sp["items"].extend([
            {"id": "sp-owner", "appId": "owner-app", "servicePrincipalType": "Application",
             "accountEnabled": True},
            {"id": "sp-graph", "appId": "00000003-0000-0000-c000-000000000000",
             "servicePrincipalType": "Application", "accountEnabled": True},
        ])
        snap["collections"].append({"type": "directory_app_role_assignment", "scope": T,
            "service": "Microsoft.Graph", "status": "collected", "items": [{
                "id": "grant", "principalId": "sp-owner", "resourceId": resource,
                "appRoleValue": permission, "appRoleEnabled": True}]})
    return snap


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_user_owner_reaches_only_its_enabled_application_service_principal():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_owned()) == {"sp-a": "conditional"}
    assert _reached(_owned(object_id="app-b")) == {"sp-b": "conditional"}


def test_wrong_object_scope_status_or_disabled_target_does_not_name_path():
    assert _reached(_owned(object_id="sp-a")) == {}
    assert _reached(_owned(object_id="other")) == {}
    assert _reached(_owned(status="access_denied")) == {}
    snap = _owned()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _owned()
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    next(row for row in users["items"] if row["id"] == "u-alice")["accountEnabled"] = False
    assert _reached(snap) == {}


def test_app_only_owner_needs_enabled_graph_role_on_graph_resource():
    assert _reached(_owned(owner="sp-owner"), "sp-owner") == {"sp-a": "conditional"}
    assert _reached(_owned(owner="sp-owner", permission="Application.ReadWrite.All"),
                    "sp-owner") == {"sp-a": "conditional"}
    assert _reached(_owned(owner="sp-owner", resource="sp-a"), "sp-owner") == {}
    assert _reached(_owned(owner="sp-owner", permission="Application.Read.All"), "sp-owner") == {}
    snap = _owned(owner="sp-owner")
    grant = next(c for c in snap["collections"] if c["type"] == "directory_app_role_assignment")
    grant["items"][0]["appRoleEnabled"] = False
    assert _reached(snap, "sp-owner") == {}
    snap = _owned(owner="sp-owner")
    principals = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in principals["items"] if row["id"] == "sp-owner")["accountEnabled"] = False
    assert _reached(snap, "sp-owner") == {}
