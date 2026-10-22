"""Adding an SP owner must create a usable, new credential path."""
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
    if row["id"] == "azure-entraid-sp-owners-update")
ACTION = "microsoft.directory/servicePrincipals/owners/update"


def _snapshot(role_scope="/sp-a", owner="u-other"):
    snap = _inventory(action=ACTION, role_scope=role_scope)
    for sp_id in ("sp-a", "sp-b", "sp-external"):
        snap["collections"].append({"type": "directory_owner",
            "scope": T + "/servicePrincipals/" + sp_id,
            "status": "collected" if sp_id == "sp-a" else "empty",
            "items": [{"id": sp_id, "objectId": sp_id, "objectType": "servicePrincipal",
                       "ownerIds": [owner]}] if sp_id == "sp-a" else []})
    return snap


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_role_scope_binds_to_service_principal_not_application():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_snapshot()) == {"sp-a": "conditional"}
    assert _reached(_snapshot(role_scope="/app-a")) == {}
    assert _reached(_snapshot(role_scope="/")) == {
        "sp-a": "conditional", "sp-b": "conditional", "sp-external": "conditional"}


def test_existing_owner_and_unusable_target_do_not_create_new_path():
    assert _reached(_snapshot(owner="u-alice")) == {}
    snap = _snapshot()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _snapshot()
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["servicePrincipalType"] = "ManagedIdentity"
    assert _reached(snap) == {}


def test_known_credential_lock_and_disabled_source_excluded():
    snap = _snapshot()
    app = next(c for c in snap["collections"] if c["type"] == "directory_application")
    app["items"][0]["servicePrincipalLockConfiguration"] = {
        "isEnabled": True, "credentialsWithUsageVerify": True}
    assert _reached(snap) == {}
    snap = _snapshot()
    users = next(c for c in snap["collections"] if c["type"] == "directory_user")
    users["items"][0]["accountEnabled"] = False
    assert _reached(snap) == {}


def test_directory_role_assignment_to_app_only_source_is_not_sufficient():
    snap = _snapshot()
    assignment = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignment["items"][0]["principalId"] = "sp-b"
    assert _reached(snap, "sp-b") == {}
