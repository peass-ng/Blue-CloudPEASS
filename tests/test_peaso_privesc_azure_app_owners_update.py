"""An app-owner write role reaches only the application in its directory scope."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-app-owners-update")
ACTION = "microsoft.directory/applications/owners/update"


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_app_scoped_and_tenant_scoped_owner_grants():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_inventory(action=ACTION)) == {"sp-a": "conditional"}
    assert _reached(_inventory(role_scope="/app-b", action=ACTION)) == {"sp-b": "conditional"}
    assert _reached(_inventory(role_scope="/", action=ACTION)) == {
        "sp-a": "conditional", "sp-b": "conditional"}


def test_wrong_scope_permission_or_missing_local_app_excluded():
    assert _reached(_inventory(role_scope="/sp-a", action=ACTION)) == {}
    assert _reached(_inventory(role_scope="/unrelated", action=ACTION)) == {}
    assert _reached(_inventory(action="microsoft.directory/applications/basic/update")) == {}
    assert _reached(_inventory(applications=[], app_status="empty", action=ACTION)) == {}


def test_disabled_or_managed_identity_target_excluded():
    snap = _inventory(action=ACTION)
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}
    snap = _inventory(action=ACTION)
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["servicePrincipalType"] = "ManagedIdentity"
    assert _reached(snap) == {}


def test_directory_role_assignment_does_not_authorize_app_only_caller():
    snap = _inventory(action=ACTION)
    grant = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    grant["items"][0]["principalId"] = "sp-a"
    assert _reached(snap, "sp-a") == {}
