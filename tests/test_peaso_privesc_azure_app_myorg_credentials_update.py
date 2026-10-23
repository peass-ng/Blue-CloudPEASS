"""The myOrganization credential route reaches only its exact single-tenant app."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_azure_app_credentials_update import _inventory


ENTRY = next(row for row in yaml.safe_load((Path(__file__).resolve().parents[1] /
    "peaso/privesc/catalog/azure/entraid_apps.yaml").read_text())
    if row["id"] == "azure-entraid-app-myorg-credentials-update")
ACTION = "microsoft.directory/applications.myOrganization/credentials/update"
ALL_PROPERTIES = "microsoft.directory/applications.myOrganization/allProperties/update"


def _reached(snap, source="u-alice"):
    return reached(privesc.analyze(snap, entries=[ENTRY]), source, ENTRY["id"])


def test_exact_scope_and_tenant_role_reach_only_single_tenant_apps():
    assert validate_entry(ENTRY)[0] == []
    assert _reached(_inventory(action=ACTION)) == {"sp-a": "conditional"}
    assert _reached(_inventory(role_scope="/", action=ACTION)) == {"sp-a": "conditional"}
    assert _reached(_inventory(role_scope="/app-b", action=ACTION)) == {}


def test_wrong_scope_audience_or_permission_cannot_reach_app():
    assert _reached(_inventory(role_scope="/sp-a", action=ACTION)) == {}
    assert _reached(_inventory(role_scope="/unrelated", action=ACTION)) == {}
    assert _reached(_inventory(action="microsoft.directory/applications/basic/update")) == {}
    snap = _inventory(action=ACTION)
    app = next(c for c in snap["collections"] if c["type"] == "directory_application")
    app["items"][0]["signInAudience"] = "AzureADMultipleOrgs"
    assert _reached(snap) == {}


def test_all_properties_update_and_enabled_state():
    assert _reached(_inventory(action=ALL_PROPERTIES)) == {"sp-a": "conditional"}
    snap = _inventory(action=ACTION)
    sp = next(c for c in snap["collections"] if c["type"] == "directory_service_principal")
    next(row for row in sp["items"] if row["id"] == "sp-a")["accountEnabled"] = False
    assert _reached(snap) == {}


def test_app_only_role_assignment_without_graph_permission_is_not_enough():
    snap = _inventory(action=ACTION)
    assignment = next(c for c in snap["collections"] if c["type"] == "directory_role_assignment")
    assignment["items"][0]["principalId"] = "sp-a"
    assert _reached(snap, "sp-a") == {}
