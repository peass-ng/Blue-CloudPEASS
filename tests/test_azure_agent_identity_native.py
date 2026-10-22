"""Agent ID Graph cast lists keep exact IDs and discard unrelated fields."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "azure_agent_identity_native_reviewed", Path(__file__).resolve().parents[1] /
    "peaso/collectors/azure_agent_identity_native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def test_cast_endpoints_and_minimal_projection():
    assert native.ENDPOINTS["directory_agent_blueprint"].startswith(
        "applications/microsoft.graph.agentIdentityBlueprint?")
    assert native.ENDPOINTS["directory_agent_blueprint_principal"].startswith(
        "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?")
    assert native.ENDPOINTS["directory_agent_identity"].startswith(
        "servicePrincipals/microsoft.graph.agentIdentity?")
    row = {"@odata.type": "#microsoft.graph.agentIdentity", "id": "child", "appId": "child-app",
           "agentIdentityBlueprintId": "blueprint-app", "accountEnabled": True,
           "passwordCredentials": [{"secretText": "MUST-NOT-SURVIVE"}],
           "managerApplications": ["unrelated"]}
    assert native.project("directory_agent_identity", row) == {
        "id": "child", "appId": "child-app", "agentIdentityBlueprintId": "blueprint-app",
        "accountEnabled": True}


@pytest.mark.parametrize("field,value", [
    ("id", ""), ("appId", None), ("agentIdentityBlueprintId", None),
    ("accountEnabled", None), ("@odata.type", "#microsoft.graph.servicePrincipal"),
])
def test_missing_or_conflicting_agent_facts_are_rejected(field, value):
    row = {"@odata.type": "#microsoft.graph.agentIdentity", "id": "child", "appId": "child-app",
           "agentIdentityBlueprintId": "blueprint-app", "accountEnabled": True}
    row[field] = value
    with pytest.raises(ValueError):
        native.project("directory_agent_identity", row)
