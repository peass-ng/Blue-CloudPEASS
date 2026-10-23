"""Read only the Graph fields needed to bind Agent ID blueprints to principals."""
from __future__ import annotations


ENDPOINTS = {
    "directory_agent_blueprint":
        "applications/microsoft.graph.agentIdentityBlueprint?$select=id,appId,disabledByMicrosoftStatus",
    "directory_agent_blueprint_principal":
        "servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal?$select=id,appId,accountEnabled,disabledByMicrosoftStatus",
    "directory_agent_identity":
        "servicePrincipals/microsoft.graph.agentIdentity?$select=id,appId,agentIdentityBlueprintId,accountEnabled,disabledByMicrosoftStatus",
}
TYPES = {
    "directory_agent_blueprint": "#microsoft.graph.agentIdentityBlueprint",
    "directory_agent_blueprint_principal": "#microsoft.graph.agentIdentityBlueprintPrincipal",
    "directory_agent_identity": "#microsoft.graph.agentIdentity",
}


def project(kind, row):
    """Reject incomplete identities and discard unrelated Graph fields."""
    if kind not in ENDPOINTS or not isinstance(row, dict):
        raise ValueError("malformed Graph agent identity")
    if row.get("@odata.type") not in (None, TYPES[kind]):
        raise ValueError("Graph agent object has the wrong derived type")
    required = ("id", "appId", "agentIdentityBlueprintId") if kind == "directory_agent_identity" else ("id", "appId")
    if any(not isinstance(row.get(key), str) or not row[key].strip() for key in required):
        raise ValueError("Graph agent identity or blueprint link unavailable")
    if kind != "directory_agent_blueprint" and not isinstance(row.get("accountEnabled"), bool):
        raise ValueError("Graph agent sign-in state unavailable")
    fields = (*required, "disabledByMicrosoftStatus")
    if kind != "directory_agent_blueprint":
        fields += ("accountEnabled",)
    return {key: row[key] for key in fields if key in row}
