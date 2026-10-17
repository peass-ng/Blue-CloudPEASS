"""Signed Azure Defender pricing extension declaration, scoped to one subscription."""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, optional
from .fixtures import CASES

ID = "azure.cis.agentless_scanning_machines_component_status"
PLAN = "VirtualMachines"
EXTENSION = "AgentlessVmScanning"


def _subscription(item):
    scope = get(item, "scope", str).rstrip("/")
    parts = scope.split("/")
    if len(parts) != 3 or parts[0] != "" or parts[1].lower() != "subscriptions" or not parts[2]:
        return None
    return scope


@register(ID, "azure", "hardening", "security_pricing",
          "Defender for Servers pricing declares agentless VM scanning enabled", "medium", "SI-4",
          "With the subscription owner, inspect the VirtualMachines Defender pricing extension and its operation status; enable AgentlessVmScanning only after cost, permissions and coverage review, then verify actual scanning separately.",
          target="scope", dependencies=["security_pricing"])
def agentless_scanning_declaration(item, index):
    scope = _subscription(item)
    if scope is None:
        return "NOT_APPLICABLE", {"reason": "Defender VirtualMachines pricing extension is evaluated at subscription scope"}
    rows = complete_items(index, "security_pricing")
    matches = []
    for row in rows:
        rid = get(row, "id", str)
        if not rid.casefold().startswith(scope.casefold() + "/"):
            continue
        name = get(row, "name", str)
        expected = scope + "/providers/Microsoft.Security/pricings/" + name
        if not name or rid.casefold() != expected.casefold():
            raise Unavailable("Defender pricing row belongs to another scope or service")
        if name == PLAN:
            matches.append(row)
    if len(matches) != 1:
        return unknown("VirtualMachines pricing resource absent or ambiguous in complete subscription inventory",
                       observed_matches=len(matches))
    properties = get(matches[0], "properties", dict)
    tier = get(properties, "pricingTier", str)
    if tier not in ("Free", "Standard"):
        return unknown("unrecognized Defender pricing tier", observed_tier=tier)
    if tier == "Free":
        return result(True, pricing_tier=tier,
                      semantics="Free subscription pricing is a configured-plan failure; actual scan coverage is not assessed")
    extensions = list_of_objects(get(properties, "extensions", list))
    matched = [row for row in extensions if get(row, "name", str) == EXTENSION]
    if len(matched) > 1:
        return unknown("duplicate AgentlessVmScanning extension records")
    if not matched:
        return result(True, pricing_tier=tier, extension_present=False,
                      semantics="Complete observed subscription pricing declaration only; actual scans, covered machines and operation health unproved")
    setting = get(matched[0], "isEnabled", str)
    if setting not in ("True", "False"):
        return unknown("unrecognized AgentlessVmScanning enablement", configured=setting)
    operation = optional(matched[0], "operationStatus", None)
    operation_code = None
    if operation is not None:
        if not isinstance(operation, dict):
            return unknown("malformed AgentlessVmScanning operation status")
        operation_code = optional(operation, "code", None)
        if operation_code is not None and not isinstance(operation_code, str):
            return unknown("malformed AgentlessVmScanning operation code")
    return result(setting != "True", pricing_tier=tier,
                  extension_present=True, configured_is_enabled=setting, operation_code=operation_code,
                  semantics="Configured subscription extension only; operation health, actual scans and covered machines unproved")


_SCOPE = {"scope": "/subscriptions/sub"}
_BASE = "/subscriptions/sub/providers/Microsoft.Security/pricings/VirtualMachines"

def _inventory(tier, enabled):
    extension = [] if enabled is None else [{"name": EXTENSION, "isEnabled": enabled}]
    row = {"id": _BASE, "name": PLAN, "properties": {"pricingTier": tier, "extensions": extension}}
    return {"collections": {"security_pricing": [{"scope": "/subscriptions/sub", "status": "collected"}]},
            "security_pricing": [{"data": row}]}


CASES[ID] = {"pass": _SCOPE, "fail": _SCOPE, "pass_index": _inventory("Standard", "True"),
             "fail_index": _inventory("Standard", "False"), "missing": _SCOPE,
             "malformed": {"scope": None}}
