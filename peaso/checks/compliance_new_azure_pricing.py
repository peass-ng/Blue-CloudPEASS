"""Signed Azure Defender subscription pricing declarations.

These checks inspect a complete subscription pricing inventory. They do not
assert successful host monitoring, image scanning, or resource-level coverage.
"""
from __future__ import annotations

from datetime import datetime
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized, optional
from .fixtures import CASES

FIM_ID = "azure.cis.file_integrity_monitoring_component_status"
CONTAINERS_ID = "azure.cis.auto_provision_defender_containers_components"
IDS = (FIM_ID, CONTAINERS_ID)
_CONTAINERS_EXTENSIONS = frozenset({"AgentlessDiscoveryForKubernetes", "ContainerRegistriesVulnerabilityAssessments",
                                    "AgentlessVmScanning", "ContainerSensor", "ContainerIntegrityContribution"})


def _subscription(item):
    scope = get(item, "scope", str).rstrip("/")
    parts = scope.split("/")
    if len(parts) != 3 or parts[0] != "" or parts[1].casefold() != "subscriptions" or not parts[2]:
        return None
    return scope


def _pricing_rows(index):
    rows = {}
    for row in complete_items(index, "security_pricing"):
        rid = get(row, "id", str)
        name = get(row, "name", str)
        marker = "/providers/microsoft.security/pricings/"
        at = rid.casefold().rfind(marker)
        prefix, suffix = (rid[:at], rid[at + len(marker):]) if at >= 0 else ("", "")
        if not prefix or suffix.casefold() != name.casefold():
            raise Unavailable("Defender pricing resource identity malformed")
        key = (prefix.casefold(), name.casefold())
        if key in rows:
            raise Unavailable("duplicate Defender pricing resource identity")
        rows[key] = row
    return rows


def _pricing(index, scope, name):
    rows = memoized(index, ("compliance_new_azure_pricing_rows",), lambda: _pricing_rows(index))
    return rows.get((scope.casefold(), name.casefold()))


def _plan(pricing):
    properties = get(pricing, "properties", dict)
    tier = get(properties, "pricingTier", str)
    if tier not in ("Free", "Standard"):
        raise Unavailable("unrecognized Defender pricing tier")
    return properties, tier


def _extensions(properties):
    entries = list_of_objects(get(properties, "extensions", list))
    names = {}
    for entry in entries:
        name = get(entry, "name", str)
        if not name or name in names:
            raise Unavailable("Defender extension name missing or duplicated")
        names[name] = entry
    return names


def _enabled(entry):
    setting = get(entry, "isEnabled", str)
    if setting not in ("True", "False"):
        raise Unavailable("unrecognized Defender extension enablement")
    operation = optional(entry, "operationStatus", None)
    if operation is not None:
        if not isinstance(operation, dict):
            raise Unavailable("malformed Defender extension operation status")
        code = optional(operation, "code", None)
        if code is not None and not isinstance(code, str):
            raise Unavailable("malformed Defender extension operation code")
        if code not in (None, "Succeeded", "Failed", "InProgress", "Pending"):
            raise Unavailable("unrecognized Defender extension operation code")
    else:
        code = None
    return setting, code


def _full_coverage(properties):
    coverage = optional(properties, "resourcesCoverageStatus", None)
    if coverage is not None and coverage not in ("FullyCovered", "PartiallyCovered", "NotCovered"):
        raise Unavailable("unrecognized Defender resource coverage status")
    return coverage


@register(FIM_ID, "azure", "hardening", "security_pricing",
          "Defender for Servers subscription pricing declares P2 file integrity monitoring",
          "medium", "SI-7",
          "Review the VirtualMachines Defender plan, P2 cost and rollout with the subscription and VM owners; enable the FileIntegrityMonitoring extension only after approval and verify actual host telemetry separately.",
          target="scope", dependencies=["security_pricing"])
def file_integrity_pricing(item, index):
    scope = _subscription(item)
    if scope is None:
        return "NOT_APPLICABLE", {"reason": "Defender VirtualMachines pricing is assessed at subscription scope"}
    pricing = _pricing(index, scope, "VirtualMachines")
    if pricing is None:
        return unknown("VirtualMachines pricing resource absent in complete subscription inventory", scope=scope)
    properties, tier = _plan(pricing)
    if tier == "Free":
        return result(True, scope=scope, pricing_tier=tier,
                      semantics="Observed subscription plan configuration; resource overrides and host monitoring unverified")
    subplan = get(properties, "subPlan", str)
    if subplan not in ("P1", "P2"):
        return unknown("unrecognized Defender for Servers subplan", observed_subplan=subplan)
    if subplan != "P2":
        return result(True, scope=scope, pricing_tier=tier, subplan=subplan,
                      semantics="Observed subscription plan configuration; resource overrides and host monitoring unverified")
    extensions = _extensions(properties)
    entry = extensions.get("FileIntegrityMonitoring")
    if entry is None:
        return result(True, scope=scope, pricing_tier=tier, subplan=subplan,
                      extension_present=False,
                      semantics="Complete observed subscription extension declaration; host monitoring unverified")
    setting, code = _enabled(entry)
    if setting == "True" and code in ("Failed", "InProgress", "Pending"):
        return unknown("FileIntegrityMonitoring activation is not confirmed", scope=scope,
                       configured_is_enabled=setting, operation_code=code)
    coverage = _full_coverage(properties)
    if setting == "True" and coverage != "FullyCovered":
        return unknown("subscription plan does not prove full resource coverage", scope=scope,
                       configured_is_enabled=setting, operation_code=code, resources_coverage_status=coverage)
    return result(setting != "True", scope=scope, pricing_tier=tier, subplan=subplan,
                  configured_is_enabled=setting, operation_code=code, resources_coverage_status=coverage,
                  semantics="Configured subscription extension only; resource-level overrides and host monitoring unverified")


def _containers_owner(index, scope):
    def validated():
        context = index.get("context")
        metadata = context.get("metadata") if isinstance(context, dict) else None
        policy = metadata.get("defender_containers_policy") if isinstance(metadata, dict) else None
        if not isinstance(policy, dict) or policy.get("status") != "collected":
            raise Unavailable("Defender Containers owner policy missing or invalid")
        has_observed, has_age = "observed_at" in policy, "max_age_seconds" in policy
        if has_observed != has_age:
            raise Unavailable("Defender Containers owner policy expiry pair incomplete")
        if has_observed:
            observed, age, captured = policy["observed_at"], policy["max_age_seconds"], context.get("created_at")
            if not isinstance(observed, str) or not isinstance(captured, str) or type(age) is not int or age <= 0:
                raise Unavailable("Defender Containers owner policy freshness malformed")
            try:
                before = datetime.fromisoformat(observed.replace("Z", "+00:00"))
                after = datetime.fromisoformat(captured.replace("Z", "+00:00"))
                if before.utcoffset() is None or after.utcoffset() is None:
                    raise ValueError("timezone absent")
                elapsed = (after - before).total_seconds()
            except ValueError as exc:
                raise Unavailable("Defender Containers owner policy timestamp malformed") from exc
            if not 0 <= elapsed <= age:
                raise Unavailable("Defender Containers owner policy stale or future")
        entries = policy.get("subscriptions")
        budget = policy.get("max_policy_items")
        if type(budget) is not int or not 0 < budget <= 1000 or not isinstance(entries, list) or not entries or len(entries) > budget:
            raise Unavailable("Defender Containers owner policy subscription set malformed")
        result, count = {}, 0
        for row in entries:
            if not isinstance(row, dict) or not isinstance(row.get("scope"), str) or not re.fullmatch(r"/subscriptions/[A-Za-z0-9._-]{1,128}", row["scope"]):
                raise Unavailable("Defender Containers owner policy subscription entry malformed")
            key = row["scope"].casefold()
            names = row.get("required_extensions")
            if key in result or not isinstance(names, list) or not names or len(names) > budget or any(type(x) is not str or x not in _CONTAINERS_EXTENSIONS for x in names) or len(set(names)) != len(names):
                raise Unavailable("Defender Containers owner required extension set malformed")
            result[key] = tuple(names)
            count += 1 + len(names)
            if count > budget:
                raise Unavailable("Defender Containers owner policy item budget exceeded")
        return result
    rows = memoized(index, ("compliance_new_azure_containers_owner",), validated)
    if scope.casefold() not in rows:
        raise Unavailable("subscription has no approved required Containers extension set")
    return rows[scope.casefold()]


@register(CONTAINERS_ID, "azure", "hardening", "security_pricing",
          "Defender for Containers subscription plan declares approved required extensions",
          "medium", "SI-4",
          "Review the approved Containers extension set, plan cost and resource applicability with the subscription owner; align the configured plan and extensions only after approval, then verify operation and cluster coverage separately.",
          target="scope", dependencies=["security_pricing"])
def containers_pricing(item, index):
    scope = _subscription(item)
    if scope is None:
        return "NOT_APPLICABLE", {"reason": "Defender Containers pricing is assessed at subscription scope"}
    required = _containers_owner(index, scope)
    pricing = _pricing(index, scope, "Containers")
    if pricing is None:
        return unknown("Containers pricing resource absent in complete subscription inventory", scope=scope)
    properties, tier = _plan(pricing)
    if tier == "Free":
        return result(True, scope=scope, pricing_tier=tier, required_extension_count=len(required),
                      semantics="Observed subscription plan configuration; resource overrides and cluster coverage unverified")
    extensions = _extensions(properties)
    missing, disabled, pending = [], [], []
    for name in required:
        entry = extensions.get(name)
        if entry is None:
            missing.append(name)
            continue
        setting, code = _enabled(entry)
        if setting == "False":
            disabled.append(name)
        elif code in ("Failed", "InProgress", "Pending"):
            pending.append({"name": name, "operation_code": code})
    counts = {"scope": scope, "pricing_tier": tier, "required_extension_count": len(required),
              "missing_extension_count": len(missing), "disabled_extension_count": len(disabled),
              "pending_or_failed_count": len(pending),
              "semantics": "Configured subscription extensions only; resource overrides, operation health and cluster coverage unverified"}
    if missing or disabled:
        return result(True, **counts, missing_examples=missing[:20], disabled_examples=disabled[:20])
    if pending:
        return unknown("required Containers extension activation is not confirmed",
                       **counts, operation_examples=pending[:20])
    coverage = _full_coverage(properties)
    if coverage != "FullyCovered":
        return unknown("subscription plan does not prove full resource coverage",
                       **counts, resources_coverage_status=coverage)
    return result(False, **counts, resources_coverage_status=coverage)


_SCOPE = {"scope": "/subscriptions/sub"}
_BASE = "/subscriptions/sub/providers/Microsoft.Security/pricings/"
def _index(plan, properties, policy=None):
    row = {"id": _BASE + plan, "name": plan, "properties": properties}
    return {"collections": {"security_pricing": [{"status": "collected"}]},
            "security_pricing": [{"data": row}],
            "context": {"created_at": "2026-10-12T00:00:00Z", "metadata": {"defender_containers_policy":
                policy or {"status": "collected", "observed_at": "2026-10-12T00:00:00Z", "max_age_seconds": 600,
                           "max_policy_items": 10,
                           "subscriptions": [{"scope": "/subscriptions/sub", "required_extensions": ["ContainerSensor"]}]}}}}


CASES[FIM_ID] = {"pass": _SCOPE, "fail": _SCOPE, "missing": _SCOPE,
                 "pass_index": _index("VirtualMachines", {"pricingTier": "Standard", "subPlan": "P2", "resourcesCoverageStatus": "FullyCovered",
                              "extensions": [{"name": "FileIntegrityMonitoring", "isEnabled": "True"}]}),
                 "fail_index": _index("VirtualMachines", {"pricingTier": "Standard", "subPlan": "P1", "extensions": []})}
CASES[CONTAINERS_ID] = {"pass": _SCOPE, "fail": _SCOPE, "missing": _SCOPE,
                        "pass_index": _index("Containers", {"pricingTier": "Standard", "resourcesCoverageStatus": "FullyCovered",
                                     "extensions": [{"name": "ContainerSensor", "isEnabled": "True"}]}),
                        "fail_index": _index("Containers", {"pricingTier": "Standard", "extensions": []})}
