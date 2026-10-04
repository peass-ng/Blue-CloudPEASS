"""Catalog helpers and public API for the shared CloudPEASS risk engine."""
from __future__ import annotations
import json
from typing import Iterable
try:
    from . import cloud_permission_risks as _shared
except ImportError:
    import cloud_permission_risks as _shared

RISK_ORDER = _shared.RISK_ORDER
RISK_LEVELS = _shared.RISK_LEVELS
load_rules = _shared.load_rules
load_criticality_combinations = _shared.load_criticality_combinations
classify_permission = _shared.classify_permission
classify_all = _shared.classify_all
aws_regex_classify = _shared.aws_regex_classify
gcp_regex_classify = _shared.gcp_regex_classify
azure_regex_classify = _shared.azure_regex_classify


def load_aws_permissions_from_managed_policies(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    policies = data.get("policies", [])
    if not isinstance(policies, list):
        raise ValueError("Unexpected AWS dataset format: expected top-level key 'policies' list")

    permissions: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict):
            continue
        actions = policy.get("effective_action_names", [])
        if not isinstance(actions, list):
            continue
        for action in actions:
            if isinstance(action, str) and action.strip():
                permissions.add(action.strip())
    return permissions


def load_gcp_permissions_from_sorted(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict):
        return {k.strip() for k in data.keys() if isinstance(k, str) and k.strip()}
    if isinstance(data, list):
        return {x.strip() for x in data if isinstance(x, str) and x.strip()}
    raise ValueError("Unexpected GCP dataset format: expected dict or list")


def load_azure_permissions_from_provider_operations(path: str) -> set[str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    permissions: set[str] = set()

    def extract_from_operations_list(ops) -> None:
        if not isinstance(ops, list):
            return
        for op in ops:
            if not isinstance(op, dict):
                continue
            name = op.get("name")
            if isinstance(name, str) and name.strip() and "/" in name:
                permissions.add(name.strip())

    if not isinstance(data, list):
        raise ValueError("Unexpected Azure dataset format: expected a top-level list")

    for provider in data:
        if not isinstance(provider, dict):
            continue
        extract_from_operations_list(provider.get("operations"))
        for rt in provider.get("resourceTypes", []) or []:
            if not isinstance(rt, dict):
                continue
            extract_from_operations_list(rt.get("operations"))

    return permissions


def _legacy_candidate_actions(provider: str, risk_levels: Iterable[str]) -> list[str]:
    """
    Return a stable, de-duplicated list of *exact* permission strings that are useful
    to test for the given risk levels.

    Notes:
    - This is intentionally conservative: it only returns exact strings stored in `risk_rules/*.yaml`.
    - Wildcards are excluded because downstream callers often use this list for simulation APIs
      that require concrete action names.
    """
    provider = provider.lower().strip()
    levels = [str(x).strip().lower() for x in risk_levels if str(x).strip()]
    levels = [x for x in levels if x in RISK_LEVELS]
    if not levels:
        return []

    out: list[str] = []
    seen: set[str] = set()

    def add_many(items: Iterable[str]) -> None:
        for p in items:
            if not isinstance(p, str):
                continue
            p = p.strip()
            if not p or "*" in p:
                continue
            if p in seen:
                continue
            seen.add(p)
            out.append(p)

    if provider == "aws":
        r = load_rules("aws")
        if "critical" in levels:
            add_many(r.critical_exact)
        if "high" in levels:
            add_many(r.high_exact)
        if "low" in levels:
            add_many(r.low_exact)
        combinations = load_criticality_combinations("aws")
        for level in ("critical", "high"):
            if level in levels:
                for combination in combinations[level]:
                    add_many(combination)
        # Medium has no exact list in our rule format currently.
        return out

    if provider == "gcp":
        r = load_rules("gcp")
        if "critical" in levels:
            add_many(r.critical_exact)
        if "low" in levels:
            add_many(r.low_exact)
        combinations = load_criticality_combinations("gcp")
        for level in ("critical", "high"):
            if level in levels:
                for combination in combinations[level]:
                    add_many(combination)
        # High/medium are mostly heuristic/verb-based for GCP rules.
        return out

    if provider == "azure":
        r = load_rules("azure")
        # Azure rules are primarily regex/keyword based; exact lists are optional.
        if "critical" in levels:
            add_many(getattr(r, "critical_exact", []) or [])
        if "low" in levels:
            add_many(getattr(r, "low_exact", []) or [])
        combinations = load_criticality_combinations("azure")
        for level in ("critical", "high"):
            if level in levels:
                for combination in combinations[level]:
                    add_many(combination)
        return out

    raise ValueError(f"Unknown provider: {provider}")


def candidate_actions(provider: str, risk_levels: Iterable[str]) -> list[str]:
    provider = provider.lower().strip()
    levels = {str(level).lower().strip() for level in risk_levels} & set(RISK_LEVELS)
    candidates = set(_legacy_candidate_actions(provider, levels))
    rules = load_rules(provider)
    for level in levels:
        candidates.update(getattr(rules, f"{level}_exact", ()) or ())
    candidates.update(permission for permission, level in _shared._load_yaml(provider).get("severity_overrides", {}).items() if level in levels)
    # Retain companion actions needed to recognize complete combinations.
    return sorted(permission for permission in candidates if "*" not in permission)
