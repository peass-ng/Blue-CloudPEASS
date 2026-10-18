"""Signed Azure data-service backup configuration checks.

Cosmos DB backup configuration is not evidence of a completed or restorable backup.
The SQL geo-LTR proposal is held because current database backup redundancy does
not establish redundancy of existing long-term backup copies.
"""
from __future__ import annotations

from datetime import datetime
import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES


COSMOS_ID = "azure_cosmos_account_10_5_1_5_2029065"
IDS = (COSMOS_ID,)
_SCOPE = re.compile(r"/subscriptions/[A-Za-z0-9._-]{1,128}\Z", re.I)
_ACCOUNT = re.compile(
    r"/subscriptions/[A-Za-z0-9._-]{1,128}/resourceGroups/[^/?#\x00-\x1f]{1,90}"
    r"/providers/Microsoft\.DocumentDB/databaseAccounts/[^/?#\x00-\x1f]{1,256}\Z", re.I)


def _instant(value):
    if not isinstance(value, str):
        raise Unavailable("Cosmos backup policy timestamp malformed")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("timezone absent")
        return parsed
    except ValueError as exc:
        raise Unavailable("Cosmos backup policy timestamp malformed") from exc


def _owner(index):
    def parse():
        context = index.get("context")
        if not isinstance(context, dict):
            raise Unavailable("Cosmos backup evaluation context unavailable")
        metadata = context.get("metadata")
        policy = metadata.get("cosmos_backup_retention") if isinstance(metadata, dict) else None
        if not isinstance(policy, dict) or policy.get("status") != "collected":
            raise Unavailable("Cosmos backup owner minimum absent or malformed")
        required = {"status", "max_policy_items", "accounts"}
        allowed = required | {"source", "observed_at", "max_age_seconds"}
        if not required <= set(policy) or set(policy) - allowed:
            raise Unavailable("Cosmos backup owner policy shape invalid")
        age, budget = policy.get("max_age_seconds"), policy.get("max_policy_items")
        if type(budget) is not int or budget <= 0:
            raise Unavailable("Cosmos backup owner policy bounds invalid")
        has_observed, has_age = "observed_at" in policy, "max_age_seconds" in policy
        if has_observed != has_age:
            raise Unavailable("Cosmos backup owner policy expiry pair incomplete")
        if has_observed:
            if type(age) is not int or age <= 0:
                raise Unavailable("Cosmos backup owner policy expiry invalid")
            elapsed = (_instant(context.get("created_at")) - _instant(policy["observed_at"])).total_seconds()
            if not 0 <= elapsed <= age:
                raise Unavailable("Cosmos backup owner minimum stale or future")
        accounts = policy.get("accounts")
        if not isinstance(accounts, list) or not accounts or len(accounts) > budget:
            raise Unavailable("Cosmos backup owner account set unavailable or over budget")
        mapping = {}
        for row in accounts:
            if not isinstance(row, dict) or set(row) != {"subscription_scope", "resource_id", "min_retention_days"}:
                raise Unavailable("Cosmos backup owner account malformed")
            scope, rid, days = row.get("subscription_scope"), row.get("resource_id"), row.get("min_retention_days")
            if not isinstance(scope, str) or not _SCOPE.fullmatch(scope) or not isinstance(rid, str) or not _ACCOUNT.fullmatch(rid):
                raise Unavailable("Cosmos backup owner account identity malformed")
            if not rid.casefold().startswith(scope.casefold() + "/") or type(days) is not int or days <= 0:
                raise Unavailable("Cosmos backup owner minimum or scope invalid")
            key = rid.casefold()
            if key in mapping:
                raise Unavailable("Cosmos backup owner account duplicated")
            mapping[key] = (scope.casefold(), days)
        return mapping
    return memoized(index, ("compliance_new_azure_cosmos_backup_owner",), parse)


def _retention_hours(account):
    policy = get(account, "properties.backupPolicy", dict)
    mode = get(policy, "type", str)
    if mode == "Periodic":
        hours = get(policy, "periodicModeProperties.backupRetentionIntervalInHours", int)
        if hours <= 0:
            raise Unavailable("Cosmos periodic backup retention invalid")
        return mode, hours
    if mode == "Continuous":
        tier = get(policy, "continuousModeProperties.tier", str)
        days = {"Continuous7Days": 7, "Continuous30Days": 30}.get(tier)
        if days is None:
            raise Unavailable("Cosmos continuous backup tier unrecognized")
        return mode, days * 24
    raise Unavailable("Cosmos backup mode unrecognized")


@register(COSMOS_ID, "azure", "hardening", "cosmos_account",
          "Cosmos DB backup retention meets the approved account minimum", "medium", "CP-9",
          "Confirm the account's approved retention and restore requirements with its owner; review mode, tier, cost and migration limits before changing the owned Cosmos DB backup policy or IaC, then verify a restorable backup independently.",
          target="scope", dependencies=["cosmos_account"])
def cosmos_backup_retention(item, index):
    scope = get(item, "scope", str).rstrip("/")
    if not _SCOPE.fullmatch(scope):
        return "NOT_APPLICABLE", {"reason": "Cosmos backup retention is evaluated at subscription scope"}
    accounts = complete_items(index, "cosmos_account")
    if not accounts:
        return "NOT_APPLICABLE", {"reason": "complete subscription inventory contains no Cosmos DB accounts"}
    owner = _owner(index)
    observed = set()
    failures, unresolved, examples = 0, 0, []
    for account in accounts:
        try:
            rid = get(account, "id", str)
            if not _ACCOUNT.fullmatch(rid) or not rid.casefold().startswith(scope.casefold() + "/"):
                raise Unavailable("Cosmos account identity outside selected subscription")
            key = rid.casefold()
            if key in observed:
                raise Unavailable("duplicate Cosmos account identity")
            observed.add(key)
            policy = owner.get(key)
            if policy is None or policy[0] != scope.casefold():
                raise Unavailable("Cosmos account lacks a current approved retention minimum")
            mode, hours = _retention_hours(account)
            if hours < policy[1] * 24:
                failures += 1
                if len(examples) < 20:
                    examples.append({"resource_id": rid, "mode": mode, "observed_hours": hours,
                                     "required_hours": policy[1] * 24})
        except Unavailable:
            unresolved += 1
    selected = {rid for rid, (owner_scope, _) in owner.items() if owner_scope == scope.casefold()}
    if selected - observed:
        unresolved += len(selected - observed)
    evidence = {"scope": scope, "account_count": len(accounts), "below_minimum_count": failures,
                "unresolved_count": unresolved, "below_minimum_examples": examples,
                "semantics": "Configured backup retention only; backup completion and restore readiness unverified"}
    if failures:
        return result(True, **evidence)
    if unresolved:
        return unknown("Cosmos backup policy or account facts incomplete", **evidence)
    return result(False, **evidence)


_CASE_SCOPE = "/subscriptions/sub"
_CASE_ID = _CASE_SCOPE + "/resourceGroups/rg/providers/Microsoft.DocumentDB/databaseAccounts/account-a"
_CASE_POLICY = {"status": "collected", "observed_at": "2026-10-12T00:00:00Z", "max_age_seconds": 600,
                "max_policy_items": 10, "accounts": [{"subscription_scope": _CASE_SCOPE,
                                                     "resource_id": _CASE_ID, "min_retention_days": 7}]}


def _case_index(hours):
    return {"context": {"scope": _CASE_SCOPE, "created_at": "2026-10-12T00:00:00Z",
                        "metadata": {"cosmos_backup_retention": _CASE_POLICY}},
            "collections": {"cosmos_account": [{"status": "collected", "scope": _CASE_SCOPE}]},
            "cosmos_account": [{"data": {"id": _CASE_ID, "properties": {"backupPolicy": {
                "type": "Periodic", "periodicModeProperties": {"backupRetentionIntervalInHours": hours}}}}}]}


CASES[COSMOS_ID] = {"pass": {"scope": _CASE_SCOPE}, "fail": {"scope": _CASE_SCOPE},
                    "missing": {"scope": _CASE_SCOPE}, "pass_index": _case_index(168),
                    "fail_index": _case_index(24),
                    "unknown_index": {**_case_index(168), "collections": {"cosmos_account": [{"status": "denied"}]}}}
