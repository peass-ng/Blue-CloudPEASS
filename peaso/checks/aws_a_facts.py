"""AWS-A complete scoped joins and captured-clock helpers, all offline."""
from __future__ import annotations

from datetime import datetime
import re

from .facts import Unavailable, guard, get


def scope_subject(item):
    scope = get(item, "scope", str)
    account_global = (item.get("evaluation_scope") == "aws_account"
                      and item.get("Account") == scope.split("/", 1)[0]
                      and re.fullmatch(r"[0-9]{12}/global", scope))
    if not account_global and not re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
        raise Unavailable("malformed AWS account/region scope")
    return scope


def complete_items(index, kind, scope=None):
    if not isinstance(index, dict) or not isinstance(index.get("collections"), dict):
        raise Unavailable("missing collection index")
    envelopes = index["collections"].get(kind)
    if not isinstance(envelopes, list) or not envelopes:
        raise Unavailable("inventory not collected: " + kind)
    items = []
    for envelope in envelopes:
        if scope:
            account = scope.split("/")[0]
            same_scope = envelope.get("scope") == scope if isinstance(envelope, dict) else False
            same_global = isinstance(envelope, dict) and envelope.get("global") is True and envelope.get("account_id") == account
            if not same_scope and not same_global:
                raise Unavailable("foreign/unverified dependency scope: " + kind)
            if envelope.get("account_id") not in (None, account):
                raise Unavailable("conflicting dependency account identity: " + kind)
        if not isinstance(envelope, dict) or envelope.get("status") not in {"collected", "empty"}:
            raise Unavailable("incomplete inventory: " + kind)
        batch = envelope.get("items")
        if not isinstance(batch, list) or any(not isinstance(item, dict) for item in batch):
            raise Unavailable("malformed inventory: " + kind)
        if envelope["status"] == "empty" and batch:
            raise Unavailable("malformed empty inventory: " + kind)
        for item in batch:
            guard(item)
        items.extend(batch)
    return items


def captured_clock(item, index):
    provenance = item.get("_provenance", {})
    stamp = provenance.get("collected_at") if isinstance(provenance, dict) else None
    if not stamp:
        context = index.get("context", {}) if isinstance(index, dict) else {}
        stamp = context.get("created_at") if isinstance(context, dict) else None
    if not isinstance(stamp, str):
        raise Unavailable("captured snapshot clock unavailable")
    value = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    if value.tzinfo is None:
        raise Unavailable("captured snapshot clock must have a timezone")
    return value


def csv_boolean(item, field):
    value = get(item, field, str)
    if value not in {"true", "false"}:
        raise Unavailable("unsupported/malformed credential report boolean: " + field)
    return value == "true"


def api_optional(item, field, expected, default, *, operation):
    """Only a proved complete native response establishes an optional omission."""
    guard(item)
    if field in item:
        return get(item, field, expected)
    coverage_entries = item.get("_coverage", {})
    if field in coverage_entries:
        get({"value": default, "_coverage": {"value": coverage_entries[field]}}, "value")
    if get(item, "_provenance.operation", str) != operation or get(item, "_provenance.native_response_complete", bool) is not True:
        raise Unavailable("optional API omission is not proven: " + field)
    return default


def scope_fixture(kind, items, *, status=None):
    return {"collections": {kind: [{"type": kind, "scope": "123456789012/us-east-1",
        "status": status or ("collected" if items else "empty"), "items": items,
        "global": True, "account_id": "123456789012"}]}}
