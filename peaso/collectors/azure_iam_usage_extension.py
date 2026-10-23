"""Reuse a collected Azure Activity Log or fetch its missing subscription once."""
import copy
import re

from peaso.snapshot import make_snapshot

SUBSCRIPTION = re.compile(r"/subscriptions/[0-9a-fA-F-]{36}")


def enrich_snapshot(snapshot, connector):
    existing = {(c["type"], c["scope"].casefold()) for c in snapshot["collections"]}
    missing = sorted({scope for scope in snapshot.get("scopes", [])
                      if isinstance(scope, str) and SUBSCRIPTION.fullmatch(scope)
                      and ("activity_log", scope.casefold()) not in existing})
    if not missing:
        return snapshot
    from .azure import collect

    collections = copy.deepcopy(snapshot["collections"])
    # The native reader owns pagination, the Activity Log window and parallel
    # per-subscription jobs. One reader authenticates for all missing scopes.
    options = {**(connector.get("options") or {}), "inventories": ["activity_log"]}
    options.pop("_resume_collection_lookup", None)
    options.pop("_collection_callback", None)
    options.setdefault("activity_days", 90)
    selected = {**connector, "scopes": missing, "options": options}
    try:
        read = collect(selected, ["activity_log"])
        logs = {c["scope"].casefold(): c for c in read["collections"] if c["type"] == "activity_log"}
        for scope in missing:
            collections.append(logs.get(scope.casefold()) or {"type": "activity_log", "scope": scope,
                "service": "Microsoft.Insights", "status": "not_collected", "items": [],
                "error": {"code": "activity_log_missing"}})
    except Exception:
        for scope in missing:
            collections.append({"type": "activity_log", "scope": scope, "service": "Microsoft.Insights",
                "status": "unknown", "items": [], "error": {"code": "activity_log_read_failed"}})
    return make_snapshot(snapshot["provider"], snapshot["scopes"], collections,
                         created_at=snapshot["created_at"], metadata=snapshot.get("metadata"))
