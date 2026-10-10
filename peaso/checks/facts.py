"""Strict, offline accessors. An absent fact is never a safe configuration."""
from __future__ import annotations


class Unavailable(ValueError):
    pass


FIELD_SPECS = {}


def guard(item):
    if not isinstance(item, dict):
        raise Unavailable("native resource is not an object")
    if item.get("collection_status") not in (None, "collected", "empty"):
        raise Unavailable("resource detail unavailable: " + str(item["collection_status"]))
    if "_coverage" in item and not isinstance(item["_coverage"], dict):
        raise Unavailable("malformed resource fact coverage")


def get(item, path, expected=None):
    guard(item)
    value = item
    for part in path.split("."):
        if not isinstance(value, dict):
            raise Unavailable("malformed parent of " + path)
        guard(value)
        coverage = value.get("_coverage", {}).get(part) if isinstance(value.get("_coverage", {}), dict) else None
        if coverage is not None and (not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty")):
            raise Unavailable("fact unavailable or malformed coverage: " + path)
        if part not in value:
            raise Unavailable("missing fact: " + path)
        value = value[part]
    if isinstance(value, dict):
        guard(value)
    if expected is not None and (type(value) is not expected if expected in (bool, int) else not isinstance(value, expected)):
        raise Unavailable("malformed fact: " + path)
    return value


def field_check(check_id, provider, kind, path, good, bad, title, *, category="hardening", severity="medium", control="CM-6", expected=bool):
    """Register a strict scalar/list predicate and its independently specified fixture."""
    from . import register, result, unknown
    from .fixtures import CASES, nest
    FIELD_SPECS[check_id] = {"path": path, "good": good, "bad": bad, "expected": expected}
    @register(check_id, provider, category, kind, title, severity, control, "Review the collected setting and configure " + path + " according to the intended security policy.")
    def evaluate(item, index):
        value = get(item, path, expected)
        # Unknown enum variants are not failures or passes.
        if expected is str and value not in set(good if isinstance(good, tuple) else (good,)) | {bad}:
            return unknown("unrecognized setting", field=path, configured=value)
        return result(value not in good if isinstance(good, tuple) else value != good, field=path, configured=value)
    evaluate.__name__ = check_id.replace(".", "_")
    CASES[check_id] = {"pass": nest(path, good[0] if isinstance(good, tuple) else good), "fail": nest(path, bad), "missing": {}, "malformed": nest(path, {"unexpected": True})}


def list_of_objects(value):
    if not isinstance(value, list) or any(not isinstance(x, dict) for x in value):
        raise Unavailable("expected a list of native objects")
    return value
