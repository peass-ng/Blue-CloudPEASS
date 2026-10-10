"""Shared pure projection helpers. Native evidence is copied, never rewritten."""
from __future__ import annotations

import copy
import hashlib
import json
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps

FRAMEWORKS = ["HackTricks Cloud Best Practices"]
RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONTEXT = ContextVar("peaso_analysis_context", default=None)


@contextmanager
def analysis_context(snapshot):
    """Bounded, scan-local caches; concurrent evaluations do not share facts."""
    current = _CONTEXT.get()
    if current is not None and current["snapshot"] is snapshot:
        yield current
        return
    value = {"snapshot": snapshot, "collections": {(c["scope"], c["type"]): c for c in snapshot["collections"]},
             "derivations": {}}
    token = _CONTEXT.set(value)
    try:
        yield value
    finally:
        _CONTEXT.reset(token)


def with_analysis_context(function):
    @wraps(function)
    def wrapped(snapshot, *args, **kwargs):
        with analysis_context(snapshot):
            return function(snapshot, *args, **kwargs)
    return wrapped


def derived(resource, kind, compute):
    context = _CONTEXT.get()
    if context is None:
        return compute()
    key = (kind, node_id(resource))
    cache = context["derivations"]
    if key not in cache:
        cache[key] = compute()
    return cache[key]


def stable_id(*parts):
    encoded = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return "analysis:" + hashlib.sha256(encoded.encode()).hexdigest()[:24]


def as_list(value):
    return value if isinstance(value, list) else [] if value is None else [value]


def native_id(resource):
    return resource.get("native_id", resource.get("id", resource.get("resource_id", "")))


def node_id(resource):
    return stable_id(resource["provider"], resource["scope"], resource["type"], native_id(resource))


def source(snapshot, resource, path):
    context = _CONTEXT.get()
    if context is not None and context["snapshot"] is snapshot:
        collection = context["collections"].get((resource["scope"], resource["type"]), {})
    else:
        collection = next((c for c in snapshot["collections"]
                           if c["scope"] == resource["scope"] and c["type"] == resource["type"]), {})
    return {"snapshot_id": snapshot.get("snapshot_id"), "resource_id": native_id(resource),
            "resource_type": resource["type"], "scope": resource["scope"], "path": path,
            "collection_status": collection.get("status", "unknown"),
            "request_evidence": copy.deepcopy(resource["data"].get("_evidence", resource["data"].get("_provenance", resource["data"].get("provenance", {})))),
            "native_scope": copy.deepcopy(snapshot.get("metadata", {}).get("cluster_id"))}


def finding(snapshot, resource, category, check, title, severity, evidence, *, status="MANUAL"):
    return {"id": stable_id(category, check, node_id(resource)),
            "category": category, "check_id": check, "title": title,
            "provider": resource["provider"], "service": resource.get("service", resource["type"]),
            "resource_id": resource.get("id", native_id(resource)), "scope": resource["scope"], "severity": severity,
            "status": status, "frameworks": list(FRAMEWORKS), "evidence": copy.deepcopy(evidence),
            "remediation": "Have the resource owner validate business need, conditions, inheritance, and usage coverage; narrow grants or exposure only after review and a tested rollback plan."}


def node(resource):
    data = resource["data"]
    meta = data.get("metadata", {})
    if not isinstance(meta, dict):
        meta = {}
    label = (data.get("UserName") or data.get("RoleName") or data.get("GroupName")
             or data.get("PolicyName") or data.get("name") or meta.get("name") or native_id(resource))
    return {"id": node_id(resource), "resource_id": resource.get("id", native_id(resource)),
            "native_id": native_id(resource), "label": str(label),
            "type": resource["type"], "native_kind": resource["type"],
            "provider_specific": {"native_kind": resource["type"]},
            "provider": resource["provider"], "scope": resource["scope"],
            "evidence": {"native_resource": copy.deepcopy(data)}, "risk_annotations": []}


def relationship(source_id, target_id, kind, evidence, *, layer="structural", confidence="high"):
    path = evidence.get("source", evidence).get("path")
    return {"id": stable_id(source_id, target_id, kind, path), "source": source_id,
            "target": target_id, "type": kind, "layer": layer, "confidence": confidence,
            "evidence": copy.deepcopy(evidence)}


def usage(snapshot, resource):
    return derived(resource, "usage", lambda: _usage(snapshot, resource))


def _usage(snapshot, resource):
    data = resource["data"]
    observed = {k: copy.deepcopy(data[k]) for k in ("Usage", "usage", "LastUsed", "RoleLastUsed",
        "PasswordLastUsed", "AccessKeys", "activity", "signInActivity") if k in data}
    metadata = snapshot.get("metadata", {})
    window = metadata.get("usage_window", metadata.get("activity_window", metadata.get("coverageWindow")))
    completeness = metadata.get("usage_completeness", "unknown")
    detail = data.get("Usage", data.get("usage", {}))
    if isinstance(detail, dict):
        window = detail.get("window", window)
        completeness = detail.get("completeness", completeness)
    return {"observations": observed, "window": copy.deepcopy(window), "completeness": completeness,
            "provider_observation_context": {k: copy.deepcopy(metadata[k]) for k in
                ("usage_evidence", "activity", "activity_window", "activity_coverage", "directory_coverage", "logging_coverage") if k in metadata},
            "inactive_observation": isinstance(detail, dict) and detail.get("activity_count") == 0,
            "safe_to_remove": False,
            "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window."}


def principal_scope(provider, principal):
    import re
    text = str(principal)
    if provider == "aws":
        match = re.search(r"(?:^|:)\d{12}(?=:|$)", text)
        return match.group().strip(":") if match else None
    if provider == "gcp":
        match = re.search(r"@([^.@]+)\.iam\.gserviceaccount\.com$", text)
        return match.group(1) if match else None
    # An Azure object ID does not establish a tenant. A Kubernetes subject
    # belongs to a cluster, which cannot be inferred from its namespace.
    return None


def externality(snapshot, principal, *, tenant=None):
    text = str(principal)
    if text in {"*", "allUsers", "allAuthenticatedUsers", "system:anonymous", "system:unauthenticated"}:
        return "public"
    if text == "system:authenticated":
        return "everyone_authenticated"
    metadata = snapshot.get("metadata", {})
    allowed = metadata.get("trusted_scope_ids", [])
    if isinstance(allowed, dict):
        allowed = allowed.get(snapshot["provider"], [])
    scope = tenant or principal_scope(snapshot["provider"], text)
    if scope is not None and isinstance(allowed, list) and allowed:
        return "allowlisted" if str(scope) in allowed else "external"
    if snapshot["provider"] == "gcp" and "@" in text:
        domains = metadata.get("trusted_domains", [])
        if domains:
            return "allowlisted" if text.split("@", 1)[1] in domains else "external"
    return "unknown"
