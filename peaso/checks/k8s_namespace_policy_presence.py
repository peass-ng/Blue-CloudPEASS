"""Signed CIS 5.3.2 namespace NetworkPolicy declaration check."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import re
from urllib.parse import quote

from . import register, result
from .facts import Unavailable, complete_items, get, memoized


def _inventory(index, kind, scope):
    pages = get(index, "collections", dict).get(kind)
    if not isinstance(pages, list) or not pages:
        raise Unavailable("dependency not collected: " + kind)
    if any(not isinstance(page, dict) or page.get("scope") != scope or
           page.get("type") != kind or page.get("status") not in ("collected", "empty") or
           page.get("status") == "empty" and page.get("items") != [] for page in pages):
        raise Unavailable("incomplete or foreign-scope " + kind + " inventory")
    wrappers = index.get(kind, [])
    if not isinstance(wrappers, list) or any(not isinstance(row, dict) or
           row.get("scope") != scope or row.get("type") != kind or
           row.get("provider", "k8s") != "k8s" for row in wrappers):
        raise Unavailable("foreign or malformed resource wrappers in " + kind)
    rows = complete_items(index, kind)
    raw = [item for page in pages for item in get(page, "items", list)]
    try:
        if Counter(json.dumps(row, sort_keys=True) for row in rows) != Counter(
                json.dumps(row, sort_keys=True) for row in raw):
            raise Unavailable("inventory content mismatch")
    except (TypeError, ValueError) as exc:
        raise Unavailable("inventory content malformed") from exc
    return rows


def _identity(row, kind, cluster, scope):
    meta = get(row, "metadata", dict)
    name = get(meta, "name", str)
    namespace = "_cluster" if kind == "namespace" else get(meta, "namespace", str)
    provenance = get(row, "provenance", dict)
    if (not name or not namespace or provenance.get("cluster_id") != cluster or
            provenance.get("namespace") != namespace or
            kind == "namespace" and meta.get("namespace") not in (None, "") or
            scope != "*" and (name if kind == "namespace" else namespace) != scope):
        raise Unavailable("foreign or malformed namespace-policy identity")
    uid = meta.get("uid")
    if uid is not None and (not isinstance(uid, str) or not uid):
        raise Unavailable("malformed namespace-policy UID")
    if provenance.get("uid") != uid:
        raise Unavailable("namespace-policy UID provenance mismatch")
    expected = "k8s://" + "/".join(quote(part, safe="") for part in (cluster, kind, namespace, uid or name))
    if get(row, "id", str) != expected:
        raise Unavailable("namespace-policy immutable ID mismatch")
    return name, namespace


def _system_namespaces(context, cluster):
    policy = get(context, "metadata.compliance_policy", dict)
    if policy.get("status") != "collected" or policy.get("source") != "operator-supplied" or policy.get("cluster_id") != cluster:
        raise Unavailable("operator policy unavailable or foreign cluster")
    if "observed_at" in policy or "max_age_seconds" in policy:
        observed = get(policy, "observed_at", str)
        capture = get(context, "created_at", str)
        age = get(policy, "max_age_seconds", int)
        utc = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|\+00:00)"
        if (not re.fullmatch(utc, observed) or not re.fullmatch(utc, capture) or
                type(age) is not int or age <= 0):
            raise Unavailable("operator policy observation malformed")
        try:
            elapsed = (datetime.fromisoformat(capture.replace("Z", "+00:00")) -
                       datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
        except ValueError as exc:
            raise Unavailable("operator policy observation malformed") from exc
        if not 0 <= elapsed <= age:
            raise Unavailable("operator policy stale or future")
    names = get(policy, "system_namespaces", list)
    dns = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    if (not names or any(not isinstance(name, str) or len(name) > 63 or
                         not re.fullmatch(dns, name) for name in names) or
            len(names) != len(set(names))):
        raise Unavailable("operator system_namespaces malformed")
    return set(names)


def _validated_scope(index, context, cluster, scope):
    namespaces = _inventory(index, "namespace", scope)
    policies = _inventory(index, "networkpolicy", scope)
    members, counts, seen = {}, Counter(), set()
    for kind, rows in (("namespace", namespaces), ("networkpolicy", policies)):
        for row in rows:
            name, namespace = _identity(row, kind, cluster, scope)
            key = (kind, namespace, name)
            if key in seen:
                raise Unavailable("duplicate namespace-policy identity")
            seen.add(key)
            if kind == "namespace":
                identifier = get(row, "id", str)
                if identifier in members:
                    raise Unavailable("duplicate namespace-policy immutable ID")
                members[identifier] = row
            else:
                counts[namespace] += 1
    system = _system_namespaces(context, cluster)
    return members, dict(counts), frozenset(system)


@register(
    "k8s.cis.namespace_has_networkpolicy", "k8s", "network", "namespace",
    "Namespace declares at least one NetworkPolicy", "medium", "SC-7",
    "Declare a NetworkPolicy in each in-scope namespace and separately verify CNI enforcement and intended coverage.",
    dependencies=("namespace", "networkpolicy"),
)
def namespace_has_networkpolicy(item, index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "k8s":
        raise Unavailable("foreign provider")
    scope = get(context, "scope", str)
    cluster = get(context, "metadata.cluster_id", str)
    if not scope or not cluster:
        raise Unavailable("snapshot identity missing")
    members, counts, system = memoized(
        index, ("k8s_namespace_policy_presence", scope, cluster),
        lambda: _validated_scope(index, context, cluster, scope))
    canonical = members.get(get(item, "id", str))
    if canonical is None or canonical != item:
        raise Unavailable("item not present in complete namespace inventory")
    name = get(canonical, "metadata.name", str)
    if name in system:
        return "NOT_APPLICABLE", {"reason": "explicitly configured system namespace", "namespace": name}
    count = counts.get(name, 0)
    return result(count == 0, namespace=name, network_policy_count=count,
                  semantics="NetworkPolicy declaration presence only; CNI enforcement, default deny and Pod coverage unverified")
