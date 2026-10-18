"""Three signed Kubernetes declaration checks over complete collected facts.

These verdicts do not prove effective RBAC authorization, group membership,
tenant isolation, or overall framework compliance.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import json
import re
from urllib.parse import quote

from . import register, result, unknown
from .facts import Unavailable, get, memoized, optional

IDS = (
    "k8s.cis.avoid_use_of_system_masters_group",
    "k8s_response_team_required_binding",
    "k8s_pod_pod_deployed_within_specific_namespace_0daa0bd46b",
)
KINDS = {IDS[0]: "clusterrolebinding", IDS[1]: "rolebinding", IDS[2]: "pod"}
DEPENDENCIES = {IDS[0]: ("clusterrolebinding", "rolebinding"),
                IDS[1]: ("rolebinding", "clusterrolebinding")}
_NAMESPACED = {"rolebinding", "pod"}


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "k8s":
        raise Unavailable("Kubernetes context unavailable")
    scope = get(context, "scope", str)
    cluster = get(get(context, "metadata", dict), "cluster_id", str)
    if not scope or not cluster:
        raise Unavailable("cluster or scope unavailable")
    return context, scope, cluster


def _inventory(index, kind):
    """Validate one entire collection and build its ID map once per MemoIndex."""
    context, scope, cluster = _context(index)

    def build():
        pages = get(get(index, "collections", dict), kind, list)
        if not pages:
            raise Unavailable("dependency not collected: " + kind)
        native = []
        for page in pages:
            if (get(page, "type", str) != kind or get(page, "scope", str) != scope or
                    get(page, "status", str) not in ("collected", "empty")):
                raise Unavailable("incomplete or foreign inventory: " + kind)
            items = get(page, "items", list)
            if page["status"] == "empty" and items:
                raise Unavailable("empty inventory has resources")
            native.extend(items)
        # The engine omits the wrapper key for a complete empty collection.
        wrappers = index.get(kind, [])
        if not isinstance(wrappers, list):
            raise Unavailable("resource wrappers malformed")
        data = []
        for wrapper in wrappers:
            if (get(wrapper, "scope", str) != scope or get(wrapper, "type", str) != kind or
                    wrapper.get("provider", "k8s") != "k8s"):
                raise Unavailable("foreign resource wrapper")
            data.append(get(wrapper, "data", dict))
        try:
            encode = lambda rows: Counter(json.dumps(row, sort_keys=True) for row in rows)
            if encode(data) != encode(native):
                raise Unavailable("collection and wrapper facts differ")
        except (TypeError, ValueError) as exc:
            raise Unavailable("malformed collection facts") from exc
        by_id, by_name = {}, set()
        for row in data:
            provenance = get(row, "provenance", dict)
            if get(provenance, "cluster_id", str) != cluster or get(provenance, "evidence", str) != "read-only list":
                raise Unavailable("unverified resource provenance")
            rid = get(row, "id", str)
            name = get(row, "metadata.name", str)
            ns = get(row, "metadata.namespace", str) if kind in _NAMESPACED else "_cluster"
            token = optional(get(row, "metadata", dict), "uid", name, str)
            expected_id = "k8s://" + "/".join(quote(str(x), safe="") for x in (cluster, kind, ns, token))
            if rid != expected_id or not name or (kind in _NAMESPACED and not ns):
                raise Unavailable("resource identity unavailable")
            if kind in _NAMESPACED and scope != "*" and ns != scope:
                raise Unavailable("resource outside namespace scope")
            if rid in by_id or (ns, name) in by_name:
                raise Unavailable("duplicate resource identity")
            by_id[rid] = row
            by_name.add((ns, name))
        return by_id

    return memoized(index, ("native_next_inventory", kind, scope, cluster), build)


def _member(item, index, kind):
    rows = _inventory(index, kind)
    rid = get(item, "id", str)
    if rid not in rows or rows[rid] != item:
        raise Unavailable("resource not in complete collection")
    return item


def _policy(index, key, typ):
    context, _, cluster = _context(index)
    policy = get(get(context, "metadata", dict), "compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "cluster_id", str) != cluster:
        raise Unavailable("operator policy unavailable or foreign cluster")
    observed = get(policy, "observed_at", str)
    age = get(policy, "max_age_seconds", int)
    captured = get(context, "created_at", str)
    try:
        delta = (datetime.fromisoformat(captured.replace("Z", "+00:00")) -
                 datetime.fromisoformat(observed.replace("Z", "+00:00"))).total_seconds()
    except ValueError as exc:
        raise Unavailable("operator policy timestamp invalid") from exc
    if age <= 0 or not 0 <= delta <= age:
        raise Unavailable("operator policy stale or future")
    return get(policy, key, typ)


def _names(index, key):
    names = _policy(index, key, list)
    if not names or any(not isinstance(x, str) or not (key == "allowed_namespaces" and x == "*" or
               re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", x)) for x in names) or len(names) != len(set(names)):
        raise Unavailable("operator name list malformed")
    return set(names)


def _subjects(row, binding_kind):
    subjects = optional(row, "subjects", [], list)
    for subject in subjects:
        if not isinstance(subject, dict):
            raise Unavailable("RBAC subject malformed")
        kind = get(subject, "kind", str)
        if kind not in ("User", "Group", "ServiceAccount") or not get(subject, "name", str):
            raise Unavailable("RBAC subject malformed")
        # Kubernetes defaults apiGroup by subject kind. Its RBAC resolver
        # defaults an unqualified RoleBinding SA to the binding namespace.
        api_group = optional(subject, "apiGroup", "" if kind == "ServiceAccount" else
                             "rbac.authorization.k8s.io", str)
        namespace = optional(subject, "namespace", "", str)
        if api_group != ("" if kind == "ServiceAccount" else "rbac.authorization.k8s.io"):
            raise Unavailable("RBAC subject API group malformed")
        if kind == "ServiceAccount" and not namespace:
            if binding_kind == "rolebinding":
                namespace = get(row, "metadata.namespace", str)
            if not namespace:
                raise Unavailable("ServiceAccount subject namespace unavailable")
        if kind != "ServiceAccount" and namespace:
            raise Unavailable("User or Group subject has namespace")
    return subjects


def _system_masters_subjects(row):
    """Inspect only subjects that could be the selected Group identity."""
    subjects = optional(row, "subjects", [], list)
    matches = []
    for subject in subjects:
        if not isinstance(subject, dict):
            raise Unavailable("RBAC subject kind unavailable")
        kind = get(subject, "kind", str)
        if kind != "Group":
            continue
        name = get(subject, "name", str)
        if name != "system:masters":
            continue
        api_group = optional(subject, "apiGroup", "rbac.authorization.k8s.io", str)
        namespace = optional(subject, "namespace", "", str)
        if api_group != "rbac.authorization.k8s.io":
            raise Unavailable("system:masters Group API group malformed")
        if namespace:
            raise Unavailable("system:masters Group has namespace")
        matches.append(subject)
    return matches


def _evaluate(check_id, item, index):
    kind = KINDS[check_id]
    if check_id == IDS[0]:
        context, _, _ = _context(index)
        if item != context:
            raise Unavailable("scope target mismatch")
        inventories = {kind: _inventory(index, kind) for kind in ("clusterrolebinding", "rolebinding")}
        matches = []
        for binding_kind, bindings in inventories.items():
            for binding in bindings.values():
                for _ in _system_masters_subjects(binding):
                    matches.append({"kind": binding_kind, "binding_id": binding["id"]})
        if matches:
            return result(True, affected_bindings=matches, semantics="observed RBAC bindings only")
        return unknown("RBAC bindings contain no system:masters subject; certificate and provider group memberships unobserved")
    if check_id == IDS[1]:
        context, scope, _ = _context(index)
        if item != context:
            raise Unavailable("scope target mismatch")
        allowed = _names(index, "allowed_namespaces")
        required = tuple(_policy(index, key, str) for key in
                         ("required_subject_kind", "required_subject_name", "required_role_kind", "required_role_name"))
        if required[0] not in ("User", "Group", "ServiceAccount") or required[2] not in ("Role", "ClusterRole") or not required[1] or not required[3]:
            raise Unavailable("required binding policy malformed")
        if required[0] == "ServiceAccount":
            raise Unavailable("required ServiceAccount namespace absent from trusted operator policy")
        bindings = [(k, row) for k in ("rolebinding", "clusterrolebinding") for row in _inventory(index, k).values()]
        matches = []
        for binding_kind, row in bindings:
            if get(row, "roleRef.apiGroup", str) != "rbac.authorization.k8s.io":
                raise Unavailable("role reference API group malformed or unavailable")
            role = (get(row, "roleRef.kind", str), get(row, "roleRef.name", str))
            if role[0] not in ("Role", "ClusterRole") or not role[1] or (binding_kind == "clusterrolebinding" and role[0] != "ClusterRole"):
                raise Unavailable("role reference malformed")
            namespace = get(row, "metadata.namespace", str) if binding_kind == "rolebinding" else "*"
            for subject in _subjects(row, binding_kind):
                if namespace in allowed and role == required[2:] and (subject["kind"], subject["name"]) == required[:2]:
                    matches.append(row["id"])
        if matches:
            return result(False, binding_id=matches[0], semantics="declared binding only")
        return result(True, semantics="required declared binding absent")

    _member(item, index, kind)
    if check_id == IDS[2]:
        namespace = get(item, "metadata.namespace", str)
        return result(namespace not in _names(index, "approved_namespaces"), namespace=namespace)
    raise Unavailable("unsupported candidate ID")


def evaluate(check_id, item, index):
    if check_id not in IDS:
        raise ValueError("unknown Kubernetes declaration check ID")
    try:
        return _evaluate(check_id, item, index)
    except (Unavailable, ValueError, TypeError, KeyError) as exc:
        return unknown(str(exc))


@register(IDS[0], "k8s", "least_privilege", "clusterrolebinding",
          "Observed RBAC bindings avoid the system:masters Group", "high", "AC-6",
          "Remove observed system:masters Group subjects from owned bindings and review certificate/provider group membership separately.",
          target="scope", dependencies=DEPENDENCIES[IDS[0]])
def system_masters_binding(item, index):
    return evaluate(IDS[0], item, index)


@register(IDS[1], "k8s", "least_privilege", "rolebinding",
          "Required response team RBAC binding is declared", "medium", "AC-2",
          "Declare the owner-required User or Group binding within an allowed namespace and verify effective authorization separately.",
          target="scope", dependencies=DEPENDENCIES[IDS[1]])
def response_team_binding(item, index):
    return evaluate(IDS[1], item, index)


@register(IDS[2], "k8s", "hardening", "pod",
          "Pod is declared in an approved namespace", "medium", "CM-6",
          "Set the Pod or controller manifest namespace to an approved namespace and review actual tenant isolation separately.",
          dependencies=["pod"])
def pod_approved_namespace(item, index):
    return evaluate(IDS[2], item, index)
