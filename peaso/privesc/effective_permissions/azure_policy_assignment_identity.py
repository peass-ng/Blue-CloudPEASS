"""Bind Azure Policy assignment writes to a visible, writable definition and UAMI."""
from __future__ import annotations

import re

from . import items


ASSIGNMENT = "/providers/microsoft.authorization/policyassignments/"
DEFINITION = "/providers/microsoft.authorization/policydefinitions/"
WRITE_ASSIGNMENT = "microsoft.authorization/policyassignments/write"
WRITE_DEFINITION = "microsoft.authorization/policydefinitions/write"
ASSIGN_UAMI = "microsoft.managedidentity/userassignedidentities/assign/action"


def _low(value):
    return str(value or "").casefold()


def _subscription(scope):
    match = re.match(r"/subscriptions/[^/]+", scope)
    return match.group() if match else None


def _parents(model):
    known = set()
    for kind in ("subscription", "resource_group", "management_group"):
        for _, row in items(model.snapshot, kind):
            rid = _low(row.get("id"))
            if (kind == "subscription" and re.fullmatch(r"/subscriptions/[^/]+", rid)
                    or kind == "resource_group" and re.fullmatch(r"/subscriptions/[^/]+/resourcegroups/[^/]+", rid)
                    or kind == "management_group" and re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", rid)):
                known.add(rid)
    for _, row in items(model.snapshot, "policy_assignment"):
        rid = _low(row.get("id"))
        parent, marker, name = rid.rpartition(ASSIGNMENT)
        if marker and name and "/" not in name:
            known.add(parent)
    return known


def _assignment_paths(model):
    parents = _parents(model)
    paths = {(parent + ASSIGNMENT + "peaso-privesc-probe", parent)
             for parent in parents if (re.fullmatch(r"/subscriptions/[^/]+(?:/resourcegroups/[^/]+)?", parent)
                                       or re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", parent))}
    for _, row in items(model.snapshot, "policy_assignment"):
        rid = _low(row.get("id"))
        parent, marker, name = rid.rpartition(ASSIGNMENT)
        if marker and name and "/" not in name and parent in parents:
            paths.add((rid, parent))
    return sorted(paths)


def _definition_paths(model, assignment_parent):
    scopes = set()
    subscription = _subscription(assignment_parent)
    if subscription:
        scopes.add(subscription)
        scopes.update(scope for scope in model.ancestors(subscription)
                      if re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", scope))
    elif re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", assignment_parent):
        scopes.add(assignment_parent)
        scopes.update(scope for scope in model.ancestors(assignment_parent)
                      if re.fullmatch(r"/providers/microsoft.management/managementgroups/[^/]+", scope))
    paths = {scope + DEFINITION + "peaso-privesc-probe" for scope in scopes}
    for kind in ("policy_definition", "resource_graph"):
        for _, row in items(model.snapshot, kind):
            rid = _low(row.get("id"))
            parent, marker, name = rid.rpartition(DEFINITION)
            if marker and name and "/" not in name and parent in scopes:
                props = row.get("properties") or {}
                if _low(props.get("policyType")) == "custom":
                    paths.add(rid)
    return sorted(paths)


def select(model, candidates, source):
    assignments = _assignment_paths(model)
    if not assignments:
        return {}
    definition_paths = {parent: _definition_paths(model, parent) for _, parent in assignments}
    out = {}
    for tid, target in candidates.items():
        uami = target.attrs.get("uai_resource")
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned" or not uami:
            continue
        grant = model.cached_check(source, {"action": ASSIGN_UAMI}, uami)
        if grant is None or grant.confidence == "unknown":
            continue
        for assignment, parent in assignments:
            write = model.cached_check(source, {"action": WRITE_ASSIGNMENT}, assignment)
            if write is None or write.confidence == "unknown":
                continue
            if any((def_grant := model.cached_check(source, {"action": WRITE_DEFINITION}, path)) is not None
                   and def_grant.confidence != "unknown" for path in definition_paths[parent]):
                out[tid] = ("conditional", "policy_assignment_definition_and_identity_join")
                break
    return out
