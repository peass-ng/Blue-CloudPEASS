"""Effective Defender pricing for agentless Kubernetes discovery, per AKS cluster."""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects


ID = "azure.cis.agentless_discovery_kubernetes_component_status"
SPEC_SHA256 = "1f98a3ca6689b7b5940ac053f15b223764c27b733b76ea30ed312749bfb9a666"
_PLANS = {"Containers", "CloudPosture"}
_EXTENSION = "AgentlessDiscoveryForKubernetes"
_AKS_ID = re.compile(
    r"^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/"
    r"Microsoft\.ContainerService/managedClusters/[^/]+$", re.I)
_SUBSCRIPTION = re.compile(r"^/subscriptions/[^/]+$", re.I)


def _scope(item, index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "azure":
        raise Unavailable("Azure context unavailable")
    scope = get(context, "scope", str)
    if not _SUBSCRIPTION.fullmatch(scope) or get(item, "scope", str).casefold() != scope.casefold():
        raise Unavailable("subscription scope missing or foreign")
    return scope


def _inventory(index, kind, scope):
    collections = get(index, "collections", dict)
    envelopes = collections.get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("inventory missing or ambiguous: " + kind)
    envelope = envelopes[0]
    if (get(envelope, "type", str) != kind or
            get(envelope, "scope", str).casefold() != scope.casefold()):
        raise Unavailable("foreign inventory: " + kind)
    rows = complete_items(index, kind)
    declared = get(envelope, "items", list)
    wrappers = get(index, kind, list)
    if (len(rows) != len(declared) or len(rows) != len(wrappers) or
            (get(envelope, "status", str) == "empty") != (len(rows) == 0)):
        raise Unavailable("inventory count or status conflict: " + kind)
    for row, native, wrapper in zip(rows, declared, wrappers):
        if (native != row or get(wrapper, "type", str) != kind or
                get(wrapper, "scope", str).casefold() != scope.casefold()):
            raise Unavailable("inventory row has foreign or conflicting scope: " + kind)
    return rows


def _clusters(index, scope):
    rows = _inventory(index, "aks_cluster", scope)
    identities = set()
    for row in rows:
        rid = get(row, "id", str)
        if (not _AKS_ID.fullmatch(rid) or
                not rid.casefold().startswith(scope.casefold() + "/") or
                rid.casefold() in identities):
            raise Unavailable("AKS identity malformed, duplicate, or foreign")
        identities.add(rid.casefold())
    return identities


def _pricing_rows(index, scope, clusters):
    rows = _inventory(index, "defender_pricing", scope)
    found = {}
    for row in rows:
        cluster = get(row, "id", str)
        key = cluster.casefold()
        if (not _AKS_ID.fullmatch(cluster) or key not in clusters or
                key in found):
            raise Unavailable("effective pricing cluster identity missing, duplicate, or foreign")
        provenance = get(row, "_provenance", dict)
        if (get(provenance, "source_operation", str) != "Microsoft.Security/pricings GET" or
                get(provenance, "api_version", str) != "2024-01-01" or
                get(provenance, "read_only", bool) is not True or
                get(provenance, "effective_scope", str).casefold() != key):
            raise Unavailable("effective resource-scope pricing provenance unavailable")
        plans = list_of_objects(get(row, "plans", list))
        by_name = {}
        for plan in plans:
            name = get(plan, "name", str)
            if name not in _PLANS or name in by_name:
                raise Unavailable("pricing plan missing, unsupported, or duplicate")
            expected = cluster + "/providers/Microsoft.Security/pricings/" + name
            if get(plan, "id", str).casefold() != expected.casefold():
                raise Unavailable("pricing plan is not a resource-scope GET result")
            by_name[name] = plan
        if set(by_name) != _PLANS:
            raise Unavailable("both effective Defender plans were not read")
        found[key] = by_name
    if set(found) != clusters:
        raise Unavailable("effective pricing missing for an AKS cluster")
    return found


def _plan_enabled(plan):
    properties = get(plan, "properties", dict)
    tier = get(properties, "pricingTier", str)
    if tier not in ("Free", "Standard"):
        raise Unavailable("unsupported Defender pricing tier")
    inherited = get(properties, "inherited", str)
    if inherited not in ("True", "False"):
        raise Unavailable("unsupported pricing inheritance value")
    if inherited == "True":
        parent = get(properties, "inheritedFrom", str)
        rid = get(plan, "id", str)
        cluster = rid.rsplit("/providers/Microsoft.Security/pricings/", 1)[0]
        if not parent or not cluster.casefold().startswith(parent.casefold() + "/"):
            raise Unavailable("pricing inheritance parent is missing or foreign")
    elif "inheritedFrom" in properties or "inheritedFrom" in properties.get("_coverage", {}):
        parent = get(properties, "inheritedFrom", (str, type(None)))
        if parent:
            raise Unavailable("non-inherited pricing names a foreign inheritance parent")
    extensions = list_of_objects(get(properties, "extensions", list))
    matched = []
    for extension in extensions:
        name = get(extension, "name", str)
        if not name:
            raise Unavailable("unnamed Defender pricing extension")
        if name == _EXTENSION:
            matched.append(extension)
    if len(matched) > 1:
        raise Unavailable("duplicate agentless Kubernetes extension")
    if not matched:
        return False
    extension = matched[0]
    enabled = get(extension, "isEnabled", str)
    if enabled not in ("True", "False"):
        raise Unavailable("unsupported agentless Kubernetes extension enablement")
    if "operationStatus" in extension or "operationStatus" in extension.get("_coverage", {}):
        operation = get(extension, "operationStatus", dict)
        code = get(operation, "code", str)
        if code == "Failed":
            raise Unavailable("agentless Kubernetes extension operation failed")
        if code not in ("Succeeded", "Success"):
            raise Unavailable("unrecognized agentless Kubernetes operation status")
    return tier == "Standard" and enabled == "True"


@register(ID, "azure", "hardening", "defender_pricing",
          "Ensure that 'Agentless discovery for Kubernetes' component status 'On'",
          "medium", "CM-6",
          "Azure portal > Defender for Cloud > Environment settings > select subscription > Defender plans > Containers: set Standard and turn on Agentless discovery for Kubernetes.",
          target="scope", dependencies=["aks_cluster", "defender_pricing"])
def agentless_discovery_kubernetes(item, index):
    scope = _scope(item, index)
    clusters = _clusters(index, scope)
    if not clusters:
        # The signed predicate applies per in-scope cluster.
        return "NOT_APPLICABLE", {"reason": "complete AKS inventory has no clusters"}
    plans = _pricing_rows(index, scope, clusters)
    disabled = []
    for cluster in sorted(clusters):
        active = [_plan_enabled(plans[cluster][name]) for name in sorted(_PLANS)]
        if not any(active):
            disabled.append(cluster)
    if disabled:
        return result(True, cluster_count=len(clusters), clusters_without_enabled_extension=disabled,
                      semantics="Complete effective Defender pricing configuration; discovery activity unverified")
    return result(False, cluster_count=len(clusters),
                  semantics="Complete effective Defender pricing configuration; discovery activity unverified")
