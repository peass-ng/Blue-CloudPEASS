"""Snapshot-only Azure gateway redirect and VM platform metric declarations.

These are configuration checks, not probes of traffic or proof of log delivery.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, list_of_objects, memoized, optional
from .fixtures import CASES

GATEWAY_ID = "azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7"
VM_ID = "azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679"
IDS = (GATEWAY_ID, VM_ID)
_REDIRECT_TYPES = {"Permanent", "Found", "SeeOther", "Temporary"}
_ARM_PART = r"[A-Za-z0-9._-]+"
_RESOURCE_PREFIX = rf"/subscriptions/{_ARM_PART}/resourceGroups/{_ARM_PART}/providers/"
_DESTINATIONS = {
    "workspaceId": re.compile(_RESOURCE_PREFIX + rf"Microsoft\.OperationalInsights/workspaces/{_ARM_PART}", re.I),
    "storageAccountId": re.compile(_RESOURCE_PREFIX + rf"Microsoft\.Storage/storageAccounts/{_ARM_PART}", re.I),
    "eventHubAuthorizationRuleId": re.compile(_RESOURCE_PREFIX + rf"Microsoft\.EventHub/namespaces/{_ARM_PART}/(?:eventhubs/{_ARM_PART}/)?authorizationRules/{_ARM_PART}", re.I),
    # The REST contract permits Marketplace partners of several provider
    # types; without a known provider/type we cannot validate an ID here.
}


def _validated_inventory(index, kind):
    def validate():
        complete_items(index, kind)
        return True
    memoized(index, ("compliance_new_azure_network_monitoring", kind), validate)


def _objects(properties, name):
    return list_of_objects(get(properties, name, list))


def _identity(row, parent, kind):
    rid = get(row, "id", str)
    prefix = parent.rstrip("/") + "/" + kind + "/"
    if not rid.casefold().startswith(prefix.casefold()) or not rid[len(prefix):] or "/" in rid[len(prefix):]:
        raise Unavailable("malformed or foreign Application Gateway child identity")
    return rid.casefold()


def _indexed(rows, parent, kind):
    found = {}
    for row in rows:
        identity = _identity(row, parent, kind)
        if identity in found:
            raise Unavailable("duplicate Application Gateway child identity")
        found[identity] = row
    return found


def _reference(properties, key, parent, kind):
    value = optional(properties, key, None)
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Unavailable("malformed Application Gateway route reference")
    return _identity(value, parent, kind)


def _redirect(ref, redirects, listeners, parent):
    redirect = redirects.get(ref)
    if redirect is None:
        raise Unavailable("Application Gateway redirect reference unresolved")
    properties = get(redirect, "properties", dict)
    if get(properties, "redirectType", str) not in _REDIRECT_TYPES:
        raise Unavailable("unsupported Application Gateway redirect type")
    listener = _reference(properties, "targetListener", parent, "httpListeners")
    target_url = optional(properties, "targetUrl", None)
    if listener is not None and target_url is not None:
        raise Unavailable("ambiguous Application Gateway redirect target")
    if listener is not None:
        target = listeners.get(listener)
        if target is None:
            raise Unavailable("Application Gateway target listener unresolved")
        protocol = get(target, "properties.protocol", str)
        if protocol not in ("Http", "Https"):
            raise Unavailable("unsupported Application Gateway target protocol")
        return protocol == "Https"
    if not isinstance(target_url, str) or not target_url:
        raise Unavailable("Application Gateway redirect target missing")
    try:
        parsed = urlsplit(target_url)
        if not parsed.hostname or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("invalid URL authority")
    except ValueError as exc:
        raise Unavailable("malformed Application Gateway target URL") from exc
    if parsed.scheme.casefold() not in ("http", "https"):
        raise Unavailable("unsupported Application Gateway target URL scheme")
    return parsed.scheme.casefold() == "https"


def _route(properties, parent, redirects, listeners):
    ref = _reference(properties, "redirectConfiguration", parent, "redirectConfigurations")
    if ref is not None:
        return _redirect(ref, redirects, listeners, parent)
    # A fully resolved backend route without redirection is an observed gap.
    for key, kind in (("backendAddressPool", "backendAddressPools"),
                      ("backendHttpSettings", "backendHttpSettingsCollection")):
        if _reference(properties, key, parent, kind) is not None:
            return False
    raise Unavailable("Application Gateway route has no resolved redirect or backend")


@register(GATEWAY_ID, "azure", "hardening", "application_gateway",
          "Application Gateway HTTP routes declare HTTPS redirects", "medium", "SC-8",
          "Review each HTTP listener and effective basic/path route with the gateway owner; configure a supported HTTPS listener or URL redirect in IaC, account for client method and cache impact, and validate the resulting routing after rollout.",
          dependencies=["application_gateway"])
def gateway_http_redirect(item, index):
    _validated_inventory(index, "application_gateway")
    parent = get(item, "id", str)
    properties = get(item, "properties", dict)
    listeners = _indexed(_objects(properties, "httpListeners"), parent, "httpListeners")
    rules = _indexed(_objects(properties, "requestRoutingRules"), parent, "requestRoutingRules")
    redirects = _indexed(_objects(properties, "redirectConfigurations"), parent, "redirectConfigurations")
    maps = _indexed(_objects(properties, "urlPathMaps"), parent, "urlPathMaps")
    http = set()
    for rid, listener in listeners.items():
        protocol = get(listener, "properties.protocol", str)
        if protocol not in ("Http", "Https"):
            raise Unavailable("unsupported Application Gateway listener protocol")
        if protocol == "Http":
            http.add(rid)
    if not http:
        return "NOT_APPLICABLE", {"reason": "No HTTP listener in the complete gateway declaration"}
    # Index once, then walk each declared route. A missing route cannot prove a redirect.
    seen, assessed, forwarding, uncertain = set(), 0, 0, 0
    for row in rules.values():
        rule = get(row, "properties", dict)
        listener = _reference(rule, "httpListener", parent, "httpListeners")
        if listener not in http:
            if listener not in listeners:
                uncertain += 1
            continue
        seen.add(listener)
        kind = get(rule, "ruleType", str)
        if kind == "Basic":
            routes = [rule]
        elif kind == "PathBasedRouting":
            map_ref = _reference(rule, "urlPathMap", parent, "urlPathMaps")
            path_map = maps.get(map_ref)
            if path_map is None:
                uncertain += 1
                continue
            map_properties = get(path_map, "properties", dict)
            routes = [{"redirectConfiguration": optional(map_properties, "defaultRedirectConfiguration", None),
                       "backendAddressPool": optional(map_properties, "defaultBackendAddressPool", None),
                       "backendHttpSettings": optional(map_properties, "defaultBackendHttpSettings", None)}]
            path_ids = set()
            for path in _objects(map_properties, "pathRules"):
                path_id = get(path, "id", str)
                prefix = map_ref + "/pathrules/"
                if (not path_id.casefold().startswith(prefix) or not path_id[len(prefix):]
                        or "/" in path_id[len(prefix):] or path_id.casefold() in path_ids):
                    raise Unavailable("malformed Application Gateway path rule identity")
                path_ids.add(path_id.casefold())
                routes.append(get(path, "properties", dict))
        else:
            uncertain += 1
            continue
        for route in routes:
            try:
                good = _route(route, parent, redirects, listeners)
            except Unavailable:
                uncertain += 1
                continue
            assessed += 1
            forwarding += not good
    if forwarding:
        return result(True, http_listener_count=len(http), assessed_route_count=assessed,
                      non_https_route_count=forwarding, uncertain_route_count=uncertain,
                      semantics="Observed route declarations; live redirect behavior untested")
    if uncertain or seen != http or not assessed:
        return unknown("HTTP listener route or redirect unresolved", http_listener_count=len(http),
                       assessed_route_count=assessed, uncertain_route_count=uncertain,
                       unbound_listener_count=len(http - seen))
    return result(False, http_listener_count=len(http), assessed_route_count=assessed,
                  semantics="Configured HTTPS redirects; live traffic and certificate validity untested")


@register(VM_ID, "azure", "hardening", "vm",
          "Azure VM declares export of platform metrics to a destination", "medium", "AU-12",
          "Review VM platform metric support and the approved monitoring destination; enable AllMetrics export in a VM diagnostic setting through owned IaC after cost review, then verify ingestion separately. Guest OS telemetry requires separate AMA and DCR review.",
          dependencies=["vm"])
def vm_platform_metrics(item, index):
    _validated_inventory(index, "vm")
    rid = get(item, "id", str)
    coverage = get(item, "_coverage.diagnosticSettings", dict)
    if get(coverage, "status", str) not in ("collected", "empty"):
        raise Unavailable("VM diagnostic settings inventory incomplete")
    settings = _objects(item, "diagnosticSettings")
    if not settings:
        return result(True, vm_id=rid, setting_count=0,
                      semantics="No per-VM platform-metric export setting observed; guest telemetry unassessed")
    uncertain = False
    for setting in settings:
        try:
            if get(setting, "parent_id", str).casefold() != rid.casefold():
                raise Unavailable("VM diagnostic setting belongs to another resource")
            setting_id = get(setting, "id", str)
            prefix = rid.rstrip("/") + "/providers/Microsoft.Insights/diagnosticSettings/"
            if (not setting_id.casefold().startswith(prefix.casefold()) or
                    not setting_id[len(prefix):] or "/" in setting_id[len(prefix):]):
                raise Unavailable("VM diagnostic setting native identity malformed or foreign")
            metrics = _objects(get(setting, "properties", dict), "metrics")
            for metric in metrics:
                category = get(metric, "category", str)
                enabled = get(metric, "enabled", bool)
                if category != "AllMetrics":
                    # Specific enabled categories may satisfy an owner-approved
                    # required set; that set is not collected by this check.
                    uncertain |= enabled
                    continue
                if not enabled:
                    continue
                props = get(setting, "properties", dict)
                destinations = [(key, optional(props, key, None)) for key in
                                (*_DESTINATIONS, "marketplacePartnerId")]
                if any(isinstance(value, str) and pattern.fullmatch(value) for key, value in destinations
                       if (pattern := _DESTINATIONS.get(key)) is not None):
                    return result(False, vm_id=rid, setting_count=len(settings), metric_category="AllMetrics",
                                  semantics="Configured platform-metric export only; destination existence, ingestion and guest AMA/DCR unverified")
                uncertain = True
        except Unavailable:
            uncertain = True
    if uncertain:
        return unknown("VM platform-metric export or destination unresolved", vm_id=rid,
                       setting_count=len(settings))
    return result(True, vm_id=rid, setting_count=len(settings),
                  semantics="No enabled AllMetrics export observed in complete VM diagnostic settings; guest telemetry unassessed")


_GATEWAY = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/applicationGateways/gw"
_VM = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
_REDIRECT = {"id": _GATEWAY + "/redirectConfigurations/redirect",
             "properties": {"redirectType": "Permanent",
                            "targetListener": {"id": _GATEWAY + "/httpListeners/secure"}}}
_GATEWAY_PASS = {"id": _GATEWAY, "properties": {
    "httpListeners": [{"id": _GATEWAY + "/httpListeners/http", "properties": {"protocol": "Http"}},
                      {"id": _GATEWAY + "/httpListeners/secure", "properties": {"protocol": "Https"}}],
    "redirectConfigurations": [_REDIRECT], "urlPathMaps": [],
    "requestRoutingRules": [{"id": _GATEWAY + "/requestRoutingRules/route", "properties": {
        "ruleType": "Basic", "httpListener": {"id": _GATEWAY + "/httpListeners/http"},
        "redirectConfiguration": {"id": _REDIRECT["id"]}}}]}}
_VM_PASS = {"id": _VM, "_coverage": {"diagnosticSettings": {"status": "collected"}},
            "diagnosticSettings": [{"id": _VM + "/providers/Microsoft.Insights/diagnosticSettings/platform",
                                    "parent_id": _VM, "properties": {
                "metrics": [{"category": "AllMetrics", "enabled": True}],
                "workspaceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/logs"}}]}
CASES[GATEWAY_ID] = {"pass": _GATEWAY_PASS,
                     "fail": {**_GATEWAY_PASS, "properties": {**_GATEWAY_PASS["properties"],
                              "redirectConfigurations": [{**_REDIRECT, "properties": {
                                  "redirectType": "Permanent", "targetUrl": "http://example.org"}}]}},
                     "missing": {"id": _GATEWAY, "properties": {}},
                     "malformed": {"id": _GATEWAY, "properties": {"httpListeners": "bad"}},
                     "index": {"collections": {"application_gateway": [{"status": "collected"}]},
                               "application_gateway": [{"data": _GATEWAY_PASS}]}}
CASES[VM_ID] = {"pass": _VM_PASS,
                "fail": {"id": _VM, "_coverage": {"diagnosticSettings": {"status": "empty"}},
                         "diagnosticSettings": []},
                "missing": {"id": _VM},
                "malformed": {"id": _VM, "_coverage": {"diagnosticSettings": {"status": "collected"}},
                              "diagnosticSettings": "bad"},
                "index": {"collections": {"vm": [{"status": "collected"}]},
                          "vm": [{"data": _VM_PASS}]}}
