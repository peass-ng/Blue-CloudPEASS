"""Bind Load Testing identity assignment and code execution to one resource."""
from __future__ import annotations

import re

from . import items


RG = re.compile(r"/subscriptions/[^/]+/resourcegroups/[^/]+")
SUB = re.compile(r"/subscriptions/[^/]+")
LOAD_TEST = re.compile(RG.pattern + r"/providers/microsoft\.loadtestservice/loadtests/[^/]+")
ASSIGN = {"action": "microsoft.managedidentity/userassignedidentities/assign/action"}
WRITE = {"action": "microsoft.loadtestservice/loadtests/write"}
WRITE_TEST = {"action": "microsoft.loadtestservice/loadtests/writetest/action", "data_action": True}
START_TEST = {"action": "microsoft.loadtestservice/loadtests/starttest/action", "data_action": True}
CREATE_RG = {"action": "microsoft.resources/subscriptions/resourcegroups/write"}


def _low(value):
    return value.casefold() if isinstance(value, str) else ""


def _held(model, source, action, scope):
    grant = model.cached_check(source, action, scope)
    return grant is not None and grant.confidence != "unknown"


def select(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    resources = {rid for rid, row in model.resources.items()
                 if row.get("type") == "microsoft.loadtestservice/loadtests" and LOAD_TEST.fullmatch(rid)}
    groups = {_low(row.get("id")) for _, row in items(model.snapshot, "resource_group")
              if isinstance(row, dict) and RG.fullmatch(_low(row.get("id")))}
    for _, row in items(model.snapshot, "subscription"):
        sub = _low(row.get("id")) if isinstance(row, dict) else ""
        if SUB.fullmatch(sub):
            proposed = sub + "/resourcegroups/peaso-candidate"
            if _held(model, source, CREATE_RG, proposed):
                groups.add(proposed)
    resources.update(rg + "/providers/microsoft.loadtestservice/loadtests/peaso-candidate"
                     for rg in groups)
    runnable = [rid for rid in resources if _held(model, source, WRITE, rid)
                and _held(model, source, WRITE_TEST, rid)
                and _held(model, source, START_TEST, rid)]
    if not runnable:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity" or target.attrs.get("mi_type") != "user_assigned":
            continue
        resource = target.attrs.get("uai_resource")
        if resource and _held(model, source, ASSIGN, resource):
            out[tid] = ("conditional", "same_load_test_engine_identity_reference_and_code_execution")
    return out


def select_existing(model, candidates, source):
    if source is None or source.attrs.get("account_enabled") is False:
        return {}
    out = {}
    for tid, target in candidates.items():
        if target.kind != "azure_managed_identity":
            continue
        for host in target.attrs.get("hosts") or ():
            if (not isinstance(host, str) or not LOAD_TEST.fullmatch(host)
                    or model.resources.get(host, {}).get("type") != "microsoft.loadtestservice/loadtests"):
                continue
            if _held(model, source, WRITE_TEST, host) and _held(model, source, START_TEST, host):
                out[tid] = ("conditional", "engine_identity_selection_and_test_execution")
                break
    return out
