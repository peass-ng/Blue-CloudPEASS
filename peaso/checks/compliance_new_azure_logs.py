"""Signed Azure Log Analytics workspace default-retention check.

The workspace setting does not describe table-specific overrides, actual log
ingestion, or long-term total retention.
"""
from __future__ import annotations

from . import register, result, unknown
from .facts import Unavailable, complete_items, get
from .fixtures import CASES

ID = "azure_log_analytics_workspace_10_5_1_4_8c74ccb"


def _threshold(index):
    context = index.get("context", {})
    if not isinstance(context, dict):
        raise Unavailable("malformed evaluation context")
    policy = context.get("policy", {})
    if not isinstance(policy, dict):
        raise Unavailable("malformed retention policy")
    days = policy.get("MinRetentionTime", 365)
    if type(days) is not int or days <= 0:
        raise Unavailable("missing or malformed MinRetentionTime")
    return days


@register(ID, "azure", "hardening", "log_analytics_workspace",
          "Log Analytics workspace default interactive retention meets policy", "medium", "AU-11",
          "Review the workspace and any table overrides with the log owner; set the workspace default interactive retention to the approved number of days through the owned Azure configuration after cost and impact review.",
          dependencies=["log_analytics_workspace"])
def workspace_default_retention(item, index):
    complete_items(index, "log_analytics_workspace")
    threshold = _threshold(index)
    observed = get(item, "properties.retentionInDays", int)
    if observed <= 0:
        return unknown("unrecognized Log Analytics workspace retention", observed_days=observed)
    return result(observed < threshold, observed_days=observed, required_days=threshold,
                  semantics="Workspace default interactive retention only; table overrides, ingestion and total retention are unassessed")


def _index(status="collected", policy=None):
    return {"collections": {"log_analytics_workspace": [{"status": status}]},
            "log_analytics_workspace": [],
            "context": {"policy": {} if policy is None else policy}}


CASES[ID] = {
    "pass": {"properties": {"retentionInDays": 365}},
    "fail": {"properties": {"retentionInDays": 30}},
    "missing": {"properties": {}},
    "malformed": {"properties": {"retentionInDays": "365"}},
    "pass_index": _index(), "fail_index": _index(), "unknown_index": _index("denied"),
}
