"""Shared helpers for the claude2_azure partition predicates (prefix ``azure.claude2.``).

Reuses the strict readers of claude_azure_common: every helper raises ``Unavailable`` (-> UNKNOWN) on a
missing, denied, malformed or unrecognized native fact and never turns absence into a FAIL.
"""
from __future__ import annotations
from . import register, result, unknown
from .facts import get, list_of_objects, optional, complete_items, unique_join, Unavailable
from .fixtures import CASES, nest
from .claude_azure_common import (enum, nullable_string, diagnostic_settings, diagnostic_logs, diag_log, diag_case, scoped,
                                  scope_index)

PREFIX = "azure.claude2."
CHECK_IDS = []
SUB = "/subscriptions/s"
SCOPE = {"scope": SUB}
DEFAULT_REMEDIATION = ("Review the declared configuration for the intended workload and configure the setting through "
                       "ARM/Bicep/Terraform or the portal; collected settings do not establish runtime enforcement.")


def claude2(slug, kind, title, *, severity="medium", control="CM-6", remediation=None, category="hardening",
            target="resource", dependencies=None):
    """Register ``azure.claude2.<slug>``; dependencies default to the evaluated kind."""
    check_id = PREFIX + slug
    CHECK_IDS.append(check_id)
    return register(check_id, "azure", category, kind, title, severity, control, remediation or DEFAULT_REMEDIATION,
                    target=target, dependencies=list(dependencies or [kind]))


def cid(slug):
    return PREFIX + slug


def na(reason, **evidence):
    return "NOT_APPLICABLE", {"reason": reason, **evidence}


def is_subscription(item):
    scope = get(item, "scope", str)
    return scope.startswith("/subscriptions/") and len(scope.rstrip("/").split("/")) == 3


def scope_check(slug, kind, title, dependencies=None, **kwargs):
    """Subscription-anchored aggregate; tenant and management-group anchors are NOT_APPLICABLE."""
    decorator = claude2(slug, kind, title, target="scope", dependencies=list(dependencies or [kind]), **kwargs)

    def wrap(function):
        def evaluate(item, index):
            if not is_subscription(item):
                return na("Subscription predicate does not apply to a tenant or management-group anchor")
            return function(item, index)
        evaluate.__name__ = function.__name__
        return decorator(evaluate)
    return wrap


def omitted(item, parent, key, proof, default=None):
    """ARM omits unset properties; a present required sibling (``proof``) proves the object was fully returned."""
    container = get(item, parent, dict)
    if key in container:
        return get(container, key)
    if proof not in container:
        raise Unavailable("cannot distinguish omitted " + parent + "." + key + " from an uncollected fact")
    return default


def lower_id(value):
    if not isinstance(value, str) or not value:
        raise Unavailable("malformed ARM resource id")
    return value.rstrip("/").lower()


def ieq(a, b):
    return isinstance(a, str) and isinstance(b, str) and a.lower() == b.lower()


__all__ = ["claude2", "cid", "na", "is_subscription", "scope_check", "omitted", "lower_id", "ieq", "enum", "nullable_string",
           "diagnostic_settings", "diagnostic_logs", "diag_log", "diag_case", "scoped", "scope_index", "get", "list_of_objects",
           "optional", "complete_items", "unique_join", "Unavailable", "result", "unknown", "CASES", "nest", "CHECK_IDS",
           "PREFIX", "SUB", "SCOPE"]
