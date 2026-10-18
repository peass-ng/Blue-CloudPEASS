"""Shared helpers for the claude2_aws_b partition (AWS-B rows taken over from stalled Codex workers).

Every predicate is a pure function over collected snapshot facts. Missing, denied,
partial or malformed facts raise ``Unavailable`` (UNKNOWN). A fact is treated as a
configured absence only when the documented API response omits it and a sentinel
member proves the response was actually read. Policy evaluators work on private
copies and never mutate snapshot items.

The generic policy, routing and join helpers are imported read-only from
claude_aws_b_common (same semantics, same pinned upstream revisions). This module
keeps its own registries so the two partitions' provenance never mixes.
"""
from __future__ import annotations

import copy

from . import register, result, unknown  # noqa: F401
from .facts import Unavailable, get, guard, list_of_objects, optional, complete_items  # noqa: F401
from .fixtures import CASES, nest
from .claude_aws_b_common import (  # noqa: F401
    text, strings, absent_or, empty, clock, parse_time, account, policy_document, wildcard_principal, turbot_unrestricted,
    turbot_public_statements, wildcard_allow_statements, has_public_principal, has_restrictive_source_arn_condition,
    is_condition_block_restrictive, is_condition_block_restrictive_organization, is_condition_restricting_from_private_ip,
    is_policy_public, subnet_route_table, subnet_vpc, igw_default_route, subnet_is_public_prowler, subnet_is_public_turbot,
    explicit_igw_subnets, selection_resources, sg_rule_open, security_groups, kms_manager, protected_resources, add_months,
    scope_of, inventory, indexes, _merge, ACCOUNT, SCOPE, CONTEXT)

IDS = []
# native check id -> upstream row ids it ports (shard generator input)
ROWS = {}
# native check id -> official documentation URLs
DOCS = {}
# native check id -> short review note (semantics, deviations, pinned lists)
NOTES = {}

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."
ABSENT = {"collection_status": "empty", "absent": True, "error": {"code": "ResourceNotFoundException"}}
MISSING = object()


def _denied_copy(value):
    if not isinstance(value, dict):
        return {"collection_status": "denied"}
    out = copy.deepcopy(value)
    out["_coverage"] = {key: {"status": "denied"} for key in value if key != "_coverage"}
    return out


def _denied_index(index, dependencies):
    out = copy.deepcopy(index or {})
    out.setdefault("collections", {})
    for kind in dependencies:
        out["collections"][kind] = [{"scope": SCOPE, "status": "denied"}]
        out[kind] = []
    return out


def install(cid, kind, title, passing, failing, *, rows, severity, remediation, docs=(), note=None,
            category="hardening", control="CM-6", target="resource", dependencies=None, extra=None,
            unknown_case=None, unknown_index=None):
    """Register a native check, its behaviour fixtures and its upstream row provenance."""
    if not rows:
        raise ValueError("every claude2_aws_b predicate must port at least one upstream row")
    if not cid.startswith("aws.c2b."):
        raise ValueError("claude2_aws_b native ids use the aws.c2b. prefix")

    def decorate(function):
        register(cid, "aws", category, kind, title, severity, control, remediation, target=target, dependencies=dependencies)(function)
        IDS.append(cid)
        ROWS[cid] = list(rows)
        DOCS[cid] = list(docs)
        if note:
            NOTES[cid] = note
        case = {"pass": passing, "fail": failing, "missing": {}, "malformed": None}
        case.update(extra or {})
        index = case.get("index", {})
        if target == "scope":
            case["unknown"] = copy.deepcopy(passing) if unknown_case is None else unknown_case
            case["unknown_index"] = unknown_index if unknown_index is not None else _denied_index(case.get("pass_index", index), dependencies or [kind])
        else:
            case["unknown"] = _denied_copy(passing) if unknown_case is None else unknown_case
            if unknown_index is not None:
                case["unknown_index"] = unknown_index
        CASES[cid] = case
        return function
    return decorate


def flag(cid, kind, title, path, *, rows, severity, remediation, sentinel, base=None, good=True, bad=None, default=MISSING,
         expected=bool, applies=None, na_item=None, docs=(), note=None, category="hardening", control="CM-6", dependencies=None, extra=None):
    """A single-field predicate: PASS iff the field equals ``good`` (or is in ``good`` when a tuple).

    ``sentinel`` is a member always present in the same API response; with ``default`` set,
    a documented omission of ``path`` is the default instead of UNKNOWN. ``applies(item)``
    returns None when applicable or an evidence dict for NOT_APPLICABLE.
    """
    base = dict(base or {})
    goods = good if isinstance(good, tuple) else (good,)
    if bad is None:
        bad = (not goods[0]) if expected is bool else "DISABLED"
    passing = _merge({sentinel: base.get(sentinel, "x"), **base}, nest(path, goods[0]))
    failing = _merge({sentinel: base.get(sentinel, "x"), **base}, nest(path, bad))
    more = dict(extra or {})
    if na_item is not None:
        more["not_applicable"] = na_item

    @install(cid, kind, title, passing, failing, rows=rows, severity=severity, remediation=remediation, docs=docs, note=note,
             category=category, control=control, dependencies=dependencies, extra=more)
    def evaluate(item, index):
        get(item, sentinel)
        if applies is not None:
            skip = applies(item)
            if skip is not None:
                return "NOT_APPLICABLE", skip
        if default is MISSING:
            value = get(item, path, expected)
        else:
            value = absent_or(item, sentinel, path, default, expected)
        if expected is not None and value is not None and (type(value) is not expected if expected in (bool, int) else not isinstance(value, expected)):
            raise Unavailable("malformed fact: " + path)
        return result(value not in goods, field=path, configured=value, expected=list(goods))
    evaluate.__name__ = cid.replace(".", "_")
    return evaluate


def manual_case(cid, manual, manual_index=None):
    """Replace the FAIL fixture of ``cid`` with a MANUAL fixture (review-only outcomes)."""
    case = CASES[cid]
    case.pop("fail", None)
    case["manual"] = manual
    if manual_index is not None:
        case["manual_index"] = manual_index


def detail(item, key):
    """A detail-call container: None for a documented not-found marker, else the collected response."""
    container = get(item, key, dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return None
    if container.get("collection_status") not in (None, "collected"):
        raise Unavailable("detail not collected: " + key)
    return container


def detail_list(item, key, field="items"):
    """A paginated child list stored as {collection_status, items}; only complete lists are usable."""
    container = get(item, key, dict)
    if container.get("collection_status") not in ("collected", "empty"):
        raise Unavailable("child list not collected: " + key)
    return list_of_objects(container.get(field, []))


def region_of(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    scope = context.get("scope") if isinstance(context, dict) else None
    if not isinstance(scope, str) or "/" not in scope:
        raise Unavailable("audited region unavailable")
    return scope.split("/", 1)[1]


def days_between(later, earlier):
    """Calendar-day difference, as steampipe date(a) - date(b)."""
    return (later.date() - earlier.date()).days


def resource_policy_public(statements):
    """aws-perimeter local.resource_policy_public_sql: Allow, wildcard principal, no restricting condition."""
    return bool(turbot_public_statements(statements))
