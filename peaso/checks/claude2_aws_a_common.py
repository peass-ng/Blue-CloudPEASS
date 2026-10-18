"""Shared helpers for the claude2_aws_a partition (AWS-A rows taken over from stalled Codex workers).

Every predicate is a pure function over collected snapshot facts. Missing, denied,
partial or malformed facts raise ``Unavailable`` (UNKNOWN). A fact is treated as a
configured absence only when the collector recorded a documented API absence
(``{"collection_status": "empty", "absent": True}``) or a documented omission.
Evaluators never mutate snapshot items.

Generic policy helpers are imported read-only from claude_aws_b_common (same pinned
upstream revisions). This module keeps its own registries so provenance never mixes.
"""
from __future__ import annotations

import copy
from datetime import datetime, time, timedelta, timezone

from . import register, result, unknown  # noqa: F401
from .facts import Unavailable, get, guard, list_of_objects, optional  # noqa: F401
from .fixtures import CASES
from .aws_a_facts import captured_clock, complete_items, scope_subject  # noqa: F401
from .claude_aws_b_common import (  # noqa: F401
    text, strings, absent_or, empty, parse_time, policy_document, wildcard_principal, turbot_public_statements,
    has_public_principal, is_policy_public)
from .claude2_aws_a_rows import QUERY_ROWS

PREFIX = "aws.claude2_a."
P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."

IDS = []
# native check id -> upstream row ids it ports (shard generator input)
ROWS = {}
# native check id -> official documentation URLs
DOCS = {}
# native check id -> short review note (semantics, deviations, pinned lists)
NOTES = {}

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = ACCOUNT + "/" + REGION
CREATED = "2026-10-10T12:00:00+00:00"
CONTEXT = {"provider": "aws", "scope": SCOPE, "_scope": SCOPE, "created_at": CREATED, "Account": ACCOUNT}
ABSENT = {"collection_status": "empty", "absent": True, "error": {"code": "NotFound"}}
GLOBAL_KINDS = {"aws_account", "aws_account_configuration", "cloudtrail_account_inventory", "iam_user", "iam_role", "iam_account_summary",
                "iam_credential_report", "iam_access_key", "iam_virtual_mfa_device", "bucket", "config_delegated_administrator"}


def rows_for(*queries, extra=()):
    """Benchmark rows of the pinned aws-compliance queries, plus explicit prowler/perimeter rows."""
    out = []
    for query in queries:
        out.extend(QUERY_ROWS[query])
    out.extend(extra)
    return out


def idx(scope=SCOPE, created_at=CREATED, **kinds):
    """A fixture scoped index: complete envelopes plus resource rows, as the engine builds them."""
    out = {"collections": {}, "context": {**CONTEXT, "scope": scope, "_scope": scope, "created_at": created_at}}
    for kind, value in kinds.items():
        status, items = (value, []) if isinstance(value, str) else (None, list(value))
        out["collections"][kind] = [{"type": kind, "scope": scope, "status": status or ("collected" if items else "empty"),
                                     "items": copy.deepcopy(items), "global": kind in GLOBAL_KINDS, "account_id": scope.split("/")[0]}]
        out[kind] = [{"type": kind, "scope": scope, "data": copy.deepcopy(item)} for item in items]
    return out


def denied_copy(value):
    """A copy of a passing item whose every top-level fact is marked denied."""
    if not isinstance(value, dict):
        return {"collection_status": "denied"}
    out = copy.deepcopy(value)
    out["_coverage"] = {key: {"status": "denied"} for key in value if key != "_coverage"}
    return out


def install(name, kind, title, cases, *, rows, severity, remediation, docs=(), note=None, category="hardening", control="CM-6",
            target="resource", dependencies=None):
    """Register a native check, its behaviour fixtures and its upstream row provenance."""
    cid = PREFIX + name
    if not rows:
        raise ValueError("every claude2_aws_a predicate must port at least one upstream row")

    def decorate(function):
        register(cid, "aws", category, kind, title, severity, control, remediation, target=target, dependencies=dependencies)(function)
        IDS.append(cid)
        ROWS[cid] = list(rows)
        DOCS[cid] = list(docs)
        if note:
            NOTES[cid] = note
        case = {"missing": {}, "malformed": None}
        case.update(copy.deepcopy(cases))
        if "unknown" not in case:
            if target == "scope":
                case["unknown"] = copy.deepcopy(case["pass"])
                deps = dependencies or [kind]
                base = copy.deepcopy(case.get("pass_index", case.get("index", {})))
                for dep in deps:
                    base.setdefault("collections", {})[dep] = [{"type": dep, "scope": SCOPE, "status": "denied", "items": [],
                                                                 "global": dep in GLOBAL_KINDS, "account_id": ACCOUNT}]
                    base[dep] = []
                case["unknown_index"] = base
            else:
                case["unknown"] = denied_copy(case["pass"])
        CASES[cid] = case
        return function
    return decorate


def detail(item, key):
    """A detail-call container: None for a documented not-found marker, else the collected response."""
    container = get(item, key, dict)
    if container.get("collection_status") == "empty" and container.get("absent") is True:
        return None
    if container.get("collection_status") not in (None, "collected"):
        raise Unavailable("detail not collected: " + key)
    return container


def collected(container, what):
    """FAIL-by-omission requires proof that the response was actually read."""
    if container.get("collection_status") != "collected":
        raise Unavailable("response not proven collected: " + what)


def scope_region(index):
    scope = get(index, "context.scope", str)
    if "/" not in scope:
        raise Unavailable("audited region unavailable")
    return scope.split("/", 1)[1]


def scope_account(index):
    scope = get(index, "context.scope", str)
    account = scope.split("/", 1)[0]
    if len(account) != 12 or not account.isdigit():
        raise Unavailable("audited account unavailable")
    return account


def home_copy(trail, index):
    """Steampipe ``region = home_region``: the trail row observed in its own home region."""
    return get(trail, "HomeRegion", str) == scope_region(index)


def not_home(trail, index):
    return "NOT_APPLICABLE", {"home_region": get(trail, "HomeRegion", str), "observed_region": scope_region(index),
                              "reason": "Shadow copy of a trail; the pinned query evaluates the home-region row only"}


def midnight_cutoff(item, index, days):
    """Steampipe ``current_date - interval 'N' day`` at the captured snapshot clock (UTC midnight)."""
    observed = captured_clock(item if isinstance(item, dict) else {}, index).astimezone(timezone.utc)
    return datetime.combine(observed.date(), time(), tzinfo=timezone.utc) - timedelta(days=days)


def trail_bucket(trail, index):
    """The same-account bucket the trail delivers to; None when it is not in the audited inventory."""
    name = get(trail, "S3BucketName", str)
    rows = complete_items(index, "bucket", get(index, "context.scope", str))
    matches = [row for row in rows if get(row, "Name", str) == name]
    if len(matches) > 1:
        raise Unavailable("ambiguous trail bucket join")
    return matches[0] if matches else None


def principal_aws_values(statement):
    """policy_std normalisation of Principal: "*" becomes {"AWS": ["*"]}; AWS values as a list of strings."""
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if not isinstance(principal, dict):
        return []
    values = principal.get("AWS", [])
    values = [values] if isinstance(values, str) else values
    return [v for v in values if isinstance(v, str)]


REPORT_NULLS = {"N/A", "no_information", "not_supported"}


def report_time(row, field):
    """Credential-report timestamp; N/A, no_information and not_supported are SQL null."""
    value = get(row, field, str)
    if value in REPORT_NULLS:
        return None
    return parse_time(value)


def report_bool(row, field):
    value = get(row, field, str)
    if value not in ("true", "false"):
        raise Unavailable("unsupported credential report boolean: " + field)
    return value == "true"
