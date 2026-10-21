"""Shared helpers for the claude_aws_a partition (AWS services ebs..vpc).

Every predicate is a pure function over collected snapshot facts. Missing,
denied, partial or malformed facts raise ``Unavailable`` (UNKNOWN). A fact is
only treated as a configured absence when the documented API response shape
omits it and a member that is always present in the same response proves the
response was read. Evaluators work on private copies and never mutate items.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime
from ipaddress import ip_address, ip_network

from . import register, result, unknown  # noqa: F401  (re-exported for service modules)
from .facts import MemoIndex, Unavailable, get, guard, list_of_objects, memoized, optional, complete_items
from .fixtures import CASES, nest  # noqa: F401

PREFIX = "aws.claude_a."
CHECK_IDS = []
ROWS = {}
DOCS = {}
NOTES = {}

ACCOUNT = "123456789012"
REGION = "us-east-1"
SCOPE = ACCOUNT + "/" + REGION
CREATED = "2026-01-01T00:00:00+00:00"
CONTEXT = {"provider": "aws", "scope": SCOPE, "_scope": SCOPE, "Account": ACCOUNT, "created_at": CREATED}

C = "aws-compliance.control."
P = "prowler.aws."
R = "aws-perimeter.control."


def _denied_copy(value):
    """A copy of a passing item whose every top-level fact is marked denied."""
    if not isinstance(value, dict):
        return {"collection_status": "denied"}
    out = copy.deepcopy(value)
    out["_coverage"] = {key: {"status": "denied"} for key in value if key != "_coverage"}
    return out


def _denied_index(index, dependencies):
    out = copy.deepcopy(index or {})
    out.setdefault("collections", {})
    for kind in dependencies:
        out["collections"][kind] = [{"type": kind, "scope": SCOPE, "status": "denied", "items": []}]
        out[kind] = []
    return out


def idx(**kinds):
    """A scoped fixture index: ``kind=[items]`` (complete) or ``kind=None`` (denied)."""
    out = {"collections": {}, "context": dict(CONTEXT)}
    for kind, items in kinds.items():
        if items is None:
            out["collections"][kind] = [{"type": kind, "scope": SCOPE, "status": "denied", "items": []}]
            out[kind] = []
            continue
        out["collections"][kind] = [{"type": kind, "scope": SCOPE, "status": "collected" if items else "empty", "items": list(items)}]
        out[kind] = [{"type": kind, "scope": SCOPE, "data": item} for item in items]
    return out


def install(cid, kind, title, passing, failing, *, rows, severity, remediation, docs=(), note=None,
            category="hardening", control="CM-6", target="resource", dependencies=None, extra=None,
            index=None, pass_index=None, fail_index=None, unknown_case=None, unknown_index=None, allow_incomplete_failure=False):
    """Register a native check, its behaviour fixtures and its upstream row provenance."""
    if not cid.startswith(PREFIX):
        raise ValueError("claude_aws_a predicate ids must use the partition prefix")
    if not rows:
        raise ValueError("every claude_aws_a predicate must port at least one upstream row")
    if target == "scope" and not dependencies:
        dependencies = [kind]

    def decorate(function):
        register(cid, "aws", category, kind, title, severity, control, remediation, target=target, dependencies=dependencies, allow_incomplete_failure=allow_incomplete_failure)(function)
        CHECK_IDS.append(cid)
        ROWS[cid] = list(rows)
        DOCS[cid] = list(docs)
        if note:
            NOTES[cid] = note
        case = {"pass": passing, "fail": failing, "missing": {}, "malformed": None}
        if index is not None:
            case["index"] = index
        if pass_index is not None:
            case["pass_index"] = pass_index
        if fail_index is not None:
            case["fail_index"] = fail_index
        for key, value in (extra or {}).items():
            # ``na``: NOT_APPLICABLE fixture (item or (item, index)); ``pass_*``/``fail_*``: extra variants.
            item_value, item_index = value if isinstance(value, tuple) else (value, None)
            if key in ("na", "not_applicable"):
                case["not_applicable"] = item_value
                if item_index is not None:
                    case["not_applicable_index"] = item_index
            elif key.startswith(("pass_", "fail_")):
                expected = "PASS" if key.startswith("pass_") else "FAIL"
                case.setdefault("variants", []).append((expected, item_value, item_index))
            else:
                case[key] = value
        if target == "scope":
            case["unknown"] = copy.deepcopy(passing) if unknown_case is None else unknown_case
            base = case.get("pass_index", case.get("index", {}))
            case["unknown_index"] = unknown_index if unknown_index is not None else _denied_index(base, dependencies or [kind])
        else:
            case["unknown"] = _denied_copy(passing) if unknown_case is None else unknown_case
            if unknown_index is not None:
                case["unknown_index"] = unknown_index
        CASES[cid] = case
        return function
    return decorate


# ---------------------------------------------------------------------------
# Basic strict accessors.
# ---------------------------------------------------------------------------
def items(index, kind):
    return complete_items(index, kind)


def text(value, what="string"):
    if not isinstance(value, str):
        raise Unavailable("expected string fact: " + what)
    return value


def strings(value, what="list"):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise Unavailable("expected list of strings: " + what)
    return value


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def absent_or(item, sentinel, path, default=None, expected=None):
    """Read optional ``path`` once ``sentinel`` proves the detail response was collected.

    AWS omits unset optional members (for example PublicIpAddress). The sentinel is
    a member always present in that same response, so the omission is a configured
    absence and not an unread fact. Explicit _coverage on the member stays strict.
    """
    get(item, sentinel)
    parts = path.split(".")
    parent = item
    for part in parts[:-1]:
        guard(parent)
        if part not in parent and part not in parent.get("_coverage", {}):
            return default
        parent = get(parent, part, dict)
    return optional(parent, parts[-1], default, expected)


def parse_time(value):
    if isinstance(value, datetime):
        stamp = value
    else:
        if not isinstance(value, str):
            raise Unavailable("expected ISO-8601 timestamp")
        try:
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise Unavailable("malformed timestamp") from exc
    if stamp.tzinfo is None:
        raise Unavailable("timestamp without timezone")
    return stamp


def clock(item, index):
    from .aws_a_facts import captured_clock
    return captured_clock(item if isinstance(item, dict) else {}, index)


def age_days(item, index, value):
    return (clock(item, index) - parse_time(value)).total_seconds() / 86400.0


def account(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    value = context.get("Account") if isinstance(context, dict) else None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{12}", value):
        raise Unavailable("audited account identity unavailable")
    return value


def region(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    scope = context.get("scope") if isinstance(context, dict) else None
    if not isinstance(scope, str) or not re.fullmatch(r"[0-9]{12}/[a-z]{2}(?:-[a-z]+)+-[0-9]", scope):
        raise Unavailable("audited region scope unavailable")
    return scope.split("/", 1)[1]


def policy_document(value):
    """A parsed policy document's statements; strings are decoded, anything else is malformed."""
    if isinstance(value, str):
        from urllib.parse import unquote
        try:
            value = json.loads(unquote(value) if value.startswith("%7B") else value)
        except ValueError as exc:
            raise Unavailable("malformed policy JSON") from exc
    if not isinstance(value, dict):
        raise Unavailable("malformed policy document")
    statements = get(value, "Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable("malformed policy statements")
    return copy.deepcopy(statements)


def tags(item, key="Tags"):
    """AWS Key/Value tag list to dict; omitted Tags is an empty set once the item is a dict."""
    guard(item)
    raw = optional(item, key, [], list)
    out = {}
    for tag in list_of_objects(raw):
        out[text(tag.get("Key"), "tag key")] = tag.get("Value")
    return out


# ---------------------------------------------------------------------------
# Steampipe policy_std style evaluators (aws-compliance / aws-perimeter).
# ---------------------------------------------------------------------------
def _statement_effect(statement):
    """Required native statement Effect; unavailable/unknown variants prove neither side."""
    effect = get(statement, "Effect", str)
    if effect not in ("Allow", "Deny"):
        raise Unavailable("unrecognized policy statement Effect")
    return effect


def _public_principal_value(statement):
    principal = optional(statement, "Principal", "")
    if not isinstance(principal, (str, list, dict)):
        raise Unavailable("malformed policy principal")
    if isinstance(principal, list) and any(not isinstance(v, str) for v in principal):
        raise Unavailable("malformed policy principal list")
    if isinstance(principal, dict):
        guard(principal)
    return principal


def _public_condition_document(statement, selections=None):
    # An omitted Condition is the documented unrestricted default. A present
    # null (or explicit unreadability marker) is not that omission.
    raw = optional(statement, "Condition", {}, dict)
    guard(raw)
    cleaned = copy.deepcopy(raw)
    cleaned.pop("_coverage", None)
    operators = set(raw) | set(raw.get("_coverage", {})) if selections is None else set(selections)
    for operator in operators - {"_coverage"}:
        block = optional(raw, operator, None, dict)
        if block is None:
            continue
        safe = copy.deepcopy(block)
        safe.pop("_coverage", None)
        keys = (set(block) | set(block.get("_coverage", {}))) - {"_coverage"}
        for key in keys:
            if selections is not None and str(key).lower() not in selections[operator]:
                continue
            # IAM condition keys are literal map members and may contain dots.
            # facts.get interprets dots as nested paths, so check this literal
            # member's authority before reading the member itself.
            coverage_entries = block.get("_coverage", {})
            coverage = coverage_entries.get(key)
            if key in coverage_entries and (not isinstance(coverage, dict) or coverage.get("status") not in ("collected", "empty")):
                raise Unavailable("policy condition member unavailable")
            if key not in block:
                raise Unavailable("policy condition member missing")
            value = block[key]
            if coverage is not None and coverage["status"] == "empty" and not (
                value is None or value == "" or value == [] or value == {}
            ):
                raise Unavailable("empty coverage contradicts policy condition member")
            if isinstance(value, dict):
                guard(value)
            if operator in ("StringEquals", "StringEqualsIgnoreCase", "StringLike", "ArnEquals", "ArnLike", "IpAddress"):
                strings(as_list(value), "policy condition values")
            safe[key] = value
        cleaned[operator] = safe
    return cleaned


def _aws_principals(statement):
    principal = _public_principal_value(statement)
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        value = optional(principal, "AWS", None)
        if value is not None and not isinstance(value, (str, list)):
            raise Unavailable("malformed AWS principal member")
        return strings(as_list(value), "AWS principals")
    return []


def wildcard_principal(statement):
    """Turbot: Principal.AWS = ["*"] or Principal = "*" (after policy_std dedupe)."""
    values = _aws_principals(statement)
    return bool(values) and set(values) == {"*"}


def _conditions(statement):
    raw = _public_condition_document(statement)
    out = {}
    for operator, block in raw.items():
        if not isinstance(block, dict):
            raise Unavailable("malformed policy condition block")
        out[operator] = {str(k).lower(): as_list(v) for k, v in block.items() if k != "_coverage"}
    return out


TURBOT_KEYS = ("aws:sourceowner", "aws:sourceaccount", "aws:principalorgid", "aws:principalaccount", "aws:principalarn", "aws:sourcearn")


def turbot_unrestricted(statement, keys=TURBOT_KEYS, arn_equals_wildcard=False):
    """True when none of the Turbot restricting condition keys effectively constrains the statement.

    ``arn_equals_wildcard`` reproduces the KMS variant, where ArnEquals ["*"] also counts as unrestricted.
    """
    cond = _conditions(statement)
    for key in keys:
        if key in cond.get("StringEquals", {}) or key in cond.get("StringEqualsIgnoreCase", {}):
            return False
        values = cond.get("StringLike", {}).get(key)
        if values is not None and "*" not in values:
            return False
        if key in ("aws:principalarn", "aws:sourcearn"):
            equals = cond.get("ArnEquals", {}).get(key)
            if equals is not None and (not arn_equals_wildcard or "*" not in equals):
                return False
            like = cond.get("ArnLike", {}).get(key)
            if like is not None and "*" not in like:
                return False
    return True


def turbot_public_statements(statements, keys=TURBOT_KEYS, arn_equals_wildcard=False):
    """aws-perimeter public-principal statement predicate."""
    public, unavailable = [], []
    for statement in statements:
        try:
            if _statement_effect(statement) == "Allow" and wildcard_principal(statement) and turbot_unrestricted(statement, keys, arn_equals_wildcard):
                public.append(statement)
        except Unavailable as exc:
            unavailable.append(exc)
    if public:
        return public
    if unavailable:
        raise unavailable[0]
    return []


def wildcard_allow_statements(statements):
    """aws-compliance *_restrict_public_access: Allow with wildcard principal, conditions ignored."""
    public, unavailable = [], []
    for statement in statements:
        try:
            if _statement_effect(statement) == "Allow" and wildcard_principal(statement):
                public.append(statement)
        except Unavailable as exc:
            unavailable.append(exc)
    if public:
        return public
    if unavailable:
        raise unavailable[0]
    return []


# ---------------------------------------------------------------------------
# Prowler policy helpers, ported from prowler/providers/aws/services/iam/lib/policy.py
# (pinned 61d2cc55c4539a6b48a3cf9f3729d8f2af300882). Inputs are private copies.
# ---------------------------------------------------------------------------
def iam_pattern_matches(pattern, value):
    """IAM wildcard match: ``*`` any run, ``?`` one character, case-insensitive."""
    pattern = pattern.strip().lower()
    action = value.lower()
    p = a = 0
    star = resume = -1
    while a < len(action):
        if p < len(pattern) and pattern[p] in ("?", action[a]):
            p += 1
            a += 1
        elif p < len(pattern) and pattern[p] == "*":
            star = p
            resume = a
            p += 1
        elif star >= 0:
            resume += 1
            a = resume
            p = star + 1
        else:
            return False
    return all(char == "*" for char in pattern[p:])


def has_public_principal(statement):
    principal = _public_principal_value(statement)
    if isinstance(principal, (str, list)):
        if "*" in principal or "arn:aws:iam::*:root" in principal:
            return True
    if isinstance(principal, dict):
        if "*" in principal or "arn:aws:iam::*:root" in principal:
            return True
        for key in ("AWS", "CanonicalUser"):
            value = optional(principal, key, "")
            if not isinstance(value, (str, list)) or isinstance(value, list) and any(not isinstance(v, str) for v in value):
                raise Unavailable("malformed policy principal member")
            if "*" in value or "arn:aws:iam::*:root" in value:
                return True
    return False


def has_restrictive_source_arn_condition(statement, source_account=""):
    condition = _public_condition_document(statement)
    for operator in condition:
        block = condition[operator]
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if str(key).lower() == "aws:sourcearn":
                for arn in (value if isinstance(value, list) else [value]):
                    if not isinstance(arn, str):
                        return False
                    if arn == "*" or arn.count("*") >= 3 or arn.endswith(":::*") or arn.endswith(":*"):
                        return False
                    if source_account:
                        parts = arn.split(":")
                        if len(parts) > 4 and parts[4] and parts[4] != "*":
                            if parts[4].isdigit():
                                if source_account not in arn:
                                    return False
                            elif parts[4] != source_account:
                                return False
                        elif len(parts) > 4 and parts[4] == "*":
                            return False
                return True
    return False


_VALID_STRING_KEYS = ["aws:sourceaccount", "aws:sourceowner", "aws:sourcearn", "aws:principalaccount", "aws:principalarn",
    "aws:principalorgid", "aws:principalorgpaths", "aws:resourceaccount", "aws:sourcevpc", "aws:sourcevpce", "aws:sourceorgid",
    "aws:sourceorgpaths", "aws:userid", "aws:username", "aws:calledvia", "aws:calledviafirst", "aws:calledvialast",
    "kms:calleraccount", "kms:viaservice", "s3:resourceaccount", "lambda:eventsourcetoken"]
_VALID_OPTIONS = {"StringEquals": _VALID_STRING_KEYS, "StringLike": _VALID_STRING_KEYS,
    "ArnLike": ["aws:sourcearn", "aws:principalarn"], "ArnEquals": ["aws:sourcearn", "aws:principalarn"]}


def _lower_block(condition, operator):
    block = condition.get(operator)
    if not isinstance(block, dict):
        raise Unavailable("malformed policy condition block")
    return {str(k).lower(): v for k, v in block.items()}


def is_condition_block_restrictive(condition, source_account="", is_cross_account_allowed=False):
    if not isinstance(condition, dict):
        raise Unavailable("malformed policy condition")
    valid = False
    for operator, keys in _VALID_OPTIONS.items():
        if operator not in condition:
            continue
        block = _lower_block(condition, operator)
        for key in keys:
            if key not in block:
                continue
            value = block[key]
            if isinstance(value, list):
                restrictive = True
                if not is_cross_account_allowed:
                    for entry in value:
                        if key not in ("aws:sourcevpc", "aws:sourcevpce"):
                            if key == "aws:sourcearn":
                                restrictive = has_restrictive_source_arn_condition({"Condition": {operator: {key: value}}}, source_account)
                                if not restrictive:
                                    break
                            elif not isinstance(entry, str) or source_account not in entry:
                                restrictive = False
                                break
                if restrictive:
                    valid = True
            elif isinstance(value, str):
                if key in ("aws:sourcevpc", "aws:sourcevpce") or is_cross_account_allowed:
                    valid = True
                elif key == "aws:sourcearn":
                    valid = has_restrictive_source_arn_condition({"Condition": {operator: {key: value}}}, source_account)
                elif source_account in value:
                    valid = True
    return valid


def is_condition_block_restrictive_organization(condition):
    valid = False
    for operator in ("StringEquals", "StringLike"):
        if operator not in condition:
            continue
        block = _lower_block(condition, operator)
        value = block.get("aws:principalorgid")
        if isinstance(value, list):
            valid = "*" not in value
        elif isinstance(value, str):
            if "*" not in value:
                valid = True
    return valid


def is_condition_restricting_from_private_ip(condition):
    block = condition.get("IpAddress", {})
    if not block:
        return False
    if not isinstance(block, dict):
        raise Unavailable("malformed IpAddress condition")
    block = {str(k).lower(): v for k, v in block.items()}
    ips = block.get("aws:sourceip", "")
    if not ips:
        return False
    for ip in (ips if isinstance(ips, list) else [ips]):
        if not isinstance(ip, str) or ip in ("*", "0.0.0.0/0"):
            return False
        try:
            private = ip_network(ip, strict=False).is_private if "/" in ip else ip_address(ip).is_private
        except ValueError:
            return False
        if not private:
            return False
    return True


def is_policy_public(statements, source_account="", is_cross_account_allowed=True, not_allowed_actions=(),
                     check_cross_service_confused_deputy=False):
    """Prowler is_policy_public (no trusted account/IP lists, which prowler defaults to empty)."""
    trusted = {source_account} if source_account else set()
    unavailable = []
    for statement in statements:
        try:
            if _statement_effect(statement) != "Allow":
                continue
            action_unavailable = None
            if not_allowed_actions:
                try:
                    action = optional(statement, "Action", None)
                    if action is not None and not isinstance(action, (str, list)):
                        raise Unavailable("malformed policy action")
                    if isinstance(action, list):
                        strings(action, "policy actions")
                    hit = (isinstance(action, list) and ("*" in action or any(a in not_allowed_actions for a in action))) or (isinstance(action, str) and (action == "*" or action in not_allowed_actions))
                    if not hit:
                        continue
                except Unavailable as exc:
                    action_unavailable = exc
            public = has_public_principal(statement)
            principal = _public_principal_value(statement)
            if not public and isinstance(principal, dict) and source_account and not is_cross_account_allowed:
                aws = optional(principal, "AWS", None)
                if isinstance(aws, str) and not any(t in aws for t in trusted):
                    public = True
                if isinstance(aws, list) and not all(any(t in str(p) for t in trusted) for p in aws):
                    public = True
            if not public and isinstance(principal, dict) and check_cross_service_confused_deputy:
                svc = optional(principal, "Service", [])
                if not isinstance(svc, (str, list)):
                    raise Unavailable("malformed service principal member")
                services = strings(as_list(svc), "service principals")
                cross = any(s == "*" or s.endswith(".amazonaws.com") or s.endswith(".amazon.com") for s in services)
                exempt = any(s in ("secretsmanager.amazonaws.com", "eks.amazonaws.com") for s in services)
                if cross and not exempt:
                    public = True
            if not public:
                continue
            if action_unavailable is not None:
                raise action_unavailable
            selections = {**_VALID_OPTIONS, "IpAddress": ["aws:sourceip"]}
            condition = _public_condition_document(statement, selections)
            if not condition or (not is_condition_block_restrictive(copy.deepcopy(condition), source_account, is_cross_account_allowed)
                    and not is_condition_block_restrictive_organization(copy.deepcopy(condition))
                    and not is_condition_restricting_from_private_ip(copy.deepcopy(condition))):
                return True
        except Unavailable as exc:
            unavailable.append(exc)
    if unavailable:
        raise unavailable[0]
    return False


# ---------------------------------------------------------------------------
# EC2 security group helpers.
# ---------------------------------------------------------------------------
def is_cidr_public(cidr, any_address=False):
    """Prowler _is_cidr_public: 0.0.0.0/0 and ::/0 always; otherwise is_global unless any_address."""
    if not isinstance(cidr, str):
        raise Unavailable("malformed CIDR")
    if cidr in ("0.0.0.0/0", "::/0"):
        return True
    if not any_address:
        try:
            return ip_network(cidr).is_global
        except ValueError as exc:
            raise Unavailable("malformed CIDR") from exc
    return False


def _rule_ranges(rule):
    v4 = [get(r, "CidrIp", str) for r in list_of_objects(get(rule, "IpRanges", list))]
    v6 = [get(r, "CidrIpv6", str) for r in list_of_objects(get(rule, "Ipv6Ranges", list))]
    return v4, v6


def _sg_protocol(value):
    """EC2 accepts protocol names and their IANA numbers in IpPermission."""
    names = {"tcp": "6", "udp": "17", "icmp": "1", "icmpv6": "58"}
    if value in names:
        return names[value]
    if value == "-1" or (value.isascii() and value.isdecimal() and 0 <= int(value) <= 255):
        return str(int(value))
    raise Unavailable("unrecognized security-group protocol")


def _sg_bounds(rule, proto):
    # EC2 ignores port fields for all-protocol permissions. ICMP fields are
    # independent type/code values, not an ordered TCP/UDP port interval.
    if proto == "-1":
        return None
    if proto in ("6", "17", "1", "58"):
        low, high = get(rule, "FromPort", int), get(rule, "ToPort", int)
        valid = (0 <= low <= high <= 65535) if proto in ("6", "17") else (-1 <= low <= 255 and -1 <= high <= 255)
        if not valid or (proto in ("1", "58") and low == -1 and high != -1):
            raise Unavailable("invalid security-group port or ICMP type/code")
        return low, high
    # Other protocol numbers have no TCP/UDP port interval in the API.
    return None


def prowler_sg_open(rule, protocol, ports=None, any_address=False, all_ports=False):
    """Prowler declaration predicate, with native EC2 protocol/range validation."""
    ports = ports or []
    proto = _sg_protocol(get(rule, "IpProtocol", str))
    requested = _sg_protocol(protocol)
    bounds = _sg_bounds(rule, proto)
    v4, v6 = _rule_ranges(rule)
    for version, ranges in ((4, v4), (6, v6)):
        for cidr in ranges:
            try:
                if ip_network(cidr).version != version:
                    raise ValueError("address family mismatch")
            except ValueError as exc:
                raise Unavailable("malformed security-group CIDR") from exc
    public = any(is_cidr_public(cidr, any_address) for cidr in v4 + v6)
    if proto == "-1":
        return public
    if requested != "-1" and proto != requested:
        return False
    if bounds is not None:
        low, high = bounds
        return public and (any(low <= port <= high for port in ports) or
                           (low == 0 and high == 65535) or (all_ports and not ports))
    return False


def sg_ingress(sg):
    return list_of_objects(get(sg, "IpPermissions", list))


def sg_egress(sg):
    return list_of_objects(get(sg, "IpPermissionsEgress", list))


def turbot_rule_rows(sg, egress=False):
    """aws_vpc_security_group_rule rows: one per (permission x CIDR entry)."""
    rows = []
    for perm in (sg_egress(sg) if egress else sg_ingress(sg)):
        proto = get(perm, "IpProtocol", str)
        low = optional(perm, "FromPort", None, int)
        high = optional(perm, "ToPort", None, int)
        v4, v6 = _rule_ranges(perm)
        for cidr in v4:
            rows.append({"ip_protocol": proto, "from_port": low, "to_port": high, "cidr_ipv4": cidr, "cidr_ipv6": None})
        for cidr in v6:
            rows.append({"ip_protocol": proto, "from_port": low, "to_port": high, "cidr_ipv4": None, "cidr_ipv6": cidr})
    return rows


def turbot_port_hit(row, ports=(), ranges=()):
    """``(ip_protocol = '-1' and from_port is null) or from_port <= p and to_port >= p`` for any p or [lo, hi]."""
    if row["ip_protocol"] == "-1" and row["from_port"] is None:
        return True
    low, high = row["from_port"], row["to_port"]
    if low is None or high is None:
        return False
    return any(low <= p and high >= p for p in ports) or any(low <= lo and high >= hi for lo, hi in ranges)


def network_interfaces(index):
    return items(index, "network_interface")


def _hashable(value):
    try:
        hash(value)
    except TypeError:
        return False
    return True


def _sg_eni_map(index):
    """GroupId -> ENIs carrying it, in inventory order and once per ENI (as the per-group scan returns them)."""
    out = {}
    for eni in network_interfaces(index):
        seen = set()
        for group in list_of_objects(get(eni, "Groups", list)):
            gid = group.get("GroupId")
            if _hashable(gid) and gid not in seen:
                seen.add(gid)
                out.setdefault(gid, []).append(eni)
    return out


def sg_enis(index, group_id):
    if type(index) is MemoIndex and _hashable(group_id):
        return list(memoized(index, ("sg_enis",), lambda: _sg_eni_map(index)).get(group_id, ()))
    out = []
    for eni in network_interfaces(index):
        for group in list_of_objects(get(eni, "Groups", list)):
            if group.get("GroupId") == group_id:
                out.append(eni)
                break
    return out


def _eni_field_values(index, field):
    return frozenset(value for value in (eni.get(field) for eni in network_interfaces(index)) if _hashable(value))


def vpc_in_use(index, vpc_id):
    if type(index) is MemoIndex and _hashable(vpc_id):
        return vpc_id in memoized(index, ("eni_values", "VpcId"), lambda: _eni_field_values(index, "VpcId"))
    return any(eni.get("VpcId") == vpc_id for eni in network_interfaces(index))


def subnet_in_use(index, subnet_id):
    if type(index) is MemoIndex and _hashable(subnet_id):
        return subnet_id in memoized(index, ("eni_values", "SubnetId"), lambda: _eni_field_values(index, "SubnetId"))
    return any(eni.get("SubnetId") == subnet_id for eni in network_interfaces(index))


def sg_in_use(sg, index):
    """Prowler: SG's VPC is in use (has ENIs) and the SG has ENIs."""
    gid = get(sg, "GroupId", str)
    vpc_id = absent_or(sg, "GroupId", "VpcId", None, str)
    if vpc_id is None:
        return False
    vpcs = [v for v in items(index, "vpc") if v.get("VpcId") == vpc_id]
    return bool(vpcs) and vpc_in_use(index, vpc_id) and bool(sg_enis(index, gid))


def _sg_by_id(index):
    """GroupId -> security group row; the last row wins, as in the sequential scan. None when an id is unhashable."""
    out = {}
    for row in items(index, "security_group"):
        gid = row.get("GroupId")
        if not _hashable(gid):
            return None
        out[gid] = row
    return out


def security_groups(index, ids):
    by_id = memoized(index, ("sg_by_id",), lambda: _sg_by_id(index)) if type(index) is MemoIndex else None
    if by_id is not None and isinstance(ids, (list, tuple, set, frozenset)) and all(_hashable(g) for g in ids):
        found = {g: by_id[g] for g in ids if g in by_id}
        if set(found) != set(ids):
            raise Unavailable("security group join unresolved")
        return [found[g] for g in ids]
    found = {}
    for row in items(index, "security_group"):
        if row.get("GroupId") in ids:
            found[row["GroupId"]] = row
    if set(found) != set(ids):
        raise Unavailable("security group join unresolved")
    return [found[g] for g in ids]


# ---------------------------------------------------------------------------
# Network ACL: prowler ec2/lib/network_acls.check_network_acl.
# ---------------------------------------------------------------------------
def _validate_nacl_rule(rule):
    """Validate native entry facts before treating a non-match as a safe rule."""
    get(rule, "Egress", bool)
    number = get(rule, "RuleNumber", int)
    if not 1 <= number <= 32767:
        raise Unavailable("invalid network ACL rule number")
    if get(rule, "RuleAction", str) not in ("allow", "deny"):
        raise Unavailable("unrecognized network ACL action")
    protocol = get(rule, "Protocol", str)
    if protocol != "-1" and not (protocol.isascii() and protocol.isdecimal() and 0 <= int(protocol) <= 255):
        raise Unavailable("unrecognized network ACL protocol")
    protocol = str(int(protocol))
    families = 0
    for field, version in (("CidrBlock", 4), ("Ipv6CidrBlock", 6)):
        cidr = optional(rule, field, None, str)
        if cidr is None:
            continue
        families += 1
        try:
            if ip_network(cidr).version != version:
                raise ValueError("address family mismatch")
        except ValueError as exc:
            raise Unavailable("malformed network ACL CIDR") from exc
    if families != 1:
        raise Unavailable("network ACL entry needs exactly one address family")
    bounds = optional(rule, "PortRange", None, dict)
    if protocol in ("6", "17") or bounds is not None:
        low, high = get(rule, "PortRange.From", int), get(rule, "PortRange.To", int)
        if not 0 <= low <= high <= 65535:
            raise Unavailable("invalid network ACL port interval")
    icmp = optional(rule, "IcmpTypeCode", None, dict)
    if icmp is not None:
        typ, code = get(icmp, "Type", int), get(icmp, "Code", int)
        if not (-1 <= typ <= 255 and -1 <= code <= 255) or (typ == -1 and code != -1):
            raise Unavailable("invalid network ACL ICMP type/code")
    return protocol


def _nacl_match(rule, protocol, port):
    proto = _validate_nacl_rule(rule)
    if proto == "-1":
        return True
    if proto != protocol:
        return False
    low, high = get(rule, "PortRange.From", int), get(rule, "PortRange.To", int)
    return low <= port <= high


def prowler_nacl_open(entries, protocol, port):
    entries = list_of_objects(entries)
    for rule in entries:
        _validate_nacl_rule(rule)
    v6 = sorted([r for r in entries if r.get("CidrBlock") is None and not r["Egress"]], key=lambda r: r["RuleNumber"])
    for rule in v6:
        if rule.get("Ipv6CidrBlock") == "::/0" and _nacl_match(rule, protocol, port):
            if rule["RuleAction"] == "deny":
                break
            if rule["RuleAction"] == "allow":
                return True
    v4 = sorted([r for r in entries if r.get("Ipv6CidrBlock") is None and not r["Egress"]], key=lambda r: r["RuleNumber"])
    for rule in v4:
        if rule.get("CidrBlock") == "0.0.0.0/0" and _nacl_match(rule, protocol, port):
            if rule["RuleAction"] == "deny":
                return False
            if rule["RuleAction"] == "allow":
                return True
    return False


# ---------------------------------------------------------------------------
# VPC routing helpers.
# ---------------------------------------------------------------------------
def subnet_route_table(index, subnet_id, vpc_id):
    """Explicit association, else the VPC main route table (EC2 semantics)."""
    explicit, main = [], []
    for table in items(index, "route_table"):
        for association in list_of_objects(get(table, "Associations", list)):
            if association.get("SubnetId") == subnet_id:
                explicit.append(table)
            if association.get("Main") is True and table.get("VpcId") == vpc_id:
                main.append(table)
    if len(explicit) == 1:
        return explicit[0]
    if explicit:
        raise Unavailable("ambiguous explicit route table association")
    if len(main) != 1:
        raise Unavailable("VPC main route table unresolved")
    return main[0]


def subnet_by_id(index, subnet_id):
    rows = [s for s in items(index, "subnet") if s.get("SubnetId") == subnet_id]
    if len(rows) != 1:
        raise Unavailable("subnet join unresolved: " + str(subnet_id))
    return rows[0]


def subnet_public_prowler(index, subnet):
    """Prowler vpc_service: 0.0.0.0/0 (or ::/0 for IPv6) via igw- in the effective route table."""
    table = subnet_route_table(index, get(subnet, "SubnetId", str), get(subnet, "VpcId", str))
    v4 = v6 = False
    for route in list_of_objects(get(table, "Routes", list)):
        igw = isinstance(route.get("GatewayId"), str) and route["GatewayId"].startswith("igw-")
        v4 = v4 or (igw and route.get("DestinationCidrBlock") == "0.0.0.0/0")
        v6 = v6 or (igw and route.get("DestinationIpv6CidrBlock") == "::/0")
    return v4, v6


def kv(path, value):
    return nest(path, value)
