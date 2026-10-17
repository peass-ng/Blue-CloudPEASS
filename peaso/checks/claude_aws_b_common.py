"""Shared helpers for the claude_aws_b partition (AWS services fsx..workspaces).

Every predicate is a pure function over collected snapshot facts. Missing,
denied, partial or malformed facts raise ``Unavailable`` (UNKNOWN); a fact is
only treated as a configured absence when the documented API response shape
omits it and a detail-call sentinel proves the response was actually read.
Policy evaluators work on private copies and never mutate snapshot items.
"""
from __future__ import annotations

import copy
import json
from ipaddress import ip_address, ip_network

from . import register, result, unknown
from .facts import Unavailable, get, guard, list_of_objects, optional, complete_items
from .fixtures import CASES, nest

IDS = []
# native check id -> upstream row ids it ports (shard generator input)
ROWS = {}
# native check id -> official documentation URLs
DOCS = {}
# native check id -> short review note (semantics, deviations, pinned lists)
NOTES = {}

ACCOUNT = "111111111111"
SCOPE = ACCOUNT + "/us-east-1"
CONTEXT = {"scope": SCOPE, "Account": ACCOUNT, "provider": "aws", "created_at": "2026-01-01T00:00:00+00:00"}


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
        out["collections"][kind] = [{"scope": SCOPE, "status": "denied"}]
        out[kind] = []
    return out


def install(cid, kind, title, passing, failing, *, rows, severity, remediation, docs=(), note=None,
            category="hardening", control="CM-6", target="resource", dependencies=None, extra=None,
            unknown_case=None, unknown_index=None):
    """Register a native check, its behaviour fixtures and its upstream row provenance."""
    if not rows:
        raise ValueError("every claude_aws_b predicate must port at least one upstream row")

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


def text(value):
    if not isinstance(value, str):
        raise Unavailable("expected string fact")
    return value


def strings(value, what="list"):
    if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
        raise Unavailable("expected list of strings: " + what)
    return value


def absent_or(item, sentinel, path, default=None, expected=None):
    """Read optional ``path`` once ``sentinel`` proves the detail response was collected.

    AWS omits unset optional members (for example KmsKeyId). The sentinel is a
    member always present in that same response, so the omission is a configured
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


def empty(value):
    return value is None or value == "" or value == [] or value == {}


def clock(item, index):
    from .aws_a_facts import captured_clock
    return captured_clock(item if isinstance(item, dict) else {}, index)


def parse_time(value):
    from datetime import datetime
    if not isinstance(value, str):
        raise Unavailable("expected ISO-8601 timestamp")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise Unavailable("timestamp without timezone")
    return stamp


def account(index):
    context = index.get("context", {}) if isinstance(index, dict) else {}
    value = context.get("Account") if isinstance(context, dict) else None
    if not isinstance(value, str) or len(value) != 12 or not value.isdigit():
        raise Unavailable("audited account identity unavailable")
    return value


def policy_document(value):
    """A parsed policy document; strings are decoded, anything else is malformed."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise Unavailable("malformed policy JSON") from exc
    if not isinstance(value, dict):
        raise Unavailable("malformed policy document")
    if "collection_status" in value or "_coverage" in value:
        raise Unavailable("policy document not collected")
    statements = value.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable("malformed policy statements")
    return copy.deepcopy(statements)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ---------------------------------------------------------------------------
# Steampipe policy_std style evaluators (aws-compliance / aws-perimeter).
# policy_std lowercases condition keys and turns principals/values into arrays.
# ---------------------------------------------------------------------------
def _aws_principals(statement):
    principal = statement.get("Principal")
    if principal == "*":
        return ["*"]
    if isinstance(principal, dict):
        aws = principal.get("AWS")
        return [x for x in _as_list(aws)]
    return []


def wildcard_principal(statement):
    """Turbot: Principal.AWS = ["*"] or Principal = "*" (after policy_std dedupe)."""
    values = _aws_principals(statement)
    return bool(values) and set(values) == {"*"}


_RESTRICT = ("aws:sourceowner", "aws:sourceaccount", "aws:principalorgid", "aws:principalaccount", "aws:principalarn", "aws:sourcearn")


def _conditions(statement):
    raw = statement.get("Condition", {}) or {}
    if not isinstance(raw, dict):
        raise Unavailable("malformed policy condition")
    out = {}
    for operator, block in raw.items():
        if not isinstance(block, dict):
            raise Unavailable("malformed policy condition block")
        out[operator] = {str(k).lower(): _as_list(v) for k, v in block.items()}
    return out


def turbot_unrestricted(statement):
    """True when none of the Turbot restricting condition keys effectively constrains the statement."""
    cond = _conditions(statement)
    for key in _RESTRICT:
        if key in cond.get("StringEquals", {}) or key in cond.get("StringEqualsIgnoreCase", {}):
            return False
        operators = ["StringLike"] + (["ArnEquals", "ArnLike"] if key in ("aws:principalarn", "aws:sourcearn") else [])
        for operator in operators:
            values = cond.get(operator, {}).get(key)
            if values is not None and "*" not in values:
                return False
    return True


def turbot_public_statements(statements):
    """aws-perimeter resource_policy_public_sql statement predicate."""
    return [s for s in statements if s.get("Effect") == "Allow" and turbot_unrestricted(s) and wildcard_principal(s)]


def wildcard_allow_statements(statements):
    """aws-compliance *_restrict_public_access: Allow with wildcard principal, conditions ignored."""
    return [s for s in statements if s.get("Effect") == "Allow" and wildcard_principal(s)]


# ---------------------------------------------------------------------------
# Prowler policy helpers, ported faithfully from prowler/providers/aws/services/iam/lib/policy.py
# (pinned 61d2cc55c4539a6b48a3cf9f3729d8f2af300882). Inputs are private copies.
# ---------------------------------------------------------------------------
def has_public_principal(statement):
    principal = statement.get("Principal", "")
    if isinstance(principal, (str, list)):
        if "*" in principal or "arn:aws:iam::*:root" in principal:
            return True
    if isinstance(principal, dict):
        if "*" in principal or "arn:aws:iam::*:root" in principal:
            return True
        aws = principal.get("AWS", "")
        canonical = principal.get("CanonicalUser", "")
        if isinstance(aws, (str, list)) and ("*" in aws or "arn:aws:iam::*:root" in aws):
            return True
        if isinstance(canonical, (str, list)) and ("*" in canonical or "arn:aws:iam::*:root" in canonical):
            return True
    return False


def has_restrictive_source_arn_condition(statement, source_account=""):
    if "Condition" not in statement:
        return False
    for operator in statement["Condition"]:
        block = statement["Condition"][operator]
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


def is_condition_block_restrictive_sns_endpoint(condition):
    import re
    valid = False
    pattern = re.compile(r".+@[^*]+|^https:\/\/[^*]+|^arn:aws:sns:[^*]+")
    for operator in ("StringEquals", "StringLike"):
        if operator not in condition:
            continue
        block = _lower_block(condition, operator)
        value = block.get("sns:endpoint")
        if isinstance(value, str) and pattern.fullmatch(value):
            valid = True
    return valid


def is_condition_restricting_from_private_ip(condition):
    block = condition.get("IpAddress", {})
    if not block:
        return False
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


def is_policy_public(statements, source_account="", is_cross_account_allowed=True):
    """Prowler is_policy_public with default arguments (no trusted lists, no action filter)."""
    trusted = {source_account} if source_account else set()
    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        public = has_public_principal(statement)
        principal = statement.get("Principal", "")
        if not public and isinstance(principal, dict) and source_account and not is_cross_account_allowed:
            aws = principal.get("AWS")
            if isinstance(aws, str) and not any(t in aws for t in trusted):
                public = True
            if isinstance(aws, list) and not all(any(t in str(p) for t in trusted) for p in aws):
                public = True
        if public:
            condition = copy.deepcopy(statement.get("Condition", {}) or {})
            if not isinstance(condition, dict):
                raise Unavailable("malformed policy condition")
            if not condition or (not is_condition_block_restrictive(copy.deepcopy(condition), source_account, is_cross_account_allowed)
                    and not is_condition_block_restrictive_organization(copy.deepcopy(condition))
                    and not is_condition_restricting_from_private_ip(copy.deepcopy(condition))):
                return True
    return False


# ---------------------------------------------------------------------------
# VPC routing helpers.
# ---------------------------------------------------------------------------
def _route_tables(index):
    return complete_items(index, "route_table")


def subnet_route_table(index, subnet_id, vpc_id=None):
    """Explicit association, else the VPC main route table (EC2 semantics)."""
    tables = _route_tables(index)
    explicit, main = [], []
    for table in tables:
        for association in list_of_objects(get(table, "Associations", list)):
            if association.get("SubnetId") == subnet_id:
                explicit.append(table)
            if association.get("Main") is True and (vpc_id is None or table.get("VpcId") == vpc_id):
                main.append(table)
    if len(explicit) == 1:
        return explicit[0], "explicit"
    if explicit:
        raise Unavailable("ambiguous explicit route table association")
    if vpc_id is None:
        raise Unavailable("subnet has no explicit route table and its VPC is unknown")
    if len(main) != 1:
        raise Unavailable("VPC main route table unresolved")
    return main[0], "main"


def subnet_vpc(index, subnet_id):
    rows = [s for s in complete_items(index, "subnet") if s.get("SubnetId") == subnet_id]
    if len(rows) != 1:
        raise Unavailable("subnet join unresolved: " + str(subnet_id))
    return rows[0]


def igw_default_route(table):
    routes = list_of_objects(get(table, "Routes", list))
    return any(r.get("DestinationCidrBlock") == "0.0.0.0/0" and str(r.get("GatewayId", "")).startswith("igw-") for r in routes)


def subnet_is_public_prowler(index, subnet_id):
    """Prowler vpc_service: route 0.0.0.0/0 via igw- in the effective route table."""
    subnet = subnet_vpc(index, subnet_id)
    table, _ = subnet_route_table(index, subnet_id, get(subnet, "VpcId", str))
    return igw_default_route(table)


def subnet_is_public_turbot(index, subnet_id):
    """aws-compliance *_no_public_subnet: 0.0.0.0/0 to igw-% or nat-% in the explicit, else main, table."""
    subnet = subnet_vpc(index, subnet_id)
    table, _ = subnet_route_table(index, subnet_id, get(subnet, "VpcId", str))
    for route in list_of_objects(get(table, "Routes", list)):
        if route.get("DestinationCidrBlock") != "0.0.0.0/0":
            continue
        if str(route.get("GatewayId", "")).startswith("igw-") or str(route.get("NatGatewayId", "")).startswith("nat-"):
            return True
    return False


def explicit_igw_subnets(index):
    """aws-compliance opensearch_domain_in_vpc: subnets explicitly associated with a 0.0.0.0/0 igw- route table."""
    out = set()
    for table in _route_tables(index):
        if igw_default_route(table):
            for association in list_of_objects(get(table, "Associations", list)):
                if isinstance(association.get("SubnetId"), str):
                    out.add(association["SubnetId"])
    return out


def selection_resources(index):
    """Prowler backup_client.protected_resources: Resources of every backup plan selection."""
    out = []
    for plan in complete_items(index, "backup_plan"):
        selections = get(plan, "Selections", dict)
        if selections.get("collection_status") not in ("collected", "empty"):
            raise Unavailable("backup selections unavailable")
        for selection in list_of_objects(selections.get("items", [])):
            body = get(selection, "Selection.BackupSelection", dict)
            resources = optional(body, "Resources", [], list)
            out.extend(strings(resources, "BackupSelection.Resources"))
    return out


# ---------------------------------------------------------------------------
# Security group helper: prowler ec2 check_security_group.
# ---------------------------------------------------------------------------
def sg_rule_open(rule, protocol, ports=None, any_address=False):
    ports = ports or []
    ranges = [r.get("CidrIp") for r in list_of_objects(rule.get("IpRanges", []))] + [r.get("CidrIpv6") for r in list_of_objects(rule.get("Ipv6Ranges", []))]
    public = any(c in ("0.0.0.0/0", "::/0") for c in ranges)
    if not any_address:
        # any_address=False in prowler also accepts any public CIDR; this partition only uses any_address=True.
        raise ValueError("only any_address=True semantics are ported")
    if not public:
        return False
    proto = str(rule.get("IpProtocol"))
    if proto == "-1":
        return True
    if proto != protocol:
        return False
    low, high = rule.get("FromPort"), rule.get("ToPort")
    if not isinstance(low, int) or not isinstance(high, int):
        raise Unavailable("malformed security group port range")
    if high - low + 1 == 65536:
        return True
    if not ports:
        return False
    return any(low <= port <= high for port in ports)


def security_groups(index, ids):
    rows = complete_items(index, "security_group")
    found = {}
    for row in rows:
        gid = row.get("GroupId")
        if gid in ids:
            found[gid] = row
    if set(found) != set(ids):
        raise Unavailable("security group join unresolved")
    return [found[g] for g in ids]


# ---------------------------------------------------------------------------
# Joins.
# ---------------------------------------------------------------------------
def kms_manager(index, key_ref):
    """Resolve a KMS key reference (ARN or key id) to KeyManager via the complete kms_key inventory."""
    keys = complete_items(index, "kms_key")
    matches = []
    for key in keys:
        meta = get(key, "Metadata.KeyMetadata", dict)
        if key_ref in (meta.get("Arn"), meta.get("KeyId")):
            matches.append(meta)
    if len(matches) != 1:
        raise Unavailable("KMS key join unresolved or ambiguous")
    manager = get(matches[0], "KeyManager", str)
    if manager not in ("CUSTOMER", "AWS"):
        raise Unavailable("unknown KMS key manager")
    return manager


def protected_resources(index):
    return complete_items(index, "backup_protected_resource")


def kv(item, path, value):
    return nest(path, value)


MISSING = object()


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
    passing = {sentinel: base.get(sentinel, "x"), **base}
    passing = _merge(passing, nest(path, goods[0]))
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


def _merge(left, right):
    out = copy.deepcopy(left)
    for key, value in right.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = value
    return out


def add_months(stamp, months):
    import calendar
    month = stamp.month - 1 + months
    year = stamp.year + month // 12
    month = month % 12 + 1
    day = min(stamp.day, calendar.monthrange(year, month)[1])
    return stamp.replace(year=year, month=month, day=day)


def scope_of(item):
    return get(item, "scope", str)


def inventory(kind, rows, status=None):
    """A fixture index holding a complete inventory for ``kind``."""
    return {"collections": {kind: [{"scope": SCOPE, "status": status or ("collected" if rows else "empty")}]}, kind: [{"data": r} for r in rows], "context": dict(CONTEXT)}


def indexes(*parts):
    out = {"collections": {}, "context": dict(CONTEXT)}
    for part in parts:
        for key, value in part.items():
            if key == "collections":
                out["collections"].update(value)
            elif key != "context":
                out[key] = value
    return out
