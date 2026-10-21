"""Three-valued evaluation of IAM policy Condition blocks against what a snapshot can prove.

evaluate(condition, ctx) -> (verdict, reasons)
    verdict True   the condition provably holds for the technique's request,
            False  it provably does not hold (an Allow does not grant, a Deny does not apply),
            None   it cannot be decided from the snapshot (the edge stays conditional; reasons say why).

The request context is described by a Context: values the snapshot proves (principal ARN/account/tags, target
resource tags, the services a role is passed to), keys that are provably ABSENT from a direct API call
(aws:SourceArn, aws:CalledVia, ...), keys the requester chooses (aws:RequestTag/*, aws:RequestedRegion of regional
services) and everything else (unknown). Operator semantics follow the IAM reference: negated operators are true
for a missing key, ...IfExists is true for a missing key, Null tests presence, ForAnyValue/ForAllValues compare sets.
"""
from __future__ import annotations

import ipaddress
import re

from . import as_list, glob_match

ABSENT = object()      # the key is provably not in the request context
UNKNOWN = object()     # the snapshot cannot tell
CHOSEN = object()      # the requester picks the value (request tags, region of a regional service, ...)

# Keys never present in a principal's direct call (they are set when a service calls on its behalf).
ABSENT_KEYS = {
    "aws:sourcearn", "aws:sourceaccount", "aws:sourceorgid", "aws:sourceorgpaths", "aws:calledvia",
    "aws:calledviafirst", "aws:calledvialast", "aws:principalservicename", "aws:principalservicenameslist",
    "aws:sourceowner", "aws:sourceidentity",
}
FALSE_KEYS = {"aws:viaawsservice": ["false"], "aws:principalisawsservice": ["false"], "aws:securetransport": ["true"]}
CHOSEN_PREFIXES = ("aws:requesttag/",)
CHOSEN_KEYS = {"aws:tagkeys"}
GLOBAL_SERVICES = {"iam", "organizations", "account", "cloudfront", "route53", "waf", "globalaccelerator", "support",
                   "budgets", "ce", "health", "shield", "trustedadvisor", "aws-portal", "chatbot"}
NEGATED = {"stringnotequals", "stringnotequalsignorecase", "stringnotlike", "arnnotequals", "arnnotlike",
           "numericnotequals", "datenotequals", "notipaddress", "binarynotequals"}
PRINCIPAL_KEYS = ("aws:principalarn", "aws:principaltag/", "aws:username", "aws:userid", "aws:principaltype",
                  "aws:principalaccount", "aws:principalorgid", "aws:principalorgpaths", "aws:principalisawsservice")
RESOURCE_KEYS = ("aws:resourcetag/", "iam:resourcetag/", "aws:resourceaccount", "iam:associatedresourcearn",
                 "aws:resourceorgid", "aws:resourceorgpaths")
_VAR = re.compile(r"\$\{([^}]*)\}")


class Context:
    """Request-context facts for one (principal, action, resource, technique) evaluation."""

    def __init__(self, principal=None, action="", resource=None, passed_to=(), resource_tags=None, org_id=None,
                 overrides=None):
        """resource None means "a resource the requester picks" (an ANY check): it lives in the principal's account."""
        self.overrides = overrides or {}
        self.principal = principal
        self.action = action
        self.resource = resource
        self.passed_to = tuple(passed_to)
        self.resource_tags = resource_tags          # dict, {} (no tags) or None (unknown)
        self.org_id = org_id

    def value(self, key):
        """list of values | ABSENT | UNKNOWN | CHOSEN for a lower-cased condition key."""
        if key in self.overrides:
            return self.overrides[key]
        p = self.principal
        attrs = p.attrs if p is not None else {}
        if key in ABSENT_KEYS:
            return ABSENT
        if key in FALSE_KEYS:
            return FALSE_KEYS[key]
        if key in CHOSEN_KEYS or key.startswith(CHOSEN_PREFIXES):
            return CHOSEN
        if key == "aws:requestedregion":
            return ["us-east-1"] if self.action.split(":", 1)[0] in GLOBAL_SERVICES else CHOSEN
        if p is not None:
            if key == "aws:principalarn":
                return [p.id]
            if key == "aws:principalaccount":
                return [p.scope]
            if key == "aws:principaltype":
                return ["User"] if p.kind == "aws_user" else ["AssumedRole"] if p.kind == "aws_role" else UNKNOWN
            if key == "aws:username":
                return [p.label] if p.kind == "aws_user" else ABSENT
            if key.startswith("aws:principaltag/"):
                tags = attrs.get("tags")
                if tags is None:
                    return UNKNOWN
                tag = _tag(tags, key.split("/", 1)[1])
                return ABSENT if tag is None else [tag]
            if key == "aws:principalorgid":
                return [self.org_id] if self.org_id else UNKNOWN
        if key.startswith(("aws:resourcetag/", "iam:resourcetag/")) or (
                key.split(":", 1)[0] not in ("aws", "iam") and ":resourcetag/" in key):
            if self.resource_tags is None:
                return UNKNOWN
            tag = _tag(self.resource_tags, key.split("/", 1)[1])
            return ABSENT if tag is None else [tag]
        if key == "aws:resourceaccount":
            if self.resource is None:
                return [p.scope] if p is not None else UNKNOWN
            account = self.resource.split(":")[4] if isinstance(self.resource, str) and self.resource.count(":") >= 5 else ""
            return [account] if account.isdigit() else UNKNOWN
        if key == "iam:passedtoservice":
            if not self.action.startswith("iam:passrole"):
                return ABSENT
            return list(self.passed_to) if self.passed_to else UNKNOWN
        return UNKNOWN

    def variable(self, name):
        """Value of a ${...} policy variable or None when unknown."""
        low = name.lower()
        if low in ("*", "?", "$"):
            return name
        got = self.value(low)
        if isinstance(got, list) and len(got) == 1:
            return got[0]
        return None


def _tag(tags, key):
    low = key.lower()
    for k, v in tags.items():
        if str(k).lower() == low:  # tag keys are case-insensitive in condition matching
            return str(v)
    return None


def principal_dependent(condition, resources=()):
    """True when the statement's outcome depends on who the principal is (not only on its policies)."""
    text = (repr(condition) + repr(list(resources))).lower()
    return any(k in text for k in PRINCIPAL_KEYS)


def resource_dependent(condition):
    text = repr(condition).lower()
    return any(k in text for k in RESOURCE_KEYS) or ":resourcetag/" in text


def substitute(pattern, ctx):
    """Replace ${...} variables in a resource pattern; None when one is unknown."""
    if "${" not in pattern:
        return pattern
    missing = []

    def repl(match):
        got = ctx.variable(match.group(1)) if ctx is not None else None
        if got is None:
            missing.append(match.group(1))
            return "*"
        return got
    out = _VAR.sub(repl, pattern)
    return None if missing else out


def evaluate(condition, ctx, effect="allow"):
    """(True | False | None, [reasons]) for a whole Condition block (operators AND keys AND)."""
    if not condition:
        return True, []
    if not isinstance(condition, dict):
        return None, ["condition_unparsable"]
    verdict, reasons = True, []
    for operator, block in condition.items():
        if not isinstance(block, dict):
            return None, ["condition_unparsable"]
        for key, values in block.items():
            got, why = _one(str(operator), str(key).lower(), as_list(values), ctx, effect)
            if got is False:
                return False, [why] if why else []
            if got is None:
                verdict = None
                reasons.append(why or f"condition_{key}")
    return verdict, reasons


def _one(operator, key, expected, ctx, effect):
    op = operator.lower()
    qualifier = None
    if op.startswith("foranyvalue:"):
        qualifier, op = "any", op.split(":", 1)[1]
    elif op.startswith("forallvalues:"):
        qualifier, op = "all", op.split(":", 1)[1]
    if_exists = op.endswith("ifexists")
    if if_exists:
        op = op[:-len("ifexists")]
    actual = ctx.value(key) if ctx is not None else UNKNOWN
    reason = f"condition_{key}"
    if (key == "iam:associatedresourcearn" and actual is UNKNOWN and ctx is not None
            and ctx.action.startswith("iam:passrole")):
        # The resource is created by the technique: only its service is known. A pattern for another service proves
        # the role cannot be passed this way; a pattern for the right service is plausible but not proven.
        prefixes = {_arn_service(s) for s in ctx.passed_to}
        if not prefixes:
            return None, reason
        plausible = any(_pattern_service_matches(str(v), prefixes) for v in expected)
        if op in NEGATED:
            return None, reason
        return (None, "condition_iam:associatedresourcearn_resource_not_proven") if plausible else (False, None)
    if op == "null":
        want_absent = [str(v).lower() == "true" for v in expected]
        if actual is UNKNOWN:
            return None, reason
        if actual is CHOSEN:
            return (True if effect == "allow" else False), None  # requester includes or omits the key
        present = actual is not ABSENT
        return any(w != present for w in want_absent), None
    if actual is CHOSEN:
        # The requester controls the value: an Allow may be satisfiable, a Deny may be avoidable; neither is proven.
        return None, f"requester_controlled_{key}"
    if actual is UNKNOWN:
        return None, reason
    if actual is ABSENT:
        if if_exists or qualifier == "all":
            return True, None
        if qualifier == "any":
            return False, None
        return op in NEGATED, None
    values = [substitute(str(v), ctx) for v in expected]
    if any(v is None for v in values):
        return None, "condition_variable_unknown"
    if key == "iam:passedtoservice" and len(actual) > 1 and qualifier is None:
        # The technique's service is one of several candidates: true when any candidate passes, false when none does.
        hits = [_match(op, [a], values) for a in actual]
        if any(h is None for h in hits):
            return None, reason
        return any(hits), None
    got = _match(op, actual, values, qualifier)
    return (got, None) if got is not None else (None, reason)


def _match(op, actual, values, qualifier=None):
    """Compare request values with policy values; None for operators a snapshot can never decide."""
    negated = op in NEGATED
    core = op.replace("not", "", 1) if negated else op
    if core.startswith("string"):
        ignore = core.endswith("ignorecase")
        like = core.startswith("stringlike")

        def test(a):
            if like:
                return any(glob_match(v, a, ignore_case=False) for v in values)
            return any((a.lower() == v.lower()) if ignore else (a == v) for v in values)
    elif core.startswith("arn"):
        def test(a):  # ArnEquals and ArnLike both accept wildcards, case-sensitive
            return any(glob_match(v, a, ignore_case=False) for v in values)
    elif core == "bool":
        def test(a):
            return any(a.lower() == v.lower() for v in values)
    elif core == "ipaddress":
        def test(a):
            try:
                ip = ipaddress.ip_address(a)
                return any(ip in ipaddress.ip_network(v, strict=False) for v in values)
            except ValueError:
                return False
    else:
        return None  # Numeric*/Date*/Binary*: values a snapshot never proves
    hits = [test(str(a)) != negated for a in actual]
    if qualifier == "all":
        return all(hits)
    if qualifier == "any" or len(hits) != 1:
        return any(hits)
    return hits[0]


ARN_SERVICE = {"ecs-tasks": "ecs", "elasticmapreduce": "elasticmapreduce", "tasks.apprunner": "apprunner",
               "cognito-identity": "cognito-identity", "pods.eks": "eks"}


def _arn_service(service):
    service = str(service).lower()
    for prefix, arn in ARN_SERVICE.items():
        if service.startswith(prefix + "."):
            return arn
    return service.split(".", 1)[0]


def _pattern_service_matches(pattern, prefixes):
    parts = pattern.split(":")
    if len(parts) < 3:
        return pattern in ("*",)
    return any(glob_match(parts[2], p, ignore_case=True) for p in prefixes)
