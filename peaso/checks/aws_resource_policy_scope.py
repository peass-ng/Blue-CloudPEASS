"""Bounded declaration review for IAM resource policies, across AWS services."""
import json
import re
from ipaddress import ip_network, collapse_addresses

from .facts import Unavailable, get

_ACCOUNT = re.compile(r"[0-9]{12}")
_ORG = re.compile(r"o-[a-z0-9]{10,32}")
_VPC = re.compile(r"vpc-[a-f0-9]{8,17}")
_VPCE = re.compile(r"vpce-[a-f0-9]{8,17}")


def strings(value):
    values = [value] if isinstance(value, str) else value
    if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
        raise Unavailable("policy member must be a nonempty string or string list")
    return values


def boundary(condition):
    """Only positive, required identity/network boundaries limit public grants.

    IfExists and ForAllValues require a matching Null:false existence guard.
    Negative operators alone do not restrict a positive grant.
    Transport, dates, MFA, region, resource names and arbitrary tags do not
    identify a trusted caller. All alternatives for one key must be bounded.
    """
    if not isinstance(condition, dict):
        raise Unavailable("malformed resource policy condition")
    required_keys = {
        key.casefold() for operator, block in condition.items()
        if isinstance(operator, str) and operator.casefold() == "null" and isinstance(block, dict)
        for key, value in block.items() if isinstance(key, str)
        and (value is False or isinstance(value, str) and value.casefold() == "false")
    }
    bounded = False
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict):
            raise Unavailable("malformed resource policy condition operator")
        for key, raw in block.items():
            if not isinstance(key, str):
                raise Unavailable("malformed resource policy condition key")
            # Bool/Null/numeric values are valid IAM conditions, but never an
            # identity/network boundary by themselves.
            values = [raw] if isinstance(raw, (str, bool, int, float)) else raw
            if not isinstance(values, list) or not values or any(not isinstance(v, (str, bool, int, float)) for v in values):
                raise Unavailable("malformed resource policy condition values")
            op, key = operator.casefold(), key.casefold()
            if op.startswith("forallvalues:"):
                if key not in required_keys:
                    continue
                op = op.split(":", 1)[1]
            elif op.startswith("foranyvalue:"):
                op = op.split(":", 1)[1]
            if op.endswith("ifexists"):
                if key not in required_keys:
                    continue
                op = op[:-8]
            if op == "stringequalsignorecase":
                op = "stringequals"
                values = [value.casefold() if isinstance(value, str) else value for value in values]
            if op not in {"stringequals", "stringlike", "arnequals", "arnlike", "ipaddress"}:
                continue
            if not all(isinstance(v, str) and v for v in values):
                continue
            if key in {"aws:principalaccount", "aws:sourceaccount", "aws:sourceowner"}:
                bounded |= all(_ACCOUNT.fullmatch(v) is not None for v in values)
            elif key in {"aws:principalorgid", "aws:sourceorgid"}:
                bounded |= all(_ORG.fullmatch(v) is not None for v in values)
            elif key in {"aws:principalorgpaths", "aws:sourceorgpaths"}:
                bounded |= all("/" in v and _ORG.fullmatch(v.split("/", 1)[0]) is not None and bool(v.split("/", 1)[1]) for v in values)
            elif key == "aws:sourcevpc":
                bounded |= all(_VPC.fullmatch(v) is not None for v in values)
            elif key in {"aws:sourcevpce", "aws:vpcesourcevpce"}:
                bounded |= all(_VPCE.fullmatch(v) is not None for v in values)
            elif key in {"aws:principalarn", "aws:sourcearn"}:
                def arn_bound(value):
                    parts = value.split(":", 5)
                    if len(parts) != 6 or parts[0] != "arn" or not parts[1] or not parts[2]:
                        return False
                    if any(char in parts[1] + parts[2] + parts[4] for char in "*?${}"):
                        return False
                    if _ACCOUNT.fullmatch(parts[4]):
                        return bool(parts[5])
                    # S3 source ARNs have no account component: require a fixed
                    # bucket rather than accepting arn:aws:s3:::*.
                    return key == "aws:sourcearn" and parts[2] == "s3" and not parts[4] and bool(parts[5]) and not any(c in parts[5].split("/", 1)[0] for c in "*?${}")
                bounded |= all(arn_bound(v) for v in values)
            elif key == "aws:sourceip" and op == "ipaddress":
                networks = []
                for value in values:
                    try:
                        networks.append(ip_network(value, strict=False))
                    except ValueError as exc:
                        raise Unavailable("malformed source IP boundary") from exc
                # Very broad public ranges do not establish a trusted network.
                collapsed = [n for version in (4, 6) for n in collapse_addresses([n for n in networks if n.version == version])]
                bounded |= all(n.prefixlen >= (8 if n.version == 4 else 32) for n in collapsed)
    return bounded


def public_principal(statement):
    if "NotPrincipal" in statement:
        strings(statement["NotPrincipal"]) if isinstance(statement["NotPrincipal"], str) else principal_values(statement["NotPrincipal"])
        # The complement of everybody is empty. AWS supports NotPrincipal
        # only as a broad complement, never as a wildcard-matching ARN glob.
        return statement["NotPrincipal"] not in ("*", {"AWS": "*"}, {"AWS": ["*"]})
    return "*" in principal_values(get(statement, "Principal"))


def principal_values(value):
    if isinstance(value, str):
        return strings(value)
    if not isinstance(value, dict) or not value:
        raise Unavailable("malformed resource policy principal")
    if any(key not in {"AWS", "Service", "Federated", "CanonicalUser"} for key in value):
        raise Unavailable("unknown resource policy principal kind")
    return [entry for raw in value.values() for entry in strings(raw)]


def review_document(document):
    if isinstance(document, str):
        try:
            document = json.loads(document)
        except (ValueError, TypeError) as exc:
            raise Unavailable("malformed JSON resource policy") from exc
    if not isinstance(document, dict) or "Statement" not in document:
        raise Unavailable("resource policy statement inventory unavailable")
    statements = document["Statement"]
    statements = [statements] if isinstance(statements, dict) else statements
    if not isinstance(statements, list) or any(not isinstance(s, dict) for s in statements):
        raise Unavailable("malformed resource policy statements")
    allows, denies = [], []
    for number, statement in enumerate(statements):
        if statement.get("Effect") not in {"Allow", "Deny"}:
            raise Unavailable("unrecognized resource policy effect")
        if ("Action" in statement) == ("NotAction" in statement):
            raise Unavailable("policy needs Action or NotAction")
        strings(statement.get("Action", statement.get("NotAction")))
        if "Resource" in statement:
            strings(statement["Resource"])
        if "NotResource" in statement:
            strings(statement["NotResource"])
        if "Resource" in statement and "NotResource" in statement:
            raise Unavailable("policy contains Resource and NotResource")
        if ("Principal" in statement) == ("NotPrincipal" in statement):
            raise Unavailable("policy needs Principal or NotPrincipal")
        principal_values(statement.get("Principal", statement.get("NotPrincipal")))
        bound = boundary(statement.get("Condition", {}))
        if statement["Effect"] == "Deny":
            denies.append(statement)
        elif public_principal(statement) and not bound:
            allows.append((number, statement))
    violations, uncertain = [], []
    for number, allow in allows:
        # Exact unconditional Deny-everyone covering this whole Allow proves
        # that it grants no access. Arbitrary IAM Deny interaction is not guessed.
        def covers_scope(deny):
            if deny.get("Principal") not in ("*", {"AWS": "*"}, {"AWS": ["*"]}) or "NotAction" in deny or "NotResource" in deny:
                return False
            actions = {value.casefold() for value in strings(deny["Action"])}
            if "NotAction" in allow and "*" not in actions:
                return False
            if "*" not in actions and not {value.casefold() for value in strings(allow.get("Action", "*"))} <= actions:
                return False
            resources = strings(deny.get("Resource", "*"))
            return "*" in resources or ("Resource" in allow and "NotResource" not in allow and set(strings(allow["Resource"])) <= set(resources))

        def complementary_boundary(condition):
            # A single negated boundary denies its entire outside. More ANDed
            # predicates can weaken that Deny and require separate reasoning.
            if len(condition) != 1:
                return False
            operator, block = next(iter(condition.items()))
            if not isinstance(block, dict) or len(block) != 1:
                return False
            positive = {
                "stringnotequals": "StringEquals", "stringnotlike": "StringLike",
                "stringnotequalsignorecase": "StringEqualsIgnoreCase",
                "arnnotequals": "ArnEquals", "arnnotlike": "ArnLike",
                "notipaddress": "IpAddress",
                "forallvalues:stringnotequals": "ForAnyValue:StringEquals",
                "forallvalues:stringnotequalsignorecase": "ForAnyValue:StringEqualsIgnoreCase",
                "forallvalues:stringnotlike": "ForAnyValue:StringLike",
            }.get(operator.casefold())
            return bool(positive and boundary({positive: block}))

        if any(covers_scope(d) and (not d.get("Condition") or complementary_boundary(d["Condition"])) for d in denies):
            continue
        relevant = []
        for deny in denies:
            # Empty complements deny no request. Matching exclusions likewise
            # leave this Allow untouched, even when it uses wildcard patterns.
            if "NotAction" in deny and "*" in strings(deny["NotAction"]):
                continue
            if "NotResource" in deny and "*" in strings(deny["NotResource"]):
                continue
            if "Action" in allow and "NotAction" in deny:
                excluded = {action.casefold() for action in strings(deny["NotAction"])}
                if {action.casefold() for action in strings(allow["Action"])} <= excluded:
                    continue
            if "Resource" in allow and "NotResource" in deny:
                if set(strings(allow["Resource"])) <= set(strings(deny["NotResource"])):
                    continue
            if "Resource" in allow and "Resource" in deny:
                # Literal prefixes before wildcards/variables can prove two
                # resource scopes disjoint. Compatible prefixes prove nothing.
                allowed_prefixes = [re.split(r"[*?$]", value, maxsplit=1)[0] for value in strings(allow["Resource"])]
                denied_prefixes = [re.split(r"[*?$]", value, maxsplit=1)[0] for value in strings(deny["Resource"])]
                if all(not a.startswith(d) and not d.startswith(a) for a in allowed_prefixes for d in denied_prefixes):
                    continue
            # Denying a finite caller population, or denying only callers
            # inside a positive boundary, leaves the outside population public.
            if not public_principal(deny):
                continue
            if boundary(deny.get("Condition", {})):
                continue
            if "Action" in deny and "Action" in allow:
                actions = strings(deny["Action"])
                allowed_actions = strings(allow["Action"])
                # Two literal action sets can be proven disjoint. Wildcard
                # intersections are deliberately left unresolved.
                if not any("*" in a or "?" in a or "*" in b or "?" in b or a.casefold() == b.casefold()
                           for a in actions for b in allowed_actions):
                    continue
            # Transport/date/tag conditions alone cannot establish who is
            # trusted. Only principal/network predicates might bound the grant.
            condition = deny.get("Condition", {})
            if condition and not any(str(key).casefold() in {
                "aws:principalarn", "aws:principalaccount", "aws:principalorgid", "aws:principalorgpaths",
                "aws:sourceaccount", "aws:sourceowner", "aws:sourcearn", "aws:sourceorgid", "aws:sourceorgpaths",
                "aws:sourcevpc", "aws:sourcevpce", "aws:sourceip"}
                for block in condition.values() for key in block):
                continue
            relevant.append(deny)
        record = {"statement_index": number, "sid": allow.get("Sid", "<unnamed>")}
        (uncertain if relevant else violations).append(record)
    return violations, uncertain


def evaluate(item, index):
    from . import result, unknown
    try:
        scope = get(index, "context.scope", str)
        if get(index, "context.provider", str) != "aws" or not re.fullmatch(r"[0-9]{12}/[a-z0-9-]+", scope):
            raise Unavailable("AWS account and Region scope unavailable")
        arn = get(item, "ResourceArn", str)
        parts = arn.split(":", 5)
        account, region = scope.split("/", 1)
        provenance = item.get("_provenance", {})
        source_region = provenance.get("source_region", region)
        if source_region != region and (provenance.get("owner_account") != account or provenance.get("collection_region") != region):
            raise Unavailable("home-endpoint policy lacks bound collection provenance")
        if len(parts) != 6 or parts[0] != "arn" or parts[4] not in (account, "") or parts[3] not in (source_region, ""):
            raise Unavailable("resource policy ARN differs from assessed account or Region")
        if not parts[4] and get(item, "_provenance.owner_account", str) != account:
            raise Unavailable("accountless resource ARN requires owned-list provenance")
        violations, uncertain = review_document(get(item, "Policy"))
        if violations:
            return result(True, resource_arn=arn, unrestricted_statements=violations,
                          observed=f"{len(violations)} Allow statements grant wildcard principals access without a recognized caller or network boundary.",
                          semantics="Resource-policy declaration review; identity policies, SCPs and resource public-access blocks are separate controls.")
        if uncertain:
            return unknown("A wildcard grant interacts with Deny statements requiring full IAM evaluation", resource_arn=arn, statements=uncertain)
        return result(False, resource_arn=arn, unrestricted_statements=[], observed="No unrestricted wildcard-principal Allow is declared in the collected policy.")
    except (Unavailable, ValueError, TypeError) as exc:
        return unknown(str(exc))


def install():
    """Replace the bounded historical implementation without editing signed source."""
    from dataclasses import replace
    from . import CHECKS
    for position, check in enumerate(CHECKS):
        if check.id == "aws_cis_aws_resource_policy_unrestricted_principal":
            CHECKS[position] = replace(check, evaluate=evaluate, allow_incomplete_failure=True,
                remediation="Remove unrestricted wildcard-principal grants or require a positive boundary to approved principals, accounts, organizations or private networks.")
            return
    raise ValueError("Resource policy base check is not registered")
