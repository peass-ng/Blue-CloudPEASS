"""Signed Lambda execution-role existence over complete cached IAM inventory."""
from __future__ import annotations

import re

from . import register, result
from .facts import Unavailable, complete_items, get, memoized
from .fixtures import CASES


CHECK_ID = "aws_cis_lambda_execution_role_exists"
_SCOPE = re.compile(r"^([0-9]{12})/([a-z0-9-]+)$")
_CALLER = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):[^:]+:[^:]*:([0-9]{12}):.+$")
_FUNCTION = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):lambda:([a-z0-9-]+):([0-9]{12}):function:[^:]+$")
_ROLE = re.compile(r"^arn:(aws|aws-cn|aws-us-gov):iam::([0-9]{12}):role/.+$")


def _authority(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS scope authority unavailable")
    match = _SCOPE.fullmatch(get(context, "scope", str))
    account = get(context, "Account", str)
    if match is None or match.group(1) != account:
        raise Unavailable("audited regional account scope unavailable")
    callers = get(context, "metadata.caller_identities", list)
    partitions = set()
    for caller in callers:
        if not isinstance(caller, dict):
            raise Unavailable("malformed caller identity")
        if caller.get("Account") != account:
            continue
        arn = _CALLER.fullmatch(get(caller, "Arn", str))
        if arn is None or arn.group(2) != account:
            raise Unavailable("caller ARN does not prove audited account")
        partitions.add(arn.group(1))
    if len(partitions) != 1:
        raise Unavailable("caller partition unavailable or ambiguous")
    return account, match.group(2), partitions.pop()


def _facts(index):
    account, region, partition = _authority(index)
    collections = get(index, "collections", dict)
    for kind, scope, global_kind in (("lambda_function", f"{account}/{region}", False),
                                     ("iam_role", f"{account}/global", True)):
        envelopes = collections.get(kind)
        if not isinstance(envelopes, list) or len(envelopes) != 1:
            raise Unavailable("scoped inventory envelope unavailable: " + kind)
        envelope = envelopes[0]
        if (not isinstance(envelope, dict) or envelope.get("type") != kind or
                envelope.get("scope") != scope or envelope.get("account_id") != account or
                envelope.get("global") is not global_kind):
            raise Unavailable("inventory scope authority unavailable: " + kind)
    functions = {}
    for item in complete_items(index, "lambda_function"):
        arn = get(item, "FunctionArn", str)
        parsed = _FUNCTION.fullmatch(arn)
        if parsed is None or parsed.groups()[:3] != (partition, region, account) or arn in functions:
            raise Unavailable("malformed or duplicate Lambda function ARN in scoped inventory")
        if get(item, "AccountId", str) != account or get(item, "Region", str) != region:
            raise Unavailable("Lambda item account or Region differs from audited scope")
        functions[arn] = item
    roles = set()
    for item in complete_items(index, "iam_role"):
        arn = get(item, "Arn", str)
        parsed = _ROLE.fullmatch(arn)
        if parsed is None or parsed.groups() != (partition, account) or arn in roles:
            raise Unavailable("malformed or duplicate IAM role ARN in account-global inventory")
        if get(item, "AccountId", str) != account:
            raise Unavailable("IAM role item account differs from audited account")
        roles.add(arn)
    return account, region, partition, functions, roles


@register(CHECK_ID, "aws", "least_privilege", "lambda_function",
          "Lambda execution role resolves to an existing IAM role", "medium", "AC-6",
          "Restore or assign an owner-approved existing execution role to the function, then verify it can run with its intended permissions.",
          dependencies=["lambda_function", "iam_role"])
def execution_role_exists(item, index):
    account, region, partition, functions, roles = memoized(
        index, ("aws_lambda_role_existence",), lambda: _facts(index))
    function_arn = get(item, "FunctionArn", str)
    if functions.get(function_arn) != item:
        raise Unavailable("Lambda function differs from complete scoped inventory")
    role_arn = get(item, "Role", str)
    role = _ROLE.fullmatch(role_arn)
    if role is None or role.groups() != (partition, account):
        raise Unavailable("Lambda execution role ARN is malformed or outside audited account")
    return result(role_arn not in roles, function_arn=function_arn, execution_role_arn=role_arn,
                  semantics="Declared IAM role existence only; trust and effective permissions are separate")


@register("aws_cis_lambda_execution_role_unique", "aws", "least_privilege", "lambda_function",
          "Active Lambda functions use distinct execution roles", "medium", "AC-6",
          "Assign an owner-reviewed dedicated execution role to each active function that shares a role.",
          dependencies=["lambda_function"])
def execution_role_unique(item, index):
    account, region, partition = _authority(index)
    arn = get(item, "FunctionArn", str)
    fn = _FUNCTION.fullmatch(arn)
    role_arn = get(item, "Role", str)
    role = _ROLE.fullmatch(role_arn)
    if (fn is None or fn.groups() != (partition, region, account) or role is None or
            role.groups() != (partition, account) or get(item, "AccountId", str) != account or
            get(item, "Region", str) != region):
        raise Unavailable("Lambda function or role is outside the audited account/Region/partition")
    envelopes = get(index, "collections", dict).get("lambda_function")
    if (not isinstance(envelopes, list) or len(envelopes) != 1 or not isinstance(envelopes[0], dict) or
            envelopes[0].get("scope") != f"{account}/{region}" or
            envelopes[0].get("account_id") != account or envelopes[0].get("global") is not False or
            envelopes[0].get("status") not in {"collected", "partial"}):
        raise Unavailable("regional Lambda inventory authority unavailable")
    rows = get(index, "lambda_function", list)
    if sum(isinstance(row, dict) and row.get("data") == item for row in rows) != 1:
        raise Unavailable("Lambda item is detached from regional inventory")
    config = get(item, "Configuration", dict)
    if get(config, "collection_status", str) != "collected":
        raise Unavailable("Lambda configuration detail unavailable")
    if config.get("FunctionArn") not in (None, arn) or config.get("Role") not in (None, role_arn):
        raise Unavailable("Lambda configuration identity mismatch")
    state = get(config, "State", str)
    if state in {"Pending", "Inactive", "Failed", "Deactivating", "Deactivated", "ActiveNonInvocable", "Deleting"}:
        return "NOT_APPLICABLE", {"function_arn": arn, "state": state,
                                  "reason": "signed role-uniqueness rule applies to active functions"}
    if state != "Active":
        raise Unavailable("unrecognized Lambda State")
    usage = get(index, "context.metadata.lambda_execution_role_usage", dict)
    if get(usage, "schema_version", int) != 1:
        raise Unavailable("Lambda role-usage summary schema unavailable")
    accounts = get(usage, "accounts", list)
    matching = [row for row in accounts if isinstance(row, dict) and row.get("account_id") == account]
    if len(matching) != 1:
        raise Unavailable("account-wide Lambda role-usage summary unavailable")
    summary = matching[0]
    if summary.get("partition") != partition or summary.get("status") not in {"collected", "partial"}:
        raise Unavailable("Lambda role-usage summary authority unavailable")
    observed = get(summary, "observed_regions", list)
    if region not in observed or any(not isinstance(x, str) for x in observed):
        raise Unavailable("Lambda Region absent from role-usage summary")
    shared = get(summary, "shared_active_roles", list)
    if any(not isinstance(row, dict) or not isinstance(row.get("role_arn"), str) or
           type(row.get("function_count")) is not int or row["function_count"] < 2 for row in shared):
        raise Unavailable("malformed shared Lambda role summary")
    matching_roles = [row for row in shared if row["role_arn"] == role_arn]
    if len(matching_roles) > 1:
        raise Unavailable("duplicate role in account-wide summary")
    if matching_roles:
        return result(True, function_arn=arn, execution_role_arn=role_arn,
                      active_function_count=matching_roles[0]["function_count"],
                      account_coverage=summary["status"])
    if summary["status"] != "collected":
        raise Unavailable("full account Lambda inventory unavailable for uniqueness pass")
    enabled = get(summary, "enabled_regions", list)
    if (envelopes[0]["status"] != "collected" or not enabled or
            any(not isinstance(x, str) for x in enabled) or len(set(enabled)) != len(enabled) or
            len(set(observed)) != len(observed) or set(enabled) != set(observed)):
        raise Unavailable("account-wide enabled-Region coverage inconsistent with regional inventory")
    return result(False, function_arn=arn, execution_role_arn=role_arn,
                  account_coverage="collected")


_account = "123456789012"
_regional_scope = _account + "/eu-west-1"
_global_scope = _account + "/global"
_role_arn = "arn:aws:iam::123456789012:role/app-exec"
_function_arn = "arn:aws:lambda:eu-west-1:123456789012:function:app"
_lambda_function = {"FunctionArn": _function_arn, "FunctionName": "app",
    "Role": _role_arn, "AccountId": _account, "Region": "eu-west-1",
    "Configuration": {"collection_status": "collected", "FunctionArn": _function_arn,
        "Role": _role_arn, "State": "Active"}}
_lambda_role = {"Arn": _role_arn, "RoleName": "app-exec", "AccountId": _account}


def _lambda_index(row, roles=(), *, usage=None, role_status="collected"):
    metadata = {"caller_identities": [{"Account": _account,
        "Arn": "arn:aws:sts::123456789012:assumed-role/Audit/peaso-read-only"}]}
    if usage is not None:
        metadata["lambda_execution_role_usage"] = {"schema_version": 1, "accounts": [{
            "account_id": _account, "partition": "aws", "status": usage[0],
            "enabled_regions": ["eu-west-1"], "observed_regions": ["eu-west-1"],
            "shared_active_roles": usage[1]}]}
    return {"context": {"provider": "aws", "scope": _regional_scope,
        "Account": _account, "metadata": metadata},
        "collections": {
            "lambda_function": [{"type": "lambda_function", "scope": _regional_scope,
                "status": "collected", "account_id": _account, "global": False,
                "items": [row]}],
            "iam_role": [{"type": "iam_role", "scope": _global_scope,
                "status": role_status, "account_id": _account, "global": True,
                "items": list(roles)}]},
        "lambda_function": [{"type": "lambda_function", "scope": _regional_scope,
            "data": row}],
        "iam_role": [{"type": "iam_role", "scope": _global_scope, "data": role}
            for role in roles]}


CASES[CHECK_ID] = {"pass": _lambda_function,
    "pass_index": _lambda_index(_lambda_function, [_lambda_role]),
    "fail": _lambda_function, "fail_index": _lambda_index(_lambda_function),
    "unknown": _lambda_function,
    "unknown_index": _lambda_index(_lambda_function, [_lambda_role], role_status="denied"),
    "index": _lambda_index(_lambda_function, [_lambda_role])}
_shared = [{"role_arn": _role_arn, "function_count": 2}]
CASES["aws_cis_lambda_execution_role_unique"] = {
    "pass": _lambda_function,
    "pass_index": _lambda_index(_lambda_function, usage=("collected", [])),
    "fail": _lambda_function,
    "fail_index": _lambda_index(_lambda_function, usage=("partial", _shared)),
    "unknown": _lambda_function, "unknown_index": _lambda_index(_lambda_function),
    "index": _lambda_index(_lambda_function, usage=("collected", []))}
