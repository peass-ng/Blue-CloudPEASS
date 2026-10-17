"""Reviewed CloudWatch configuration predicates; no log contents or queries."""
from __future__ import annotations

from . import register, result, unknown
from .facts import get
from .fixtures import CASES
from .aws_a_facts import api_optional, complete_items, scope_subject, scope_fixture

NATIVE_IDS = []
LOG_PROVENANCE = {"operation": "logs:DescribeLogGroups", "native_response_complete": True}


@register("aws.a.cloudwatch.alarm_actions_enabled", "aws", "hardening", "cloudwatch_alarm", "CloudWatch metric alarm actions are enabled",
    "medium", "SI-4", "Enable the actions for applicable metric alarms.")
def actions_enabled(item, index):
    enabled = get(item, "ActionsEnabled", bool)
    return result(not enabled, actions_enabled=enabled)
CASES["aws.a.cloudwatch.alarm_actions_enabled"] = {"pass": {"ActionsEnabled": True}, "fail": {"ActionsEnabled": False}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.alarm_actions_enabled")


@register("aws.a.cloudwatch.alarm_state_actions", "aws", "hardening", "cloudwatch_alarm", "CloudWatch metric alarm has ALARM-state actions",
    "medium", "SI-4", "Configure appropriate actions for the ALARM state.")
def alarm_actions(item, index):
    actions = get(item, "AlarmActions", list)
    if any(not isinstance(action, str) or not action for action in actions):
        return unknown("malformed alarm actions")
    return result(not bool(actions), alarm_actions=actions)
CASES["aws.a.cloudwatch.alarm_state_actions"] = {"pass": {"AlarmActions": ["arn:aws:sns:us-east-1:123456789012:alerts"]}, "fail": {"AlarmActions": []}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.alarm_state_actions")


@register("aws.a.cloudwatch.any_state_actions", "aws", "hardening", "cloudwatch_alarm", "CloudWatch alarm has at least one action in any state",
    "medium", "SI-4", "Configure appropriate ALARM, OK or INSUFFICIENT_DATA actions.")
def any_actions(item, index):
    arrays = {field: get(item, field, list) for field in ("AlarmActions", "OKActions", "InsufficientDataActions")}
    if any(not isinstance(value, str) or not value for array in arrays.values() for value in array):
        return unknown("malformed alarm state actions")
    return result(not any(arrays.values()), state_actions=arrays)
CASES["aws.a.cloudwatch.any_state_actions"] = {"pass": {"AlarmActions": [], "OKActions": ["arn:aws:sns:us-east-1:123456789012:alerts"], "InsufficientDataActions": []},
    "fail": {"AlarmActions": [], "OKActions": [], "InsufficientDataActions": []}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.any_state_actions")


@register("aws.a.cloudwatch.log_kms_encryption", "aws", "hardening", "log_group", "CloudWatch log group has a KMS key associated",
    "medium", "SC-13", "Associate an appropriate KMS key with the log group where required.")
def log_kms(item, index):
    get(item, "logGroupName", str)
    key = api_optional(item, "kmsKeyId", str, "", operation="logs:DescribeLogGroups")
    return result(not bool(key), kms_key_id=key)
CASES["aws.a.cloudwatch.log_kms_encryption"] = {"pass": {"logGroupName": "audit", "kmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/inert"}, "fail": {"logGroupName": "audit", "_provenance": LOG_PROVENANCE}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.log_kms_encryption")


@register("aws.a.cloudwatch.log_retention_at_least_365", "aws", "hardening", "log_group", "CloudWatch log group retains logs at least 365 days or indefinitely",
    "medium", "AU-11", "Configure the intended retention, preserving source default minimum 365 days and indefinite retention applicability.")
def retention(item, index):
    get(item, "logGroupName", str)
    days = api_optional(item, "retentionInDays", int, None, operation="logs:DescribeLogGroups")
    if days is None:
        return result(False, retention="never_expire", minimum_days=365)
    if days <= 0:
        return unknown("invalid native retention duration")
    return result(days < 365, retention_days=days, minimum_days=365)
CASES["aws.a.cloudwatch.log_retention_at_least_365"] = {"pass": {"logGroupName": "audit", "retentionInDays": 365}, "fail": {"logGroupName": "audit", "retentionInDays": 30}, "missing": {}, "malformed": None}
NATIVE_IDS.append("aws.a.cloudwatch.log_retention_at_least_365")


@register("aws.a.cloudwatch.cross_account_role_absent", "aws", "exposure", "aws_account", "CloudWatch cross-account sharing role is absent",
    "medium", "AC-3", "Review the declared CloudWatch cross-account sharing role and its approved use.", target="scope", dependencies=["iam_role"])
def cross_account_role(item, index):
    scope = scope_subject(item)
    roles = complete_items(index, "iam_role", scope)
    matching = [get(role, "RoleName", str) for role in roles if get(role, "RoleName", str) == "CloudWatch-CrossAccountSharingRole"]
    return result(bool(matching), matching_roles=matching, semantics="Exact declared role-name predicate; effective trust/access is separate")
CASES["aws.a.cloudwatch.cross_account_role_absent"] = {"pass": {"scope": "123456789012/us-east-1"}, "fail": {"scope": "123456789012/us-east-1"}, "missing": {}, "malformed": None,
    "index": scope_fixture("iam_role", []), "pass_index": scope_fixture("iam_role", []), "fail_index": scope_fixture("iam_role", [{"RoleName": "CloudWatch-CrossAccountSharingRole"}])}
NATIVE_IDS.append("aws.a.cloudwatch.cross_account_role_absent")


@register("aws.a.cloudwatch.agentcore_data_protection", "aws", "hardening", "log_group", "Default-prefix AgentCore log group has active or inherited data protection",
    "high", "SC-28", "Activate log-group data protection or verify inherited account data protection without reading log content.")
def agentcore_protection(item, index):
    name = get(item, "logGroupName", str)
    prefixes = ("/aws/bedrock-agentcore/", "/aws/vendedlogs/bedrock-agentcore/")
    if not name.startswith(prefixes):
        return "NOT_APPLICABLE", {"log_group_name": name, "reason": "Outside the pinned default AgentCore prefixes"}
    status = api_optional(item, "dataProtectionStatus", str, None, operation="logs:DescribeLogGroups")
    if status not in {None, "ACTIVATED", "DELETED", "ARCHIVED", "DISABLED"}:
        return unknown("unrecognized native data protection status")
    if status == "ACTIVATED":
        return result(False, data_protection_status=status)
    inherited = api_optional(item, "inheritedProperties", list, [], operation="logs:DescribeLogGroups")
    if any(not isinstance(value, str) for value in inherited):
        return unknown("malformed inherited log-group properties")
    return result("ACCOUNT_DATA_PROTECTION" not in inherited, data_protection_status=status, inherited_properties=inherited)
CASES["aws.a.cloudwatch.agentcore_data_protection"] = {"pass": {"logGroupName": "/aws/bedrock-agentcore/runtimes/app", "dataProtectionStatus": "ACTIVATED"},
    "fail": {"logGroupName": "/aws/bedrock-agentcore/runtimes/app", "_provenance": LOG_PROVENANCE}, "missing": {}, "malformed": None,
    "not_applicable": {"logGroupName": "/aws/lambda/app"}}
NATIVE_IDS.append("aws.a.cloudwatch.agentcore_data_protection")
