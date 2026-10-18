"""claude2_aws_a CloudWatch cross-account sharing, CloudWatch Logs, Config and DLM predicates."""
from __future__ import annotations

from .claude2_aws_a_common import (
    ABSENT, ACCOUNT, P, X, Unavailable, absent_or, collected, complete_items, detail, get, idx, install, is_policy_public,
    list_of_objects, policy_document, principal_aws_values, result, rows_for, scope_account, scope_subject, strings,
    turbot_public_statements, unknown)

IDENTITY = {"Account": ACCOUNT, "Arn": "arn:aws:iam::" + ACCOUNT + ":role/audit", "UserId": "AROAEXAMPLE", "AccountId": ACCOUNT}


# --- cloudwatch cross-account sharing -------------------------------------------------------
ROLE = {"RoleName": "CloudWatch-CrossAccountSharingRole", "Arn": "arn:aws:iam::" + ACCOUNT + ":role/CloudWatch-CrossAccountSharingRole",
        "AssumeRolePolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::210987654321:root"}, "Action": "sts:AssumeRole"}]}}


@install("cloudwatch.cross_account_sharing_role_absent", "aws_account", "CloudWatch cross-account sharing role is absent (or reviewed)", {
    "pass": IDENTITY, "manual": IDENTITY, "index": idx(iam_role=[{"RoleName": "app", "Arn": "arn:aws:iam::" + ACCOUNT + ":role/app"}]),
    "manual_index": idx(iam_role=[ROLE]), "roles_denied": IDENTITY, "roles_denied_expect": "UNKNOWN", "roles_denied_index": idx(iam_role="denied"),
    }, rows=rows_for("cloudwatch_cross_account_sharing"), severity="low", category="exposure", control="AC-3", dependencies=["aws_account", "iam_role"],
    remediation="Confirm the accounts trusted by CloudWatch-CrossAccountSharingRole are approved; delete the role if sharing is not needed.",
    docs=["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Cross-Account-Cross-Region.html"],
    note="Upstream emits info (not alarm) when the role exists, so presence is MANUAL with the trusted principals as evidence.")
def cross_account_sharing(item, index):
    if get(item, "Account", str) != scope_account(index):
        raise Unavailable("account identity does not match the audited scope")
    roles = complete_items(index, "iam_role", get(index, "context.scope", str))
    matching = [r for r in roles if get(r, "RoleName", str) == "CloudWatch-CrossAccountSharingRole"]
    if not matching:
        return result(False, cross_account_sharing_role=None)
    trusted = []
    for role in matching:
        for statement in policy_document(get(role, "AssumeRolePolicyDocument")):
            trusted.extend(principal_aws_values(statement))
    return "MANUAL", {"cross_account_sharing_role": [r.get("Arn") for r in matching], "trusted_principals": sorted(set(trusted)),
                      "reason": "CloudWatch shares data cross-account; confirm the trusted accounts"}


# --- cloudwatch logs ----------------------------------------------------------------------------
LOG_GROUP = {"logGroupName": "app", "arn": "arn:aws:logs:us-east-1:" + ACCOUNT + ":log-group:app:*"}
PUBLIC_DOC = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"logs:PutLogEvents","Resource":"*"}]}'
SERVICE_DOC = ('{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"route53.amazonaws.com"},"Action":"logs:PutLogEvents",'
               '"Resource":"arn:aws:logs:us-east-1:' + ACCOUNT + ':log-group:/aws/route53/*"}]}')
LOG_POLICY = {"policyName": "route53", "policyDocument": SERVICE_DOC}


@install("logs.log_group_not_public_via_resource_policy", "log_group", "CloudWatch log group is not exposed by a public Logs resource policy", {
    "pass": LOG_GROUP, "fail": LOG_GROUP, "index": idx(log_resource_policy=[LOG_POLICY]),
    "fail_index": idx(log_resource_policy=[{"policyName": "open", "policyDocument": PUBLIC_DOC}]),
    "no_policies": LOG_GROUP, "no_policies_expect": "PASS", "no_policies_index": idx(log_resource_policy=[]),
    "policies_denied": LOG_GROUP, "policies_denied_expect": "UNKNOWN", "policies_denied_index": idx(log_resource_policy="denied"),
    }, rows=[P + "cloudwatch_log_group_not_publicly_accessible"], severity="high", category="exposure", control="AC-3",
    dependencies=["log_group", "log_resource_policy"], remediation="Restrict the CloudWatch Logs resource policy principals and resources so no log group is public.",
    docs=["https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeResourcePolicies.html"],
    note="Joins the collected log_resource_policy inventory (logs:DescribeResourcePolicies); missing or denied is UNKNOWN. As upstream: for every resource policy that is_policy_public, any statement Resource containing the log-group ARN, or '*', exposes the group.")
def log_group_public(item, index):
    arn = get(item, "arn", str)
    policies = complete_items(index, "log_resource_policy", get(index, "context.scope", str))
    account = scope_account(index)
    exposing = []
    for policy in policies:
        statements = policy_document(get(policy, "policyDocument"))
        if not is_policy_public(statements, account):
            continue
        for statement in statements:
            resources = statement.get("Resource", [])
            resources = [resources] if isinstance(resources, str) else strings(resources, "Resource")
            if any(arn in resource or resource == "*" for resource in resources):
                exposing.append(get(policy, "policyName", str))
                break
    return result(bool(exposing), exposing_policies=exposing)


@install("logs.resource_policy_not_public", "log_resource_policy", "CloudWatch Logs resource policy does not allow public access", {
    "pass": LOG_POLICY, "fail": {"policyName": "open", "policyDocument": PUBLIC_DOC},
    }, rows=[X + "cloudwatch_log_resource_policy_prohibit_public_access"], severity="high", category="exposure", control="AC-3",
    remediation="Remove wildcard principals from the CloudWatch Logs resource policy or restrict them with source account/ARN conditions.",
    docs=["https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeResourcePolicies.html"],
    note="aws-perimeter resource_policy_public_sql over the collected policyDocument (logs:DescribeResourcePolicies).")
def log_policy_public(item, index):
    get(item, "policyName", str)
    public = turbot_public_statements(policy_document(get(item, "policyDocument")))
    return result(bool(public), public_statements=len(public))


# --- config -------------------------------------------------------------------------------------
AUTH = {"AggregationAuthorizationArn": "arn:aws:config:us-east-1:" + ACCOUNT + ":aggregation-authorization/" + ACCOUNT + "/us-east-1",
        "AuthorizedAccountId": ACCOUNT, "AuthorizedAwsRegion": "us-east-1"}


@install("config.aggregation_authorization_trusted", "config_aggregate_authorization", "Config aggregation authorization is granted only to trusted accounts", {
    "pass": AUTH, "manual": {**AUTH, "AuthorizedAccountId": "210987654321"}, "index": idx(),
    }, rows=[X + "config_aggregator_shared_with_trusted_accounts"], severity="medium", category="exposure", control="AC-3",
    remediation="Delete aggregation authorizations for accounts that are not approved aggregator accounts.",
    docs=["https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeAggregationAuthorizations.html"],
    note="Upstream emits info for accounts outside the operator's trusted_accounts list; without that list only the audited account is trusted, so other accounts are MANUAL. Reads the collected config_aggregate_authorization inventory.")
def aggregation_authorization(item, index):
    authorized = get(item, "AuthorizedAccountId", str)
    if authorized == scope_account(index):
        return result(False, authorized_account=authorized)
    return "MANUAL", {"authorized_account": authorized, "reason": "Confirm the authorized aggregator account is trusted"}


AGG = {"ConfigurationAggregatorName": "org", "ConfigurationAggregatorArn": "arn:aws:config:us-east-1:" + ACCOUNT + ":config-aggregator/config-aggregator-x",
       "OrganizationAggregationSource": {"RoleArn": "arn:aws:iam::" + ACCOUNT + ":role/agg", "AllAwsRegions": True}}
ADMIN = {"Id": "210987654321", "Arn": "arn:aws:organizations::" + ACCOUNT + ":account/o-abc/210987654321", "Status": "ACTIVE"}


@install("config.org_aggregator_all_regions_with_delegated_admin", "config_aggregator", "Config aggregator is an all-Region organization aggregator with a delegated administrator", {
    "pass": AGG, "fail": {k: v for k, v in AGG.items() if k != "OrganizationAggregationSource"}, "index": idx(config_delegated_administrator=[ADMIN]),
    "some_regions": {**AGG, "OrganizationAggregationSource": {"AllAwsRegions": False, "AwsRegions": ["us-east-1"]}}, "some_regions_expect": "FAIL",
    "no_admin": AGG, "no_admin_expect": "FAIL", "no_admin_index": idx(config_delegated_administrator=[]),
    "admin_unknown": AGG, "admin_unknown_expect": "UNKNOWN", "admin_unknown_index": idx(config_delegated_administrator="denied"),
    }, rows=[P + "config_delegated_admin_and_org_aggregator_all_regions"], severity="high", control="CA-7",
    dependencies=["config_aggregator", "config_delegated_administrator"],
    remediation="Register a delegated administrator for config.amazonaws.com and use an organization aggregator with AllAwsRegions=true.",
    docs=["https://docs.aws.amazon.com/config/latest/APIReference/API_DescribeConfigurationAggregators.html",
          "https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListDelegatedAdministrators.html"],
    note="Per aggregator, as upstream: not an organization aggregator or not AllAwsRegions is FAIL; no delegated admin is FAIL; an unavailable or denied delegated-admin lookup is UNKNOWN (FAIL still wins when the aggregator itself fails). "
         "The synthetic 'no aggregator in any region' FAIL is not evaluated (account-wide absence). Needs config:DescribeConfigurationAggregators (kind config_aggregator) and organizations:ListDelegatedAdministrators (kind config_delegated_administrator); not yet collected, so UNKNOWN.")
def org_aggregator(item, index):
    get(item, "ConfigurationAggregatorArn", str)
    source = absent_or(item, "ConfigurationAggregatorName", "OrganizationAggregationSource", None, dict)
    issues = []
    if source is None:
        issues.append("not an organization aggregator")
    elif source.get("AllAwsRegions", False) is not True:
        issues.append("does not cover all AWS regions")
    try:
        admins = complete_items(index, "config_delegated_administrator", get(index, "context.scope", str))
    except Unavailable:
        admins = None
    if admins is not None and not admins:
        issues.append("no delegated administrator registered for config.amazonaws.com")
    if issues:
        return result(True, issues=issues)
    if admins is None:
        return unknown("delegated administrator lookup for config.amazonaws.com unavailable")
    return result(False, delegated_administrators=[a.get("Id") for a in admins])


# --- dlm ----------------------------------------------------------------------------------------
def _dlm(*targets, state="ENABLED", policy_type="EBS_SNAPSHOT_MANAGEMENT"):
    schedules = [{"Name": "s%d" % i, "ShareRules": [{"TargetAccounts": list(t)}]} for i, t in enumerate(targets)]
    return {"PolicyId": "policy-1", "State": state, "PolicyType": policy_type,
            "Details": {"collection_status": "collected", "Policy": {"PolicyId": "policy-1", "State": state,
                                                                     "PolicyDetails": {"PolicyType": policy_type, "Schedules": schedules}}}}


@install("dlm.snapshot_sharing_trusted_accounts", "dlm_policy", "DLM EBS snapshot policy shares snapshots only with trusted accounts", {
    "pass": _dlm([ACCOUNT]), "manual": _dlm([], ["210987654321"]), "index": idx(),
    "not_applicable": _dlm(["210987654321"], state="DISABLED"), "ami": _dlm(["210987654321"], policy_type="IMAGE_MANAGEMENT"), "ami_expect": "NOT_APPLICABLE",
    "detail_denied": {**_dlm(["210987654321"]), "Details": {"collection_status": "denied", "error": {"code": "AccessDenied"}}}, "detail_denied_expect": "UNKNOWN",
    }, rows=[X + "dlm_ebs_snapshot_policy_shared_with_trusted_accounts"], severity="medium", category="exposure", control="AC-3",
    remediation="Remove untrusted target accounts from DLM snapshot share rules.",
    docs=["https://docs.aws.amazon.com/dlm/latest/APIReference/API_ShareRule.html"],
    note="EBS_SNAPSHOT_MANAGEMENT policies only; DISABLED is NOT_APPLICABLE. Schedules 0..3, ShareRules[0].TargetAccounts minus trusted accounts (the audited account; upstream info) are MANUAL. Reads the collected dlm_policy summary (PolicyType, State) and its GetLifecyclePolicy Details; a denied or missing detail is UNKNOWN.")
def dlm_sharing(item, index):
    get(item, "PolicyId", str)
    policy_type = get(item, "PolicyType", str)
    if policy_type != "EBS_SNAPSHOT_MANAGEMENT":
        return "NOT_APPLICABLE", {"policy_type": policy_type}
    if get(item, "State", str) == "DISABLED":
        return "NOT_APPLICABLE", {"state": "DISABLED"}
    trusted = {scope_account(index)}
    container = detail(item, "Details")
    if container is None:
        raise Unavailable("lifecycle policy detail not found")
    schedules = list_of_objects(get(container, "Policy.PolicyDetails.Schedules", list))
    untrusted = []
    for schedule in schedules[:4]:
        rules = list_of_objects(schedule.get("ShareRules", []))
        if rules:
            untrusted.extend(a for a in strings(rules[0].get("TargetAccounts", []), "TargetAccounts") if a not in trusted)
    if untrusted:
        return "MANUAL", {"untrusted_target_accounts": sorted(set(untrusted)), "reason": "Confirm the snapshot share target accounts are trusted"}
    return result(False, untrusted_target_accounts=[])
