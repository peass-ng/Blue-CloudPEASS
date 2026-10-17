"""Signed AWS compliance checks for the sw07 defensive slice."""
from __future__ import annotations

import re
import math

from . import register, result, unknown
from .facts import Unavailable, complete_items, get, guard, memoized

SPECS = {'aws.nist.codebuild_exact_aws_key_env_names': {'category': 'hardening',
                                                'kind': 'codebuild_project',
                                                'remediation': 'Use Secrets Manager or Parameter Store for '
                                                               'AWS access keys instead of plaintext project '
                                                               'variables.',
                                                'severity': 'medium',
                                                'sha': 'c2aaaca9fdef531db00ae29d09c9788a2fba0173409db7baaf0abc686cb94774',
                                                'title': 'CodeBuild projects avoid plaintext AWS access key '
                                                         'variables'},
 'aws.pci.codebuild.aws_key_environment_vars': {'category': 'hardening',
                                                'kind': 'codebuild_project',
                                                'remediation': 'Remove AWS_ACCESS_KEY_ID and '
                                                               'AWS_SECRET_ACCESS_KEY from CodeBuild '
                                                               'environmentVariables; use the project IAM '
                                                               'role.',
                                                'severity': 'high',
                                                'sha': '2489057cce9025713a3148b65323368a55c7eb1f51f934c2d95d17c25c582dcb',
                                                'title': 'CodeBuild projects do not declare static AWS key '
                                                         'variables'},
 'aws_backup_failure_notification': {'category': 'hardening',
                                     'kind': 'backup_vault',
                                     'remediation': 'Set AWS Backup vault notification SNSTopicArn and '
                                                    'include BACKUP_JOB_FAILED in BackupVaultEvents.',
                                     'severity': 'high',
                                     'sha': '4467c9e86474916100828fe7317eddc4d5d174f21692d3591047e45bb97ea41c',
                                     'title': 'Backup failure notifications are configured'},
 'aws_cis_batch_job_cloudwatch_logging': {'category': 'hardening',
                                          'kind': 'batch_job_definition',
                                          'remediation': 'Configure awslogs and a retained CloudWatch log '
                                                         'group.',
                                          'severity': 'medium',
                                          'sha': 'c1c58475bdd9088d91316093056a0c8c1850d2bc17486737bfe374b3fdde3c6b',
                                          'title': 'Batch jobs send logs to CloudWatch Logs'},
 'aws_ec2_running_instance_cpu_alarm_present': {'category': 'hardening',
                                                'kind': 'instance',
                                                'remediation': 'Create a CloudWatch AWS/EC2 CPUUtilization '
                                                               'alarm with the instance ID dimension, '
                                                               'approved threshold and AlarmActions.',
                                                'severity': 'medium',
                                                'sha': '50cc47430e0b2b11886402b5c7a4724b5252a2cfce63ad01d189f52056af5d61',
                                                'title': 'Running EC2 CPU capacity alarm'},
 'aws_ec2_status_alarm': {'category': 'hardening',
                          'kind': 'instance',
                          'remediation': 'Review the production instance and stopped-instance policy, then '
                                         'create or enable a same-Region AWS/EC2 StatusCheckFailed alarm '
                                         'with its exact InstanceId dimension and an approved action.',
                          'severity': 'high',
                          'sha': '16f7a673cec9408fe27b4f65bda34977a85675cdf380d513abc26923529ec434',
                          'title': 'EC2 failures trigger status-check alarms'},
 'aws_external_key_store_connected': {'category': 'hardening',
                                      'kind': 'kms_external_key_store',
                                      'remediation': 'Restore the external KMS key-store proxy endpoint and '
                                                     'credentials until ConnectionState=CONNECTED.',
                                      'severity': 'high',
                                      'sha': '14c98a073caf7b83370f6e958c9aacdff521394eeb21058d2534ad9deb0dab71',
                                      'title': 'External KMS key stores are connected'},
 'aws_g6_redshift_automatic_version_upgrade': {'category': 'hardening',
                                               'kind': 'redshift_cluster',
                                               'remediation': 'Set AllowVersionUpgrade=true on each Redshift '
                                                              'cluster.',
                                               'severity': 'medium',
                                               'sha': 'ad979ddc6088494278a5100080090a456ab9d01e0cea7ff54e7e33bc4e5badb3',
                                               'title': 'Redshift clusters allow automatic version upgrades'},
 'aws_sns_delivery_failure_alarm_present': {'category': 'hardening',
                                            'kind': 'sns_topic',
                                            'remediation': 'Create an AWS/SNS NumberOfNotificationsFailed '
                                                           'alarm with the matching TopicName dimension and '
                                                           'enabled AlarmActions.',
                                            'severity': 'medium',
                                            'sha': '27a24bff00c02b8871b69ea5398386fb94e40d1588813a0d13f67a821edd17e2',
                                            'title': 'SNS delivery failure alarm'},
 'aws_wafv2_baseline_managed_rules': {'category': 'hardening',
                                      'kind': 'wafv2_web_acl',
                                      'remediation': 'Add every approved WAFv2 managed rule group to the web '
                                                     'ACL and remove Count overrides from its baseline '
                                                     'rules.',
                                      'severity': 'medium',
                                      'sha': '3fc52dfeabeccc812ccc849cc24f3f867002e8425617ca844e2acbb3212aecd2',
                                      'title': 'WAF baseline managed rules'},
 'aws_wafv2_blanket_rate_rule': {'category': 'hardening',
                                 'kind': 'wafv2_web_acl',
                                 'remediation': 'Add a WAFv2 rate-based Block rule with AggregateKeyType=IP, '
                                                'no scope-down statement and Limit at or below the approved '
                                                'ceiling.',
                                 'severity': 'medium',
                                 'sha': '244b01371bffac1288a175138d2bd7e3f3624eed64dd97e99466c19cefc8d328',
                                 'title': 'Blanket rate-based rules'},
 'aws_wafv2_managed_rule_groups': {'category': 'hardening',
                                   'kind': 'wafv2_web_acl',
                                   'remediation': 'Add the required nonbaseline managed WAFv2 rule group and '
                                                  'remove Count-only override action.',
                                   'severity': 'medium',
                                   'sha': 'ba5e29f89926b8070ec74acfd87ee41352a2ef64e477a152760934946d645217',
                                   'title': 'Additional managed rules'},
 'aws_wafv2_scoped_rate_rules': {'category': 'hardening',
                                 'kind': 'wafv2_web_acl',
                                 'remediation': 'Add a WAFv2 rate-based Block rule with the approved '
                                                'ScopeDownStatement and Limit at or below the ceiling.',
                                 'severity': 'medium',
                                 'sha': 'f2aeb06475c3cb59e48b8fb46f49b1451e849ba2f85a7ca1509cf1cf7b7e1e57',
                                 'title': 'WAF scoped rate rules'},
 'aws_wafv2_service_exclusion_rules': {'category': 'hardening',
                                       'kind': 'wafv2_web_acl',
                                       'remediation': 'Add the approved service exception names to the WAFv2 '
                                                      'managed rule group ExcludedRules or '
                                                      'RuleActionOverrides.',
                                       'severity': 'medium',
                                       'sha': '3b6c9fb400eb08d45f9b46f0f631a18ec4d71776f441ab88801c95973ed0a7ea',
                                       'title': 'WAF service-specific exclusion rules'}}
SPECS.update({'aws.pci.iam.role_required_managed_policies': {'category': 'hardening',
                                                'kind': 'iam_role',
                                                'remediation': 'Attach every required managed PolicyArn to '
                                                               'the scoped roles using iam '
                                                               'attach-role-policy.',
                                                'severity': 'medium',
                                                'sha': 'a014cc68cb2406480b5a10562fb62718a5facaa562a9f05ead0c5ecc2afa7b74',
                                                'title': 'IAM roles carry required managed policies'},
 'aws.pci.sns.delivery_status_logging': {'category': 'hardening',
                                         'kind': 'sns_topic',
                                         'remediation': 'Set the SNS topic protocol-specific '
                                                        'FailureFeedbackRoleArn and SuccessFeedbackRoleArn, '
                                                        'with SuccessFeedbackSampleRate above zero.',
                                         'severity': 'medium',
                                         'sha': '519295c8b0863ef7fb5de71b60d976132bb5eca14e5ec5921e68a3307b676afa',
                                         'title': 'SNS delivery status logging is configured'},
 'aws_account_expected_organization_master': {'category': 'hardening',
                                              'kind': 'aws_account_configuration',
                                              'remediation': 'Have the organization owner validate the '
                                                             'expected management account ID and resolve '
                                                             'mismatched account membership through an '
                                                             'approved migration.',
                                              'severity': 'medium',
                                              'sha': '0045af44a9cf7511e344b3d473293ebdee510d78c8c9426fb413fc8668a31e17',
                                              'title': 'AWS account belongs to expected organization master'},
 'aws_cloudwatch_metric_alarm_has_threshold': {'category': 'hardening',
                                               'kind': 'cloudwatch_alarm',
                                               'remediation': 'Set each CloudWatch MetricAlarm Threshold and '
                                                              'ComparisonOperator to the approved range and '
                                                              'operator for its Namespace and MetricName.',
                                               'severity': 'medium',
                                               'sha': '4439e7e90b46117c598cf120bb7b5c5b1954492361e645f76f0b9d3fed46d1dc',
                                               'title': 'CloudWatch metric alarms meet approved thresholds'},
 'aws_ec2_ami_trusted_principals': {'category': 'hardening',
                                    'kind': 'ami',
                                    'remediation': 'Remove untrusted account IDs from AMI launchPermission '
                                                   'using ec2 modify-image-attribute.',
                                    'severity': 'medium',
                                    'sha': 'c8b452947d1de6f1ded5138f40afe20921f3c03f69951ac088ec3c37661731e1',
                                    'title': 'EC2 AMI launch permissions use trusted principals'}})
PROPOSED_SPEC_SHA256 = {check_id: spec["sha"] for check_id, spec in SPECS.items()}


def _context(index):
    context = get(index, "context", dict)
    if get(context, "provider", str) != "aws":
        raise Unavailable("AWS context unavailable")
    scope = get(context, "scope", str)
    if re.fullmatch(r"[0-9]{12}/(?:global|[a-z]{2}(?:-[a-z]+)+-[0-9])", scope) is None:
        raise Unavailable("AWS scope unavailable")
    return context, scope


def _inventory(index, kind):
    _, scope = _context(index)
    # One validation per immutable scoped index, including negative outcomes.
    # Return a fresh outer list so callers cannot alter another check's rows.
    return list(memoized(index, (__name__, 'validated_inventory', scope, kind),
                         lambda: _validated_inventory(index, kind)))


def _validated_inventory(index, kind):
    _, scope = _context(index)
    if scope.endswith("/global") != (kind in {"iam_role", "aws_account_configuration"}):
        raise Unavailable("collection global/regional scope mismatch: " + kind)
    collections = get(index, "collections", dict)
    envelopes = collections.get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("collection scope authority unavailable: " + kind)
    envelope = get(envelopes[0], "type", str)
    if envelope != kind or get(envelopes[0], "scope", str) != scope:
        raise Unavailable("foreign collection scope: " + kind)
    rows = complete_items(index, kind)
    envelope_items = get(envelopes[0], "items", list)
    if envelope_items != rows or (envelopes[0].get("status") == "empty" and rows):
        raise Unavailable("collection envelope and index disagree: " + kind)
    wrappers = get(index, kind, list)
    if len(wrappers) != len(rows):
        raise Unavailable("collection item count mismatch: " + kind)
    for wrapper, row in zip(wrappers, rows):
        if (get(wrapper, "type", str) != kind or get(wrapper, "scope", str) != scope
                or get(wrapper, "data", dict) != row):
            raise Unavailable("foreign or malformed resource wrapper: " + kind)
    if any(sum(candidate == row for candidate in rows) != 1 for row in rows):
        raise Unavailable("duplicate collection resource: " + kind)
    account, region = scope.split("/")
    arn_fields = {"cloudwatch_alarm": ("AlarmArn", "cloudwatch", "alarm:"),
                  "wafv2_web_acl": ("ARN", "wafv2", ""),
                  "sns_topic": ("TopicArn", "sns", ""),
                  "iam_role": ("Arn", "iam", "role/"),
                  "batch_job_definition": ("jobDefinitionArn", "batch", "job-definition/")}
    if kind in arn_fields:
        field, service, suffix = arn_fields[kind]
        if kind == "iam_role" and region != "global":
            raise Unavailable("IAM role needs account-global inventory")
        native_region = "" if kind == "iam_role" else region
        prefix = f"arn:aws:{service}:{native_region}:{account}:{suffix}"
        for row in rows:
            arn = get(row, field, str)
            if not arn.startswith(prefix) or not arn[len(prefix):]:
                raise Unavailable("foreign or malformed resource ARN: " + kind)
            if kind == "wafv2_web_acl" and re.fullmatch(r"(?:regional|global)/webacl/[^/]+/[^/]+", arn[len(prefix):]) is None:
                raise Unavailable("malformed WAF web ACL identity")
    optional_arns = {"backup_vault": ("BackupVaultArn", "backup"),
                     "redshift_cluster": ("ClusterNamespaceArn", "redshift")}
    if kind in optional_arns:
        field, service = optional_arns[kind]
        for row in rows:
            arn = _optional(row, field, None, str)
            if arn is not None and not arn.startswith(f"arn:aws:{service}:{region}:{account}:"):
                raise Unavailable("foreign native resource ARN: " + kind)
    if kind == "ami":
        for row in rows:
            owner = _optional(row, "OwnerId", account, str)
            if owner != account:
                raise Unavailable("AMI belongs to a foreign account")
    return rows


def _subject(item, index, kind, identity):
    rows = _inventory(index, kind)
    wanted = get(item, identity, str)
    if not wanted or sum(get(row, identity, str) == wanted for row in rows) != 1:
        raise Unavailable("resource identity absent or duplicated")
    if next(row for row in rows if row[identity] == wanted) != item:
        raise Unavailable("item differs from complete collection")
    return wanted


def _policy(index, key, expected):
    context, scope = _context(index)
    metadata = get(context, "metadata", dict)
    policy = get(metadata, "compliance_policy", dict)
    if get(policy, "status", str) != "collected" or get(policy, "scope", str) != scope:
        raise Unavailable("owner policy missing or foreign scope")
    return get(policy, key, expected)


def _approved_for(index, key, arn, expected):
    mapping = _policy(index, key, dict)
    return _mapping_value(mapping, arn, expected)


def _mapping_value(mapping, key, expected):
    # Namespace/metric names and resource ARNs are literal keys, not dotted paths.
    guard(mapping)
    if key not in mapping:
        raise Unavailable("owner policy entry missing")
    selected = {"value": mapping[key]}
    if key in mapping.get("_coverage", {}):
        selected["_coverage"] = {"value": mapping["_coverage"][key]}
    return get(selected, "value", expected)


def _optional(item, key, default, expected):
    guard(item)
    if key in item or key in item.get("_coverage", {}):
        return get(item, key, expected)
    return default


def _waf_rules(item, index):
    arn = _subject(item, index, "wafv2_web_acl", "ARN")
    if not arn.startswith("arn:aws") or ":wafv2:" not in arn:
        raise Unavailable("malformed WAF web ACL ARN")
    if get(item, "WebACL.ARN", str) != arn:
        raise Unavailable("WAF GetWebACL identity mismatch")
    rules = get(item, "WebACL.Rules", list)
    for rule in rules:
        guard(rule)
        statement = get(rule, "Statement", dict)
        selectors = set(statement) - {"_coverage"}
        known = {"ByteMatchStatement", "SqliMatchStatement", "XssMatchStatement", "SizeConstraintStatement",
                 "GeoMatchStatement", "RuleGroupReferenceStatement", "IPSetReferenceStatement",
                 "RegexPatternSetReferenceStatement", "RegexMatchStatement", "RateBasedStatement",
                 "AndStatement", "OrStatement", "NotStatement", "ManagedRuleGroupStatement",
                 "LabelMatchStatement", "AsnMatchStatement"}
        if len(selectors) != 1 or not selectors <= known:
            raise Unavailable("WAF statement selector absent or malformed")
        get(statement, next(iter(selectors)), dict)
        group = _managed(rule)
        if group:
            _count_override(rule, group[2])
    return arn, rules


def _managed(rule):
    statement = get(rule, "Statement", dict)
    group = _optional(statement, "ManagedRuleGroupStatement", None, dict)
    if group is None:
        return None
    vendor, name = get(group, "VendorName", str), get(group, "Name", str)
    if not vendor or not name:
        raise Unavailable("managed rule group identity missing")
    return vendor, name, group


def _count_override(rule, group):
    override = get(rule, "OverrideAction", dict)
    if set(override) not in ({"None"}, {"Count"}):
        raise Unavailable("unrecognized managed rule override action")
    if get(override, next(iter(override)), dict):
        raise Unavailable("malformed managed rule override action")
    overrides = _optional(group, "RuleActionOverrides", [], list)
    for entry in overrides:
        if not get(entry, "Name", str):
            raise Unavailable("managed rule action override name missing")
        action = get(entry, "ActionToUse", dict)
        if set(action) not in ({"Allow"}, {"Block"}, {"Count"}, {"Captcha"}, {"Challenge"}):
            raise Unavailable("unrecognized rule action override")
        get(action, next(iter(action)), dict)
    return "Count" in override or any("Count" in x["ActionToUse"] for x in overrides)


def _baseline(index, arn):
    baseline = _approved_for(index, "wafv2_baselines", arn, list)
    pairs = []
    for row in baseline:
        pairs.append((get(row, "VendorName", str), get(row, "Name", str)))
    if len(pairs) != len(set(pairs)) or any(not a or not b for a, b in pairs):
        raise Unavailable("approved WAF baseline malformed")
    return set(pairs)


def _waf_baseline(item, index):
    arn, rules = _waf_rules(item, index)
    baseline = _baseline(index, arn)
    observed = {}
    for rule in rules:
        group = _managed(rule)
        if group is None:
            continue
        pair = group[:2]
        if pair in observed:
            raise Unavailable("duplicate managed rule group")
        observed[pair] = _count_override(rule, group[2])
    missing = sorted(baseline - observed.keys())
    counted = sorted(pair for pair in baseline & observed.keys() if observed[pair])
    return result(bool(missing or counted), web_acl_arn=arn, missing=missing, count_only=counted)


def _waf_extra_managed(item, index):
    arn, rules = _waf_rules(item, index)
    baseline = _baseline(index, arn)
    extra = []
    for rule in rules:
        group = _managed(rule)
        if group and group[:2] not in baseline and "Count" not in get(rule, "OverrideAction", dict):
            extra.append(group[:2])
    return result(not extra, web_acl_arn=arn, additional_managed_groups=sorted(extra))


def _rate_rules(rules):
    for rule in rules:
        statement = get(rule, "Statement", dict)
        rate = _optional(statement, "RateBasedStatement", None, dict)
        if rate is None:
            continue
        limit = get(rate, "Limit", int)
        if limit <= 0:
            raise Unavailable("invalid WAF rate limit")
        action = get(rule, "Action", dict)
        if set(action) not in ({"Allow"}, {"Block"}, {"Count"}, {"Captcha"}, {"Challenge"}):
            raise Unavailable("unrecognized WAF rate action")
        get(action, next(iter(action)), dict)
        yield rate, limit, action


def _waf_blanket_rate(item, index):
    arn, rules = _waf_rules(item, index)
    ceiling = _approved_for(index, "wafv2_request_ceilings", arn, int)
    if ceiling <= 0:
        raise Unavailable("invalid approved WAF request ceiling")
    matching = []
    for rate, limit, action in _rate_rules(rules):
        aggregate = get(rate, "AggregateKeyType", str)
        if aggregate not in {"IP", "FORWARDED_IP", "CUSTOM_KEYS", "CONSTANT"}:
            raise Unavailable("unrecognized WAF aggregate key type")
        scoped = _optional(rate, "ScopeDownStatement", None, dict)
        if aggregate == "IP" and scoped is None and limit <= ceiling and "Block" in action:
            matching.append(limit)
    return result(not matching, web_acl_arn=arn, approved_ceiling=ceiling, matching_limits=matching)


def _waf_scoped_rate(item, index):
    arn, rules = _waf_rules(item, index)
    approved = _approved_for(index, "wafv2_scoped_rate", arn, dict)
    statement = get(approved, "ScopeDownStatement", dict)
    ceiling = get(approved, "Limit", int)
    if not statement or ceiling <= 0:
        raise Unavailable("approved scope or ceiling malformed")
    matching = [limit for rate, limit, action in _rate_rules(rules)
                if _optional(rate, "ScopeDownStatement", None, dict) == statement
                and limit <= ceiling and "Block" in action]
    return result(not matching, web_acl_arn=arn, approved_ceiling=ceiling, matching_limits=matching)


def _waf_exclusions(item, index):
    arn, rules = _waf_rules(item, index)
    approved = _approved_for(index, "wafv2_service_exclusions", arn, dict)
    required = {}
    for group_key, names in approved.items():
        if not isinstance(group_key, str) or len(group_key.split("/")) != 2 or not all(group_key.split("/")) or not isinstance(names, list):
            raise Unavailable("malformed approved WAF service exclusion")
        if any(not isinstance(name, str) or not name for name in names):
            raise Unavailable("malformed approved WAF exclusion name")
        required[group_key] = set(names)
    observed = {key: set() for key in required}
    for rule in rules:
        group = _managed(rule)
        if not group:
            continue
        key = group[0] + "/" + group[1]
        for field in ("ExcludedRules", "RuleActionOverrides"):
            values = _optional(group[2], field, [], list)
            for value in values:
                name = get(value, "Name", str)
                if key in observed:
                    observed[key].add(name)
    missing = {key: sorted(values - observed[key]) for key, values in required.items()
               if values - observed[key]}
    return result(bool(missing), web_acl_arn=arn, missing_exclusions=missing)


def _redshift_upgrade(item, index):
    cluster = _subject(item, index, "redshift_cluster", "ClusterIdentifier")
    enabled = get(item, "AllowVersionUpgrade", bool)
    return result(not enabled, cluster_identifier=cluster, allow_version_upgrade=enabled)


def _codebuild_variables(item, index):
    name = _subject(item, index, "codebuild_project", "name")
    configuration = get(item, "Configuration", dict)
    if get(configuration, "collection_status", str) != "collected":
        raise Unavailable("BatchGetProjects incomplete")
    projects = get(configuration, "projects", list)
    if len(projects) != 1 or get(projects[0], "name", str) != name:
        raise Unavailable("BatchGetProjects identity mismatch")
    _, scope = _context(index)
    account, region = scope.split("/")
    arn = _optional(projects[0], "arn", None, str)
    if arn is not None and not arn.startswith(f"arn:aws:codebuild:{region}:{account}:project/"):
        raise Unavailable("CodeBuild detail belongs to a foreign scope")
    variables = get(projects[0], "environment.environmentVariables", list)
    for variable in variables:
        if not get(variable, "name", str):
            raise Unavailable("CodeBuild environment variable name missing")
        if get(variable, "type", str) not in {"PLAINTEXT", "PARAMETER_STORE", "SECRETS_MANAGER"}:
            raise Unavailable("CodeBuild environment variable type unknown")
    return name, variables


_AWS_KEY_NAMES = {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}


def _codebuild_exact_plaintext(item, index):
    name, variables = _codebuild_variables(item, index)
    matches = sorted({x["name"] for x in variables if x["name"].upper() in _AWS_KEY_NAMES
                      and x["type"] == "PLAINTEXT"})
    return result(bool(matches), project_name=name, matching_variable_names=matches)


def _codebuild_any_type(item, index):
    name, variables = _codebuild_variables(item, index)
    matches = sorted({x["name"] for x in variables if x["name"] in _AWS_KEY_NAMES})
    return result(bool(matches), project_name=name, matching_variable_names=matches)


def _backup_notification(item, index):
    name = _subject(item, index, "backup_vault", "BackupVaultName")
    notification = get(item, "Notifications", dict)
    state = get(notification, "collection_status", str)
    if state == "empty" and notification.get("absent") is True:
        return result(True, backup_vault_name=name, notification_absent=True)
    if state != "collected":
        raise Unavailable("backup vault notification unreadable")
    arn = get(notification, "SNSTopicArn", str)
    events = get(notification, "BackupVaultEvents", list)
    if any(not isinstance(x, str) for x in events):
        raise Unavailable("malformed backup event list")
    return result(not arn or "BACKUP_JOB_FAILED" not in events,
                  backup_vault_name=name, sns_topic_arn=arn, failure_event_configured="BACKUP_JOB_FAILED" in events)


def _external_store(item, index):
    name = _subject(item, index, "kms_external_key_store", "CustomKeyStoreName")
    kind = get(item, "CustomKeyStoreType", str)
    if kind == "AWS_CLOUDHSM":
        return "NOT_APPLICABLE", {"custom_key_store_name": name, "reason": "not an external key store"}
    if kind != "EXTERNAL_KEY_STORE":
        raise Unavailable("unrecognized custom key store type")
    approved = _policy(index, "external_key_store_connectivity", list)
    if not approved or any(not isinstance(x, str) or x not in {"PUBLIC_ENDPOINT", "VPC_ENDPOINT"} for x in approved):
        raise Unavailable("approved external key store connectivity malformed")
    state = get(item, "ConnectionState", str)
    connectivity = get(item, "XksProxyConnectivity", str)
    if state not in {"CONNECTED", "DISCONNECTED", "FAILED", "CONNECTING", "DISCONNECTING"} or connectivity not in {"PUBLIC_ENDPOINT", "VPC_ENDPOINT"}:
        raise Unavailable("external key store state unrecognized")
    return result(state != "CONNECTED" or connectivity not in approved,
                  custom_key_store_name=name, connection_state=state, proxy_connectivity=connectivity)


def _batch_job_logs(item, index):
    arn = _subject(item, index, "batch_job_definition", "jobDefinitionArn")
    status = get(item, "status", str)
    if status == "INACTIVE":
        return "NOT_APPLICABLE", {"job_definition_arn": arn, "reason": "inactive job definition"}
    if status != "ACTIVE":
        raise Unavailable("Batch job status unrecognized")
    containers = []
    roots = [root for root in ("containerProperties", "nodeProperties", "ecsProperties") if root in item]
    if len(roots) != 1:
        raise Unavailable("Batch container representation absent or ambiguous")
    for root in ("containerProperties", "nodeProperties", "ecsProperties"):
        if root in item.get("_coverage", {}) and root not in item:
            get(item, root)
        if root not in item:
            continue
        if root == "containerProperties":
            containers.append(get(item, root, dict))
        elif root == "nodeProperties":
            ranges = get(item, "nodeProperties.nodeRangeProperties", list)
            if not ranges:
                raise Unavailable("Batch node range inventory empty")
            containers.extend(get(row, "container", dict) for row in ranges)
        else:
            tasks = get(item, "ecsProperties.taskProperties", list)
            if not tasks:
                raise Unavailable("Batch task property inventory empty")
            for task in tasks:
                task_containers = get(task, "containers", list)
                if not task_containers:
                    raise Unavailable("Batch task container inventory empty")
                containers.extend(task_containers)
    if not containers:
        raise Unavailable("Batch job container inventory unavailable")
    bad = []
    for number, container in enumerate(containers):
        log = get(container, "logConfiguration", dict)
        driver = get(log, "logDriver", str)
        group = get(log, "options.awslogs-group", str) if driver == "awslogs" else None
        if driver != "awslogs" or not group:
            bad.append(number)
    return result(bool(bad), job_definition_arn=arn, container_count=len(containers), nonlogging_containers=bad)


def _dimensions(alarm):
    dimensions = get(alarm, "Dimensions", list)
    parsed = []
    for dimension in dimensions:
        parsed.append((get(dimension, "Name", str), get(dimension, "Value", str)))
    if not parsed or any(not name or not value for name, value in parsed) or len(parsed) != len({name for name, value in parsed}):
        raise Unavailable("CloudWatch alarm dimensions malformed")
    return parsed


def _actionable_alarm(alarm, namespace, metric, dimension_name, dimension_value):
    if get(alarm, "Namespace", str) != namespace or get(alarm, "MetricName", str) != metric:
        return False
    dimensions = _dimensions(alarm)
    actions = get(alarm, "AlarmActions", list)
    if any(not isinstance(action, str) or not action for action in actions):
        raise Unavailable("CloudWatch AlarmActions malformed")
    return (dimensions == [(dimension_name, dimension_value)] and
            get(alarm, "ActionsEnabled", bool) and any(actions))


def _ec2_alarm(item, index, metric, *, stopped_scope=False):
    instance_id = _subject(item, index, "instance", "InstanceId")
    state = get(item, "State.Name", str)
    if state not in {"running", "stopped", "pending", "stopping", "shutting-down", "terminated"}:
        raise Unavailable("EC2 instance state unrecognized")
    if stopped_scope:
        scoped = _policy(index, "status_alarm_instance_ids", list)
        if any(not isinstance(x, str) for x in scoped):
            raise Unavailable("status alarm owner scope malformed")
        if instance_id not in scoped:
            return "NOT_APPLICABLE", {"instance_id": instance_id, "reason": "outside owner alarm scope"}
    elif state != "running":
        return "NOT_APPLICABLE", {"instance_id": instance_id, "reason": "instance is not running"}
    alarms = _inventory(index, "cloudwatch_alarm")
    matching = []
    for alarm in alarms:
        if _actionable_alarm(alarm, "AWS/EC2", metric, "InstanceId", instance_id):
            matching.append(get(alarm, "AlarmArn", str))
    return result(not matching, instance_id=instance_id, metric_name=metric, matching_alarm_arns=matching)


def _cpu_alarm(item, index):
    return _ec2_alarm(item, index, "CPUUtilization")


def _status_alarm(item, index):
    return _ec2_alarm(item, index, "StatusCheckFailed", stopped_scope=True)


def _sns_alarm(item, index):
    arn = _subject(item, index, "sns_topic", "TopicArn")
    context, scope = _context(index)
    account, region = scope.split("/", 1)
    parts = arn.split(":", 5)
    if len(parts) != 6 or parts[:3] != ["arn", "aws", "sns"] or parts[3:5] != [region, account] or not parts[5]:
        raise Unavailable("SNS TopicArn foreign or malformed")
    subscriptions = _inventory(index, "sns_subscription")
    confirmed = []
    for row in subscriptions:
        topic = get(row, "TopicArn", str)
        subscription = get(row, "SubscriptionArn", str)
        if topic == arn and subscription not in {"PendingConfirmation", "Deleted"}:
            if not subscription.startswith(arn + ":"):
                raise Unavailable("SNS subscription ARN does not match topic")
            confirmed.append(subscription)
    if not confirmed:
        return "NOT_APPLICABLE", {"topic_arn": arn, "reason": "no confirmed subscriptions"}
    alarms = _inventory(index, "cloudwatch_alarm")
    matching = [get(alarm, "AlarmArn", str) for alarm in alarms if _actionable_alarm(
        alarm, "AWS/SNS", "NumberOfNotificationsFailed", "TopicName", parts[5])]
    return result(not matching, topic_arn=arn, confirmed_subscriptions=len(confirmed), matching_alarm_arns=matching)


def _role_required_policies(item, index):
    arn = _subject(item, index, "iam_role", "Arn")
    required = _policy(index, "required_policy_arns", list)
    policy_arn = r"arn:aws:iam::(?:aws|[0-9]{12}):policy/[A-Za-z0-9_+=,.@/-]+"
    if any(not isinstance(x, str) or re.fullmatch(policy_arn, x) is None for x in required):
        raise Unavailable("required role policy ARN inventory absent or malformed")
    policies = get(item, "AttachedManagedPolicies", list)
    attached = {get(row, "PolicyArn", str) for row in policies}
    if any(re.fullmatch(policy_arn, arn) is None for arn in attached):
        raise Unavailable("attached managed policy ARN malformed")
    return result(bool(set(required) - attached), role_arn=arn,
                  missing_policy_arns=sorted(set(required) - attached))


def _threshold_policy(item, index):
    arn = _subject(item, index, "cloudwatch_alarm", "AlarmArn")
    if "Metrics" in item.get("_coverage", {}) and "Metrics" not in item:
        get(item, "Metrics")
    if "Metrics" in item:
        metrics = get(item, "Metrics", list)
        if len(metrics) != 1:
            raise Unavailable("metric math alarm identity cannot be reduced to one metric")
        query = metrics[0]
        if _optional(query, "Expression", None, str) is not None or not _optional(query, "ReturnData", True, bool):
            raise Unavailable("alarm query does not monitor one raw metric")
        metric = get(query, "MetricStat.Metric", dict)
        namespace = get(metric, "Namespace", str)
        name = get(metric, "MetricName", str)
    else:
        namespace = get(item, "Namespace", str)
        name = get(item, "MetricName", str)
    if not namespace or not name:
        raise Unavailable("alarm metric identity missing")
    policy = _policy(index, "cloudwatch_threshold_policy", dict)
    expected = _mapping_value(policy, namespace + "/" + name, dict)
    floor = get(expected, "min_threshold")
    ceiling = get(expected, "max_threshold")
    operators = get(expected, "comparison_operators", list)
    for value in (floor, ceiling):
        if isinstance(value, bool) or not isinstance(value, (float, int)) or not math.isfinite(value):
            raise Unavailable("approved threshold range malformed")
    if floor > ceiling or not operators or any(not isinstance(x, str) for x in operators):
        raise Unavailable("approved threshold policy malformed")
    observed = get(item, "Threshold")
    if isinstance(observed, bool) or not isinstance(observed, (float, int)) or not math.isfinite(observed):
        raise Unavailable("alarm threshold unavailable or malformed")
    comparison = get(item, "ComparisonOperator", str)
    known = {"GreaterThanThreshold", "GreaterThanOrEqualToThreshold", "LessThanThreshold",
             "LessThanOrEqualToThreshold", "LessThanLowerOrGreaterThanUpperThreshold",
             "LessThanLowerThreshold", "GreaterThanUpperThreshold"}
    if comparison not in known or any(x not in known for x in operators):
        raise Unavailable("alarm comparison operator unrecognized")
    return result(not (floor <= observed <= ceiling and comparison in operators), alarm_arn=arn,
                  namespace=namespace, metric_name=name, threshold=observed,
                  comparison_operator=comparison, approved_min=floor, approved_max=ceiling)


_FEEDBACK_PREFIX = {"http": "HTTP", "https": "HTTP", "lambda": "Lambda", "sqs": "SQS",
                    "application": "Application", "firehose": "Firehose"}


def _sns_feedback(item, index):
    arn = _subject(item, index, "sns_topic", "TopicArn")
    subscriptions = _inventory(index, "sns_subscription")
    protocols = set()
    for row in subscriptions:
        if get(row, "TopicArn", str) == arn:
            protocol = get(row, "Protocol", str)
            if protocol in _FEEDBACK_PREFIX:
                protocols.add(_FEEDBACK_PREFIX[protocol])
            elif protocol not in {"email", "email-json"}:
                raise Unavailable("SNS protocol feedback requires uncollected evidence: " + protocol)
    if not protocols:
        return "NOT_APPLICABLE", {"topic_arn": arn, "reason": "no configured delivery feedback protocols"}
    wrapper = get(item, "Attributes", dict)
    if get(wrapper, "collection_status", str) != "collected":
        raise Unavailable("SNS GetTopicAttributes incomplete")
    attrs = get(wrapper, "Attributes", dict)
    if get(attrs, "TopicArn", str) != arn:
        raise Unavailable("SNS topic attribute identity mismatch")

    def optional_attribute(key):
        if key in attrs or key in attrs.get("_coverage", {}):
            return get(attrs, key, str)
        return ""

    bad = []
    for prefix in sorted(protocols):
        failure = optional_attribute(prefix + "FailureFeedbackRoleArn")
        success = optional_attribute(prefix + "SuccessFeedbackRoleArn")
        sample = optional_attribute(prefix + "SuccessFeedbackSampleRate")
        for role in (failure, success):
            if role and re.fullmatch(r"arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9_+=,.@/-]+", role) is None:
                raise Unavailable("SNS feedback role ARN malformed")
        if sample:
            if re.fullmatch(r"[0-9]+", sample) is None:
                raise Unavailable("SNS feedback sample rate malformed")
            try:
                rate = int(sample)
            except ValueError as exc:
                raise Unavailable("SNS feedback sample rate malformed") from exc
            if not 0 <= rate <= 100:
                raise Unavailable("SNS feedback sample rate out of range")
        else:
            rate = 0
        if not failure or not success or rate <= 0:
            bad.append(prefix)
    return result(bool(bad), topic_arn=arn, configured_protocols=sorted(protocols),
                  missing_feedback_protocols=bad)


def _expected_org_master(item, index):
    _subject(item, index, "aws_account_configuration", "id")
    expected = _policy(index, "expected_management_account_id", str)
    if re.fullmatch(r"[0-9]{12}", expected) is None:
        raise Unavailable("expected management account ID malformed")
    organization = get(item, "Organization", dict)
    state = get(organization, "collection_status", str)
    if state == "empty" and organization.get("absent") is True:
        return result(True, reason="complete Organizations response says account is outside an organization")
    if state != "collected":
        raise Unavailable("DescribeOrganization incomplete")
    observed = get(organization, "MasterAccountId", str)
    if re.fullmatch(r"[0-9]{12}", observed) is None:
        raise Unavailable("observed management account ID malformed")
    return result(observed != expected, observed_management_account_id=observed,
                  expected_management_account_id=expected)


def _ami_trusted(item, index):
    image_id = _subject(item, index, "ami", "ImageId")
    approved = _policy(index, "ami_trusted_principals", dict)
    allowed = {}
    for key in ("account_ids", "organization_arns", "organizational_unit_arns"):
        values = get(approved, key, list)
        if any(not isinstance(x, str) or not x for x in values):
            raise Unavailable("AMI trusted principal policy malformed")
        allowed[key] = set(values)
    patterns = {"account_ids": r"[0-9]{12}",
                "organization_arns": r"arn:aws:organizations::[0-9]{12}:organization/o-[a-z0-9]+",
                "organizational_unit_arns": r"arn:aws:organizations::[0-9]{12}:ou/o-[a-z0-9]+/ou-[a-z0-9]+-[a-z0-9]+"}
    if any(re.fullmatch(patterns[key], value) is None for key, values in allowed.items() for value in values):
        raise Unavailable("AMI trusted principal identity malformed")
    read = get(item, "LaunchPermissions", dict)
    if get(read, "collection_status", str) not in {"collected", "empty"}:
        raise Unavailable("DescribeImageAttribute launch permissions incomplete")
    permissions = get(read, "items", list)
    if read["collection_status"] == "empty" and permissions:
        raise Unavailable("empty AMI permission status conflicts with items")
    unsafe = []
    for permission in permissions:
        guard(permission)
        fields = [key for key in ("UserId", "OrganizationArn", "OrganizationalUnitArn", "Group") if key in permission]
        if len(fields) != 1:
            raise Unavailable("AMI launch permission malformed")
        key = fields[0]
        value = get(permission, key, str)
        policy_key = {"UserId": "account_ids", "OrganizationArn": "organization_arns",
                      "OrganizationalUnitArn": "organizational_unit_arns"}.get(key)
        if not value:
            raise Unavailable("AMI launch permission principal missing")
        if policy_key and re.fullmatch(patterns[policy_key], value) is None:
            raise Unavailable("AMI launch permission principal malformed")
        if (key == "Group" and value == "all") or (policy_key and value not in allowed[policy_key]):
            unsafe.append(key + ":" + value)
        elif key == "Group":
            raise Unavailable("AMI launch permission group unrecognized")
    return result(bool(unsafe), image_id=image_id, untrusted_principals=unsafe)


_EVALUATORS = {
    "aws_wafv2_baseline_managed_rules": _waf_baseline,
    "aws_wafv2_blanket_rate_rule": _waf_blanket_rate,
    "aws_wafv2_managed_rule_groups": _waf_extra_managed,
    "aws_wafv2_scoped_rate_rules": _waf_scoped_rate,
    "aws_wafv2_service_exclusion_rules": _waf_exclusions,
    "aws_backup_failure_notification": _backup_notification,
    "aws_g6_redshift_automatic_version_upgrade": _redshift_upgrade,
    "aws.nist.codebuild_exact_aws_key_env_names": _codebuild_exact_plaintext,
    "aws.pci.codebuild.aws_key_environment_vars": _codebuild_any_type,
    "aws_cis_batch_job_cloudwatch_logging": _batch_job_logs,
    "aws_external_key_store_connected": _external_store,
    "aws_ec2_running_instance_cpu_alarm_present": _cpu_alarm,
    "aws_ec2_status_alarm": _status_alarm,
    "aws_sns_delivery_failure_alarm_present": _sns_alarm,
    "aws.pci.iam.role_required_managed_policies": _role_required_policies,
    "aws_cloudwatch_metric_alarm_has_threshold": _threshold_policy,
    "aws.pci.sns.delivery_status_logging": _sns_feedback,
    "aws_account_expected_organization_master": _expected_org_master,
    "aws_ec2_ami_trusted_principals": _ami_trusted,
}


def _register(check_id):
    spec = SPECS[check_id]
    dependencies = [spec["kind"]]
    if check_id in {"aws_ec2_running_instance_cpu_alarm_present", "aws_ec2_status_alarm", "aws_sns_delivery_failure_alarm_present"}:
        dependencies.append("cloudwatch_alarm")
    if check_id == "aws_sns_delivery_failure_alarm_present":
        dependencies.append("sns_subscription")
    if check_id == "aws.pci.sns.delivery_status_logging":
        dependencies.append("sns_subscription")

    @register(check_id, "aws", spec["category"], spec["kind"], spec["title"],
              spec["severity"], "CM-6", spec["remediation"],
              dependencies=dependencies)
    def evaluate(item, index):
        return _EVALUATORS[check_id](item, index)

    evaluate.__name__ = check_id.replace(".", "_")


for _check_id in SPECS:
    _register(_check_id)

