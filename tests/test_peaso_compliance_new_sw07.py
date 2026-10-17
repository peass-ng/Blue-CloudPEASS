"""Source-bound tests for the sw07 AWS compliance checks."""
from __future__ import annotations

import copy
import sys

import pytest

import peaso.checks as checks_package
from peaso.checks import CHECKS, evaluate_check
PREEXISTING_CHECKS = tuple(CHECKS)
PREEXISTING_MODULE = sys.modules.get("peaso.checks.compliance_new_sw07")
from peaso.checks import compliance_new_sw07 as sw

SCOPE = "123456789012/us-east-1"
WAF_ARN = "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/example/abc"
SNS_ARN = "arn:aws:sns:us-east-1:123456789012:alerts"


@pytest.fixture(scope="module", autouse=True)
def clean_registry_after_module():
    yield
    CHECKS[:] = list(PREEXISTING_CHECKS)
    if PREEXISTING_MODULE is None:
        sys.modules.pop("peaso.checks.compliance_new_sw07", None)
        if getattr(checks_package, "compliance_new_sw07", None) is sw:
            delattr(checks_package, "compliance_new_sw07")


def index(kind, rows, *, extra=None, policy=None, status="collected", scope=SCOPE):
    collections = {kind: [{"type": kind, "scope": scope, "status": status, "items": rows}]}
    resources = {kind: [{"type": kind, "scope": scope, "data": row} for row in rows]}
    for dependency, dep_rows in (extra or {}).items():
        collections[dependency] = [{"type": dependency, "scope": scope,
                                    "status": "collected" if dep_rows else "empty", "items": dep_rows}]
        resources[dependency] = [{"type": dependency, "scope": scope, "data": row} for row in dep_rows]
    metadata = {"compliance_policy": {"status": "collected", "scope": scope, **(policy or {})}}
    return {"context": {"provider": "aws", "scope": scope, "metadata": metadata},
            "collections": collections, **resources}


def evaluate(check_id, row, facts):
    return evaluate_check(check_id, row, facts)[0]


def waf(rules):
    return {"ARN": WAF_ARN, "WebACL": {"ARN": WAF_ARN, "Rules": rules}}


def managed(vendor="AWS", name="AWSManagedRulesCommonRuleSet", count=False, overrides=None):
    group = {"VendorName": vendor, "Name": name}
    if overrides is not None:
        group["RuleActionOverrides"] = overrides
    return {"Statement": {"ManagedRuleGroupStatement": group},
            "OverrideAction": {"Count": {}} if count else {"None": {}}}


def rate(limit=100, *, aggregate="IP", scoped=None, block=True):
    value = {"Limit": limit, "AggregateKeyType": aggregate}
    if scoped is not None:
        value["ScopeDownStatement"] = scoped
    return {"Statement": {"RateBasedStatement": value},
            "Action": {"Block": {}} if block else {"Count": {}}}


@pytest.mark.parametrize("check_id,policy,passing,failing", [
    ("aws_wafv2_baseline_managed_rules", {"wafv2_baselines": {WAF_ARN: [
        {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}]}},
     [managed()], [managed(count=True)]),
    ("aws_wafv2_blanket_rate_rule", {"wafv2_request_ceilings": {WAF_ARN: 100}},
     [rate()], [rate(101)]),
    ("aws_wafv2_managed_rule_groups", {"wafv2_baselines": {WAF_ARN: [
        {"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}]}},
     [managed(name="AWSManagedRulesSQLiRuleSet")], [managed()]),
    ("aws_wafv2_scoped_rate_rules", {"wafv2_scoped_rate": {WAF_ARN: {
        "ScopeDownStatement": {"ByteMatchStatement": {"SearchString": "status"}}, "Limit": 100}}},
     [rate(scoped={"ByteMatchStatement": {"SearchString": "status"}})], [rate()]),
    ("aws_wafv2_service_exclusion_rules", {"wafv2_service_exclusions": {WAF_ARN: {
        "AWS/AWSManagedRulesCommonRuleSet": ["SizeRestrictions_BODY"]}}},
     [managed(overrides=[{"Name": "SizeRestrictions_BODY", "ActionToUse": {"Count": {}}}])],
     [managed()]),
])
def test_waf_rules_pass_fail_and_policy_unknown(check_id, policy, passing, failing):
    row = waf(passing)
    assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "PASS"
    row = waf(failing)
    assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "FAIL"
    assert evaluate(check_id, row, index("wafv2_web_acl", [row])) == "UNKNOWN"
    malformed = waf([{"Statement": {"ManagedRuleGroupStatement": {"Name": 3}}}])
    assert evaluate(check_id, malformed, index("wafv2_web_acl", [malformed], policy=policy)) == "UNKNOWN"


def test_waf_masked_optional_scope_and_envelope_mismatch_are_unknown():
    check_id = "aws_wafv2_blanket_rate_rule"
    policy = {"wafv2_request_ceilings": {WAF_ARN: 100}}
    masked = rate()
    masked["Statement"]["RateBasedStatement"]["_coverage"] = {
        "ScopeDownStatement": {"status": "denied"}}
    row = waf([masked])
    assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "UNKNOWN"
    good = waf([rate()])
    facts = index("wafv2_web_acl", [good], policy=policy)
    facts["collections"]["wafv2_web_acl"][0]["items"] = []
    assert evaluate(check_id, good, facts) == "UNKNOWN"


def test_codebuild_variable_names_and_types():
    def project(variables):
        return {"name": "build", "Configuration": {"collection_status": "collected", "projects": [
            {"name": "build", "environment": {"environmentVariables": variables}}]}}
    safe = project([{"name": "OTHER", "type": "PLAINTEXT"}])
    plaintext = project([{"name": "aws_secret_access_key", "type": "PLAINTEXT"}])
    protected = project([{"name": "AWS_ACCESS_KEY_ID", "type": "SECRETS_MANAGER"}])
    for check_id in ("aws.nist.codebuild_exact_aws_key_env_names", "aws.pci.codebuild.aws_key_environment_vars"):
        assert evaluate(check_id, safe, index("codebuild_project", [safe])) == "PASS"
        assert evaluate(check_id, plaintext, index("codebuild_project", [plaintext])) == ("FAIL" if check_id.startswith("aws.nist") else "PASS")
        expected = "PASS" if check_id.startswith("aws.nist") else "FAIL"
        assert evaluate(check_id, protected, index("codebuild_project", [protected])) == expected
        missing = project([])
        del missing["Configuration"]["projects"][0]["environment"]["environmentVariables"]
        assert evaluate(check_id, missing, index("codebuild_project", [missing])) == "UNKNOWN"
        malformed = project([{"name": "OTHER", "type": 3}])
        assert evaluate(check_id, malformed, index("codebuild_project", [malformed])) == "UNKNOWN"


def test_backup_notification():
    good = {"BackupVaultName": "primary", "Notifications": {"collection_status": "collected",
        "SNSTopicArn": SNS_ARN, "BackupVaultEvents": ["BACKUP_JOB_FAILED"]}}
    bad = copy.deepcopy(good)
    bad["Notifications"]["BackupVaultEvents"] = ["BACKUP_JOB_COMPLETED"]
    assert evaluate("aws_backup_failure_notification", good, index("backup_vault", [good])) == "PASS"
    assert evaluate("aws_backup_failure_notification", bad, index("backup_vault", [bad])) == "FAIL"
    missing = copy.deepcopy(good)
    missing.pop("Notifications")
    assert evaluate("aws_backup_failure_notification", missing, index("backup_vault", [missing])) == "UNKNOWN"
    malformed = copy.deepcopy(good)
    malformed["Notifications"]["BackupVaultEvents"] = "BACKUP_JOB_FAILED"
    assert evaluate("aws_backup_failure_notification", malformed, index("backup_vault", [malformed])) == "UNKNOWN"


def test_redshift_upgrade():
    check_id = "aws_g6_redshift_automatic_version_upgrade"
    for value, expected in ((True, "PASS"), (False, "FAIL"), ("true", "UNKNOWN")):
        row = {"ClusterIdentifier": "warehouse", "AllowVersionUpgrade": value}
        assert evaluate(check_id, row, index("redshift_cluster", [row])) == expected
    row = {"ClusterIdentifier": "warehouse"}
    assert evaluate(check_id, row, index("redshift_cluster", [row])) == "UNKNOWN"


def test_batch_container_logs():
    check_id = "aws_cis_batch_job_cloudwatch_logging"
    base = {"jobDefinitionArn": "arn:aws:batch:us-east-1:123456789012:job-definition/job:1",
            "status": "ACTIVE", "containerProperties": {"logConfiguration": {
                "logDriver": "awslogs", "options": {"awslogs-group": "jobs"}}}}
    assert evaluate(check_id, base, index("batch_job_definition", [base])) == "PASS"
    bad = copy.deepcopy(base)
    bad["containerProperties"]["logConfiguration"]["logDriver"] = "json-file"
    assert evaluate(check_id, bad, index("batch_job_definition", [bad])) == "FAIL"
    missing = copy.deepcopy(base)
    del missing["containerProperties"]["logConfiguration"]
    assert evaluate(check_id, missing, index("batch_job_definition", [missing])) == "UNKNOWN"
    malformed = copy.deepcopy(base)
    malformed["containerProperties"]["logConfiguration"]["options"] = []
    assert evaluate(check_id, malformed, index("batch_job_definition", [malformed])) == "UNKNOWN"
    inactive = copy.deepcopy(base)
    inactive["status"] = "INACTIVE"
    assert evaluate(check_id, inactive, index("batch_job_definition", [inactive])) == "NOT_APPLICABLE"


def test_external_key_store():
    check_id = "aws_external_key_store_connected"
    policy = {"external_key_store_connectivity": ["VPC_ENDPOINT"]}
    base = {"CustomKeyStoreName": "xks", "CustomKeyStoreType": "EXTERNAL_KEY_STORE",
            "ConnectionState": "CONNECTED", "XksProxyConnectivity": "VPC_ENDPOINT"}
    assert evaluate(check_id, base, index("kms_external_key_store", [base], policy=policy)) == "PASS"
    bad = {**base, "ConnectionState": "DISCONNECTED"}
    assert evaluate(check_id, bad, index("kms_external_key_store", [bad], policy=policy)) == "FAIL"
    assert evaluate(check_id, bad, index("kms_external_key_store", [bad])) == "UNKNOWN"
    malformed = {**base, "ConnectionState": 5}
    assert evaluate(check_id, malformed, index("kms_external_key_store", [malformed], policy=policy)) == "UNKNOWN"
    other = {**base, "CustomKeyStoreType": "AWS_CLOUDHSM"}
    assert evaluate(check_id, other, index("kms_external_key_store", [other], policy=policy)) == "NOT_APPLICABLE"


def alarm(metric, dimension, value, *, namespace="AWS/EC2", actions=True):
    return {"AlarmArn": f"arn:aws:cloudwatch:us-east-1:123456789012:alarm:{metric}",
            "Namespace": namespace, "MetricName": metric,
            "Dimensions": [{"Name": dimension, "Value": value}],
            "ActionsEnabled": actions, "AlarmActions": [SNS_ARN]}


def test_ec2_cpu_and_status_alarms():
    instance = {"InstanceId": "i-abc", "State": {"Name": "running"}}
    cpu = alarm("CPUUtilization", "InstanceId", "i-abc")
    status = alarm("StatusCheckFailed", "InstanceId", "i-abc")
    for check_id, matching in (("aws_ec2_running_instance_cpu_alarm_present", cpu),
                               ("aws_ec2_status_alarm", status)):
        policy = {"status_alarm_instance_ids": ["i-abc"]}
        assert evaluate(check_id, instance, index("instance", [instance], extra={"cloudwatch_alarm": [matching]}, policy=policy)) == "PASS"
        assert evaluate(check_id, instance, index("instance", [instance], extra={"cloudwatch_alarm": []}, policy=policy)) == "FAIL"
        assert evaluate(check_id, instance, index("instance", [instance], policy=policy)) == "UNKNOWN"
        malformed = {**matching, "Dimensions": "bad"}
        assert evaluate(check_id, instance, index("instance", [instance], extra={"cloudwatch_alarm": [malformed]}, policy=policy)) == "UNKNOWN"
        partial = index("instance", [instance], extra={"cloudwatch_alarm": [matching]}, policy=policy)
        partial["collections"]["cloudwatch_alarm"][0]["status"] = "partial"
        assert evaluate(check_id, instance, partial) == "UNKNOWN"
    stopped = {"InstanceId": "i-abc", "State": {"Name": "stopped"}}
    assert evaluate("aws_ec2_running_instance_cpu_alarm_present", stopped, index("instance", [stopped])) == "NOT_APPLICABLE"
    assert evaluate("aws_ec2_status_alarm", stopped, index("instance", [stopped],
        extra={"cloudwatch_alarm": [status]}, policy={"status_alarm_instance_ids": ["i-abc"]})) == "PASS"


def test_sns_delivery_failure_alarm():
    check_id = "aws_sns_delivery_failure_alarm_present"
    topic = {"TopicArn": SNS_ARN}
    subscription = {"TopicArn": SNS_ARN, "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:alerts:sub"}
    matched = alarm("NumberOfNotificationsFailed", "TopicName", "alerts", namespace="AWS/SNS")
    assert evaluate(check_id, topic, index("sns_topic", [topic], extra={
        "sns_subscription": [subscription], "cloudwatch_alarm": [matched]})) == "PASS"
    assert evaluate(check_id, topic, index("sns_topic", [topic], extra={
        "sns_subscription": [subscription], "cloudwatch_alarm": []})) == "FAIL"
    assert evaluate(check_id, topic, index("sns_topic", [topic], extra={
        "sns_subscription": [], "cloudwatch_alarm": []})) == "NOT_APPLICABLE"
    assert evaluate(check_id, topic, index("sns_topic", [topic])) == "UNKNOWN"
    malformed = {**matched, "AlarmActions": "bad"}
    assert evaluate(check_id, topic, index("sns_topic", [topic], extra={
        "sns_subscription": [subscription], "cloudwatch_alarm": [malformed]})) == "UNKNOWN"


def test_role_required_managed_policies():
    check_id = "aws.pci.iam.role_required_managed_policies"
    required = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    role = {"Arn": "arn:aws:iam::123456789012:role/worker",
            "AttachedManagedPolicies": [{"PolicyArn": required}]}
    policy = {"required_policy_arns": [required]}
    assert evaluate(check_id, role, index("iam_role", [role], policy=policy,
        scope="123456789012/global")) == "PASS"
    bad = {**role, "AttachedManagedPolicies": []}
    assert evaluate(check_id, bad, index("iam_role", [bad], policy=policy,
        scope="123456789012/global")) == "FAIL"
    assert evaluate(check_id, role, index("iam_role", [role], scope="123456789012/global")) == "UNKNOWN"
    malformed = {**role, "AttachedManagedPolicies": [{"PolicyArn": 3}]}
    assert evaluate(check_id, malformed, index("iam_role", [malformed], policy=policy,
        scope="123456789012/global")) == "UNKNOWN"


def test_cloudwatch_metric_alarm_threshold_policy():
    check_id = "aws_cloudwatch_metric_alarm_has_threshold"
    policy = {"cloudwatch_threshold_policy": {"AWS/EC2/CPUUtilization": {
        "min_threshold": 70, "max_threshold": 90,
        "comparison_operators": ["GreaterThanThreshold"]}}}
    row = {"AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cpu",
           "Namespace": "AWS/EC2", "MetricName": "CPUUtilization", "Threshold": 80,
           "ComparisonOperator": "GreaterThanThreshold"}
    assert evaluate(check_id, row, index("cloudwatch_alarm", [row], policy=policy)) == "PASS"
    bad = {**row, "Threshold": 95}
    assert evaluate(check_id, bad, index("cloudwatch_alarm", [bad], policy=policy)) == "FAIL"
    assert evaluate(check_id, row, index("cloudwatch_alarm", [row])) == "UNKNOWN"
    malformed = {**row, "Threshold": "80"}
    assert evaluate(check_id, malformed, index("cloudwatch_alarm", [malformed], policy=policy)) == "UNKNOWN"
    missing = {key: value for key, value in row.items() if key != "Threshold"}
    assert evaluate(check_id, missing, index("cloudwatch_alarm", [missing], policy=policy)) == "UNKNOWN"


def test_sns_feedback_configured_protocols():
    check_id = "aws.pci.sns.delivery_status_logging"
    subscription = {"TopicArn": SNS_ARN, "SubscriptionArn": "arn:aws:sns:us-east-1:123456789012:alerts:sub",
                    "Protocol": "sqs"}
    attrs = {"TopicArn": SNS_ARN, "SQSFailureFeedbackRoleArn": "arn:aws:iam::123456789012:role/failure",
             "SQSSuccessFeedbackRoleArn": "arn:aws:iam::123456789012:role/success",
             "SQSSuccessFeedbackSampleRate": "10"}
    row = {"TopicArn": SNS_ARN, "Attributes": {"collection_status": "collected", "Attributes": attrs}}
    assert evaluate(check_id, row, index("sns_topic", [row], extra={"sns_subscription": [subscription]})) == "PASS"
    bad = copy.deepcopy(row)
    bad["Attributes"]["Attributes"].pop("SQSFailureFeedbackRoleArn")
    assert evaluate(check_id, bad, index("sns_topic", [bad], extra={"sns_subscription": [subscription]})) == "FAIL"
    assert evaluate(check_id, row, index("sns_topic", [row], extra={"sns_subscription": []})) == "NOT_APPLICABLE"
    assert evaluate(check_id, row, index("sns_topic", [row])) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["Attributes"]["Attributes"]["SQSSuccessFeedbackSampleRate"] = "more"
    assert evaluate(check_id, malformed, index("sns_topic", [malformed], extra={"sns_subscription": [subscription]})) == "UNKNOWN"


def test_expected_organization_management_account():
    check_id = "aws_account_expected_organization_master"
    row = {"id": "account-configuration", "Organization": {"collection_status": "collected",
           "MasterAccountId": "123456789012"}}
    policy = {"expected_management_account_id": "123456789012"}
    def facts(value, chosen=policy):
        return index("aws_account_configuration", [value], policy=chosen, scope="123456789012/global")
    assert evaluate(check_id, row, facts(row)) == "PASS"
    bad = copy.deepcopy(row)
    bad["Organization"]["MasterAccountId"] = "999999999999"
    assert evaluate(check_id, bad, facts(bad)) == "FAIL"
    outside = {"id": "account-configuration", "Organization": {"collection_status": "empty", "absent": True}}
    assert evaluate(check_id, outside, facts(outside)) == "FAIL"
    assert evaluate(check_id, row, facts(row, {})) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["Organization"]["MasterAccountId"] = "invalid"
    assert evaluate(check_id, malformed, facts(malformed)) == "UNKNOWN"


def test_ami_trusted_launch_permissions():
    check_id = "aws_ec2_ami_trusted_principals"
    policy = {"ami_trusted_principals": {"account_ids": ["123456789012"],
              "organization_arns": [], "organizational_unit_arns": []}}
    row = {"ImageId": "ami-abc", "LaunchPermissions": {"collection_status": "collected",
           "items": [{"UserId": "123456789012"}]}}
    assert evaluate(check_id, row, index("ami", [row], policy=policy)) == "PASS"
    bad = copy.deepcopy(row)
    bad["LaunchPermissions"]["items"] = [{"Group": "all"}]
    assert evaluate(check_id, bad, index("ami", [bad], policy=policy)) == "FAIL"
    assert evaluate(check_id, row, index("ami", [row])) == "UNKNOWN"
    missing = {"ImageId": "ami-abc"}
    assert evaluate(check_id, missing, index("ami", [missing], policy=policy)) == "UNKNOWN"
    malformed = copy.deepcopy(row)
    malformed["LaunchPermissions"]["items"] = [{"UserId": 1}]
    assert evaluate(check_id, malformed, index("ami", [malformed], policy=policy)) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.SPECS))
def test_every_check_rejects_partial_or_foreign_scope(check_id):
    kind = sw.SPECS[check_id]["kind"]
    row = {}
    partial = index(kind, [row], status="partial")
    assert evaluate(check_id, row, partial) == "UNKNOWN"
    foreign = index(kind, [row], scope="123456789012/eu-west-1")
    assert evaluate(check_id, row, foreign) == "UNKNOWN"


@pytest.mark.parametrize("check_id,metric", [("aws_ec2_running_instance_cpu_alarm_present", "CPUUtilization"), ("aws_ec2_status_alarm", "StatusCheckFailed")])
@pytest.mark.parametrize("mutation", ["foreign_account", "foreign_region", "empty_action", "duplicate_dimension_name"])
def test_review_ec2_alarm_scope_actions_and_dimensions(check_id, metric, mutation):
    instance = {"InstanceId": "i-abc", "State": {"Name": "running"}}
    matched = alarm(metric, "InstanceId", "i-abc")
    if mutation == "foreign_account":
        matched["AlarmArn"] = matched["AlarmArn"].replace("123456789012", "999999999999")
    elif mutation == "foreign_region":
        matched["AlarmArn"] = matched["AlarmArn"].replace("us-east-1", "eu-west-1")
    elif mutation == "empty_action":
        matched["AlarmActions"].append("")
    else:
        matched["Dimensions"].append({"Name": "InstanceId", "Value": "i-other"})
    facts = index("instance", [instance], extra={"cloudwatch_alarm": [matched]}, policy={"status_alarm_instance_ids": ["i-abc"]})
    assert evaluate(check_id, instance, facts) == "UNKNOWN"


def test_review_sns_alarm_foreign_arn_cannot_satisfy_topic():
    topic = {"TopicArn": SNS_ARN}
    subscription = {"TopicArn": SNS_ARN, "SubscriptionArn": SNS_ARN + ":sub"}
    matched = alarm("NumberOfNotificationsFailed", "TopicName", "alerts", namespace="AWS/SNS")
    matched["AlarmArn"] = matched["AlarmArn"].replace("123456789012", "999999999999")
    assert evaluate("aws_sns_delivery_failure_alarm_present", topic, index("sns_topic", [topic], extra={"sns_subscription": [subscription], "cloudwatch_alarm": [matched]})) == "UNKNOWN"


@pytest.mark.parametrize("check_id", list(sw.SPECS))
def test_review_duplicate_resource_records_never_evaluate(check_id):
    kind = sw.SPECS[check_id]["kind"]
    assert evaluate(check_id, {}, index(kind, [{}, {}])) == "UNKNOWN"


def test_review_waf_foreign_arn_even_if_lookup_and_policy_match():
    foreign = WAF_ARN.replace("123456789012", "999999999999")
    row = {"ARN": foreign, "WebACL": {"ARN": foreign, "Rules": [rate()]}}
    policy = {"wafv2_request_ceilings": {foreign: 100}}
    assert evaluate("aws_wafv2_blanket_rate_rule", row, index("wafv2_web_acl", [row], policy=policy)) == "UNKNOWN"


@pytest.mark.parametrize("check_id", ["aws_wafv2_baseline_managed_rules", "aws_wafv2_blanket_rate_rule", "aws_wafv2_managed_rule_groups", "aws_wafv2_scoped_rate_rules", "aws_wafv2_service_exclusion_rules"])
@pytest.mark.parametrize("mutation", ["empty_statement", "masked_managed", "bad_override_payload", "missing_override_name", "bad_action_payload"])
def test_review_waf_malformed_or_masked_rules_do_not_become_valid(check_id, mutation):
    baseline = [{"VendorName": "AWS", "Name": "AWSManagedRulesCommonRuleSet"}]
    policy = {"wafv2_baselines": {WAF_ARN: baseline}, "wafv2_request_ceilings": {WAF_ARN: 100},
              "wafv2_scoped_rate": {WAF_ARN: {"Limit": 100, "ScopeDownStatement": {"GeoMatchStatement": {"CountryCodes": ["US"]}}}},
              "wafv2_service_exclusions": {WAF_ARN: {"AWS/AWSManagedRulesCommonRuleSet": ["example"]}}}
    rule = managed()
    if mutation == "empty_statement":
        rule["Statement"] = {}
    elif mutation == "masked_managed":
        rule["Statement"] = {"ByteMatchStatement": {}, "_coverage": {"ManagedRuleGroupStatement": {"status": "denied"}}}
    elif mutation == "bad_override_payload":
        rule["OverrideAction"] = {"None": "bad"}
    elif mutation == "missing_override_name":
        rule["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"] = [{"ActionToUse": {"Count": {}}}]
    else:
        rule["Statement"]["ManagedRuleGroupStatement"]["RuleActionOverrides"] = [{"Name": "example", "ActionToUse": {"Count": "bad"}}]
    row = waf([rule])
    assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "UNKNOWN"


@pytest.mark.parametrize("check_id", ["aws_wafv2_blanket_rate_rule", "aws_wafv2_scoped_rate_rules"])
def test_review_waf_masked_rate_selector_and_bad_action(check_id):
    policy = {"wafv2_request_ceilings": {WAF_ARN: 100}, "wafv2_scoped_rate": {WAF_ARN: {"Limit": 100, "ScopeDownStatement": {"GeoMatchStatement": {"CountryCodes": ["US"]}}}}}
    for rule in ({"Statement": {"ByteMatchStatement": {}, "_coverage": {"RateBasedStatement": {"status": "denied"}}}},
                 {**rate(), "Action": {"Block": "bad"}}):
        row = waf([rule])
        assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "UNKNOWN"


def test_review_external_store_future_type_is_not_an_applicability_proof():
    row = {"CustomKeyStoreName": "xks", "CustomKeyStoreType": "FUTURE_STORE"}
    assert evaluate("aws_external_key_store_connected", row, index("kms_external_key_store", [row])) == "UNKNOWN"


@pytest.mark.parametrize("properties", [
    {"ecsProperties": {"taskProperties": [{"containers": [{"logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": "jobs"}}}]}, {"containers": []}]}},
    {"containerProperties": {"logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": "jobs"}}}, "nodeProperties": {"nodeRangeProperties": []}},
    {"nodeProperties": {"nodeRangeProperties": []}},
])
def test_review_batch_nested_inventory_cannot_hide_empty_container_sets(properties):
    row = {"jobDefinitionArn": "arn:aws:batch:us-east-1:123456789012:job-definition/job:1", "status": "ACTIVE", **properties}
    assert evaluate("aws_cis_batch_job_cloudwatch_logging", row, index("batch_job_definition", [row])) == "UNKNOWN"


def test_review_threshold_policy_metric_keys_are_literal():
    row = {"AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cpu", "Namespace": "Acme.App", "MetricName": "Queue.Depth", "Threshold": 80, "ComparisonOperator": "GreaterThanThreshold"}
    key = "Acme.App/Queue.Depth"
    policy = {"cloudwatch_threshold_policy": {key: {"min_threshold": 70, "max_threshold": 90, "comparison_operators": ["GreaterThanThreshold"]}}}
    assert evaluate("aws_cloudwatch_metric_alarm_has_threshold", row, index("cloudwatch_alarm", [row], policy=policy)) == "PASS"
    policy["cloudwatch_threshold_policy"]["_coverage"] = {key: {"status": "denied"}}
    assert evaluate("aws_cloudwatch_metric_alarm_has_threshold", row, index("cloudwatch_alarm", [row], policy=policy)) == "UNKNOWN"


@pytest.mark.parametrize("query_fields", [{"Expression": "m1*2"}, {"ReturnData": False}])
def test_review_threshold_query_must_monitor_the_declared_raw_metric(query_fields):
    row = {"AlarmArn": "arn:aws:cloudwatch:us-east-1:123456789012:alarm:cpu", "Metrics": [{"MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"}}, **query_fields}], "Threshold": 80, "ComparisonOperator": "GreaterThanThreshold"}
    policy = {"cloudwatch_threshold_policy": {"AWS/EC2/CPUUtilization": {"min_threshold": 70, "max_threshold": 90, "comparison_operators": ["GreaterThanThreshold"]}}}
    assert evaluate("aws_cloudwatch_metric_alarm_has_threshold", row, index("cloudwatch_alarm", [row], policy=policy)) == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["sms_protocol", "bad_role", "bad_rate", "foreign_topic"])
def test_review_sns_feedback_supported_sources_and_well_formed_attributes(mutation):
    attrs = {"TopicArn": SNS_ARN, "SQSFailureFeedbackRoleArn": "arn:aws:iam::123456789012:role/failure", "SQSSuccessFeedbackRoleArn": "arn:aws:iam::123456789012:role/success", "SQSSuccessFeedbackSampleRate": "10"}
    subscription = {"TopicArn": SNS_ARN, "Protocol": "sqs"}
    row = {"TopicArn": SNS_ARN, "Attributes": {"collection_status": "collected", "Attributes": attrs}}
    if mutation == "sms_protocol":
        subscription["Protocol"] = "sms"
    elif mutation == "bad_role":
        attrs["SQSFailureFeedbackRoleArn"] = "not-an-arn"
    elif mutation == "bad_rate":
        attrs["SQSSuccessFeedbackSampleRate"] = "+10"
    else:
        row["TopicArn"] = SNS_ARN.replace("123456789012", "999999999999")
        attrs["TopicArn"] = row["TopicArn"]
        subscription["TopicArn"] = row["TopicArn"]
    assert evaluate("aws.pci.sns.delivery_status_logging", row, index("sns_topic", [row], extra={"sns_subscription": [subscription]})) == "UNKNOWN"


@pytest.mark.parametrize("key,selector,bad", [("account_ids", "UserId", "not-an-account"), ("organization_arns", "OrganizationArn", "arn:aws:wrong::123456789012:organization/o-abc"), ("organizational_unit_arns", "OrganizationalUnitArn", "arn:aws:organizations::123456789012:ou/bad")])
def test_review_ami_principal_policy_and_observation_are_validated(key, selector, bad):
    policy = {"ami_trusted_principals": {"account_ids": [], "organization_arns": [], "organizational_unit_arns": []}}
    row = {"ImageId": "ami-abc", "LaunchPermissions": {"collection_status": "collected", "items": [{selector: bad}]}}
    assert evaluate("aws_ec2_ami_trusted_principals", row, index("ami", [row], policy=policy)) == "UNKNOWN"
    policy["ami_trusted_principals"][key] = [bad]
    assert evaluate("aws_ec2_ami_trusted_principals", row, index("ami", [row], policy=policy)) == "UNKNOWN"


def test_review_global_and_regional_kinds_follow_collector_scope():
    row = {"ClusterIdentifier": "cluster", "AllowVersionUpgrade": True}
    assert evaluate("aws_g6_redshift_automatic_version_upgrade", row, index("redshift_cluster", [row], scope="123456789012/global")) == "UNKNOWN"
    account = {"id": "account-configuration", "Organization": {"collection_status": "collected", "MasterAccountId": "123456789012"}}
    assert evaluate("aws_account_expected_organization_master", account, index("aws_account_configuration", [account], policy={"expected_management_account_id": "123456789012"})) == "UNKNOWN"


def test_review_explicit_empty_owner_inventories_are_distinct_from_missing_policy():
    row = waf([])
    policy = {"wafv2_baselines": {WAF_ARN: []}, "wafv2_service_exclusions": {WAF_ARN: {}}}
    for check_id in ("aws_wafv2_baseline_managed_rules", "aws_wafv2_service_exclusion_rules"):
        assert evaluate(check_id, row, index("wafv2_web_acl", [row], policy=policy)) == "PASS"
        assert evaluate(check_id, row, index("wafv2_web_acl", [row])) == "UNKNOWN"
    row = waf([managed()])
    assert evaluate("aws_wafv2_managed_rule_groups", row, index("wafv2_web_acl", [row], policy=policy)) == "PASS"
    role = {"Arn": "arn:aws:iam::123456789012:role/worker", "AttachedManagedPolicies": []}
    assert evaluate("aws.pci.iam.role_required_managed_policies", role, index("iam_role", [role], policy={"required_policy_arns": []}, scope="123456789012/global")) == "PASS"
    foreign = {**role, "Arn": role["Arn"].replace("123456789012", "999999999999")}
    assert evaluate("aws.pci.iam.role_required_managed_policies", foreign, index("iam_role", [foreign], policy={"required_policy_arns": []}, scope="123456789012/global")) == "UNKNOWN"


def test_review_batch_and_codebuild_native_arns_bind_detail_to_scope():
    row = {"jobDefinitionArn": "arn:aws:batch:us-east-1:999999999999:job-definition/job:1", "status": "ACTIVE", "containerProperties": {"logConfiguration": {"logDriver": "awslogs", "options": {"awslogs-group": "jobs"}}}}
    assert evaluate("aws_cis_batch_job_cloudwatch_logging", row, index("batch_job_definition", [row])) == "UNKNOWN"
    project = {"name": "build", "Configuration": {"collection_status": "collected", "projects": [{"name": "build", "arn": "arn:aws:codebuild:us-east-1:999999999999:project/build", "environment": {"environmentVariables": []}}]}}
    for check_id in ("aws.nist.codebuild_exact_aws_key_env_names", "aws.pci.codebuild.aws_key_environment_vars"):
        assert evaluate(check_id, project, index("codebuild_project", [project])) == "UNKNOWN"


def test_review_backup_redshift_and_ami_explicit_native_owner():
    vault = {"BackupVaultName": "main", "BackupVaultArn": "arn:aws:backup:us-east-1:999999999999:backup-vault:main", "Notifications": {"collection_status": "collected", "SNSTopicArn": SNS_ARN, "BackupVaultEvents": ["BACKUP_JOB_FAILED"]}}
    assert evaluate("aws_backup_failure_notification", vault, index("backup_vault", [vault])) == "UNKNOWN"
    cluster = {"ClusterIdentifier": "main", "ClusterNamespaceArn": "arn:aws:redshift:us-east-1:999999999999:namespace:id", "AllowVersionUpgrade": True}
    assert evaluate("aws_g6_redshift_automatic_version_upgrade", cluster, index("redshift_cluster", [cluster])) == "UNKNOWN"
    ami = {"ImageId": "ami-abc", "OwnerId": "999999999999", "LaunchPermissions": {"collection_status": "empty", "items": []}}
    policy = {"ami_trusted_principals": {"account_ids": [], "organization_arns": [], "organizational_unit_arns": []}}
    assert evaluate("aws_ec2_ami_trusted_principals", ami, index("ami", [ami], policy=policy)) == "UNKNOWN"


def test_review_empty_waf_exclusion_inventory_still_requires_valid_group_keys():
    row = waf([])
    policy = {"wafv2_service_exclusions": {WAF_ARN: {"/": []}}}
    assert evaluate("aws_wafv2_service_exclusion_rules", row, index("wafv2_web_acl", [row], policy=policy)) == "UNKNOWN"


def test_review_required_role_policy_arns_cannot_approve_malformed_identifiers():
    row = {"Arn": "arn:aws:iam::123456789012:role/worker", "AttachedManagedPolicies": [{"PolicyArn": "arn:garbage"}]}
    assert evaluate("aws.pci.iam.role_required_managed_policies", row, index("iam_role", [row], policy={"required_policy_arns": ["arn:garbage"]}, scope="123456789012/global")) == "UNKNOWN"
    assert evaluate("aws.pci.iam.role_required_managed_policies", row, index("iam_role", [row], policy={"required_policy_arns": []}, scope="123456789012/global")) == "UNKNOWN"


@pytest.mark.parametrize('status', ['collected', 'partial'])
def test_complete_inventory_authority_is_validated_once_per_immutable_scope(monkeypatch,status):
    from peaso.checks.facts import MemoIndex, Unavailable
    row={'Arn':'arn:aws:iam::123456789012:role/worker','AttachedManagedPolicies':[]}
    facts=MemoIndex(index('iam_role',[row],scope='123456789012/global',status=status))
    original=sw._validated_inventory;calls=[]
    def counted(index,kind):
        calls.append(kind)
        return original(index,kind)
    monkeypatch.setattr(sw,'_validated_inventory',counted)
    if status=='collected':
        first=sw._inventory(facts,'iam_role');first.clear()
        assert sw._inventory(facts,'iam_role')==[row]
    else:
        for _ in range(2):
            with pytest.raises(Unavailable):sw._inventory(facts,'iam_role')
    assert calls==['iam_role']
    facts['context']={**facts['context'],'scope':'999999999999/global'}
    with pytest.raises(Unavailable):sw._inventory(facts,'iam_role')
    assert calls==['iam_role','iam_role']
