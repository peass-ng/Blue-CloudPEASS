"""Reviewed AWS configuration predicates over immutable native snapshot facts.

Source eligibility, joins, thresholds and compound alternatives are retained;
unavailable/malformed evidence produces UNKNOWN through the shared registry.
No upstream code is imported or executed.
"""
from __future__ import annotations

import re

from . import register, result, unknown
from .facts import Unavailable, field_check, get, list_of_objects
from .fixtures import CASES, nest


EXTENDED_IDS = []


def install(cid, kind, title, passing, failing, *, control="CM-6", severity="medium", category="hardening", extra=None):
    def decorate(evaluate):
        evaluate.__name__ = cid.replace(".", "_")
        register(cid, "aws", category, kind, title, severity, control,
            "Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.")(evaluate)
        globals()[evaluate.__name__] = evaluate
        CASES[cid] = {"pass": passing, "fail": failing, "missing": {}, "malformed": None, **(extra or {})}
        EXTENDED_IDS.append(cid)
        return evaluate
    return decorate


for cid, kind, path, title in [
    ("aws.iam.password_uppercase", "iam_password_policy", "PasswordPolicy.RequireUppercaseCharacters", "IAM password policy requires uppercase characters"),
    ("aws.iam.password_lowercase", "iam_password_policy", "PasswordPolicy.RequireLowercaseCharacters", "IAM password policy requires lowercase characters"),
    ("aws.iam.password_numbers", "iam_password_policy", "PasswordPolicy.RequireNumbers", "IAM password policy requires numbers"),
    ("aws.iam.password_symbols", "iam_password_policy", "PasswordPolicy.RequireSymbols", "IAM password policy requires symbols"),
    ("aws.rds.auto_minor_upgrade", "rds_instance", "AutoMinorVersionUpgrade", "RDS instance enables automatic minor version upgrades"),
    ("aws.rds.cluster_iam_authentication", "rds_cluster", "IAMDatabaseAuthenticationEnabled", "RDS cluster enables IAM database authentication"),
    ("aws.rds.cluster_multi_az", "rds_cluster", "MultiAZ", "RDS cluster enables Multi-AZ configuration"),
    ("aws.rds.cluster_copy_snapshot_tags", "rds_cluster", "CopyTagsToSnapshot", "RDS cluster copies tags to snapshots"),
    ("aws.rds.snapshot_encryption", "rds_snapshot", "Encrypted", "RDS instance snapshot encryption is enabled"),
]:
    field_check(cid, "aws", kind, path, True, False, title)
    EXTENDED_IDS.append(cid)


def numeric(cid, path, minimum, maximum, good, bad, title):
    @install(cid, "iam_password_policy", title, nest(path, good), nest(path, bad), control="IA-5")
    def evaluate(item, index):
        value = get(item, path, int)
        if value < 0:
            return unknown("negative password setting", field=path)
        acceptable = minimum <= value and (maximum is None or value <= maximum)
        return result(not acceptable, field=path, configured=value, minimum=minimum, maximum=maximum)


numeric("aws.iam.password_minimum_length", "PasswordPolicy.MinimumPasswordLength", 14, None, 14, 13,
    "IAM password policy requires at least 14 characters")
numeric("aws.iam.password_reuse_prevention", "PasswordPolicy.PasswordReusePrevention", 24, 24, 24, 23,
    "IAM password policy prevents reuse of exactly 24 prior passwords")
numeric("aws.iam.password_max_age", "PasswordPolicy.MaxPasswordAge", 1, 90, 90, 91,
    "IAM password policy expires passwords within 90 days")


def nonempty(cid, kind, path, title, *, control="CM-6"):
    @install(cid, kind, title, nest(path, "configured"), nest(path, ""), control=control)
    def evaluate(item, index):
        value = get(item, path, str)
        return result(not bool(value), field=path, configured=value, semantics="Declared configuration; effectiveness is not tested")


nonempty("aws.rds.vpc_configuration", "rds_instance", "DBSubnetGroup.VpcId", "RDS instance has VPC configuration", control="SC-7")
nonempty("aws.rds.enhanced_monitoring", "rds_instance", "EnhancedMonitoringResourceArn", "RDS instance declares enhanced monitoring", control="AU-2")
nonempty("aws.lambda.vpc_configuration", "lambda_function", "VpcConfig.VpcId", "Lambda function has VPC configuration", control="SC-7")
nonempty("aws.cloudtrail.kms_encryption", "cloudtrail", "KmsKeyId", "CloudTrail trail declares KMS encryption", control="SC-13")
nonempty("aws.sns.kms_encryption", "sns_topic", "Attributes.Attributes.KmsMasterKeyId", "SNS topic declares KMS encryption", control="SC-13")


@install("aws.rds.copy_snapshot_tags", "rds_instance", "Non-Aurora RDS instance copies tags to snapshots",
    {"Engine": "postgres", "CopyTagsToSnapshot": True}, {"Engine": "postgres", "CopyTagsToSnapshot": False},
    extra={"not_applicable": {"Engine": "aurora-mysql"}})
def rds_copy_tags(item, index):
    engine = get(item, "Engine", str)
    if engine in {"aurora", "aurora-mysql", "aurora-postgresql"}:
        return "NOT_APPLICABLE", {"engine": engine, "reason": "Upstream predicate excludes Aurora instances"}
    enabled = get(item, "CopyTagsToSnapshot", bool)
    return result(not enabled, engine=engine, copy_tags_to_snapshot=enabled)


@install("aws.rds.cloudwatch_log_exports", "rds_instance", "RDS instance exports logs to CloudWatch",
    {"EnabledCloudwatchLogsExports": ["postgresql"]}, {"EnabledCloudwatchLogsExports": []}, control="AU-2")
def rds_logs(item, index):
    exports = get(item, "EnabledCloudwatchLogsExports", list)
    if any(not isinstance(v, str) or not v for v in exports):
        return unknown("malformed log export types")
    return result(not bool(exports), log_exports=exports)


@install("aws.lambda.dead_letter_queue", "lambda_function", "Lambda function has a dead-letter queue configuration",
    {"DeadLetterConfig": {"TargetArn": "arn:aws:sqs:us-east-1:123456789012:dead-letter"}}, {"DeadLetterConfig": {}}, control="SI-4")
def lambda_dlq(item, index):
    config = get(item, "DeadLetterConfig", dict)
    if not config:
        return result(True, dead_letter_configuration={})
    target = get(config, "TargetArn", str)
    return result(not bool(target), target_arn=target)


@install("aws.lambda.function_url_authentication", "lambda_function", "Existing Lambda function URL requires AWS IAM authentication",
    {"FunctionUrl": {"AuthType": "AWS_IAM"}}, {"FunctionUrl": {"AuthType": "NONE"}}, category="exposure", control="AC-3",
    extra={"not_applicable": {"FunctionUrl": {"collection_status": "empty", "absent": True}}})
def lambda_url(item, index):
    config = get(item, "FunctionUrl", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return "NOT_APPLICABLE", {"reason": "No function URL exists"}
    auth = get(config, "AuthType", str)
    if auth not in {"AWS_IAM", "NONE"}:
        return unknown("unrecognized function URL auth type")
    return result(auth != "AWS_IAM", auth_type=auth, semantics="URL authentication configuration; invocation permissions and network path remain separate")


def lb_attribute(item, key):
    rows = list_of_objects(get(item, "Attributes.Attributes", list))
    selected = []
    for row in rows:
        name, value = get(row, "Key", str), get(row, "Value", str)
        if name == key:
            selected.append(value)
    if len(selected) != 1:
        raise Unavailable("missing or duplicate load balancer attribute: " + key)
    return selected[0]


def lb_fixture(key, value, **extra):
    return {"Type": "application", "Attributes": {"Attributes": [{"Key": key, "Value": value}]}, **extra}


def lb_boolean(cid, key, title, application_only=False):
    @install(cid, "load_balancer", title, lb_fixture(key, "true"), lb_fixture(key, "false"),
        extra={"not_applicable": {"Type": "network"}} if application_only else {})
    def evaluate(item, index):
        if application_only:
            kind = get(item, "Type", str)
            if kind not in {"application", "network", "gateway"}:
                return unknown("unrecognized load balancer type")
            if kind != "application":
                return "NOT_APPLICABLE", {"load_balancer_type": kind}
        value = lb_attribute(item, key)
        if value not in {"true", "false"}:
            return unknown("malformed boolean load balancer attribute", attribute=key)
        return result(value != "true", attribute=key, configured=value)


lb_boolean("aws.elbv2.deletion_protection", "deletion_protection.enabled", "ELBv2 deletion protection is enabled")
lb_boolean("aws.elbv2.access_logging", "access_logs.s3.enabled", "ELBv2 access logging to S3 is enabled")
lb_boolean("aws.elbv2.drop_invalid_headers", "routing.http.drop_invalid_header_fields.enabled", "Application load balancer drops invalid HTTP headers", True)


def desync_fixture(mode, drop):
    return {"Type": "application", "Attributes": {"Attributes": [
        {"Key": "routing.http.desync_mitigation_mode", "Value": mode},
        {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": drop}]}}


@install("aws.elbv2.desync_mitigation", "load_balancer", "Application load balancer mitigates HTTP desynchronization",
    desync_fixture("defensive", "false"), desync_fixture("monitor", "false"), control="SC-7",
    extra={"not_applicable": {"Type": "network"}})
def lb_desync(item, index):
    kind = get(item, "Type", str)
    if kind not in {"application", "network", "gateway"}:
        return unknown("unrecognized load balancer type")
    if kind != "application":
        return "NOT_APPLICABLE", {"load_balancer_type": kind}
    mode = lb_attribute(item, "routing.http.desync_mitigation_mode")
    if mode not in {"strictest", "defensive", "monitor"}:
        return unknown("unrecognized desync mitigation mode")
    if mode in {"strictest", "defensive"}:
        return result(False, desync_mitigation_mode=mode)
    drop = lb_attribute(item, "routing.http.drop_invalid_header_fields.enabled")
    if drop not in {"true", "false"}:
        return unknown("malformed header-dropping attribute")
    return result(drop != "true", desync_mitigation_mode=mode, drop_invalid_headers=drop)


@install("aws.elbv2.multiple_availability_zones", "load_balancer", "ELBv2 spans at least two availability zones",
    {"AvailabilityZones": [{"ZoneName": "us-east-1a"}, {"ZoneName": "us-east-1b"}]}, {"AvailabilityZones": [{"ZoneName": "us-east-1a"}]}, control="CP-10")
def lb_zones(item, index):
    rows = list_of_objects(get(item, "AvailabilityZones", list))
    zones = [get(row, "ZoneName", str) for row in rows]
    if any(not zone for zone in zones):
        return unknown("empty availability zone")
    return result(len(set(zones)) < 2, availability_zones=sorted(set(zones)), minimum=2)


@install("aws.sqs.encryption", "sqs_queue", "SQS queue enables KMS or SQS-managed encryption",
    {"Attributes": {"Attributes": {"KmsMasterKeyId": "", "SqsManagedSseEnabled": "true"}}},
    {"Attributes": {"Attributes": {"KmsMasterKeyId": "", "SqsManagedSseEnabled": "false"}}}, control="SC-13")
def sqs_encryption(item, index):
    attributes = get(item, "Attributes.Attributes", dict)
    if "KmsMasterKeyId" in attributes:
        kms = get(attributes, "KmsMasterKeyId", str)
        if kms:
            return result(False, encryption="KMS", kms_key_id=kms)
    if "SqsManagedSseEnabled" in attributes:
        enabled = get(attributes, "SqsManagedSseEnabled", str)
        if enabled not in {"true", "false"}:
            return unknown("malformed SQS-managed encryption flag")
        if enabled == "true":
            return result(False, encryption="SQS-managed")
    # Both alternatives must be known before asserting encryption is absent.
    kms = get(attributes, "KmsMasterKeyId", str)
    enabled = get(attributes, "SqsManagedSseEnabled", str)
    return result(not kms and enabled == "false", kms_key_id=kms, sqs_managed_sse=enabled)


@install("aws.ecr.lifecycle_policy", "ecr_repository", "ECR repository has a lifecycle policy",
    {"LifecyclePolicy": {"lifecyclePolicyText": '{"rules":[]}'}},
    {"LifecyclePolicy": {"collection_status": "empty", "absent": True}}, control="SI-12")
def ecr_lifecycle(item, index):
    config = get(item, "LifecyclePolicy", dict)
    if config.get("collection_status") == "empty" and config.get("absent") is True:
        return result(True, lifecycle_policy="absent")
    value = get(config, "lifecyclePolicyText", str)
    return result(not bool(value), lifecycle_policy_present=bool(value))


@install("aws.kms.no_pending_key_deletion", "kms_key", "Active customer-managed KMS key is not scheduled for deletion",
    {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}},
    {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "PendingDeletion"}}}, control="SC-12",
    extra={"not_applicable": {"Metadata": {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Disabled"}}}})
def kms_deletion(item, index):
    manager = get(item, "Metadata.KeyMetadata.KeyManager", str)
    if manager not in {"AWS", "CUSTOMER"}:
        return unknown("unrecognized KMS key manager")
    if manager == "AWS":
        return "NOT_APPLICABLE", {"key_manager": manager}
    state = get(item, "Metadata.KeyMetadata.KeyState", str)
    if state not in {"Creating", "Enabled", "Disabled", "PendingDeletion", "PendingImport", "PendingReplicaDeletion", "Unavailable", "Updating"}:
        return unknown("unrecognized KMS key state")
    if state == "Disabled":
        return "NOT_APPLICABLE", {"key_state": state, "reason": "Reviewed upstream default excludes disabled/unused keys"}
    return result(state == "PendingDeletion", key_manager=manager, key_state=state)


def config_fixture(role):
    return {"name": "default", "AccountId": "123456789012", "roleARN": role,
        "Status": {"ConfigurationRecordersStatus": [{"name": "default", "recording": True}]}}


@install("aws.config.service_linked_role", "config_recorder", "Recording AWS Config recorder uses its account service-linked role",
    config_fixture("arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"),
    config_fixture("arn:aws:iam::123456789012:role/custom-config"), control="AC-6")
def config_role(item, index):
    name = get(item, "name", str)
    statuses = list_of_objects(get(item, "Status.ConfigurationRecordersStatus", list))
    matching = [row for row in statuses if get(row, "name", str) == name]
    if len(matching) != 1:
        return unknown("missing/duplicate recorder status")
    recording = get(matching[0], "recording", bool)
    if not recording:
        return "NOT_APPLICABLE", {"recording": False, "reason": "Upstream predicate only applies to recording recorders"}
    account, role = get(item, "AccountId", str), get(item, "roleARN", str)
    match = re.fullmatch(r"arn:(aws|aws-us-gov|aws-cn):iam::[0-9]{12}:role/.+", role)
    if not re.fullmatch(r"[0-9]{12}", account) or not match:
        return unknown("malformed account or Config role ARN")
    expected = f"arn:{match.group(1)}:iam::{account}:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"
    return result(role != expected, role_arn=role, expected_role_arn=expected)


@install("aws.eks.secrets_encryption", "eks_cluster", "EKS secret encryption is configured or enabled by Kubernetes version defaults",
    {"Cluster": {"cluster": {"version": "1.28"}}},
    {"Cluster": {"cluster": {"version": "1.27", "encryptionConfig": []}}}, control="SC-13")
def eks_secrets(item, index):
    version = get(item, "Cluster.cluster.version", str)
    if not re.fullmatch(r"[0-9]+\.[0-9]+", version):
        return unknown("malformed Kubernetes version")
    major, minor = map(int, version.split("."))
    if major > 1 or major == 1 and minor >= 28:
        return result(False, version=version, encryption="version-default envelope encryption", semantics="Reviewed AWS service behavior; no secret values read")
    configs = list_of_objects(get(item, "Cluster.cluster.encryptionConfig", list))
    protected = False
    for config in configs:
        resources = get(config, "resources", list)
        if any(not isinstance(resource, str) for resource in resources):
            return unknown("malformed encrypted resources")
        protected = protected or "secrets" in resources
    return result(not protected, version=version, secret_encryption_configured=protected)
