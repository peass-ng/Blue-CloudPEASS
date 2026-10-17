"""claude2_aws_a partition: AWS-A rows (IAM, S3, VPC, CloudTrail, EC2, CloudWatch, EBS, KMS) taken over from stalled Codex workers.

Most rows are CIS/Steampipe aliases of questions that already have a registered native predicate (aws.a.*, aws.claude_a.*,
aws.c2b.* or core aws.*), so they are MERGED. Only questions without an equivalent registered native are ported here
(claude2_aws_a_cloudtrail, claude2_aws_a_misc). Rejections carry concrete counterexamples against official provider semantics.
Rows already held by another active shard (HELD_ELSEWHERE) are dropped from this shard.
"""
from __future__ import annotations

from . import claude2_aws_a_cloudtrail, claude2_aws_a_misc  # noqa: F401
from .claude2_aws_a_common import C, DOCS, IDS, NOTES, P, ROWS, X  # noqa: F401
from .claude2_aws_a_rows import HELD_ELSEWHERE, QUERY_ROWS

# aws-compliance query id -> (registered natives, review note). Every benchmark alias of the query maps the same way.
_QUERY_MERGES = {
    # claude_aws_a natives ported from the same pinned query.
    "ebs_volume_unused": (["aws.claude_a.ebs.volume_in_use"], "EBS volume is attached (state in-use)."),
    "ebs_snapshot_encryption_enabled": (["aws.claude_a.ebs.snapshot_encrypted"], "EBS snapshot is encrypted."),
    "ebs_snapshot_not_publicly_restorable": (["aws.claude_a.ebs.snapshot_not_public"], "EBS snapshot createVolumePermission has no group all."),
    "ebs_encryption_by_default_enabled": (["aws.claude_a.ec2.ebs_encryption_by_default"], "Region EBS encryption by default enabled."),
    "ec2_ami_restrict_public_access": (["aws.claude_a.ec2.ami_not_public"], "Owned AMI is not public."),
    "ec2_ami_ebs_encryption_enabled": (["aws.claude_a.ec2.ami_ebs_encrypted"], "Every AMI EBS block device mapping is encrypted."),
    "ec2_ami_not_older_than_90_days": (["aws.claude_a.ec2.ami_not_older_than_90_days"], "AMI creation date within 90 days."),
    "ec2_instance_detailed_monitoring_enabled": (["aws.claude_a.ec2.instance_detailed_monitoring"], "Instance monitoring state enabled."),
    "ec2_instance_using_iam_instance_role": (["aws.claude_a.ec2.instance_profile_attached"], "Instance has an IAM instance profile."),
    "ec2_instance_uses_imdsv2": (["aws.claude_a.ec2.instance_imdsv2_applied"], "Instance metadata HttpTokens required."),
    "ec2_instance_not_older_than_180_days": (["aws.claude_a.ec2.instance_not_older_than_180_days"], "Instance launch time within 180 days."),
    "ec2_stopped_instance_90_days": (["aws.claude_a.ec2.stopped_instance_90_days"], "Instance not stopped for more than 90 days."),
    "ec2_instance_attached_ebs_volume_delete_on_termination_enabled": (["aws.claude_a.ec2.instance_ebs_delete_on_termination"],
                                                                       "Every attached EBS volume has DeleteOnTermination true."),
    "ec2_instance_ssm_managed": (["aws.claude_a.ec2.instance_ssm_managed"], "Instance is an SSM managed instance."),
    "ec2_network_interface_unused": (["aws.claude_a.ec2.eni_in_use"], "Network interface is attached (status in-use)."),
    "iam_policy_all_attached_no_star_star": (["aws.claude_a.iam.attached_policy_no_star_star"], "Attached customer policy grants no Allow *:* statement."),
    "iam_user_group_role_cloudshell_fullaccess_restricted": (["aws.claude_a.iam.group_no_cloudshell_full_access", "aws.claude_a.iam.role_no_cloudshell_full_access",
                                                              "aws.claude_a.iam.user_no_cloudshell_full_access"], "AWSCloudShellFullAccess not attached to users, groups or roles."),
    "iam_user_one_active_key": (["aws.claude_a.iam.user_one_active_key"], "IAM user has at most one active access key (exact per-user key count)."),
    "iam_root_user_account_console_access_mfa_enabled": (["aws.claude_a.iam.root_console_has_mfa"], "Root account MFA enabled (account summary)."),
    "vpc_default_security_group_restricts_all_traffic": (["aws.claude_a.vpc.default_sg_no_rules"], "Default security group has no ingress or egress rules."),
    "vpc_security_group_restrict_ingress_ssh_all": (["aws.claude_a.vpc.sg_world_v4_ssh"], "No 0.0.0.0/0 ingress to port 22."),
    "vpc_security_group_restrict_ingress_rdp_all": (["aws.claude_a.vpc.sg_world_v4_rdp"], "No 0.0.0.0/0 ingress to port 3389."),
    "vpc_security_group_restrict_ingress_cifs_port_all": (["aws.claude_a.vpc.sg_world_any_cifs"], "No world (IPv4 or IPv6) ingress to port 445."),
    "vpc_security_group_remote_administration": (["aws.claude_a.vpc.sg_world_any_remote_admin"], "No world ingress to ports 22/3389."),
    "vpc_security_group_remote_administration_ipv4": (["aws.claude_a.vpc.sg_world_any_remote_admin"], "No world ingress to ports 22/3389 (same pinned SQL as the base query)."),
    "vpc_security_group_remote_administration_ipv6": (["aws.claude_a.vpc.sg_world_v6_remote_admin"], "No ::/0 ingress to ports 22/3389."),
    "vpc_network_acl_remote_administration": (["aws.claude_a.vpc.nacl_no_world_remote_admin"], "Network ACL allows no world ingress to ports 22/3389."),
    "vpc_flow_logs_enabled": (["aws.claude_a.vpc.flow_logs_active"], "VPC has an active flow log."),
    "cloudtrail_multi_region_trail_enabled": (["aws.claude_a.cloudtrail.account_has_logging_multi_region_trail"], "Account has a logging multi-Region trail."),
    # Codex aws.a.* natives written for the same pinned queries (registered).
    "account_alternate_contact_security_registered": (["aws.a.account.security_contact_present"], "SECURITY alternate contact registered."),
    "account_part_of_organizations": (["aws.a.account.organization_member"], "Account belongs to an AWS Organizations organization."),
    "cloudtrail_bucket_not_public": (["aws.a.cloudtrail.joined_bucket_declared_public_grants"], "Trail bucket has no AllUsers/AuthenticatedUsers ACL grant or public policy statement."),
    "cloudtrail_multi_region_trail_integrated_with_logs": (["aws.a.cloudtrail.home_multiregion_cloudwatch_date"],
                                                           "Home-region multi-Region trail delivered to CloudWatch Logs after the previous day."),
    "cloudtrail_s3_logging_enabled": (["aws.a.cloudtrail.home_bucket_access_logging"], "Home-region trail's in-account bucket has server access logging."),
    "cloudtrail_trail_insight_selectors_and_logging_enabled": (["aws.a.cloudtrail.home_logging_with_insights"], "Home-region trail is logging and has Insights selectors."),
    "cloudtrail_trail_integrated_with_logs": (["aws.a.cloudtrail.home_cloudwatch_date"], "Home-region trail delivered to CloudWatch Logs after the previous day."),
    "cloudtrail_trail_logs_encrypted_with_kms_cmk": (["aws.a.cloudtrail.home_kms_encryption"], "Home-region trail declares a KMS key."),
    "iam_access_analyzer_enabled": (["aws.a.accessanalyzer.region_present"], "Region has an Access Analyzer analyzer (any status)."),
    "iam_root_user_hardware_mfa_enabled": (["aws.a.iam.root_hardware_mfa"], "Root MFA enabled and no root virtual MFA device."),
    "iam_user_access_key_age_90": (["aws.a.iam.active_key_age_90"], "Active access key created within 90 days."),
    "iam_user_access_keys_and_password_at_setup": (["aws.a.iam.console_key_created_at_setup"], "Console user key not created at user setup."),
    "iam_user_no_inline_attached_policies": (["aws.a.iam.user_no_direct_policies"], "IAM user has no inline or directly attached managed policies."),
    "iam_user_no_policies": (["aws.a.iam.user_no_managed_policies"], "IAM user has no directly attached managed policies."),
    "iam_user_unused_credentials_45": (["aws.a.iam.unused_credentials_45_days"], "Password and active keys used within 45 days."),
    "iam_user_unused_credentials_90": (["aws.a.iam.unused_credentials_90_days"], "Password and active keys used within 90 days."),
    "kms_cmk_rotation_enabled": (["aws.a.kms.rotation_source_eligibility"], "Enabled symmetric AWS_KMS customer key has rotation enabled."),
    "s3_bucket_mfa_delete_enabled": (["aws.a.s3.mfa_delete_enabled"], "Bucket versioning MFA Delete enabled."),
    "s3_public_access_block_bucket_account": (["aws.a.s3.bucket_account_public_blocks"], "All four public access block settings at bucket or account level."),
    "s3_bucket_default_encryption_enabled": (["aws.a.s3.default_encryption_configuration"], "Bucket default encryption configuration present."),
    # Other registered natives.
    "autoscaling_group_propagate_tags_to_ec2_instance_enabled": (["aws.c2b.autoscaling.tags_propagate"], "Any tag with PropagateAtLaunch false alarms; no tags is ok."),
    "cloudtrail_trail_enabled": (["aws.cloudtrail.logging"], "Trail IsLogging true."),
}

MERGED = {row: (list(natives), note) for query, (natives, note) in _QUERY_MERGES.items() for row in QUERY_ROWS[query]}
MERGED[P + "accessanalyzer_enabled"] = (["aws.a.accessanalyzer.region_active"], "Per region: an analyzer exists and every analyzer is ACTIVE.")

MANUAL = {}

_SSL_DOCS = ["https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html",
             "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html",
             "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"]
_SELECTOR_DOCS = ["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html",
                  "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
                  "https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html"]
_METRIC_DOCS = ["https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_concepts.html#Dimension",
                "https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_MetricTransformation.html"]
_S3_DATA = ("Pinned selector CTE has no IsLogging test, and its bucket match uses LIKE bucket_arn || '%', so a selector for bucket 'audit-other' "
            "satisfies bucket 'audit'. A stopped trail with retained selectors also passes while recording nothing. DataResource values are exact bucket "
            "ARN prefixes ending in '/', and GetTrailStatus IsLogging governs delivery: concrete false PASS.")

_QUERY_REJECTS = {
    "s3_bucket_enforces_ssl": ("invalid_predicate", "Pinned ssl_ok CTE requires a Deny statement with wildcard principal and Bool aws:SecureTransport false "
        "(or NumericLessThan s3:TlsVersion 1.2) but never constrains Action or Resource. A policy that denies only s3:DeleteBucket on the bucket ARN over "
        "HTTP leaves s3:GetObject on object ARNs reachable over HTTP yet passes: concrete false PASS. Same rejection as the claude_aws_a and Codex reviews of this evaluator.",
        [], _SSL_DOCS),
    "cloudtrail_multi_region_read_write_enabled": ("invalid_predicate", "Basic branch accepts ReadWriteType All with IncludeManagementEvents false (data events only); "
        "advanced branch accepts any selector whose serialized JSON lacks readOnly, even eventCategory Data limited to one eventName. Both are valid "
        "configurations without all-region read/write management coverage: concrete false PASS.", ["aws.cloudtrail.management_events"], _SELECTOR_DOCS),
    "cloudtrail_s3_object_read_events_audit_enabled": ("invalid_predicate", _S3_DATA, [], _SELECTOR_DOCS),
    "cloudtrail_s3_object_write_events_audit_enabled": ("invalid_predicate", _S3_DATA, [], _SELECTOR_DOCS),
    "cloudtrail_s3_data_events_enabled": ("invalid_predicate", _S3_DATA, [], _SELECTOR_DOCS),
    "cloudtrail_security_trail_enabled": ("invalid_predicate", "For a trail using only advanced event selectors, event_selectors is NULL so both "
        "NOT(jsonb_array_length(NULL)=1 AND ...) and NOT(NULL @> IncludeManagementEvents true) evaluate to SQL NULL and never alarm; an advanced Data-only "
        "selector trail with logging, global events, multi-region, validation and KMS reaches 'ok' without management event coverage: concrete false PASS.",
        ["aws.cloudtrail.management_events"], _SELECTOR_DOCS),
    "cloudwatch_log_group_retention_period_365": ("invalid_predicate", "retention_in_days IS NULL alarms, but a null retentionInDays means the log group "
        "never expires events (DescribeLogGroups), which satisfies a keep-at-least-365-days requirement: concrete false FAIL on the most retentive setting.",
        ["aws.a.cloudwatch.log_retention_at_least_365"], ["https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_LogGroup.html"]),
    "s3_bucket_protected_by_macie": ("invalid_predicate", "Source expands only s3JobDefinition.bucketDefinitions. Macie jobs use either bucketCriteria or "
        "bucketDefinitions, never both: a RUNNING criteria job including S3_BUCKET_NAME EQ the bucket protects it yet alarms (false FAIL), and a "
        "CANCELLED job retaining the bucket definition passes with no analysis (false PASS).", ["aws.cb.macie.automated_discovery", "aws.cb.macie.enabled_where_buckets"],
        ["https://docs.aws.amazon.com/macie/latest/APIReference/jobs-jobid.html", "https://docs.aws.amazon.com/macie/latest/user/discovery-jobs-manage.html"]),
    "iam_root_last_used": ("invalid_predicate", "The CASE alarms when password_last_used >= now-90d but when access_key_N_last_used_date <= now-90d: the key "
        "comparators are inverted. A root key used yesterday (other dates null) is 'ok' and a key last used 120 days ago alarms. Credential-report fields "
        "are latest-use timestamps: concrete false PASS and false FAIL.", [],
        ["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html"]),
    "organizational_tag_policies_enabled": ("invalid_predicate", "The CTE filters type TAG_POLICY and groups by account before CASE count > 0, so every emitted "
        "row has count > 0; an account with no tag policies emits no row and the alarm branch is unreachable.", [],
        ["https://docs.aws.amazon.com/organizations/latest/APIReference/API_ListPolicies.html"]),
    "ec2_instance_user_data_no_secrets": ("intrusive_unsuitable", "Evaluating requires reading and pattern-matching instance user data (DescribeInstanceAttribute "
        "userData), i.e. collecting potential secrets into the snapshot; the regex alone also matches any mixed-case alphanumeric script line. PEASO does not "
        "collect secret-bearing content.", [], ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstanceAttribute.html"]),
}

_METRIC_ROWS = ["cloudwatch_changes_to_network_acls_alarm_configured", "cloudwatch_changes_to_network_gateways_alarm_configured",
                "cloudwatch_changes_to_network_route_tables_alarm_configured", "cloudwatch_changes_to_vpcs_alarm_configured",
                "cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled",
                "cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled", "cloudwatch_log_metric_filter_authentication_failures",
                "cloudwatch_log_metric_filter_aws_organizations_changes", "cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk",
                "cloudwatch_log_metric_filter_for_s3_bucket_policy_changes", "cloudwatch_log_metric_filter_policy_changes", "cloudwatch_log_metric_filter_root_usage",
                "cloudwatch_log_metric_filter_security_group_changes", "cloudwatch_log_metric_filter_sign_in_without_mfa",
                "cloudwatch_log_metric_filter_unauthorized_api_calls"]

REJECTED = {row: {"classification": cls, "reason": reason, "replacement": list(repl), "docs": list(docs)}
            for query, (cls, reason, repl, docs) in _QUERY_REJECTS.items() for row in QUERY_ROWS[query]}
for _name in _METRIC_ROWS:
    REJECTED[P + _name] = {"classification": "invalid_predicate", "replacement": [], "docs": list(_METRIC_DOCS), "reason":
        "Pinned shared metric-filter/alarm helper matches filter pattern, metric name, namespace and region but the service drops metric transformation and "
        "alarm dimensions. A matching filter emitting a dimensionless custom metric with an alarm on the same name but dimension Environment=Other passes, "
        "although that alarm watches a different metric (dimensions are part of metric identity): concrete false PASS."}
REJECTED[P + "account_maintain_different_contact_details_to_security_billing_and_operations"] = {
    "classification": "invalid_predicate", "replacement": ["aws.a.account.security_contact_present"],
    "docs": ["https://docs.aws.amazon.com/accounts/latest/reference/API_GetAlternateContact.html"],
    "reason": "Pinned check compares set cardinalities (4 names/phones, 3 emails) across primary, billing, security and operations contacts, but the "
              "service represents a missing alternate contact with None values. Distinct primary/billing/security plus an absent operations contact gives sets "
              "of size 4/4/3 because None counts as a distinct value, so a missing contact passes: concrete false PASS."}
REJECTED[P + "cloudtrail_logs_s3_bucket_is_not_publicly_accessible"] = {
    "classification": "invalid_predicate", "replacement": ["aws.a.cloudtrail.joined_bucket_declared_public_grants"],
    "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html", "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-overview.html"],
    "reason": "For an in-account bucket the pinned check only tests ACL grants to the AllUsers URI; it ignores bucket policies and AuthenticatedUsers grants. "
              "An owner-only ACL with a wildcard-principal s3:GetObject policy (PolicyStatus IsPublic true, no Block Public Access) passes: concrete false PASS "
              "for the claimed 'log bucket not publicly accessible' condition."}
REJECTED[P + "cloudtrail_bedrock_logging_enabled"] = {
    "classification": "invalid_predicate", "replacement": [],
    "docs": ["https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_AdvancedFieldSelector.html",
             "https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html"],
    "reason": "The pinned advanced-selector branch accepts eventCategory Data plus a recognised Bedrock resources.type and ignores the other field selectors, "
              "which AND together. A selector Data + AWS::Bedrock::Model + eventName Equals PutObject records no Bedrock model events yet passes: concrete false PASS."}


# Duplicate ownership: rows another active shard already holds are dropped (the tables above keep the full review for audit).
MERGED = {row: value for row, value in MERGED.items() if row not in HELD_ELSEWHERE}
REJECTED = {row: value for row, value in REJECTED.items() if row not in HELD_ELSEWHERE}


def ported():
    """Row -> list of native ids ported in this partition."""
    out = {}
    for cid, rows in ROWS.items():
        for row in rows:
            if row not in HELD_ELSEWHERE:
                out.setdefault(row, []).append(cid)
    return out


def dispositions():
    """Row -> (disposition, natives or detail) for every row handled by this partition."""
    out = {row: ("ported", natives) for row, natives in ported().items()}
    for row, (natives, _note) in MERGED.items():
        out[row] = ("merged", natives)
    for row, entry in MANUAL.items():
        out[row] = ("manual", entry)
    for row, entry in REJECTED.items():
        out[row] = ("rejected", entry)
    return out
