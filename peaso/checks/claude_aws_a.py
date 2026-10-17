"""claude_aws_a partition (AWS services ebs..vpc): native ports, merges, manual and rejected rows.

Ported predicates live in the claude_aws_a_* service modules; this module loads them and records the
dispositions of rows that map to existing natives, need manual attestation, or are rejected with
documented evidence. reviewed_claude_aws_a*.json are generated from these tables.

Some merge targets live in Codex aws_a_* modules that the runtime registry does not import yet
(aws_a_s3, aws_a_account, aws_a_iam_lifecycle, aws_a_iam_usage, aws_a_accessanalyzer, aws_a_kms,
aws_a_cloudtrail_variants). They are listed in ``MERGE_MODULES`` so tests can prove the targets exist;
this module deliberately does not import them (registry admission is the lead's decision).
"""
from __future__ import annotations

from . import claude_aws_a_ec2, claude_aws_a_network, claude_aws_a_iam, claude_aws_a_iam_prowler  # noqa: F401
from . import claude_aws_a_security, claude_aws_a_s3  # noqa: F401
from .claude_aws_a_common import ROWS, CHECK_IDS  # noqa: F401

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."

MERGE_MODULES = ("aws_a_s3", "aws_a_account", "aws_a_iam_lifecycle", "aws_a_iam_usage", "aws_a_accessanalyzer", "aws_a_kms",
                 "aws_a_cloudtrail_variants", "aws_a_regional", "aws", "aws_b_loadbalancing", "aws_a_cloudwatch")

# Row -> (existing native check ids, review note). Same question, same threshold and semantics.
MERGED = {
    C + "foundational_security_account_1": (["aws.a.account.security_contact_present"], "Account SECURITY alternate contact registered (same query as account_alternate_contact_security_registered)."),
    P + "organizations_account_part_of_organizations": (["aws.a.account.organization_member"], "Account belongs to an AWS Organizations organization."),
    P + "iam_policy_attached_only_to_group_or_roles": (["aws.a.iam.user_no_direct_policies"], "IAM user has no inline or directly attached managed policies."),
    C + "ec2_classic_lb_connection_draining_enabled": (["aws.b.classic_elb.connection_draining"], "Classic load balancer ConnectionDraining.Enabled true."),
    C + "foundational_security_elb_7": (["aws.b.classic_elb.connection_draining"], "Classic load balancer ConnectionDraining.Enabled true (same query)."),
    C + "log_group_encryption_at_rest_enabled": (["aws.a.cloudwatch.log_kms_encryption"], "Log group kmsKeyId set."),
    C + "s3_bucket_default_encryption_enabled": (["aws.a.s3.default_encryption_configuration"], "Bucket default encryption configuration present (absent = fail); same evaluator as the Codex-reviewed CIS aliases."),
    P + "s3_bucket_default_encryption": (["aws.a.s3.default_encryption_configuration"], "Prowler encryption is Rules[0] SSEAlgorithm; any returned configuration passes, ServerSideEncryptionConfigurationNotFoundError fails."),
    C + "s3_bucket_mfa_delete_enabled": (["aws.a.s3.mfa_delete_enabled"], "Versioning MFADelete Enabled."),
    P + "s3_bucket_no_mfa_delete": (["aws.a.s3.mfa_delete_enabled"], "Versioning MFADelete Enabled."),
    C + "s3_public_access_block_bucket_account": (["aws.a.s3.bucket_account_public_blocks"], "All four flags at bucket level OR all four at account level."),
    C + "s3_bucket_versioning_enabled": (["aws.s3.versioning"], "Versioning Status Enabled."),
    C + "s3_bucket_logging_enabled": (["aws.s3.access_logging"], "GetBucketLogging LoggingEnabled present."),
    C + "foundational_security_s3_9": (["aws.s3.access_logging"], "GetBucketLogging LoggingEnabled present (same query)."),
}

# Rows already reviewed in Codex aws_a_* shards; the same disposition is recorded here, copied from that shard.
EXISTING = {
    C + "foundational_security_cloudtrail_2": ("merged", ["aws.a.cloudtrail.home_kms_encryption"], "cloudtrail_trail_logs_encrypted_with_kms_cmk", "reviewed_aws_a_cloudtrail_variants.json"),
    C + "foundational_security_cloudtrail_5": ("merged", ["aws.a.cloudtrail.home_cloudwatch_date"], "cloudtrail_trail_integrated_with_logs", "reviewed_aws_a_cloudtrail_variants.json"),
    C + "foundational_security_iam_2": ("merged", ["aws.a.iam.user_no_direct_policies"], "iam_user_no_inline_attached_policies", "reviewed_aws_a_iam_lifecycle.json"),
    C + "foundational_security_iam_3": ("merged", ["aws.a.iam.active_key_age_90"], "iam_user_access_key_age_90", "reviewed_aws_a_iam_lifecycle.json"),
    C + "foundational_security_iam_6": ("merged", ["aws.a.iam.root_hardware_mfa"], "iam_root_user_hardware_mfa_enabled", "reviewed_aws_a_iam_lifecycle.json"),
    C + "foundational_security_iam_8": ("merged", ["aws.a.iam.unused_credentials_90_days"], "iam_user_unused_credentials_90", "reviewed_aws_a_iam_usage.json"),
    C + "iam_access_analyzer_enabled": ("merged", ["aws.a.accessanalyzer.region_present"], "iam_access_analyzer_enabled", "reviewed_aws_a_accessanalyzer.json"),
    C + "iam_root_user_hardware_mfa_enabled": ("merged", ["aws.a.iam.root_hardware_mfa"], "iam_root_user_hardware_mfa_enabled", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_server_certificate_not_expired": ("merged", ["aws.a.iam.server_certificate_expiry_date"], "iam_server_certificate_not_expired", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_user_access_key_age_90": ("merged", ["aws.a.iam.active_key_age_90"], "iam_user_access_key_age_90", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_user_access_keys_and_password_at_setup": ("merged", ["aws.a.iam.console_key_created_at_setup"], "iam_user_access_keys_and_password_at_setup", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_user_no_inline_attached_policies": ("merged", ["aws.a.iam.user_no_direct_policies"], "iam_user_no_inline_attached_policies", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_user_no_policies": ("merged", ["aws.a.iam.user_no_managed_policies"], "iam_user_no_policies", "reviewed_aws_a_iam_lifecycle.json"),
    C + "iam_user_unused_credentials_45": ("merged", ["aws.a.iam.unused_credentials_45_days"], "iam_user_unused_credentials_45", "reviewed_aws_a_iam_usage.json"),
    C + "iam_user_unused_credentials_90": ("merged", ["aws.a.iam.unused_credentials_90_days"], "iam_user_unused_credentials_90", "reviewed_aws_a_iam_usage.json"),
    C + "kms_cmk_rotation_enabled": ("merged", ["aws.a.kms.rotation_source_eligibility"], "kms_cmk_rotation_enabled", "reviewed_aws_a_kms.json"),
    P + "guardduty_is_enabled": ("merged", ["aws.a.guardduty.region_enabled"], None, "reviewed_aws_a_regional.json"),
    C + "iam_root_last_used": ("rejected", [], "iam_root_last_used", "reviewed_aws_a_iam_usage.json"),
    C + "iam_support_role": ("rejected", [], "iam_support_role", "reviewed_aws_a_source_counterexamples.json"),
    C + "organizational_tag_policies_enabled": ("rejected", [], "organizational_tag_policies_enabled", "reviewed_aws_a_source_counterexamples.json"),
}
for _q in ("bucket_policy", "cloudtrail_configuration", "config_configuration", "console_authentication_failure", "console_login_mfa",
           "disable_or_delete_cmk", "iam_policy", "network_acl", "network_gateway", "organization", "root_login", "route_table",
           "security_group", "unauthorized_api", "vpc"):
    EXISTING[C + "log_metric_filter_" + _q] = ("rejected", [], "log_metric_filter_" + _q, "reviewed_aws_a_metric_identity.json")

_SECRETS = ("Upstream runs a secret-content scanner (detect-secrets) over decoded user data. PEASO is a read-only configuration CSPM that "
            "does not collect or scan secret material, so the question is kept for operator review.")
_TRUSTED = ("The perimeter control compares against the operator-defined trusted_accounts / trusted_organizations / trusted_organization_units "
            "variables, which have no account-independent default; the trust list is an operator decision.")
_ENCLAVE = ("The Prowler check needs operator-supplied golden PCR values / deployment context and CloudTrail attestation events, which the "
            "configuration snapshot does not hold.")
MANUAL = {
    P + "s3_bucket_object_public": {
        "question": "Do spot-checked objects in each S3 bucket carry no public object ACL grants (AllUsers/AuthenticatedUsers)?",
        "title": "Spot-check S3 bucket objects for public ACLs",
        "guidance": "Prowler samples objects and reads each object's ACL. Per-object reads are outside the bucket-level snapshot; sample objects with GetObjectAcl or rely on BucketOwnerEnforced/IgnorePublicAcls.",
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAcl.html"]},
    P + "s3_bucket_shadow_resource_vulnerability": {
        "question": "Are none of the service-pattern S3 bucket names used by this account (CloudFormation, Glue, EMR, SageMaker, Athena, ...) pre-claimed by another account?",
        "title": "S3 bucket is not a known shadow resource owned by another account",
        "guidance": "Prowler probes predictable bucket names in every Region and checks ownership; probing third-party bucket names is outside the read-only snapshot of this account. Review service buckets and use ExpectedBucketOwner.",
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-owner-condition.html"]},
    C + "ec2_instance_user_data_no_secrets": {
        "question": "Is EC2 instance user data free of secrets (passwords, tokens, keys)?",
        "title": "EC2 instances user data should not have secrets", "guidance": _SECRETS,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html"]},
    P + "ec2_instance_secrets_user_data": {
        "question": "Does EC2 instance user data contain no secrets?",
        "title": "EC2 instance user data contains no secrets", "guidance": _SECRETS,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html"]},
    P + "ec2_launch_template_no_secrets": {
        "question": "Does every version of every EC2 launch template contain no secrets in user data?",
        "title": "EC2 launch template user data contains no secrets in any version", "guidance": _SECRETS,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeLaunchTemplateVersions.html"]},
    P + "ec2_elastic_ip_shodan": {
        "question": "Is no Elastic IP address of the account listed in Shodan?",
        "title": "EC2 Elastic IP address is not listed in Shodan",
        "guidance": "Requires a third-party Shodan API key and query; PEASO does not send account addresses to external services. Look the addresses up manually.",
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeAddresses.html"]},
    X + "ebs_snapshot_shared_with_trusted_accounts": {
        "question": "Are EBS snapshots shared (createVolumePermission) only with trusted AWS accounts?",
        "title": "EBS snapshots should only be shared with trusted accounts", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeSnapshotAttribute.html"]},
    X + "ec2_ami_shared_with_trusted_accounts": {
        "question": "Are EC2 AMIs shared (launchPermission UserId) only with trusted AWS accounts?",
        "title": "EC2 AMIs should only be shared with trusted accounts", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImageAttribute.html"]},
    X + "ec2_ami_shared_with_trusted_organization_units": {
        "question": "Are EC2 AMIs shared (launchPermission OrganizationalUnitArn) only with trusted organizational units?",
        "title": "EC2 AMIs should only be shared with trusted OUs", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImageAttribute.html"]},
    X + "ec2_ami_shared_with_trusted_organizations": {
        "question": "Are EC2 AMIs shared (launchPermission OrganizationArn) only with trusted organizations?",
        "title": "EC2 AMIs should only be shared with trusted organizations", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeImageAttribute.html"]},
    X + "guarduty_findings_shared_with_trusted_accounts": {
        "question": "Are GuardDuty findings shared only with a trusted administrator account?",
        "title": "GuardDuty findings should only be shared with trusted accounts", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/guardduty/latest/APIReference/API_GetAdministratorAccount.html"]},
    X + "vpc_peering_connection_cross_account_shared": {
        "question": "Are VPCs peered only with trusted AWS accounts?",
        "title": "VPCs should only be peered with trusted accounts", "guidance": _TRUSTED,
        "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcPeeringConnections.html"]},
    C + "ec2_instance_no_high_level_finding_in_inspector_scan": {
        "question": "Do EC2 instances have no High severity findings in Amazon Inspector scans?",
        "title": "EC2 instances high level findings should not be there in inspector scans",
        "guidance": "The pinned query reads aws_inspector_finding (Amazon Inspector Classic, ListFindings v1). The Inspector Classic API reference is no longer published and current Inspector (inspector2) findings use a different model, so review Inspector findings for each instance manually.",
        "docs": ["https://docs.aws.amazon.com/inspector/latest/user/what-is-inspector.html"]},
}
for _name, _q in (("bypassable_path", "Does no authorization path in the KMS enclave key policy let principals use the key without kms:RecipientAttestation?"),
                  ("no_deployment_binding", "Does the KMS enclave key attestation bind a specific deployment context (instance/account/role), not only image PCRs?"),
                  ("not_enforced", "Do sensitive actions on the KMS enclave key require kms:RecipientAttestation conditions?"),
                  ("pcr_mismatch", "Do the KMS enclave key policy attestation PCRs match the customer's golden values?"),
                  ("unknown_image", "Has no enclave with an unknown image identity called this KMS key?"),
                  ("debug", "Has no Nitro Enclave debug-mode attestation been observed against this KMS key?")):
    _row = P + ("kms_key_enclave_debug_attestation_detected" if _name == "debug" else "kms_key_enclave_attestation_" + _name)
    MANUAL[_row] = {"question": _q, "title": _row.split(".")[-1], "guidance": _ENCLAVE,
                    "docs": ["https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html", "https://docs.aws.amazon.com/kms/latest/developerguide/conditions-attestation.html"]}

_IAM_ACTION = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html"
_IAM_PRINCIPAL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html"
_CRED_REPORT = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html"
_SSL = ("Full ssl_ok CTE inspected: Action and Resource are expanded but neither is constrained; any Deny wildcard-principal statement with "
        "Bool aws:SecureTransport=false passes. A valid policy denying only s3:DeleteBucket over HTTP leaves GetObject on object ARNs "
        "reachable over HTTP yet passes. Same evaluator as the Codex rejection of cis_v130_2_1_2.")
_PUBLIC_WRITE = ("CASE branch 3 returns ok when bucket_policy_is_public and no Allow s3:Put*/Delete* policy statement exists, without re-checking the "
                 "ACL: a bucket with an AllUsers WRITE ACL grant (BlockPublicAcls off) and a public read-only policy is reported ok.")
_PERIM_ACL = ("The query alarms only on FULL_CONTROL/{op}_ACP grants to AllUsers/AuthenticatedUsers. AWS documents that {op} on a bucket "
              "{effect}, so a public {op} grant (the most common public ACL) passes.")
_EC2_ROLE = ("The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. "
             "A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the "
             "listed permission actions never appear and the control cannot alarm for a role that actually holds them.")
REJECTED = {
    C + "s3_bucket_enforces_ssl": {"classification": "invalid_predicate", "reason": _SSL, "replacement": [],
        "docs": [_IAM_ACTION, "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"]},
    C + "foundational_security_s3_5": {"classification": "invalid_predicate", "reason": _SSL, "replacement": [],
        "docs": [_IAM_ACTION, "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html"]},
    P + "s3_bucket_secure_transport_policy": {"classification": "invalid_predicate",
        "reason": "Prowler passes when any Deny statement with aws:SecureTransport=false has an Action containing 's3:PutObject' (or '*'/'s3:*'), "
                  "regardless of Resource and Principal: a Deny of s3:PutObject only over HTTP leaves GetObject reachable over HTTP yet passes; "
                  "a Deny on a non-object resource also passes. Action and Resource semantics make this a false PASS.",
        "replacement": [], "docs": [_IAM_ACTION, "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"]},
    C + "s3_bucket_restrict_public_write_access": {"classification": "invalid_predicate", "reason": _PUBLIC_WRITE, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"]},
    C + "foundational_security_s3_3": {"classification": "invalid_predicate", "reason": _PUBLIC_WRITE, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"]},
    X + "s3_bucket_acl_prohibit_public_read_access": {"classification": "invalid_predicate",
        "reason": _PERIM_ACL.format(op="READ", effect="allows the grantee to list the objects in the bucket"), "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"]},
    X + "s3_bucket_acl_prohibit_public_write_access": {"classification": "invalid_predicate",
        "reason": _PERIM_ACL.format(op="WRITE", effect="allows the grantee to create new objects in the bucket"), "replacement": [],
        "docs": ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html"]},
    C + "iam_user_access_key_unused_45": {"classification": "invalid_predicate",
        "reason": "CASE returns ok as soon as access_key_1 is inactive, before access_key_2 is evaluated: a user with key 1 inactive and an active key 2 "
                  "never used (or unused for a year) is ok. The credential report documents access_key_2_active/last_used_date as independent columns.",
        "replacement": [], "docs": [_CRED_REPORT]},
    P + "iam_avoid_root_usage": {"classification": "invalid_predicate",
        "reason": "Only the first non-default field is evaluated (password_last_used, else key 1, else key 2): a root password last used 200 days ago "
                  "with a root access key used yesterday passes. The credential report documents the three last-used columns independently.",
        "replacement": [], "docs": [_CRED_REPORT]},
    C + "iam_policy_custom_no_permissive_role_assumption": {"classification": "invalid_predicate",
        "reason": "policy_std lowercases actions, but the query compares with the literal 'sts:AssumeRole', which can never match: a customer policy "
                  "allowing sts:AssumeRole on Resource * passes. IAM documents action names as case insensitive.",
        "replacement": [], "docs": [_IAM_ACTION]},
    C + "iam_user_hardware_mfa_enabled": {"classification": "invalid_predicate",
        "reason": "The query right-joins ListVirtualMFADevices to users: a user with only a hardware MFA device has no virtual device row, so serial_number "
                  "is null and the user alarms; users with a virtual device (serial arn:...:mfa/...) are info. No user can reach ok. "
                  "ListVirtualMFADevices returns virtual MFA devices only.",
        "replacement": [], "docs": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListVirtualMFADevices.html"]},
    C + "iam_security_audit_role": {"classification": "invalid_predicate",
        "reason": "The WHERE policy_arn = SecurityAudit filter runs after the account LEFT JOIN and before GROUP BY: an account with no role holding "
                  "SecurityAudit produces no row, so the count=0 alarm branch can never be emitted (same defect class as the Codex iam_support_role rejection).",
        "replacement": [], "docs": ["https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html",
                                     "https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html"]},
    C + "iam_role_cross_account_write_access_policy": {"classification": "invalid_predicate",
        "reason": "The query looks for Principal.AWS ['*'] / Principal.Service ['*'] inside managed (identity-based) policies attached to the role. "
                  "IAM documents that the Principal element cannot be used in identity-based policies, so the containment test never matches and the control cannot alarm.",
        "replacement": [], "docs": [_IAM_PRINCIPAL]},
    X + "vpc_security_group_restrict_ingress_common_ports_all": {"classification": "invalid_predicate",
        "reason": "Each port test is from_port >= p and to_port <= p (and 9200-9300 as from_port >= 9200 and to_port <= 9300), which matches only rules "
                  "whose range lies inside the listed port: a TCP 0-65535 rule from 0.0.0.0/0, which opens all of them, passes. EC2 documents FromPort/ToPort as the start/end of the range.",
        "replacement": [], "docs": ["https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html"]},
}
for _suffix in ("passrole_and_lambda_invoke_function_access", "iam_role_attached_with_credentials_exposure_access",
                "iam_role_with_alter_critical_s3_permissions_configuration", "iam_role_with_cloud_log_tampering_access",
                "iam_role_with_data_destruction_access", "iam_role_with_database_management_write_access",
                "iam_role_with_defense_evasion_impact_of_aws_security_services_access", "iam_role_with_destruction_kms_access",
                "iam_role_with_destruction_rds_access", "iam_role_with_elastic_ip_hijacking_access", "iam_role_with_management_level_access",
                "iam_role_with_new_group_creation_with_attached_policy_access", "iam_role_with_new_role_creation_with_attached_policy_access",
                "iam_role_with_new_user_creation_with_attached_policy_access", "iam_role_with_org_write_access",
                "iam_role_with_privilege_escalation_risk_access", "iam_role_with_security_group_write_access",
                "iam_role_with_write_access_to_resource_based_policies", "iam_role_with_write_permission_on_critical_s3_configuration",
                "iam_with_write_level_access"):
    _row = C + "ec2_instance_no_" + (_suffix if _suffix.startswith("iam_") else "iam_" + _suffix)
    REJECTED[_row] = {"classification": "invalid_predicate", "reason": _EC2_ROLE, "replacement": [], "docs": [_IAM_PRINCIPAL]}


def ported():
    """Row -> list of native ids ported in this partition."""
    out = {}
    for cid, rows in ROWS.items():
        for row in rows:
            out.setdefault(row, []).append(cid)
    return out


def dispositions():
    """Row -> (disposition, natives or detail) for every row handled by this partition."""
    out = {row: ("ported", natives) for row, natives in ported().items()}
    for row, (natives, _note) in MERGED.items():
        out[row] = ("merged", natives)
    for row, (kind, natives, _query, _shard) in EXISTING.items():
        out[row] = (kind, natives if kind == "merged" else {"classification": "invalid_predicate", "shard": _shard})
    for row, entry in MANUAL.items():
        out[row] = ("manual", entry)
    for row, entry in REJECTED.items():
        out[row] = ("rejected", entry)
    return out
