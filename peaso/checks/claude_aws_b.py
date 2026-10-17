"""claude_aws_b partition (AWS services fsx..workspaces): native ports, merges, manual and rejected rows.

Ported predicates live in the claude_aws_b_* service modules; this module loads them and
records the dispositions of rows that map to existing natives, need manual attestation, or
are rejected with documented evidence. reviewed_claude_aws_b*.json are generated from here.
"""
from __future__ import annotations

from . import claude_aws_b_storage, claude_aws_b_db, claude_aws_b_messaging, claude_aws_b_compute, claude_aws_b_security  # noqa: F401
from .claude_aws_b_common import ROWS

P, C, X = "prowler.aws.", "aws-compliance.control.", "aws-perimeter.control."

# Row -> (existing native check ids, review note). Same question, same threshold and semantics.
MERGED = {
    P + "rds_cluster_copy_tags_to_snapshots": (["aws.rds.cluster_copy_snapshot_tags"], "DB cluster CopyTagsToSnapshot true."),
    P + "rds_cluster_default_admin": (["aws.b.rds_cluster.nondefault_admin"], "Cluster MasterUsername is not the engine default admin name."),
    P + "rds_cluster_deletion_protection": (["aws.rds.cluster_deletion_protection"], "Cluster DeletionProtection true."),
    P + "rds_cluster_iam_authentication_enabled": (["aws.rds.cluster_iam_authentication"], "Cluster IAMDatabaseAuthenticationEnabled true."),
    P + "rds_cluster_multi_az": (["aws.rds.cluster_multi_az"], "Cluster MultiAZ true."),
    P + "rds_cluster_storage_encrypted": (["aws.rds.cluster_encryption"], "Cluster StorageEncrypted true."),
    C + "rds_db_instance_automatic_minor_version_upgrade_enabled": (["aws.rds.auto_minor_upgrade"], "DB instance AutoMinorVersionUpgrade true."),
    C + "rds_db_instance_cloudwatch_logs_enabled": (["aws.rds.cloudwatch_log_exports"], "DB instance EnabledCloudwatchLogsExports not empty."),
    C + "rds_db_instance_in_vpc": (["aws.rds.vpc_configuration"], "DB instance has a DB subnet group VPC."),
    X + "rds_db_instance_in_vpc": (["aws.rds.vpc_configuration"], "DB instance has a DB subnet group VPC."),
    X + "rds_db_instance_prohibit_public_access": (["aws.rds.no_public_endpoint"], "DB instance PubliclyAccessible false."),
    P + "mq_broker_auto_minor_version_upgrades": (["aws.b.mq.automatic_minor_upgrade"], "Broker AutoMinorVersionUpgrade true."),
    C + "sns_topic_encrypted_at_rest": (["aws.sns.kms_encryption"], "Topic KmsMasterKeyId set (documented omission = not encrypted)."),
    C + "sqs_queue_encrypted_at_rest": (["aws.sqs.encryption"], "Queue SSE-KMS or SSE-SQS enabled."),
    C + "lambda_function_dead_letter_queue_configured": (["aws.lambda.dead_letter_queue"], "Function DeadLetterConfig.TargetArn set."),
    C + "lambda_function_in_vpc": (["aws.lambda.vpc_configuration"], "Function VpcConfig.VpcId set."),
    X + "lambda_function_in_vpc": (["aws.lambda.vpc_configuration"], "Function VpcConfig.VpcId set."),
    C + "lambda_function_restrict_public_url": (["aws.lambda.function_url_authentication"], "Function URL AuthType is not NONE."),
    P + "secretsmanager_automatic_rotation_enabled": (["aws.secretsmanager.rotation"], "Secret RotationEnabled true."),
}

MANUAL = {
    P + "route53_dangling_ip_subdomain_takeover": {
        "question": "Do Route 53 A records in public hosted zones point only to IP addresses owned by this account (no dangling public IPs that allow subdomain takeover)?",
        "title": "Route 53 A records do not point to released public IP addresses",
        "guidance": "The prowler check joins every public hosted zone record with all account EIPs, all ENI public IPs and the published AWS ip-ranges across regions. The native per-scope snapshot does not hold the account-wide EIP/ENI join nor the ip-ranges feed, so review each A record IP against currently owned addresses.",
        "docs": ["https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListResourceRecordSets.html", "https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html"],
    },
    P + "secretsmanager_has_restrictive_resource_policy": {
        "question": "Does each Secrets Manager secret have a resource policy that explicitly denies access to every principal except the intended roles and services?",
        "title": "Secrets Manager secret resource policy is restrictive (explicit deny for non-approved principals)",
        "guidance": "Prowler evaluates a deep, organisation-specific policy shape (explicit Deny with aws:PrincipalArn/aws:PrincipalServiceName exceptions and condition operators). Review each secret policy against your approved principal list.",
        "docs": ["https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html"],
    },
    P + "rolesanywhere_profile_restricts_session_permissions": {
        "question": "Does every IAM Roles Anywhere profile restrict session permissions (session policy or managed policy ARNs) to the minimum required?",
        "title": "IAM Roles Anywhere profile restricts session permissions",
        "guidance": "Whether a profile's session policy is sufficiently restrictive depends on the roles and workloads it serves; review ManagedPolicyArns and SessionPolicy of each profile.",
        "docs": ["https://docs.aws.amazon.com/rolesanywhere/latest/APIReference/API_ProfileDetail.html"],
    },
}

_SECRET_SCAN = ("Upstream runs a secret-content scanner over the decoded payload (detect-secrets). PEASO is a read-only configuration CSPM that does not collect or scan secret material; "
                "collecting full definitions/arguments/user data to grep for credentials is intrusive and unsuitable for the snapshot.")
REJECTED = {
    P + "glue_catalog_connection_no_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/glue/latest/webapi/API_Connection.html"]},
    P + "glue_etl_jobs_no_secrets_in_arguments": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/glue/latest/webapi/API_Job.html"]},
    P + "sagemaker_notebook_instance_no_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeNotebookInstanceLifecycleConfig.html"]},
    P + "ssm_document_secrets": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetDocument.html"]},
    P + "stepfunctions_statemachine_no_secrets_in_definition": {"classification": "intrusive_unsuitable", "reason": _SECRET_SCAN, "replacement": [],
        "docs": ["https://docs.aws.amazon.com/step-functions/latest/apireference/API_DescribeStateMachine.html"]},
    C + "opensearch_domain_audit_logging_enabled": {"classification": "invalid_predicate",
        "reason": "Both CASE branches of the pinned query return 'ok', so the control can never alarm. AWS documents audit logs as LogPublishingOptions.AUDIT_LOGS (Enabled + CloudWatch log group); the corrected native predicate is aws.cb.opensearch.audit_logs_enabled.",
        "replacement": ["aws.cb.opensearch.audit_logs_enabled"],
        "docs": ["https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html"]},
    C + "opensearch_domain_https_required": {"classification": "invalid_predicate",
        "reason": "The pinned query compares DomainEndpointOptions.TLSSecurityPolicy with the literal 'tlsPolicies', which is not a valid value (Policy-Min-TLS-1-0-2019-07, Policy-Min-TLS-1-2-2019-07, Policy-Min-TLS-1-2-PFS-2023-10), so it alarms on every EnforceHTTPS domain. Corrected native predicate: aws.cb.opensearch.enforce_https.",
        "replacement": ["aws.cb.opensearch.enforce_https"],
        "docs": ["https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainEndpointOptions.html"]},
}


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
    for row, entry in MANUAL.items():
        out[row] = ("manual", entry)
    for row, entry in REJECTED.items():
        out[row] = ("rejected", entry)
    return out
