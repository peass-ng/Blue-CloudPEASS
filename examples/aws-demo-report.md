# Peaso security snapshot report

Provider: **aws**  
Scopes: 111111111111/us-east-1  
Snapshot: sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f  
Collected: 2026-10-10T00:00:00+00:00

## Summary

```json
{
  "by_severity": {
    "high": 3
  },
  "by_status": {
    "FAIL": 3,
    "MANUAL": 2,
    "PASS": 6,
    "UNKNOWN": 66
  },
  "categories": [
    "hardening",
    "exposure",
    "least_privilege",
    "iam_graph",
    "network"
  ],
  "check_count": 72,
  "coverage_complete": false,
  "finding_count": 77,
  "inventory_complete": false,
  "limitations": [
    "Framework mappings retain reviewed source provenance; they are not compliance certification.",
    "Declared IAM relationships are not effective access.",
    "Network inventory relationships are not proven reachability.",
    "Upstream hardening catalogs have not all been ported; only selected native checks ran."
  ],
  "resource_count": 10
}
```

## Coverage

| Level | Check / inventory | Scope | Status | Reason |
| --- | --- | --- | --- | --- |
| collection | iam_policy | 111111111111/us-east-1 | collected |  |
| collection | iam_role | 111111111111/us-east-1 | collected |  |
| collection | vpc | 111111111111/us-east-1 | collected |  |
| collection | subnet | 111111111111/us-east-1 | collected |  |
| collection | security_group | 111111111111/us-east-1 | collected |  |
| collection | instance | 111111111111/us-east-1 | collected |  |
| collection | route_table | 111111111111/us-east-1 | empty |  |
| collection | bucket | 111111111111/us-east-1 | collected |  |
| collection | activity | 111111111111/us-east-1 | denied | demo_permission_denied |
| check | aws.iam.no_full_admin | 111111111111/us-east-1 | evaluated |  |
| check | aws.iam.restrict_public_trust | 111111111111/us-east-1 | evaluated |  |
| check | aws.iam.console_mfa | 111111111111/us-east-1 | unknown |  |
| check | aws.s3.public_access_block | 111111111111/us-east-1 | evaluated |  |
| check | aws.s3.default_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.ec2.restrict_internet_ingress | 111111111111/us-east-1 | evaluated |  |
| check | aws.ec2.imdsv2 | 111111111111/us-east-1 | evaluated |  |
| check | aws.ebs.encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cluster_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.deletion_protection | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cluster_deletion_protection | 111111111111/us-east-1 | unknown |  |
| check | aws.cloudtrail.multi_region | 111111111111/us-east-1 | unknown |  |
| check | aws.cloudtrail.log_validation | 111111111111/us-east-1 | unknown |  |
| check | aws.cloudtrail.logging | 111111111111/us-east-1 | unknown |  |
| check | aws.eks.private_endpoint | 111111111111/us-east-1 | unknown |  |
| check | aws.ecr.immutable_tags | 111111111111/us-east-1 | unknown |  |
| check | aws.ecr.scan_on_push | 111111111111/us-east-1 | unknown |  |
| check | aws.secretsmanager.rotation | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.no_root_keys | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.no_public_endpoint | 111111111111/us-east-1 | unknown |  |
| check | aws.s3.versioning | 111111111111/us-east-1 | unknown |  |
| check | aws.s3.access_logging | 111111111111/us-east-1 | unknown |  |
| check | aws.s3.no_public_acl | 111111111111/us-east-1 | unknown |  |
| check | aws.kms.rotation | 111111111111/us-east-1 | unknown |  |
| check | aws.cloudtrail.management_events | 111111111111/us-east-1 | unknown |  |
| check | aws.eks.control_plane_logging | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.access_key_count | 111111111111/us-east-1 | unknown |  |
| check | aws.logs.retention | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.backups | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.root_mfa | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_uppercase | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_lowercase | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_numbers | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_symbols | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.auto_minor_upgrade | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cluster_iam_authentication | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cluster_multi_az | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cluster_copy_snapshot_tags | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.snapshot_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_minimum_length | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_reuse_prevention | 111111111111/us-east-1 | unknown |  |
| check | aws.iam.password_max_age | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.vpc_configuration | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.enhanced_monitoring | 111111111111/us-east-1 | unknown |  |
| check | aws.lambda.vpc_configuration | 111111111111/us-east-1 | unknown |  |
| check | aws.cloudtrail.kms_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.sns.kms_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.copy_snapshot_tags | 111111111111/us-east-1 | unknown |  |
| check | aws.rds.cloudwatch_log_exports | 111111111111/us-east-1 | unknown |  |
| check | aws.lambda.dead_letter_queue | 111111111111/us-east-1 | unknown |  |
| check | aws.lambda.function_url_authentication | 111111111111/us-east-1 | unknown |  |
| check | aws.elbv2.deletion_protection | 111111111111/us-east-1 | unknown |  |
| check | aws.elbv2.access_logging | 111111111111/us-east-1 | unknown |  |
| check | aws.elbv2.drop_invalid_headers | 111111111111/us-east-1 | unknown |  |
| check | aws.elbv2.desync_mitigation | 111111111111/us-east-1 | unknown |  |
| check | aws.elbv2.multiple_availability_zones | 111111111111/us-east-1 | unknown |  |
| check | aws.sqs.encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.ecr.lifecycle_policy | 111111111111/us-east-1 | unknown |  |
| check | aws.kms.no_pending_key_deletion | 111111111111/us-east-1 | unknown |  |
| check | aws.config.service_linked_role | 111111111111/us-east-1 | unknown |  |
| check | aws.eks.secrets_encryption | 111111111111/us-east-1 | unknown |  |
| check | aws.guardduty.eks_audit_logs | 111111111111/us-east-1 | unknown |  |
| check | aws.guardduty.lambda_network_logs | 111111111111/us-east-1 | unknown |  |
| check | aws.guardduty.rds_login_events | 111111111111/us-east-1 | unknown |  |
| check | aws.guardduty.s3_data_events | 111111111111/us-east-1 | unknown |  |
| check | aws.guardduty.runtime_monitoring | 111111111111/us-east-1 | unknown |  |
| check | analysis.grant_review | selected_scopes | manual | Defensive review signals; no finding is not an effective-access pass. |
| check | analysis.inactive_identity | selected_scopes | evaluated | Defensive review signals; no finding is not an effective-access pass. |
| check | analysis.principal_exposure | selected_scopes | evaluated | Defensive review signals; no finding is not an effective-access pass. |
| check | analysis.network_review | selected_scopes | manual | Defensive review signals; no finding is not an effective-access pass. |
| check | analysis.coverage | selected_scopes | unknown | Defensive review signals; no finding is not an effective-access pass. |

Detailed coverage:

```json
[
  {
    "level": "collection",
    "reason": "",
    "resource_count": 2,
    "scope": "111111111111/us-east-1",
    "service": "iam_policy",
    "status": "collected",
    "type": "iam_policy"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 1,
    "scope": "111111111111/us-east-1",
    "service": "iam_role",
    "status": "collected",
    "type": "iam_role"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 1,
    "scope": "111111111111/us-east-1",
    "service": "vpc",
    "status": "collected",
    "type": "vpc"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 1,
    "scope": "111111111111/us-east-1",
    "service": "subnet",
    "status": "collected",
    "type": "subnet"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 2,
    "scope": "111111111111/us-east-1",
    "service": "security_group",
    "status": "collected",
    "type": "security_group"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 1,
    "scope": "111111111111/us-east-1",
    "service": "instance",
    "status": "collected",
    "type": "instance"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 0,
    "scope": "111111111111/us-east-1",
    "service": "route_table",
    "status": "empty",
    "type": "route_table"
  },
  {
    "level": "collection",
    "reason": "",
    "resource_count": 2,
    "scope": "111111111111/us-east-1",
    "service": "bucket",
    "status": "collected",
    "type": "bucket"
  },
  {
    "level": "collection",
    "reason": "demo_permission_denied",
    "resource_count": 0,
    "scope": "111111111111/us-east-1",
    "service": "audit",
    "status": "denied",
    "type": "activity"
  },
  {
    "by_status": {
      "FAIL": 1,
      "PASS": 1
    },
    "check_id": "aws.iam.no_full_admin",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "evaluated",
    "type": "iam_policy"
  },
  {
    "by_status": {
      "PASS": 1
    },
    "check_id": "aws.iam.restrict_public_trust",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "evaluated",
    "type": "iam_role"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.console_mfa",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_user"
  },
  {
    "by_status": {
      "FAIL": 1,
      "PASS": 1
    },
    "check_id": "aws.s3.public_access_block",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "evaluated",
    "type": "bucket"
  },
  {
    "by_status": {
      "PASS": 1,
      "UNKNOWN": 1
    },
    "check_id": "aws.s3.default_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "bucket"
  },
  {
    "by_status": {
      "FAIL": 1,
      "PASS": 1
    },
    "check_id": "aws.ec2.restrict_internet_ingress",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "evaluated",
    "type": "security_group"
  },
  {
    "by_status": {
      "PASS": 1
    },
    "check_id": "aws.ec2.imdsv2",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "evaluated",
    "type": "instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.ebs.encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "ebs_volume"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cluster_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.deletion_protection",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cluster_deletion_protection",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.cloudtrail.multi_region",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "cloudtrail"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.cloudtrail.log_validation",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "cloudtrail"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.cloudtrail.logging",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "cloudtrail"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.eks.private_endpoint",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "eks_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.ecr.immutable_tags",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "ecr_repository"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.ecr.scan_on_push",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "ecr_repository"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.secretsmanager.rotation",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "secret"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.no_root_keys",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_account_summary"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.no_public_endpoint",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 2
    },
    "check_id": "aws.s3.versioning",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "bucket"
  },
  {
    "by_status": {
      "UNKNOWN": 2
    },
    "check_id": "aws.s3.access_logging",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "bucket"
  },
  {
    "by_status": {
      "UNKNOWN": 2
    },
    "check_id": "aws.s3.no_public_acl",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "bucket"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.kms.rotation",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "kms_key"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.cloudtrail.management_events",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "cloudtrail"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.eks.control_plane_logging",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "eks_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.access_key_count",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_user"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.logs.retention",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "log_group"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.backups",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.root_mfa",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_credential_report"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_uppercase",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_lowercase",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_numbers",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_symbols",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.auto_minor_upgrade",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cluster_iam_authentication",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cluster_multi_az",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cluster_copy_snapshot_tags",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.snapshot_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_snapshot"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_minimum_length",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_reuse_prevention",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.iam.password_max_age",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "iam_password_policy"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.vpc_configuration",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.enhanced_monitoring",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.lambda.vpc_configuration",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "lambda_function"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.cloudtrail.kms_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "cloudtrail"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.sns.kms_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "sns_topic"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.copy_snapshot_tags",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.rds.cloudwatch_log_exports",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "rds_instance"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.lambda.dead_letter_queue",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "lambda_function"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.lambda.function_url_authentication",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "lambda_function"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.elbv2.deletion_protection",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "load_balancer"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.elbv2.access_logging",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "load_balancer"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.elbv2.drop_invalid_headers",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "load_balancer"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.elbv2.desync_mitigation",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "load_balancer"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.elbv2.multiple_availability_zones",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "load_balancer"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.sqs.encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "sqs_queue"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.ecr.lifecycle_policy",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "ecr_repository"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.kms.no_pending_key_deletion",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "kms_key"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.config.service_linked_role",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "config_recorder"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.eks.secrets_encryption",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "eks_cluster"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.guardduty.eks_audit_logs",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "guardduty_detector"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.guardduty.lambda_network_logs",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "guardduty_detector"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.guardduty.rds_login_events",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "guardduty_detector"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.guardduty.s3_data_events",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "guardduty_detector"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "aws.guardduty.runtime_monitoring",
    "level": "check",
    "reason": "",
    "scope": "111111111111/us-east-1",
    "status": "unknown",
    "type": "guardduty_detector"
  },
  {
    "by_status": {
      "MANUAL": 1
    },
    "check_id": "analysis.grant_review",
    "level": "check",
    "reason": "Defensive review signals; no finding is not an effective-access pass.",
    "scope": "selected_scopes",
    "status": "manual",
    "type": "projection"
  },
  {
    "by_status": {},
    "check_id": "analysis.inactive_identity",
    "level": "check",
    "reason": "Defensive review signals; no finding is not an effective-access pass.",
    "scope": "selected_scopes",
    "status": "evaluated",
    "type": "projection"
  },
  {
    "by_status": {},
    "check_id": "analysis.principal_exposure",
    "level": "check",
    "reason": "Defensive review signals; no finding is not an effective-access pass.",
    "scope": "selected_scopes",
    "status": "evaluated",
    "type": "projection"
  },
  {
    "by_status": {
      "MANUAL": 1
    },
    "check_id": "analysis.network_review",
    "level": "check",
    "reason": "Defensive review signals; no finding is not an effective-access pass.",
    "scope": "selected_scopes",
    "status": "manual",
    "type": "projection"
  },
  {
    "by_status": {
      "UNKNOWN": 1
    },
    "check_id": "analysis.coverage",
    "level": "check",
    "reason": "Defensive review signals; no finding is not an effective-access pass.",
    "scope": "selected_scopes",
    "status": "unknown",
    "type": "projection"
  }
]
```

## Snapshot provenance and collection plan

```json
{
  "not_live_cloud_evidence": true,
  "source": "offline_demo"
}
```


Empty and denied inventory are recorded separately from security passes. Unknown and manual results require further evidence.

## Findings

### MANUAL: Review unrestricted network rule candidates

- Check: analysis.network_review
- Category: exposure
- Severity: high
- Resource: sha256:aae0a7d8e2a2aadb6d795ab13e53d444afd03c085455fce38736f073bdb7bcc0
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "layer": "modeled_rule",
  "reachability": "unknown",
  "risk_state": "conditional",
  "rules": [
    {
      "native_rule": {
        "FromPort": 443,
        "IpProtocol": "tcp",
        "IpRanges": [
          {
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "ToPort": 443
      },
      "semantics": "AWS security-group inbound allow; routing, NACLs, attachment, and public addressing remain unresolved",
      "source": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "IpPermissions[0]",
        "request_evidence": {},
        "resource_id": "sg-public",
        "resource_type": "security_group",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      }
    }
  ],
  "telemetry": "not_collected"
}
```

Remediation: Have the resource owner validate business need, conditions, inheritance, and usage coverage; narrow grants or exposure only after review and a tested rollback plan.

### UNKNOWN: Existing Lambda function URL requires AWS IAM authentication

- Check: aws.lambda.function_url_authentication
- Category: exposure
- Severity: medium
- Resource: inventory:lambda_function
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, ProwlerThreatScore, RBI-Cyber-Security-Framework

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: RDS instance avoids a public endpoint

- Check: aws.rds.no_public_endpoint
- Category: exposure
- Severity: high
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, CIS, AWS Foundational Security Best Practices, AWS Australian Cyber Security Center (ACSC) Essential Eight, AWS Audit Manager Control Tower Guardrails, AWS CISA Cyber Essentials, AWS FedRAMP Low Revision 4, AWS FedRAMP Moderate Revision 4, AWS Federal Financial Institutions Examination Council (FFIEC), AWS GxP 21 CFR Part 11, HIPAA, AWS NIST 800-171 Revision 2, AWS NIST 800-172, NIST 800-53, NIST CSF, AWS NYDFS 23, PCI DSS, AWS RBI Cyber Security Framework, AWS Reserve Bank of India - Information Technology Framework for Non-Banking Financial Companies (RBI ITF-NBFC), SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Disable public accessibility or document the approved exposure and restrict network access.

### UNKNOWN: S3 bucket ACL has no public group grants

- Check: aws.s3.no_public_acl
- Category: exposure
- Severity: high
- Resource: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "reason": "missing fact: Acl.Grants"
}
```

Remediation: Remove public ACL grants, disable ACLs where feasible, and review Public Access Block enforcement.

### UNKNOWN: S3 bucket ACL has no public group grants

- Check: aws.s3.no_public_acl
- Category: exposure
- Severity: high
- Resource: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "reason": "missing fact: Acl.Grants"
}
```

Remediation: Remove public ACL grants, disable ACLs where feasible, and review Public Access Block enforcement.

### PASS: Bucket public access block is fully configured

- Check: aws.s3.public_access_block
- Category: exposure
- Severity: high
- Resource: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "semantics": "Bucket-level preventative configuration, not proof of effective public access.",
  "settings": {
    "BlockPublicAcls": true,
    "BlockPublicPolicy": true,
    "IgnorePublicAcls": true,
    "RestrictPublicBuckets": true
  }
}
```

Remediation: Enable all four bucket Public Access Block settings and review account-level policy and ACL controls.

### FAIL: Bucket public access block is fully configured

- Check: aws.s3.public_access_block
- Category: exposure
- Severity: high
- Resource: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "bucket_public_access_block": "absent",
  "semantics": "Missing bucket-level control; account-level controls and effective access were not evaluated."
}
```

Remediation: Enable all four bucket Public Access Block settings and review account-level policy and ACL controls.

### UNKNOWN: CloudTrail trail declares KMS encryption

- Check: aws.cloudtrail.kms_encryption
- Category: hardening
- Severity: medium
- Resource: inventory:cloudtrail
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, GDPR, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, ProwlerThreatScore, RBI-Cyber-Security-Framework, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: CloudTrail log file validation is enabled

- Check: aws.cloudtrail.log_validation
- Category: hardening
- Severity: medium
- Resource: inventory:cloudtrail
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, CIS, AWS Australian Cyber Security Center (ACSC) Essential Eight, AWS CISA Cyber Essentials, AWS FedRAMP Low Revision 4, AWS FedRAMP Moderate Revision 4, AWS General Data Protection Regulation (GDPR), AWS GxP 21 CFR Part 11, HIPAA, AWS NIST 800-171 Revision 2, AWS NIST 800-172, NIST 800-53, NIST CSF, AWS NYDFS 23, PCI DSS, SOC 2, AWS Foundational Security Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, GDPR, GxP-21-CFR-Part-11, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure LogFileValidationEnabled according to the intended security policy.

### UNKNOWN: CloudTrail trail is actively logging

- Check: aws.cloudtrail.logging
- Category: hardening
- Severity: medium
- Resource: inventory:cloudtrail
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure Status.IsLogging according to the intended security policy.

### UNKNOWN: CloudTrail records both read and write management events

- Check: aws.cloudtrail.management_events
- Category: hardening
- Severity: high
- Resource: inventory:cloudtrail
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Configure complete management event selectors and review excluded event sources.

### UNKNOWN: CloudTrail trail covers all regions

- Check: aws.cloudtrail.multi_region
- Category: hardening
- Severity: medium
- Resource: inventory:cloudtrail
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure IsMultiRegionTrail according to the intended security policy.

### UNKNOWN: Recording AWS Config recorder uses its account service-linked role

- Check: aws.config.service_linked_role
- Category: hardening
- Severity: medium
- Resource: inventory:config_recorder
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, C5, KISA-ISMS-P, NIST CSF, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: EBS volume encryption is enabled

- Check: aws.ebs.encryption
- Category: hardening
- Severity: medium
- Resource: inventory:ebs_volume
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS General Data Protection Regulation (GDPR), NIST 800-53, NIST CSF, AWS RBI Cyber Security Framework, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIST-800-171-Revision-2, PCI DSS, ProwlerThreatScore, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure Encrypted according to the intended security policy.

### PASS: Instance requires IMDSv2 tokens when metadata is enabled

- Check: aws.ec2.imdsv2
- Category: hardening
- Severity: medium
- Resource: sha256:90a249e73db4fd26a41d78be6f951276c1436977a71c2d37cfbae89b6d11423e
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "metadata_options": {
    "HttpEndpoint": "enabled",
    "HttpTokens": "required"
  }
}
```

Remediation: Require IMDSv2 or disable instance metadata if the workload does not need it.

### UNKNOWN: ECR repository enforces immutable tags

- Check: aws.ecr.immutable_tags
- Category: hardening
- Severity: medium
- Resource: inventory:ecr_repository
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure imageTagMutability according to the intended security policy.

### UNKNOWN: ECR repository has a lifecycle policy

- Check: aws.ecr.lifecycle_policy
- Category: hardening
- Severity: medium
- Resource: inventory:ecr_repository
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, KISA-ISMS-P, NIS2, PCI DSS

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: ECR repository enables scan on push

- Check: aws.ecr.scan_on_push
- Category: hardening
- Severity: medium
- Resource: inventory:ecr_repository
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure imageScanningConfiguration.scanOnPush according to the intended security policy.

### UNKNOWN: EKS enables all control-plane log categories

- Check: aws.eks.control_plane_logging
- Category: hardening
- Severity: medium
- Resource: inventory:eks_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, ISO 27001, KISA-ISMS-P, NIS2, PCI DSS, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Enable API, audit, authenticator, controllerManager and scheduler logs.

### UNKNOWN: EKS cluster provides a private API endpoint

- Check: aws.eks.private_endpoint
- Category: hardening
- Severity: medium
- Resource: inventory:eks_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure Cluster.cluster.resourcesVpcConfig.endpointPrivateAccess according to the intended security policy.

### UNKNOWN: EKS secret encryption is configured or enabled by Kubernetes version defaults

- Check: aws.eks.secrets_encryption
- Category: hardening
- Severity: medium
- Resource: inventory:eks_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS GxP EU Annex 11, HIPAA, NIST CSF, PCI DSS

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: ELBv2 access logging to S3 is enabled

- Check: aws.elbv2.access_logging
- Category: hardening
- Severity: medium
- Resource: inventory:load_balancer
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: ELBv2 deletion protection is enabled

- Check: aws.elbv2.deletion_protection
- Category: hardening
- Severity: medium
- Resource: inventory:load_balancer
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, C5, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, HIPAA, KISA-ISMS-P, NIST-800-171-Revision-2, NIST 800-53, NIST CSF

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Application load balancer mitigates HTTP desynchronization

- Check: aws.elbv2.desync_mitigation
- Category: hardening
- Severity: medium
- Resource: inventory:load_balancer
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, KISA-ISMS-P, PCI DSS

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Application load balancer drops invalid HTTP headers

- Check: aws.elbv2.drop_invalid_headers
- Category: hardening
- Severity: medium
- Resource: inventory:load_balancer
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: ELBv2 spans at least two availability zones

- Check: aws.elbv2.multiple_availability_zones
- Category: hardening
- Severity: medium
- Resource: inventory:load_balancer
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, ISO 27001, KISA-ISMS-P, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Existing GuardDuty detector enables EKS audit-log protection

- Check: aws.guardduty.eks_audit_logs
- Category: hardening
- Severity: medium
- Resource: inventory:guardduty_detector
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Existing GuardDuty detector enables Lambda network protection

- Check: aws.guardduty.lambda_network_logs
- Category: hardening
- Severity: medium
- Resource: inventory:guardduty_detector
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Existing GuardDuty detector enables RDS login-event protection

- Check: aws.guardduty.rds_login_events
- Category: hardening
- Severity: medium
- Resource: inventory:guardduty_detector
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Existing GuardDuty detector enables runtime monitoring

- Check: aws.guardduty.runtime_monitoring
- Category: hardening
- Severity: medium
- Resource: inventory:guardduty_detector
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Existing GuardDuty detector enables S3 data-event protection

- Check: aws.guardduty.s3_data_events
- Category: hardening
- Severity: medium
- Resource: inventory:guardduty_detector
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: IAM user avoids multiple active long-lived access keys

- Check: aws.iam.access_key_count
- Category: hardening
- Severity: medium
- Resource: inventory:iam_user
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review key rotation overlap and prefer short-lived role credentials.

### UNKNOWN: Console users have MFA configured

- Check: aws.iam.console_mfa
- Category: hardening
- Severity: high
- Resource: inventory:iam_user
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Enable MFA for console users; prefer federated short-lived access.

### UNKNOWN: Root account has no access keys

- Check: aws.iam.no_root_keys
- Category: hardening
- Severity: medium
- Resource: inventory:iam_account_summary
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Account-Security-Onboarding, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, ProwlerThreatScore, RBI-Cyber-Security-Framework, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure SummaryMap.AccountAccessKeysPresent according to the intended security policy.

### UNKNOWN: IAM password policy requires lowercase characters

- Check: aws.iam.password_lowercase
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure PasswordPolicy.RequireLowercaseCharacters according to the intended security policy.

### UNKNOWN: IAM password policy expires passwords within 90 days

- Check: aws.iam.password_max_age
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, ENS, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, PCI DSS, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: IAM password policy requires at least 14 characters

- Check: aws.iam.password_minimum_length
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: IAM password policy requires numbers

- Check: aws.iam.password_numbers
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure PasswordPolicy.RequireNumbers according to the intended security policy.

### UNKNOWN: IAM password policy prevents reuse of exactly 24 prior passwords

- Check: aws.iam.password_reuse_prevention
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, ENS, GDPR, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, ProwlerThreatScore, RBI-Cyber-Security-Framework, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: IAM password policy requires symbols

- Check: aws.iam.password_symbols
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure PasswordPolicy.RequireSymbols according to the intended security policy.

### UNKNOWN: IAM password policy requires uppercase characters

- Check: aws.iam.password_uppercase
- Category: hardening
- Severity: medium
- Resource: inventory:iam_password_policy
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure PasswordPolicy.RequireUppercaseCharacters according to the intended security policy.

### UNKNOWN: Root credentials have MFA configured

- Check: aws.iam.root_mfa
- Category: hardening
- Severity: high
- Resource: inventory:iam_credential_report
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-Account-Security-Onboarding, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CIS, CISA, ENS, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, ProwlerThreatScore, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Enable MFA on existing root credentials or centrally remove unused root credentials where supported.

### UNKNOWN: Active customer-managed KMS key is not scheduled for deletion

- Check: aws.kms.no_pending_key_deletion
- Category: hardening
- Severity: medium
- Resource: inventory:kms_key
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, C5, CCC, ISO 27001, KISA-ISMS-P, NIST CSF, PCI DSS, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Customer-managed symmetric KMS key rotation is enabled

- Check: aws.kms.rotation
- Category: hardening
- Severity: medium
- Resource: inventory:kms_key
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Enable automatic rotation for eligible symmetric customer-managed KMS keys.

### UNKNOWN: Lambda function has a dead-letter queue configuration

- Check: aws.lambda.dead_letter_queue
- Category: hardening
- Severity: medium
- Resource: inventory:lambda_function
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: Lambda function has VPC configuration

- Check: aws.lambda.vpc_configuration
- Category: hardening
- Severity: medium
- Resource: inventory:lambda_function
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, CCC, ISO 27001, KISA-ISMS-P, PCI DSS

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: CloudWatch log group has a retention policy

- Check: aws.logs.retention
- Category: hardening
- Severity: low
- Resource: inventory:log_group
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Set explicit retention consistent with incident response and regulatory needs.

### UNKNOWN: RDS instance enables automatic minor version upgrades

- Check: aws.rds.auto_minor_upgrade
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, CIS, CISA, FFIEC, KISA-ISMS-P, MITRE-ATTACK, PCI DSS, RBI-Cyber-Security-Framework

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure AutoMinorVersionUpgrade according to the intended security policy.

### UNKNOWN: RDS automatic backup retention is nonzero

- Check: aws.rds.backups
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Reliability-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Enable automated backups with retention suitable for recovery requirements.

### UNKNOWN: RDS instance exports logs to CloudWatch

- Check: aws.rds.cloudwatch_log_exports
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Reliability-Pillar, AWS-Well-Architected-Framework-Security-Pillar, C5, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, NIST 800-53, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: RDS cluster copies tags to snapshots

- Check: aws.rds.cluster_copy_snapshot_tags
- Category: hardening
- Severity: medium
- Resource: inventory:rds_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure CopyTagsToSnapshot according to the intended security policy.

### UNKNOWN: RDS cluster deletion protection is enabled

- Check: aws.rds.cluster_deletion_protection
- Category: hardening
- Severity: medium
- Resource: inventory:rds_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS Foundational Security Best Practices, NIST CSF

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure DeletionProtection according to the intended security policy.

### UNKNOWN: RDS cluster storage encryption is enabled

- Check: aws.rds.cluster_encryption
- Category: hardening
- Severity: medium
- Resource: inventory:rds_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS Foundational Security Best Practices, NIST CSF

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure StorageEncrypted according to the intended security policy.

### UNKNOWN: RDS cluster enables IAM database authentication

- Check: aws.rds.cluster_iam_authentication
- Category: hardening
- Severity: medium
- Resource: inventory:rds_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS Australian Cyber Security Center (ACSC) Essential Eight, AWS NIST 800-171 Revision 2, NIST CSF, PCI DSS

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure IAMDatabaseAuthenticationEnabled according to the intended security policy.

### UNKNOWN: RDS cluster enables Multi-AZ configuration

- Check: aws.rds.cluster_multi_az
- Category: hardening
- Severity: medium
- Resource: inventory:rds_cluster
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, NIST CSF

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure MultiAZ according to the intended security policy.

### UNKNOWN: Non-Aurora RDS instance copies tags to snapshots

- Check: aws.rds.copy_snapshot_tags
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-Foundational-Security-Best-Practices, C5, KISA-ISMS-P, NIS2, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: RDS instance deletion protection is enabled

- Check: aws.rds.deletion_protection
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS Foundational Security Best Practices, AWS CISA Cyber Essentials, AWS FedRAMP Low Revision 4, AWS FedRAMP Moderate Revision 4, AWS Federal Financial Institutions Examination Council (FFIEC), AWS GxP 21 CFR Part 11, HIPAA, AWS NIST 800-171 Revision 2, NIST 800-53, NIST CSF, AWS NYDFS 23, AWS Reserve Bank of India - Information Technology Framework for Non-Banking Financial Companies (RBI ITF-NBFC), SOC 2, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Reliability-Pillar, C5, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, KISA-ISMS-P, MITRE-ATTACK, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure DeletionProtection according to the intended security policy.

### UNKNOWN: RDS instance storage encryption is enabled

- Check: aws.rds.encryption
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, CIS, AWS Foundational Security Best Practices, AWS Audit Manager Control Tower Guardrails, AWS CISA Cyber Essentials, AWS FedRAMP Moderate Revision 4, AWS Federal Financial Institutions Examination Council (FFIEC), AWS General Data Protection Regulation (GDPR), AWS GxP 21 CFR Part 11, AWS GxP EU Annex 11, HIPAA, AWS NIST 800-171 Revision 2, NIST 800-53, NIST CSF, AWS NYDFS 23, PCI DSS, AWS RBI Cyber Security Framework, SOC 2, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, ENS, FedRamp-Moderate-Revision-4, FFIEC, GDPR, GxP-21-CFR-Part-11, GxP-EU-Annex-11, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIST-800-171-Revision-2, ProwlerThreatScore, RBI-Cyber-Security-Framework, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure StorageEncrypted according to the intended security policy.

### UNKNOWN: RDS instance declares enhanced monitoring

- Check: aws.rds.enhanced_monitoring
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Reliability-Pillar, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, KISA-ISMS-P, MITRE-ATTACK, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: RDS instance snapshot encryption is enabled

- Check: aws.rds.snapshot_encryption
- Category: hardening
- Severity: medium
- Resource: inventory:rds_snapshot
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure Encrypted according to the intended security policy.

### UNKNOWN: RDS instance has VPC configuration

- Check: aws.rds.vpc_configuration
- Category: hardening
- Severity: medium
- Resource: inventory:rds_instance
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-Foundational-Security-Best-Practices, ISO 27001, KISA-ISMS-P

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: S3 bucket has server access logging configured

- Check: aws.s3.access_logging
- Category: hardening
- Severity: low
- Resource: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "reason": "missing fact: Logging"
}
```

Remediation: Enable access logging to an appropriate protected bucket, or review a documented alternative data-access audit control.

### UNKNOWN: S3 bucket has server access logging configured

- Check: aws.s3.access_logging
- Category: hardening
- Severity: low
- Resource: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, HIPAA, ISO 27001, KISA-ISMS-P, NIS2, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "reason": "missing fact: Logging"
}
```

Remediation: Enable access logging to an appropriate protected bucket, or review a documented alternative data-access audit control.

### PASS: Bucket default encryption is configured

- Check: aws.s3.default_encryption
- Category: hardening
- Severity: medium
- Resource: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "algorithms": [
    "AES256"
  ],
  "semantics": "Default configuration; existing object encryption was not collected."
}
```

Remediation: Configure and verify server-side encryption; select an appropriate managed key for sensitive data.

### UNKNOWN: Bucket default encryption is configured

- Check: aws.s3.default_encryption
- Category: hardening
- Severity: medium
- Resource: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "reason": "resource detail unavailable: denied"
}
```

Remediation: Configure and verify server-side encryption; select an appropriate managed key for sensitive data.

### UNKNOWN: S3 bucket versioning is enabled

- Check: aws.s3.versioning
- Category: hardening
- Severity: medium
- Resource: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "reason": "missing fact: Versioning"
}
```

Remediation: Enable versioning and use lifecycle retention aligned with recovery needs.

### UNKNOWN: S3 bucket versioning is enabled

- Check: aws.s3.versioning
- Category: hardening
- Severity: medium
- Resource: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, ASD-Essential-Eight, AWS-AI-Security-Framework, AWS-Audit-Manager-Control-Tower-Guardrails, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, FFIEC, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "reason": "missing fact: Versioning"
}
```

Remediation: Enable versioning and use lifecycle retention aligned with recovery needs.

### UNKNOWN: Secrets Manager secret rotation is enabled

- Check: aws.secretsmanager.rotation
- Category: hardening
- Severity: medium
- Resource: inventory:secret
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the collected setting and configure RotationEnabled according to the intended security policy.

### UNKNOWN: SNS topic declares KMS encryption

- Check: aws.sns.kms_encryption
- Category: hardening
- Severity: medium
- Resource: inventory:sns_topic
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Foundational-Technical-Review, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, CISA, FedRAMP-Low-Revision-4, FedRamp-Moderate-Revision-4, GDPR, GxP-21-CFR-Part-11, GxP-EU-Annex-11, HIPAA, ISO 27001, KISA-ISMS-P, MITRE-ATTACK, NIST-800-171-Revision-2, NIST 800-53, NIST CSF, PCI DSS, RBI-Cyber-Security-Framework, SecNumCloud, SOC 2

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### UNKNOWN: SQS queue enables KMS or SQS-managed encryption

- Check: aws.sqs.encryption
- Category: hardening
- Severity: medium
- Resource: inventory:sqs_queue
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices, AWS-AI-Security-Framework, AWS-Foundational-Security-Best-Practices, AWS-Well-Architected-Framework-Security-Pillar, C5, CCC, ENS, ISO 27001, KISA-ISMS-P, SecNumCloud

Evidence:

```json
{
  "collection_status": "not_collected",
  "reason": "no collected resources",
  "semantics": "Inventory coverage, not a resource security pass."
}
```

Remediation: Review the declared setting and configure it for the intended security policy; verify collection coverage before relying on this result.

### PASS: Role trust avoids an unrestricted public principal

- Check: aws.iam.restrict_public_trust
- Category: iam_graph
- Severity: high
- Resource: sha256:025c006474a5d0a9ae43323f112995c8ae980a6af622fdeec6661f5d43744e6b
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "unrestricted_trust_statements": []
}
```

Remediation: Limit role trust to intended principals and review trust conditions, organizational controls and federation settings.

### UNKNOWN: Analysis inventory context incomplete

- Check: analysis.coverage
- Category: least_privilege
- Severity: info
- Resource: inventory
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "gaps": [
    {
      "status": "not_collected",
      "type": "iam_user"
    },
    {
      "status": "not_collected",
      "type": "iam_group"
    }
  ],
  "risk_state": "unknown"
}
```

Remediation: Have the resource owner validate business need, conditions, inheritance, and usage coverage; narrow grants or exposure only after review and a tested rollback plan.

### MANUAL: Review high-impact or broad declared grants

- Check: analysis.grant_review
- Category: least_privilege
- Severity: high
- Resource: sha256:77cc73479df8b274ee611ea15bf184cf7e08a32bb36345cd1eb3a38b586acf7a
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "criticality_source": "Bundled Blue-CloudPEASS standalone HackTricks permission criticality; combinations are not evaluated",
  "effective_access": "unknown",
  "grants": [
    {
      "allowed_declaration": true,
      "broad": true,
      "conditional": false,
      "criticality_state": "rule_based",
      "effective_access": "unknown",
      "native_grant": {
        "Action": "*",
        "Effect": "Allow",
        "Resource": "*"
      },
      "path": "PolicyDocument.Statement[0]",
      "severity": "high"
    }
  ],
  "missing_context": [
    "Effective denies, inherited grants, boundaries/SCPs, runtime conditions, and owner-approved business need must be reviewed"
  ],
  "restrictions": {},
  "risk_state": "conditional",
  "source": {
    "collection_status": "collected",
    "native_scope": null,
    "path": "grants",
    "request_evidence": {},
    "resource_id": "arn:aws:iam::111111111111:policy/Overbroad",
    "resource_type": "iam_policy",
    "scope": "111111111111/us-east-1",
    "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
  },
  "usage": {
    "completeness": "unknown",
    "inactive_observation": false,
    "observations": {},
    "provider_observation_context": {},
    "safe_to_remove": false,
    "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window.",
    "window": null
  }
}
```

Remediation: Have the resource owner validate business need, conditions, inheritance, and usage coverage; narrow grants or exposure only after review and a tested rollback plan.

### PASS: Managed policy has no unconditional full administrator grant

- Check: aws.iam.no_full_admin
- Category: least_privilege
- Severity: high
- Resource: sha256:19029d504ce5ea5b2045f27ad6e267af2bcf7905733549d591f47015b5bdf35c
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "full_admin_statements": [],
  "semantics": "Declared policy grants; this is not effective access."
}
```

Remediation: Replace full administrator grants with the actions and resources required for the workload; review conditions and explicit denies.

### FAIL: Managed policy has no unconditional full administrator grant

- Check: aws.iam.no_full_admin
- Category: least_privilege
- Severity: high
- Resource: sha256:77cc73479df8b274ee611ea15bf184cf7e08a32bb36345cd1eb3a38b586acf7a
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "full_admin_statements": [
    {
      "Action": "*",
      "Effect": "Allow",
      "Resource": "*"
    }
  ],
  "semantics": "Declared policy grants; this is not effective access."
}
```

Remediation: Replace full administrator grants with the actions and resources required for the workload; review conditions and explicit denies.

### PASS: Security group avoids broad internet ingress

- Check: aws.ec2.restrict_internet_ingress
- Category: network
- Severity: high
- Resource: sha256:17f190f149f4324fb6272763647f7b417d609a81409b2fd8a743c07b2b68b926
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "internet_ingress": [],
  "semantics": "Declared ingress; reachable services are not inferred."
}
```

Remediation: Restrict ingress CIDRs and ports to intended clients; confirm routing, attached interfaces and network ACLs separately.

### FAIL: Security group avoids broad internet ingress

- Check: aws.ec2.restrict_internet_ingress
- Category: network
- Severity: high
- Resource: sha256:aae0a7d8e2a2aadb6d795ab13e53d444afd03c085455fce38736f073bdb7bcc0
- Scope: 111111111111/us-east-1
- Frameworks: HackTricks Cloud Best Practices

Evidence:

```json
{
  "internet_ingress": [
    {
      "from_port": 443,
      "protocol": "tcp",
      "source": "0.0.0.0/0",
      "to_port": 443
    }
  ],
  "semantics": "Declared ingress; reachable services are not inferred."
}
```

Remediation: Restrict ingress CIDRs and ports to intended clients; confirm routing, attached interfaces and network ACLs separately.

## Resource inventory

Native configuration facts are retained below. No data-plane secrets or object contents are collected.

### bucket: sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "Encryption": {
      "ServerSideEncryptionConfiguration": {
        "Rules": [
          {
            "ApplyServerSideEncryptionByDefault": {
              "SSEAlgorithm": "AES256"
            }
          }
        ]
      }
    },
    "Name": "demo-private",
    "PublicAccessBlock": {
      "PublicAccessBlockConfiguration": {
        "BlockPublicAcls": true,
        "BlockPublicPolicy": true,
        "IgnorePublicAcls": true,
        "RestrictPublicBuckets": true
      }
    }
  },
  "id": "sha256:2489f2807ed2ed2e09b80a76bab28b801d7c4b064088421f000835cfea85730c",
  "native_id": "demo-private",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "bucket",
  "type": "bucket"
}
```

### bucket: sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "Encryption": {
      "collection_status": "denied",
      "error": {
        "code": "AccessDenied"
      }
    },
    "Name": "demo-unreviewed",
    "PublicAccessBlock": {
      "absent": true
    }
  },
  "id": "sha256:bcf6b86e27a6078aa120c915ed747be5beee66b11c8a1a7f983d662265aaa3e6",
  "native_id": "demo-unreviewed",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "bucket",
  "type": "bucket"
}
```

### iam_policy: sha256:77cc73479df8b274ee611ea15bf184cf7e08a32bb36345cd1eb3a38b586acf7a

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "Arn": "arn:aws:iam::111111111111:policy/Overbroad",
    "PolicyDocument": {
      "Statement": [
        {
          "Action": "*",
          "Effect": "Allow",
          "Resource": "*"
        }
      ]
    }
  },
  "id": "sha256:77cc73479df8b274ee611ea15bf184cf7e08a32bb36345cd1eb3a38b586acf7a",
  "native_id": "arn:aws:iam::111111111111:policy/Overbroad",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "iam_policy",
  "type": "iam_policy"
}
```

### iam_policy: sha256:19029d504ce5ea5b2045f27ad6e267af2bcf7905733549d591f47015b5bdf35c

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "Arn": "arn:aws:iam::111111111111:policy/ReviewedRead",
    "PolicyDocument": {
      "Statement": [
        {
          "Action": [
            "s3:ListBucket"
          ],
          "Effect": "Allow",
          "Resource": "arn:aws:s3:::demo-private"
        }
      ]
    }
  },
  "id": "sha256:19029d504ce5ea5b2045f27ad6e267af2bcf7905733549d591f47015b5bdf35c",
  "native_id": "arn:aws:iam::111111111111:policy/ReviewedRead",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "iam_policy",
  "type": "iam_policy"
}
```

### iam_role: sha256:025c006474a5d0a9ae43323f112995c8ae980a6af622fdeec6661f5d43744e6b

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "Arn": "arn:aws:iam::111111111111:role/Demo",
    "AssumeRolePolicyDocument": {
      "Statement": [
        {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          }
        }
      ]
    },
    "AttachedManagedPolicies": [
      {
        "PolicyArn": "arn:aws:iam::111111111111:policy/Overbroad"
      }
    ],
    "RoleName": "Demo"
  },
  "id": "sha256:025c006474a5d0a9ae43323f112995c8ae980a6af622fdeec6661f5d43744e6b",
  "native_id": "arn:aws:iam::111111111111:role/Demo",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "iam_role",
  "type": "iam_role"
}
```

### instance: sha256:90a249e73db4fd26a41d78be6f951276c1436977a71c2d37cfbae89b6d11423e

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "InstanceId": "i-demo",
    "MetadataOptions": {
      "HttpEndpoint": "enabled",
      "HttpTokens": "required"
    },
    "SecurityGroups": [
      {
        "GroupId": "sg-public"
      }
    ],
    "SubnetId": "subnet-demo",
    "VpcId": "vpc-demo"
  },
  "id": "sha256:90a249e73db4fd26a41d78be6f951276c1436977a71c2d37cfbae89b6d11423e",
  "native_id": "i-demo",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "instance",
  "type": "instance"
}
```

### security_group: sha256:17f190f149f4324fb6272763647f7b417d609a81409b2fd8a743c07b2b68b926

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "GroupId": "sg-private",
    "IpPermissions": [],
    "VpcId": "vpc-demo"
  },
  "id": "sha256:17f190f149f4324fb6272763647f7b417d609a81409b2fd8a743c07b2b68b926",
  "native_id": "sg-private",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "security_group",
  "type": "security_group"
}
```

### security_group: sha256:aae0a7d8e2a2aadb6d795ab13e53d444afd03c085455fce38736f073bdb7bcc0

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "GroupId": "sg-public",
    "IpPermissions": [
      {
        "FromPort": 443,
        "IpProtocol": "tcp",
        "IpRanges": [
          {
            "CidrIp": "0.0.0.0/0"
          }
        ],
        "ToPort": 443
      }
    ],
    "VpcId": "vpc-demo"
  },
  "id": "sha256:aae0a7d8e2a2aadb6d795ab13e53d444afd03c085455fce38736f073bdb7bcc0",
  "native_id": "sg-public",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "security_group",
  "type": "security_group"
}
```

### subnet: sha256:f632f32257d4b5d836a74b9d5cd82eb3957cbb7729563e7b13fd07af51a9e4bd

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "CidrBlock": "10.0.1.0/24",
    "SubnetId": "subnet-demo",
    "VpcId": "vpc-demo"
  },
  "id": "sha256:f632f32257d4b5d836a74b9d5cd82eb3957cbb7729563e7b13fd07af51a9e4bd",
  "native_id": "subnet-demo",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "subnet",
  "type": "subnet"
}
```

### vpc: sha256:f2c239d0675767d192d2329a67a5f02de7a9c23eaa10ee7a72f783667d98055b

Scope: 111111111111/us-east-1

```json
{
  "data": {
    "CidrBlock": "10.0.0.0/16",
    "VpcId": "vpc-demo"
  },
  "id": "sha256:f2c239d0675767d192d2329a67a5f02de7a9c23eaa10ee7a72f783667d98055b",
  "native_id": "vpc-demo",
  "provider": "aws",
  "scope": "111111111111/us-east-1",
  "service": "vpc",
  "type": "vpc"
}
```

## Defensive relationship graphs

Edges record observed configuration references and declared IAM grants. They do not establish effective access or network reachability.

### iam

```json
{
  "edges": [
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "AttachedManagedPolicies[0]",
        "request_evidence": {},
        "resource_id": "arn:aws:iam::111111111111:role/Demo",
        "resource_type": "iam_role",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:9fca5658bdafd9934a7ba2f7",
      "layer": "structural",
      "source": "analysis:025c006474a5d0a9ae43323f",
      "target": "analysis:77cc73479df8b274ee611ea1",
      "type": "attached_policy"
    },
    {
      "confidence": "high",
      "evidence": {
        "classification": "unknown",
        "effective_access": "unknown",
        "native_fact": {
          "Action": "sts:AssumeRole",
          "Effect": "Allow",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          }
        },
        "risk_state": "unknown",
        "source": {
          "collection_status": "collected",
          "native_scope": null,
          "path": "AssumeRolePolicyDocument.Statement[0].Principal",
          "request_evidence": {},
          "resource_id": "arn:aws:iam::111111111111:role/Demo",
          "resource_type": "iam_role",
          "scope": "111111111111/us-east-1",
          "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
        }
      },
      "id": "analysis:fe1da834909451e44866f72d",
      "layer": "structural",
      "source": "analysis:55b16c1f3c1854e852dfcaab",
      "target": "analysis:025c006474a5d0a9ae43323f",
      "type": "trust"
    }
  ],
  "nodes": [
    {
      "card": {
        "effective_access": "unknown",
        "restrictions": {},
        "source_grants": [
          {
            "allowed_declaration": true,
            "broad": true,
            "conditional": false,
            "criticality_state": "rule_based",
            "effective_access": "unknown",
            "native_grant": {
              "Action": "*",
              "Effect": "Allow",
              "Resource": "*"
            },
            "path": "PolicyDocument.Statement[0]",
            "severity": "high"
          }
        ],
        "trust": null,
        "usage": {
          "completeness": "unknown",
          "inactive_observation": false,
          "observations": {},
          "provider_observation_context": {},
          "safe_to_remove": false,
          "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window.",
          "window": null
        }
      },
      "evidence": {
        "native_resource": {
          "Arn": "arn:aws:iam::111111111111:policy/Overbroad",
          "PolicyDocument": {
            "Statement": [
              {
                "Action": "*",
                "Effect": "Allow",
                "Resource": "*"
              }
            ]
          }
        }
      },
      "id": "analysis:77cc73479df8b274ee611ea1",
      "label": "arn:aws:iam::111111111111:policy/Overbroad",
      "native_id": "arn:aws:iam::111111111111:policy/Overbroad",
      "native_kind": "iam_policy",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "iam_policy"
      },
      "resource_id": "sha256:77cc73479df8b274ee611ea15bf184cf7e08a32bb36345cd1eb3a38b586acf7a",
      "risk_annotations": [
        {
          "state": "conditional",
          "type": "high_risk_grant"
        }
      ],
      "scope": "111111111111/us-east-1",
      "type": "iam_policy"
    },
    {
      "card": {
        "effective_access": "unknown",
        "restrictions": {},
        "source_grants": [
          {
            "allowed_declaration": true,
            "broad": false,
            "conditional": false,
            "criticality_state": "rule_based",
            "effective_access": "unknown",
            "native_grant": {
              "Action": [
                "s3:ListBucket"
              ],
              "Effect": "Allow",
              "Resource": "arn:aws:s3:::demo-private"
            },
            "path": "PolicyDocument.Statement[0]",
            "severity": "low"
          }
        ],
        "trust": null,
        "usage": {
          "completeness": "unknown",
          "inactive_observation": false,
          "observations": {},
          "provider_observation_context": {},
          "safe_to_remove": false,
          "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window.",
          "window": null
        }
      },
      "evidence": {
        "native_resource": {
          "Arn": "arn:aws:iam::111111111111:policy/ReviewedRead",
          "PolicyDocument": {
            "Statement": [
              {
                "Action": [
                  "s3:ListBucket"
                ],
                "Effect": "Allow",
                "Resource": "arn:aws:s3:::demo-private"
              }
            ]
          }
        }
      },
      "id": "analysis:19029d504ce5ea5b2045f27a",
      "label": "arn:aws:iam::111111111111:policy/ReviewedRead",
      "native_id": "arn:aws:iam::111111111111:policy/ReviewedRead",
      "native_kind": "iam_policy",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "iam_policy"
      },
      "resource_id": "sha256:19029d504ce5ea5b2045f27ad6e267af2bcf7905733549d591f47015b5bdf35c",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "iam_policy"
    },
    {
      "card": {
        "effective_access": "unknown",
        "referenced_grants": [
          {
            "edge_ref": "analysis:9fca5658bdafd9934a7ba2f7",
            "grants": [
              {
                "allowed_declaration": true,
                "broad": true,
                "conditional": false,
                "criticality_state": "rule_based",
                "effective_access": "unknown",
                "native_grant": {
                  "Action": "*",
                  "Effect": "Allow",
                  "Resource": "*"
                },
                "path": "PolicyDocument.Statement[0]",
                "severity": "high"
              }
            ],
            "source_node": "analysis:77cc73479df8b274ee611ea1"
          }
        ],
        "restrictions": {},
        "source_grants": [],
        "trust": {
          "Statement": [
            {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": "ec2.amazonaws.com"
              }
            }
          ]
        },
        "usage": {
          "completeness": "unknown",
          "inactive_observation": false,
          "observations": {},
          "provider_observation_context": {},
          "safe_to_remove": false,
          "uncertainty": "No observed activity is not evidence that access is unnecessary; telemetry can exclude data events, federation, other regions, or activity outside the window.",
          "window": null
        }
      },
      "evidence": {
        "native_resource": {
          "Arn": "arn:aws:iam::111111111111:role/Demo",
          "AssumeRolePolicyDocument": {
            "Statement": [
              {
                "Action": "sts:AssumeRole",
                "Effect": "Allow",
                "Principal": {
                  "Service": "ec2.amazonaws.com"
                }
              }
            ]
          },
          "AttachedManagedPolicies": [
            {
              "PolicyArn": "arn:aws:iam::111111111111:policy/Overbroad"
            }
          ],
          "RoleName": "Demo"
        }
      },
      "id": "analysis:025c006474a5d0a9ae43323f",
      "label": "Demo",
      "native_id": "arn:aws:iam::111111111111:role/Demo",
      "native_kind": "iam_role",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "iam_role"
      },
      "resource_id": "sha256:025c006474a5d0a9ae43323f112995c8ae980a6af622fdeec6661f5d43744e6b",
      "risk_annotations": [
        {
          "basis": "analysis:9fca5658bdafd9934a7ba2f7",
          "effective_access": "unknown",
          "state": "derived",
          "type": "high_risk_grant"
        }
      ],
      "scope": "111111111111/us-east-1",
      "type": "iam_role"
    },
    {
      "card": {
        "effective_access": "unknown",
        "observed_bindings": [
          {
            "native_fact": {
              "Action": "sts:AssumeRole",
              "Effect": "Allow",
              "Principal": {
                "Service": "ec2.amazonaws.com"
              }
            },
            "resource_node": "analysis:025c006474a5d0a9ae43323f",
            "source": {
              "collection_status": "collected",
              "native_scope": null,
              "path": "AssumeRolePolicyDocument.Statement[0].Principal",
              "request_evidence": {},
              "resource_id": "arn:aws:iam::111111111111:role/Demo",
              "resource_type": "iam_role",
              "scope": "111111111111/us-east-1",
              "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
            },
            "type": "trust"
          }
        ],
        "source_grants": [],
        "trust": null,
        "usage": {
          "completeness": "unknown",
          "observations": {},
          "safe_to_remove": false,
          "uncertainty": "Principal telemetry is not established by policy or binding evidence",
          "window": null
        }
      },
      "evidence": {
        "inventory_status": "reference_only"
      },
      "id": "analysis:55b16c1f3c1854e852dfcaab",
      "label": "ec2.amazonaws.com",
      "provider": "aws",
      "resource_id": "ec2.amazonaws.com",
      "risk_annotations": [
        {
          "classification": "unknown",
          "state": "unknown"
        }
      ],
      "scope": "111111111111/us-east-1",
      "type": "principal"
    }
  ],
  "projection": {
    "collapsed": false,
    "edge_count": 2,
    "node_count": 4
  },
  "semantics": "Observed declarations and conditional risk review; no effective-access or exploit-chain claims"
}
```

### network

```json
{
  "edges": [
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "VpcId",
        "request_evidence": {},
        "resource_id": "i-demo",
        "resource_type": "instance",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:1c9e1e2e41178f64b138b272",
      "layer": "structural",
      "source": "analysis:90a249e73db4fd26a41d78be",
      "target": "analysis:f2c239d0675767d192d2329a",
      "type": "associated_with"
    },
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "SubnetId",
        "request_evidence": {},
        "resource_id": "i-demo",
        "resource_type": "instance",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:868c093f010dcca3a5c5d597",
      "layer": "structural",
      "source": "analysis:90a249e73db4fd26a41d78be",
      "target": "analysis:f632f32257d4b5d836a74b9d",
      "type": "associated_with"
    },
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "SecurityGroups[0]",
        "request_evidence": {},
        "resource_id": "i-demo",
        "resource_type": "instance",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:2e56dbb4a84ade73d41bf8b3",
      "layer": "structural",
      "source": "analysis:90a249e73db4fd26a41d78be",
      "target": "analysis:aae0a7d8e2a2aadb6d795ab1",
      "type": "protected_by"
    },
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "VpcId",
        "request_evidence": {},
        "resource_id": "sg-private",
        "resource_type": "security_group",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:1307e90c8a9ad03dc792f3e0",
      "layer": "structural",
      "source": "analysis:17f190f149f4324fb6272763",
      "target": "analysis:f2c239d0675767d192d2329a",
      "type": "associated_with"
    },
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "VpcId",
        "request_evidence": {},
        "resource_id": "sg-public",
        "resource_type": "security_group",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:a7c10bcad7bd9b2a5daa8fe4",
      "layer": "structural",
      "source": "analysis:aae0a7d8e2a2aadb6d795ab1",
      "target": "analysis:f2c239d0675767d192d2329a",
      "type": "associated_with"
    },
    {
      "confidence": "low",
      "evidence": {
        "native_rule": {
          "FromPort": 443,
          "IpProtocol": "tcp",
          "IpRanges": [
            {
              "CidrIp": "0.0.0.0/0"
            }
          ],
          "ToPort": 443
        },
        "reachability": "unknown",
        "source": {
          "collection_status": "collected",
          "native_scope": null,
          "path": "IpPermissions[0]",
          "request_evidence": {},
          "resource_id": "sg-public",
          "resource_type": "security_group",
          "scope": "111111111111/us-east-1",
          "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
        },
        "telemetry": "not_collected",
        "uncertainty": "AWS security-group inbound allow; routing, NACLs, attachment, and public addressing remain unresolved"
      },
      "id": "analysis:329e21703e4a00f534fab87f",
      "layer": "modeled_rule",
      "source": "analysis:f715d00360b7fab7cdbc0192",
      "target": "analysis:aae0a7d8e2a2aadb6d795ab1",
      "type": "rule_candidate"
    },
    {
      "confidence": "high",
      "evidence": {
        "collection_status": "collected",
        "native_scope": null,
        "path": "VpcId",
        "request_evidence": {},
        "resource_id": "subnet-demo",
        "resource_type": "subnet",
        "scope": "111111111111/us-east-1",
        "snapshot_id": "sha256:2f79d80733bea58ac4454117dd3f769d79e794146bc289c236b8ba96bfb60e0f"
      },
      "id": "analysis:9f6379b4014889e26c97f092",
      "layer": "structural",
      "source": "analysis:f632f32257d4b5d836a74b9d",
      "target": "analysis:f2c239d0675767d192d2329a",
      "type": "associated_with"
    }
  ],
  "nodes": [
    {
      "display_group": "resource",
      "evidence": {
        "native_resource": {
          "InstanceId": "i-demo",
          "MetadataOptions": {
            "HttpEndpoint": "enabled",
            "HttpTokens": "required"
          },
          "SecurityGroups": [
            {
              "GroupId": "sg-public"
            }
          ],
          "SubnetId": "subnet-demo",
          "VpcId": "vpc-demo"
        }
      },
      "id": "analysis:90a249e73db4fd26a41d78be",
      "label": "i-demo",
      "native_id": "i-demo",
      "native_kind": "instance",
      "parent_edge_refs": [
        "analysis:868c093f010dcca3a5c5d597"
      ],
      "parent_id": "analysis:f632f32257d4b5d836a74b9d",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "instance"
      },
      "resource_id": "sha256:90a249e73db4fd26a41d78be6f951276c1436977a71c2d37cfbae89b6d11423e",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "instance"
    },
    {
      "display_group": "resource",
      "evidence": {
        "native_resource": {
          "GroupId": "sg-private",
          "IpPermissions": [],
          "VpcId": "vpc-demo"
        }
      },
      "id": "analysis:17f190f149f4324fb6272763",
      "label": "sg-private",
      "native_id": "sg-private",
      "native_kind": "security_group",
      "parent_edge_refs": [
        "analysis:1307e90c8a9ad03dc792f3e0"
      ],
      "parent_id": "analysis:f2c239d0675767d192d2329a",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "security_group"
      },
      "resource_id": "sha256:17f190f149f4324fb6272763647f7b417d609a81409b2fd8a743c07b2b68b926",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "security_group"
    },
    {
      "display_group": "resource",
      "evidence": {
        "native_resource": {
          "GroupId": "sg-public",
          "IpPermissions": [
            {
              "FromPort": 443,
              "IpProtocol": "tcp",
              "IpRanges": [
                {
                  "CidrIp": "0.0.0.0/0"
                }
              ],
              "ToPort": 443
            }
          ],
          "VpcId": "vpc-demo"
        }
      },
      "id": "analysis:aae0a7d8e2a2aadb6d795ab1",
      "label": "sg-public",
      "native_id": "sg-public",
      "native_kind": "security_group",
      "parent_edge_refs": [
        "analysis:a7c10bcad7bd9b2a5daa8fe4"
      ],
      "parent_id": "analysis:f2c239d0675767d192d2329a",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "security_group"
      },
      "resource_id": "sha256:aae0a7d8e2a2aadb6d795ab13e53d444afd03c085455fce38736f073bdb7bcc0",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "security_group"
    },
    {
      "display_group": "resource",
      "evidence": {
        "native_resource": {
          "CidrBlock": "10.0.1.0/24",
          "SubnetId": "subnet-demo",
          "VpcId": "vpc-demo"
        }
      },
      "id": "analysis:f632f32257d4b5d836a74b9d",
      "label": "subnet-demo",
      "native_id": "subnet-demo",
      "native_kind": "subnet",
      "parent_edge_refs": [
        "analysis:9f6379b4014889e26c97f092"
      ],
      "parent_id": "analysis:f2c239d0675767d192d2329a",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "subnet"
      },
      "resource_id": "sha256:f632f32257d4b5d836a74b9d5cd82eb3957cbb7729563e7b13fd07af51a9e4bd",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "subnet"
    },
    {
      "display_group": "network",
      "evidence": {
        "native_resource": {
          "CidrBlock": "10.0.0.0/16",
          "VpcId": "vpc-demo"
        }
      },
      "id": "analysis:f2c239d0675767d192d2329a",
      "label": "vpc-demo",
      "native_id": "vpc-demo",
      "native_kind": "vpc",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "vpc"
      },
      "resource_id": "sha256:f2c239d0675767d192d2329a67a5f02de7a9c23eaa10ee7a72f783667d98055b",
      "risk_annotations": [],
      "scope": "111111111111/us-east-1",
      "type": "vpc"
    },
    {
      "display_group": "resource",
      "evidence": {
        "reachability": "unknown"
      },
      "id": "analysis:f715d00360b7fab7cdbc0192",
      "label": "Unrestricted source selector",
      "native_kind": "internet_source",
      "provider": "aws",
      "provider_specific": {
        "native_kind": "internet_source"
      },
      "scope": "111111111111/us-east-1",
      "type": "internet_source"
    }
  ],
  "projection": {
    "collapsed": false,
    "edge_count": 7,
    "node_count": 6
  },
  "semantics": "Structural inventory and conditional rule candidates; telemetry and routed reachability are not inferred"
}
```
