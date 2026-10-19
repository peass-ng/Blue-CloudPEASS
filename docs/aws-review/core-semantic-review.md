# AWS core semantic review

Reviewed **44 active IDs** previously labeled witness-only. These are bounded SDK-to-consumer proofs, not full semantic-completeness or live-account claims.

The tests use independent botocore-validated SDK responses through real Requests and production collection helpers, policy decoding and registered evaluators. They cover configured/alternate states and denied roots for every ID. Six representative checks also pass through immutable snapshot evaluation. No existing behavior fixtures serve as semantic proof.

## Confirmed findings

- **Fixed with coordinator authorization:** the compound CloudTrail check accepted selectors returned for a different trail and ignored denied selector-member coverage. Native collected receipts now need a valid matching trail ARN; denied fields and mixed basic/advanced selector bodies are rejected. Unmarked legacy bodies retain compatibility. Associated constants and direct selector fixtures were migrated; root owns catalog signing and any remaining unrelated historical fixtures.
- **Fixed malformed-input gaps:** three EC2 profile-attachment checks previously accepted `IamInstanceProfile={}`; the IAM inline AssumeRole-text control previously accepted a missing `PolicyDocument`. These now yield UNKNOWN, preserving complete native paths. These counterexamples concern malformed/imported snapshots; they do not claim AWS normally emits these shapes. Exact corrections and counterexamples are in the JSON.
- **Conservative coverage limits:** RDS missing monitoring ARN/VPC metadata returns UNKNOWN. `MonitoringInterval=0` alone currently does not turn the older enhanced-monitoring ARN check into FAIL. S3 encryption not-found remains UNKNOWN intentionally. Public bucket ACL groups remain MANUAL pending effective-control assessment.

## Shared contracts

### iam

UserDetailList/RoleDetailList -> UserPolicyList/RolePolicyList[].PolicyDocument; AssumeRolePolicyDocument; LoginProfile.LoginProfile; MFADevices.items.

Only benign s3:GetObject, broad Allow and quoted URL-encoded documents exercised across all inline controls; no complete action-universe, Deny, condition, boundary, group, SCP or effective-access proof. Conditional/public NotAction trust and documented no-login branch separately tested. Services-last-accessed collection is out of scope.

Official sources: [API_GetAccountAuthorizationDetails.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountAuthorizationDetails.html), [API_GetLoginProfile.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetLoginProfile.html), [API_ListMFADevices.html](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListMFADevices.html).

### instance

Reservations[].Instances[] keeps InstanceId,State.Name,VpcId,PublicIpAddress,IamInstanceProfile.{Arn,Id},KeyName.

Running instance IPv4/profile/key/VPC branches only; no reachability, effective role access or complete state/IPv6 coverage. No synthetic fields substituted for native optional omissions. Extra extension stages unrelated to these fields were not executed.

Official sources: [API_Instance.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Instance.html), [API_IamInstanceProfile.html](https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IamInstanceProfile.html).

### bucket

Each named bucket detail is the full native response under its own collected/empty/denied envelope, not a flattened payload. get_object_lock_configuration.ObjectLockConfiguration is nested; no claim about the separately owned sw35 check..

us-east-1 authenticated GetBucketLocation omission and selected successful/not-found branches only; no directory buckets, alternate Regions, cross-account callers or exhaustive malformed-subfield coverage. ACL group grants remain MANUAL in base control; configured encryption says nothing about historical objects. This is bucket metadata, not sampled object ACL or bucket-wide public safety.

Official sources: [API_GetBucketOwnershipControls.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketOwnershipControls.html), [API_GetObjectLockConfiguration.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLockConfiguration.html), [API_GetBucketVersioning.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketVersioning.html), [API_GetPublicAccessBlock.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html), [API_GetBucketEncryption.html](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketEncryption.html).

### rds_instance

DBInstances[].BackupRetentionPeriod,DBSubnetGroup.VpcId,EnhancedMonitoringResourceArn,MonitoringInterval; no synthetic monitor flag.

Backup 7/0-day thresholds plus present/omitted VPC/monitor ARN only; replica/Aurora eligibility, engine-specific support, and monitoring functionality not proved. BacktrackingSupported and unrelated RDS fixes are outside this review.

Official sources: [API_DBInstance.html](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DBInstance.html).

### cloudtrail

Status.IsLogging and EventSelectors.{TrailARN,EventSelectors[],AdvancedEventSelectors[]} are detail envelopes. Missing KmsKeyId is explicitly derived as empty string from successful DescribeTrails..

Basic All management selectors, logging toggle, KMS omission and validation toggle tested; no full advanced-selector truth table, all management-source exclusions, organization trails, multiple-shadow-trail joins or delivery health proof. Scope subject generation separately exercised by immutable snapshot engine.

Official sources: [API_GetEventSelectors.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetEventSelectors.html), [API_EventSelector.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_EventSelector.html), [API_GetTrailStatus.html](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_GetTrailStatus.html).

## Per-ID matrix

PASS/alternate/denied are observed bounded test outcomes. “Validated” never means every helper branch or every dependency field is complete.

| Active check ID | Group | Disposition | Alternate / denied | Remaining detail |
|---|---|---|---|---|
| `aws.claude2_a.cloudtrail.region_has_logging_trail` | cloudtrail | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.ec2.instance_in_vpc` | instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.ec2.instance_no_public_ip` | instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.ec2.instance_no_public_ip_not_terminated` | instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.ec2.instance_profile_attached` | instance | fixed malformed fact false pass | FAIL / UNKNOWN | Confirmed malformed retained nested evidence returned PASS before the authorized guard; missing/empty/denied identifiers/documents now UNKNOWN. Native complete and configured-absence branches preserved. |
| `aws.claude_a.ec2.instance_profile_attached_not_terminated` | instance | fixed malformed fact false pass | FAIL / UNKNOWN | Confirmed malformed retained nested evidence returned PASS before the authorized guard; missing/empty/denied identifiers/documents now UNKNOWN. Native complete and configured-absence branches preserved. |
| `aws.claude_a.ec2.internet_facing_without_profile` | instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.ec2.public_instance_has_profile` | instance | fixed malformed fact false pass | FAIL / UNKNOWN | Confirmed malformed retained nested evidence returned PASS before the authorized guard; missing/empty/denied identifiers/documents now UNKNOWN. Native complete and configured-absence branches preserved. |
| `aws.claude_a.ec2.running_instance_no_key_pair` | instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_role_inline_no_admin` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_role_inline_no_cloudtrail_full_access` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_role_inline_no_kms_full_access` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_role_inline_no_marketplace_subscribe` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_role_inline_no_privilege_escalation` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_user_inline_no_admin` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_user_inline_no_cloudtrail_full_access` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_user_inline_no_kms_full_access` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_user_inline_no_marketplace_subscribe` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.prowler_user_inline_no_privilege_escalation` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.role_inline_kms_decrypt_restricted` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.role_inline_no_admin` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.role_inline_no_blocked_kms_actions` | iam | bounded sdk contract validated | FAIL / UNKNOWN | The Steampipe-specific literal action set does not expand Action="*"; full-admin risk is covered by separate admin checks. Do not present this as complete KMS effective-access analysis. |
| `aws.claude_a.iam.user_inline_kms_decrypt_restricted` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.user_inline_no_admin` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.iam.user_inline_no_assume_role_text` | iam | fixed malformed fact false pass | FAIL / UNKNOWN | Confirmed malformed retained nested evidence returned PASS before the authorized guard; missing/empty/denied identifiers/documents now UNKNOWN. Native complete and configured-absence branches preserved. |
| `aws.claude_a.iam.user_inline_no_blocked_kms_actions` | iam | bounded sdk contract validated | FAIL / UNKNOWN | The Steampipe-specific literal action set does not expand Action="*"; full-admin risk is covered by separate admin checks. Do not present this as complete KMS effective-access analysis. |
| `aws.claude_a.s3.acls_prohibit_user_access` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.s3.bucket_public_access_block_all` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.s3.lifecycle_rule_enabled` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.s3.object_lock_configured` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.claude_a.s3.replication_rule_enabled` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.cloudtrail.kms_encryption` | cloudtrail | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.cloudtrail.management_events` | cloudtrail | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.gap.cloudtrail.trail_security_best_practices` | cloudtrail | fixed native identity and coverage false pass | FAIL / UNKNOWN | Group bounds apply. |
| `aws.iam.console_mfa` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.iam.restrict_public_trust` | iam | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.rds.backups` | rds_instance | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.rds.enhanced_monitoring` | rds_instance | conservative unknown on native omission | UNKNOWN / UNKNOWN | Native omission returns UNKNOWN; this is an observable coverage limitation, not fabricated PASS or an unproduced synthetic field. |
| `aws.rds.vpc_configuration` | rds_instance | conservative unknown on native omission | UNKNOWN / UNKNOWN | Native omission returns UNKNOWN; this is an observable coverage limitation, not fabricated PASS or an unproduced synthetic field. |
| `aws.s3.access_logging` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.s3.default_encryption` | bucket | bounded sdk contract validated | UNKNOWN / UNKNOWN | Legacy not-found encryption receipt is UNKNOWN because automatic SSE-S3 baseline does not prove the absent historical configuration unsafe. |
| `aws.s3.no_public_acl` | bucket | bounded sdk contract validated | MANUAL / UNKNOWN | Public bucket ACL group yields MANUAL, not FAIL; ownership/BPA effectiveness needs separate controls. |
| `aws.s3.public_access_block` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |
| `aws.s3.versioning` | bucket | bounded sdk contract validated | FAIL / UNKNOWN | Group bounds apply. |

The JSON assigns every enumerated field to its tested producer/nesting contract, records local source digests and lists the exact counterexamples. Unenumerated direct dictionary accesses and untested branches remain explicitly unproved.

Validation: **205 targeted tests pass** with ordinary pytest hooks: `.venv/bin/python -m pytest -q tests/test_aws_core_semantic_review_20261019.py tests/test_peaso_checks_aws_gap_core.py`. Receipt: `/tmp/peasso-aws-review-20261019/core-semantic-tests.xml`. No cloud writes, live content retrieval, deployment, build or full-suite run.
