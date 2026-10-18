# PEASO claude2_aws_a coverage

The `claude2_aws_a` partition in `peaso/rulepacks/port_partitions_claude2.json` has 323 upstream rows: 294 aws-compliance controls, 26 Prowler AWS checks and 3 aws-perimeter controls. These rows were taken over from stalled Codex workers.

**Files**
- `peaso/checks/claude2_aws_a.py`: dispositions, with MERGED, REJECTED and MANUAL (MANUAL is empty).
- `peaso/checks/claude2_aws_a_cloudtrail.py` and `peaso/checks/claude2_aws_a_misc.py`: the native predicates.
- `peaso/checks/claude2_aws_a_common.py`: helpers and the fixture index builder.
- `peaso/checks/claude2_aws_a_rows.py`: the pinned query to benchmark-row map, plus `HELD_ELSEWHERE`.
- `peaso/rulepacks/reviewed_claude2_aws_a.json` and `peaso/rulepacks/reviewed_claude2_aws_a_manual.json` (the manual shard is empty, `{}`).
- `tests/test_peaso_checks_claude2_aws_a.py`.

## Counts

| | Rows |
|---|---|
| Partition | 323 |
| Dropped: already held by another active shard (duplicate-ownership rule) | 279 |
| In this shard | 44 |
| Ported | 12 (12 unique native predicates, prefix `aws.claude2_a.`) |
| Merged into existing registered natives | 13 |
| Manual | 0 |
| Rejected | 19 (18 `invalid_predicate`, 1 `intrusive_unsuitable`) |

**Dropped rows.** When the shard was finished, `active_reviews.json` already listed these shards as holding 279 of the partition rows (ported, merged or rejected):
- `reviewed_aws_a_accessanalyzer`, `_account_presence`, `_cloudtrail_variants`;
- `_iam_key_join`, `_iam_lifecycle`, `_iam_policies`, `_iam_usage`;
- `_kms`, `_prowler_metric_identity`, `_s3`, `_shared_aliases`, `_source_counterexamples`.

Those rows are listed in `HELD_ELSEWHERE` (row to holding shard) and are excluded from the shard. The review tables in `claude2_aws_a.py` still record how this partition would have disposed of them, which agrees with the holding shards.

**Superseded row.** `prowler.aws.cloudtrail_multi_region_enabled` is pending in `reviewed.json`. Its entry carries `"supersedes"` and keeps that row's review history.

## Ported natives

| Native (`aws.claude2_a.` +) | Rows | Notes |
|---|---|---|
| `cloudtrail.trail_bucket_mfa_delete` | cloudtrail_trail_bucket_mfa_enabled | Home-region trails, logging or not, so it differs from `aws.a.cloudtrail.bucket_mfa_delete`, which checks logging trails only. A bucket outside the account is MANUAL. |
| `cloudtrail.account_has_logging_trail` | cloudtrail_trail_enabled_account | `aws_account` plus `cloudtrail_account_inventory`, using home-region status. The Codex equivalent is not registered. |
| `cloudtrail.region_has_logging_trail` | prowler cloudtrail_multi_region_enabled | Scope check: any trail homed in the region, or any multi-Region trail, is logging. The Codex equivalent is not registered. |
| `cloudtrail.threat_detection_enumeration`, `cloudtrail.threat_detection_llm_jacking`, `cloudtrail.threat_detection_privilege_escalation` | the 3 prowler threat_detection rows | Prowler ratios: distinct pinned names divided by the length of the pinned list (duplicates included), with thresholds 0.3, 0.4 and 0.2. Evaluated over `aws_cloudtrail_activity` per audited region with full pagination. This fixes the upstream single-region, first-page-only lookup. An inactive Codex shard rejects these rows as not source-equivalent for that reason. |
| `cloudwatch.cross_account_sharing_role_absent` | cloudwatch_cross_account_sharing | Upstream emits `info` when the role exists, so the native returns MANUAL with the trusted principals. This differs from `aws.a.cloudwatch.cross_account_role_absent`, which returns FAIL. |
| `logs.log_group_not_public_via_resource_policy` | prowler cloudwatch_log_group_not_publicly_accessible | Uses `log_resource_policy` with `is_policy_public`. A Resource of `*` or one covering the log-group ARN exposes the group. |
| `logs.resource_policy_not_public` | perimeter cloudwatch_log_resource_policy_prohibit_public_access | Implements resource_policy_public_sql. |
| `config.aggregation_authorization_trusted` | perimeter config_aggregator_shared_with_trusted_accounts | The audited account counts as trusted; any other account is MANUAL. |
| `config.org_aggregator_all_regions_with_delegated_admin` | prowler config_delegated_admin_and_org_aggregator_all_regions | FAIL when the aggregator is not an organization aggregator, does not cover all Regions, or has no delegated admin. A denied lookup is UNKNOWN. |
| `dlm.snapshot_sharing_trusted_accounts` | perimeter dlm_ebs_snapshot_policy_shared_with_trusted_accounts | Applies to `dlm_policy` with Details. EBS policies only; DISABLED policies are NOT_APPLICABLE. Untrusted targets are MANUAL. |

Every predicate returns UNKNOWN for missing, denied or malformed facts and never FAILs on absent data. Each one has PASS, FAIL (or MANUAL) and UNKNOWN fixtures, plus named edge fixtures.

## Merged (13 rows)

| Rows | Merged into |
|---|---|
| cis_compute_service_v100_2_9 | `aws.claude_a.ec2.instance_ssm_managed` |
| cis_v120_1_19, cis_v1x0_1_18, cis_v500_1_17, cis_v600_2_17 (9 rows) | `aws.claude_a.ec2.instance_profile_attached` (the Codex `aws.a.ec2.instance_profile_arn` is not registered) |
| cloudtrail_multi_region_trail_enabled | `aws.claude_a.cloudtrail.account_has_logging_multi_region_trail` |
| cis_compute_service_v100_2_14 | `aws.c2b.autoscaling.tags_propagate` |
| cloudtrail_trail_enabled | `aws.cloudtrail.logging` |

## Rejected (19 rows)

Each rejection carries a concrete counterexample.

**s3_bucket_enforces_ssl (8 CIS rows).** The Deny statement's Action and Resource are never constrained. A policy that denies only s3:DeleteBucket over HTTP still passes. This matches the claude_aws_a rejection.

**s3_bucket_protected_by_macie (7 CIS rows).** The query only reads bucketDefinitions:
- a bucketCriteria job gives a false FAIL;
- a CANCELLED job gives a false PASS.

Replacements: `aws.cb.macie.*`.

**cloudtrail_security_trail_enabled.** For a trail with only advanced selectors, the NULL selector logic never alarms.

**ec2_instance_user_data_no_secrets** (`intrusive_unsuitable`). Evaluating it requires collecting secret-bearing user data.

**prowler cloudtrail_logs_s3_bucket_is_not_publicly_accessible.** The check only reads ACL AllUsers grants, so a public bucket policy still passes. Replacement: `aws.a.cloudtrail.joined_bucket_declared_public_grants`.

**prowler cloudtrail_bedrock_logging_enabled.** The advanced-selector branch ignores eventName/eventSource constraints, which AND together. A Data + AWS::Bedrock::Model + eventName=PutObject selector passes.

## Notes for the supervisor

- Framework mappings for the 12 natives come from this shard. Until the shard is listed in `active_reviews.json`, the natives carry only "HackTricks Cloud Best Practices".
- Merge targets come from `claude_aws_a`, `claude2_aws_b` and core `aws.py`. All of them are registered through `peaso/checks/__init__.py`.

## COLLECTOR FACTS NEEDED

All of these are read-only APIs. Until they are collected, the affected predicates return UNKNOWN.

1. **`config:DescribeConfigurationAggregators`** (paginated) as regional kind `config_aggregator`.
   - Fields: ConfigurationAggregatorName, ConfigurationAggregatorArn, OrganizationAggregationSource {RoleArn, AllAwsRegions, AwsRegions}, AccountAggregationSources.
   - Used by `config.org_aggregator_all_regions_with_delegated_admin`.
2. **`organizations:ListDelegatedAdministrators`** with ServicePrincipal=config.amazonaws.com, as global kind `config_delegated_administrator`.
   - Fields: Id, Arn, Status.
   - Calls from non-management accounts get AccessDenied, which must stay a denied envelope, giving UNKNOWN.
   - Used by the same predicate.

These are already collected and are consumed as-is:
- `log_resource_policy`
- `config_aggregate_authorization`
- `dlm_policy` with Details (GetLifecyclePolicy)
- `aws_cloudtrail_activity`
- `cloudtrail_account_inventory`
- `cloudtrail` with Status
- `bucket` with Versioning
- `iam_role`
- `aws_account`
