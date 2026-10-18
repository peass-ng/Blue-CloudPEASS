# PEASO claude_aws_a coverage

Partition: `claude_aws_a` in `peaso/rulepacks/port_partitions_claude.json`, which has 494 AWS rows:
- 288 `aws-compliance.control.*`
- 185 `prowler.aws.*`
- 21 `aws-perimeter.control.*`

## Counts

| Disposition | Rows |
|---|---|
| Ported (native predicate) | 392 |
| Merged (existing equivalent native check) | 31 (14 new merges, 17 taken over from Codex shards) |
| Manual attestation | 19 |
| Rejected (invalid predicate, with official evidence) | 52 (34 new, 18 taken over from Codex shards) |
| **Total** | **494** |

The ported rows use 324 unique native predicates, all with the prefix `aws.claude_a.*`. Each predicate carries every source framework, plus "HackTricks Cloud Best Practices".

## Modules

- `peaso/checks/claude_aws_a.py`: the aggregator. It holds the MERGED, EXISTING, MANUAL and REJECTED tables, `ported()`, `dispositions()` and MERGE_MODULES.
- `peaso/checks/claude_aws_a_common.py`: `install()`, fixtures and helpers.
- `peaso/checks/claude_aws_a_ec2.py`: EC2, EBS, AMI and ENI.
- `peaso/checks/claude_aws_a_network.py`: VPC, security groups, NACLs, endpoints, peering, VPN and Network Firewall.
- `peaso/checks/claude_aws_a_iam.py`, `claude_aws_a_iam_prowler.py` and `claude_aws_a_iam_catalog.py`: IAM.
- `peaso/checks/claude_aws_a_lib_agentcore.py`, `claude_aws_a_lib_passrole.py` and `claude_aws_a_lib_trust.py`: shared IAM policy analysis libraries.
- `peaso/checks/claude_aws_a_security.py`: GuardDuty, Security Hub, Macie, Organizations, Access Analyzer and KMS.
- `peaso/checks/claude_aws_a_s3.py`: S3.

Shards (generated, sorted JSON):
- `peaso/rulepacks/reviewed_claude_aws_a.json`: 475 rows (ported 392, merged 31, rejected 52).
- `peaso/rulepacks/reviewed_claude_aws_a_manual.json`: 19 rows. Each is `disposition: rejected` with `review_classification: manual_attestation`, a `manual_requirement` and empty `native_checks`.

Registry line added to `peaso/checks/__init__.py`: `from . import claude_aws_a  # noqa: E402,F401`

## Note for the leader: merge targets outside the registry

These Codex modules hold merge targets, but `peaso/checks/__init__.py` does not import them:
- `aws_a_s3`
- `aws_a_account`
- `aws_a_iam_lifecycle`
- `aws_a_iam_usage`
- `aws_a_accessanalyzer`
- `aws_a_kms`
- `aws_a_cloudtrail_variants`

Their shards are also not admitted in `active_reviews.json`.

The tests import them via `claude_aws_a.MERGE_MODULES`. At runtime, the merged rows that point at them (for example `aws.a.s3.*`, `aws.a.account.*` and `aws.a.iam.user_no_direct_policies`) only become live once the leader registers those modules.

The other merge targets are already registered: `aws.s3.versioning`, `aws.s3.access_logging`, `aws.b.classic_elb.connection_draining` and `aws.a.cloudwatch.log_kms_encryption`.

## Deliberate deviations and semantics notes

**S3 object-level logging** (`aws.claude_a.s3.object_level_logging`)
- CloudTrail is joined only within the scan's regional scope.
- A bucket homed outside the scope region returns UNKNOWN, never FAIL.

**Prowler cross-region replication** (`aws.claude_a.s3.prowler_cross_region_replication`)
- When the destination bucket is not in the inventory, the check returns MANUAL.
- This mirrors Prowler's "cannot determine destination region" path.

**S3 policy public-principal evaluation** (`aws.claude_a.s3.policy_restrict_public_access`)
- It follows the source SQL CASE order: AWS, then CanonicalUser, then Federated.
- It uses the source's exact restricting condition operator/key pairs.

**Prowler group-kind test**
- The Prowler `kind in "Group"` substring test is kept as written to preserve source semantics.

**Denied data**
- A denied bucket policy, ACL or any other detail (`collection_status: denied`) returns UNKNOWN.

**Applicability**
- Resource-type applicability gives NOT_APPLICABLE. Examples: interface vs gateway endpoints, default vs custom NACLs, in-use vs unattached ENIs and volumes.

## COLLECTOR FACTS NEEDED

The predicates below return UNKNOWN until `peaso/collectors/aws.py`, which Codex owns, gathers these facts. All the listed APIs are read-only.

### New resource kinds

| Kind | Fields | Read-only API |
|---|---|---|
| `backup_protected_resource` | ResourceArn, ResourceType | backup:ListProtectedResources |
| `backup_selection` | BackupPlanId, SelectionName, Resources, ListOfTags | backup:ListBackupPlans, backup:ListBackupSelections, backup:GetBackupSelection |
| `batch_compute_environment` | computeEnvironmentName, computeResources.securityGroupIds | batch:DescribeComputeEnvironments |
| `ec2_client_vpn_endpoint` | ClientVpnEndpointId, ConnectionLogOptions | ec2:DescribeClientVpnEndpoints |
| `ec2_eip` | AllocationId, AssociationId, Domain, PublicIp | ec2:DescribeAddresses |
| `ec2_instance_image` | ImageId, DeprecationTime, ImageOwnerAlias (the AMIs used by instances) | ec2:DescribeImages |
| `ec2_launch_template` | LaunchTemplateId/Name, DefaultVersionNumber, Versions[].LaunchTemplateData | ec2:DescribeLaunchTemplates, ec2:DescribeLaunchTemplateVersions |
| `ec2_spot_fleet_request` | SpotFleetRequestId, SpotFleetRequestConfig | ec2:DescribeSpotFleetRequests |
| `ssm_managed_instance` | InstanceId, PingStatus | ssm:DescribeInstanceInformation |
| `guardduty_finding` | Id, Arn, Service.Archived | guardduty:ListFindings, guardduty:GetFindings |
| `guardduty_organization_admin_account` | AdminAccountId, AdminStatus | guardduty:ListOrganizationAdminAccounts |
| `iam_organization_features` | EnabledFeatures | iam:ListOrganizationsFeatures |
| `iam_saml_provider` | Arn | iam:ListSAMLProviders |
| `macie2_classification_job` | jobId, s3JobDefinition.bucketDefinitions[].buckets | macie2:ListClassificationJobs, macie2:DescribeClassificationJob |
| `network_firewall` | FirewallName/Arn, FirewallPolicyArn, VpcId, SubnetMappings, DeleteProtection, SubnetChangeProtection, LoggingConfiguration | network-firewall:ListFirewalls, network-firewall:DescribeFirewall, network-firewall:DescribeLoggingConfiguration |
| `network_firewall_policy` | FirewallPolicy, FirewallPolicyResponse | network-firewall:DescribeFirewallPolicy |
| `network_firewall_rule_group` | RuleGroup, RuleGroupResponse | network-firewall:DescribeRuleGroup |
| `organization_policy` | Id, Type, Content, Targets | organizations:ListPolicies (Filter), organizations:DescribePolicy, organizations:ListTargetsForPolicy |
| `s3_access_point` | Name, Bucket, AccessPointArn, PublicAccessBlockConfiguration | s3control:ListAccessPoints, s3control:GetAccessPoint |
| `s3_directory_bucket` | Name, Lifecycle | s3:ListDirectoryBuckets, s3:GetBucketLifecycleConfiguration |
| `s3_multi_region_access_point` | Name, Alias, PublicAccessBlock, Regions | s3control:ListMultiRegionAccessPoints (us-west-2 control endpoint) |
| `securityhub_hub` | HubArn, EnabledStandards, ProductSubscriptions, OrganizationConfiguration | securityhub:DescribeHub, securityhub:GetEnabledStandards, securityhub:ListEnabledProductsForImport, securityhub:DescribeOrganizationConfiguration |
| `securityhub_organization_admin_account` | AccountId, Status | securityhub:ListOrganizationAdminAccounts |
| `vpc_account_inventory` | AccountId, Region, VpcId, IsDefault | ec2:DescribeVpcs in every enabled region |
| `vpc_block_public_access_options` | VpcBlockPublicAccessOptions | ec2:DescribeVpcBlockPublicAccessOptions |
| `vpc_endpoint_service` | ServiceId, ServiceName, Owner, AcceptanceRequired, AllowedPrincipals | ec2:DescribeVpcEndpointServiceConfigurations, ec2:DescribeVpcEndpointServicePermissions |

### New fields on kinds already collected

| Kind.field | Read-only API |
|---|---|
| `bucket.Website` | s3:GetBucketWebsite |
| `guardduty_detector.Administrator` | guardduty:GetAdministratorAccount |
| `guardduty_detector.Members` | guardduty:ListMembers |
| `guardduty_detector.FindingIds` / `HighSeverityFindingIds` | guardduty:ListFindings (criteria on severity, not archived) |
| `guardduty_detector.OrganizationConfiguration` | guardduty:DescribeOrganizationConfiguration |
| `aws_account_configuration.DelegatedAdministrators` | organizations:ListDelegatedAdministrators |
| `access_analyzer.Findings` (per analyzer) | access-analyzer:ListFindings / ListFindingsV2 |
| `iam_user.ServicesLastAccessed` / `iam_role.ServicesLastAccessed` | iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails |
| KMS key tags and aliases (context for the manual enclave rows) | kms:ListResourceTags, kms:ListAliases |

## Dispositions

### Merged rows

| Row | Native target |
|---|---|
| `aws-compliance.control.ec2_classic_lb_connection_draining_enabled` | `aws.b.classic_elb.connection_draining` |
| `aws-compliance.control.foundational_security_account_1` | `aws.a.account.security_contact_present` |
| `aws-compliance.control.foundational_security_elb_7` | `aws.b.classic_elb.connection_draining` |
| `aws-compliance.control.foundational_security_s3_9` | `aws.s3.access_logging` |
| `aws-compliance.control.log_group_encryption_at_rest_enabled` | `aws.a.cloudwatch.log_kms_encryption` |
| `aws-compliance.control.s3_bucket_default_encryption_enabled` | `aws.a.s3.default_encryption_configuration` |
| `aws-compliance.control.s3_bucket_logging_enabled` | `aws.s3.access_logging` |
| `aws-compliance.control.s3_bucket_mfa_delete_enabled` | `aws.a.s3.mfa_delete_enabled` |
| `aws-compliance.control.s3_bucket_versioning_enabled` | `aws.s3.versioning` |
| `aws-compliance.control.s3_public_access_block_bucket_account` | `aws.a.s3.bucket_account_public_blocks` |
| `prowler.aws.iam_policy_attached_only_to_group_or_roles` | `aws.a.iam.user_no_direct_policies` |
| `prowler.aws.organizations_account_part_of_organizations` | `aws.a.account.organization_member` |
| `prowler.aws.s3_bucket_default_encryption` | `aws.a.s3.default_encryption_configuration` |
| `prowler.aws.s3_bucket_no_mfa_delete` | `aws.a.s3.mfa_delete_enabled` |

### Rows taken over from Codex review shards

| Row | Disposition |
|---|---|
| `aws-compliance.control.foundational_security_cloudtrail_2` | merged -> `aws.a.cloudtrail.home_kms_encryption` |
| `aws-compliance.control.foundational_security_cloudtrail_5` | merged -> `aws.a.cloudtrail.home_cloudwatch_date` |
| `aws-compliance.control.foundational_security_iam_2` | merged -> `aws.a.iam.user_no_direct_policies` |
| `aws-compliance.control.foundational_security_iam_3` | merged -> `aws.a.iam.active_key_age_90` |
| `aws-compliance.control.foundational_security_iam_6` | merged -> `aws.a.iam.root_hardware_mfa` |
| `aws-compliance.control.foundational_security_iam_8` | merged -> `aws.a.iam.unused_credentials_90_days` |
| `aws-compliance.control.iam_access_analyzer_enabled` | merged -> `aws.a.accessanalyzer.region_present` |
| `aws-compliance.control.iam_root_last_used` | rejected |
| `aws-compliance.control.iam_root_user_hardware_mfa_enabled` | merged -> `aws.a.iam.root_hardware_mfa` |
| `aws-compliance.control.iam_server_certificate_not_expired` | merged -> `aws.a.iam.server_certificate_expiry_date` |
| `aws-compliance.control.iam_support_role` | rejected |
| `aws-compliance.control.iam_user_access_key_age_90` | merged -> `aws.a.iam.active_key_age_90` |
| `aws-compliance.control.iam_user_access_keys_and_password_at_setup` | merged -> `aws.a.iam.console_key_created_at_setup` |
| `aws-compliance.control.iam_user_no_inline_attached_policies` | merged -> `aws.a.iam.user_no_direct_policies` |
| `aws-compliance.control.iam_user_no_policies` | merged -> `aws.a.iam.user_no_managed_policies` |
| `aws-compliance.control.iam_user_unused_credentials_45` | merged -> `aws.a.iam.unused_credentials_45_days` |
| `aws-compliance.control.iam_user_unused_credentials_90` | merged -> `aws.a.iam.unused_credentials_90_days` |
| `aws-compliance.control.kms_cmk_rotation_enabled` | merged -> `aws.a.kms.rotation_source_eligibility` |
| `aws-compliance.control.log_metric_filter_bucket_policy` | rejected |
| `aws-compliance.control.log_metric_filter_cloudtrail_configuration` | rejected |
| `aws-compliance.control.log_metric_filter_config_configuration` | rejected |
| `aws-compliance.control.log_metric_filter_console_authentication_failure` | rejected |
| `aws-compliance.control.log_metric_filter_console_login_mfa` | rejected |
| `aws-compliance.control.log_metric_filter_disable_or_delete_cmk` | rejected |
| `aws-compliance.control.log_metric_filter_iam_policy` | rejected |
| `aws-compliance.control.log_metric_filter_network_acl` | rejected |
| `aws-compliance.control.log_metric_filter_network_gateway` | rejected |
| `aws-compliance.control.log_metric_filter_organization` | rejected |
| `aws-compliance.control.log_metric_filter_root_login` | rejected |
| `aws-compliance.control.log_metric_filter_route_table` | rejected |
| `aws-compliance.control.log_metric_filter_security_group` | rejected |
| `aws-compliance.control.log_metric_filter_unauthorized_api` | rejected |
| `aws-compliance.control.log_metric_filter_vpc` | rejected |
| `aws-compliance.control.organizational_tag_policies_enabled` | rejected |
| `prowler.aws.guardduty_is_enabled` | merged -> `aws.a.guardduty.region_enabled` |

### Rejected rows (invalid predicate)

| Row | Reason | Evidence |
|---|---|---|
| `aws-compliance.control.ec2_instance_no_iam_passrole_and_lambda_invoke_function_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_attached_with_credentials_exposure_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_alter_critical_s3_permissions_configuration` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_cloud_log_tampering_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_data_destruction_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_database_management_write_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_defense_evasion_impact_of_aws_security_services_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_destruction_kms_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_destruction_rds_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_elastic_ip_hijacking_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_management_level_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_new_group_creation_with_attached_policy_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_new_role_creation_with_attached_policy_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_new_user_creation_with_attached_policy_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_org_write_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_privilege_escalation_risk_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_security_group_write_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_write_access_to_resource_based_policies` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_role_with_write_permission_on_critical_s3_configuration` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.ec2_instance_no_iam_with_write_level_access` | The query reads the actions of the role's assume_role_policy (trust policy) statements for Principal.Service ec2.amazonaws.com. A trust policy only says who may assume the role (sts:AssumeRole); permissions come from the role's identity policies, so the listed permission actions never appear and the control cannot alarm for a role that actually holds them. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.foundational_security_s3_3` | CASE branch 3 returns ok when bucket_policy_is_public and no Allow s3:Put*/Delete* policy statement exists, without re-checking the ACL: a bucket with an AllUsers WRITE ACL grant (BlockPublicAcls off) and a public read-only policy is reported ok. | https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html |
| `aws-compliance.control.foundational_security_s3_5` | Full ssl_ok CTE inspected: Action and Resource are expanded but neither is constrained; any Deny wildcard-principal statement with Bool aws:SecureTransport=false passes. A valid policy denying only s3:DeleteBucket over HTTP leaves GetObject on object ARNs reachable over HTTP yet passes. Same evaluator as the Codex rejection of cis_v130_2_1_2. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html |
| `aws-compliance.control.iam_policy_custom_no_permissive_role_assumption` | policy_std lowercases actions, but the query compares with the literal 'sts:AssumeRole', which can never match: a customer policy allowing sts:AssumeRole on Resource * passes. IAM documents action names as case insensitive. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html |
| `aws-compliance.control.iam_role_cross_account_write_access_policy` | The query looks for Principal.AWS ['*'] / Principal.Service ['*'] inside managed (identity-based) policies attached to the role. IAM documents that the Principal element cannot be used in identity-based policies, so the containment test never matches and the control cannot alarm. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html |
| `aws-compliance.control.iam_security_audit_role` | The WHERE policy_arn = SecurityAudit filter runs after the account LEFT JOIN and before GROUP BY: an account with no role holding SecurityAudit produces no row, so the count=0 alarm branch can never be emitted (same defect class as the Codex iam_support_role rejection). | https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListAttachedRolePolicies.html https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html |
| `aws-compliance.control.iam_user_access_key_unused_45` | CASE returns ok as soon as access_key_1 is inactive, before access_key_2 is evaluated: a user with key 1 inactive and an active key 2 never used (or unused for a year) is ok. The credential report documents access_key_2_active/last_used_date as independent columns. | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html |
| `aws-compliance.control.iam_user_hardware_mfa_enabled` | The query right-joins ListVirtualMFADevices to users: a user with only a hardware MFA device has no virtual device row, so serial_number is null and the user alarms; users with a virtual device (serial arn:...:mfa/...) are info. No user can reach ok. ListVirtualMFADevices returns virtual MFA devices only. | https://docs.aws.amazon.com/IAM/latest/APIReference/API_ListVirtualMFADevices.html |
| `aws-compliance.control.s3_bucket_enforces_ssl` | Full ssl_ok CTE inspected: Action and Resource are expanded but neither is constrained; any Deny wildcard-principal statement with Bool aws:SecureTransport=false passes. A valid policy denying only s3:DeleteBucket over HTTP leaves GetObject on object ARNs reachable over HTTP yet passes. Same evaluator as the Codex rejection of cis_v130_2_1_2. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_resource.html |
| `aws-compliance.control.s3_bucket_restrict_public_write_access` | CASE branch 3 returns ok when bucket_policy_is_public and no Allow s3:Put*/Delete* policy statement exists, without re-checking the ACL: a bucket with an AllUsers WRITE ACL grant (BlockPublicAcls off) and a public read-only policy is reported ok. | https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html |
| `aws-perimeter.control.s3_bucket_acl_prohibit_public_read_access` | The query alarms only on FULL_CONTROL/READ_ACP grants to AllUsers/AuthenticatedUsers. AWS documents that READ on a bucket allows the grantee to list the objects in the bucket, so a public READ grant (the most common public ACL) passes. | https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html |
| `aws-perimeter.control.s3_bucket_acl_prohibit_public_write_access` | The query alarms only on FULL_CONTROL/WRITE_ACP grants to AllUsers/AuthenticatedUsers. AWS documents that WRITE on a bucket allows the grantee to create new objects in the bucket, so a public WRITE grant (the most common public ACL) passes. | https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html |
| `aws-perimeter.control.vpc_security_group_restrict_ingress_common_ports_all` | Each port test is from_port >= p and to_port <= p (and 9200-9300 as from_port >= 9200 and to_port <= 9300), which matches only rules whose range lies inside the listed port: a TCP 0-65535 rule from 0.0.0.0/0, which opens all of them, passes. EC2 documents FromPort/ToPort as the start/end of the range. | https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html |
| `prowler.aws.iam_avoid_root_usage` | Only the first non-default field is evaluated (password_last_used, else key 1, else key 2): a root password last used 200 days ago with a root access key used yesterday passes. The credential report documents the three last-used columns independently. | https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html |
| `prowler.aws.s3_bucket_secure_transport_policy` | Prowler passes when any Deny statement with aws:SecureTransport=false has an Action containing 's3:PutObject' (or '*'/'s3:*'), regardless of Resource and Principal: a Deny of s3:PutObject only over HTTP leaves GetObject reachable over HTTP yet passes; a Deny on a non-object resource also passes. Action and Resource semantics make this a false PASS. | https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html |

### Manual attestation rows

| Row | Question |
|---|---|
| `aws-compliance.control.ec2_instance_no_high_level_finding_in_inspector_scan` | Do EC2 instances have no High severity findings in Amazon Inspector scans? |
| `aws-compliance.control.ec2_instance_user_data_no_secrets` | Is EC2 instance user data free of secrets (passwords, tokens, keys)? |
| `aws-perimeter.control.ebs_snapshot_shared_with_trusted_accounts` | Are EBS snapshots shared (createVolumePermission) only with trusted AWS accounts? |
| `aws-perimeter.control.ec2_ami_shared_with_trusted_accounts` | Are EC2 AMIs shared (launchPermission UserId) only with trusted AWS accounts? |
| `aws-perimeter.control.ec2_ami_shared_with_trusted_organization_units` | Are EC2 AMIs shared (launchPermission OrganizationalUnitArn) only with trusted organizational units? |
| `aws-perimeter.control.ec2_ami_shared_with_trusted_organizations` | Are EC2 AMIs shared (launchPermission OrganizationArn) only with trusted organizations? |
| `aws-perimeter.control.guarduty_findings_shared_with_trusted_accounts` | Are GuardDuty findings shared only with a trusted administrator account? |
| `aws-perimeter.control.vpc_peering_connection_cross_account_shared` | Are VPCs peered only with trusted AWS accounts? |
| `prowler.aws.ec2_elastic_ip_shodan` | Is no Elastic IP address of the account listed in Shodan? |
| `prowler.aws.ec2_instance_secrets_user_data` | Does EC2 instance user data contain no secrets? |
| `prowler.aws.ec2_launch_template_no_secrets` | Does every version of every EC2 launch template contain no secrets in user data? |
| `prowler.aws.kms_key_enclave_attestation_bypassable_path` | Does no authorization path in the KMS enclave key policy let principals use the key without kms:RecipientAttestation? |
| `prowler.aws.kms_key_enclave_attestation_no_deployment_binding` | Does the KMS enclave key attestation bind a specific deployment context (instance/account/role), not only image PCRs? |
| `prowler.aws.kms_key_enclave_attestation_not_enforced` | Do sensitive actions on the KMS enclave key require kms:RecipientAttestation conditions? |
| `prowler.aws.kms_key_enclave_attestation_pcr_mismatch` | Do the KMS enclave key policy attestation PCRs match the customer's golden values? |
| `prowler.aws.kms_key_enclave_attestation_unknown_image` | Has no enclave with an unknown image identity called this KMS key? |
| `prowler.aws.kms_key_enclave_debug_attestation_detected` | Has no Nitro Enclave debug-mode attestation been observed against this KMS key? |
| `prowler.aws.s3_bucket_object_public` | Do spot-checked objects in each S3 bucket carry no public object ACL grants (AllUsers/AuthenticatedUsers)? |
| `prowler.aws.s3_bucket_shadow_resource_vulnerability` | Are none of the service-pattern S3 bucket names used by this account (CloudFormation, Glue, EMR, SageMaker, Athena, ...) pre-claimed by another account? |

## Tests

| Command | Result |
|---|---|
| `python3 -m pytest tests/test_peaso_checks_claude_aws_a*.py -q` | 564 passed |
| `python3 -m pytest tests/test_peaso_checks_claude_aws_a.py tests/test_catalog_review.py tests/test_peaso_catalog_audit.py tests/test_peaso_catalog_summary.py tests/test_peaso_engine_coverage.py tests/test_peaso_checks.py -q` | 13204 passed |
| `python3 -m peaso catalog` | loads (2496 checks, of which 324 are `aws.claude_a.*`; no duplicate ids) |

Each predicate is tested for:
- PASS, FAIL, UNKNOWN, missing data, malformed data and denied data
- NOT_APPLICABLE where it applies, plus named variants
- never returning FAIL when a dependency inventory is missing

The tests also check:
- every partition row has exactly one disposition
- the shards match `claude_aws_a.dispositions()`
