# PEASO claude_aws_b coverage (AWS services fsx..workspaces)

The partition is `peaso/rulepacks/port_partitions_claude.json` → `partitions.claude_aws_b`. It has 367 upstream rows: Prowler, steampipe-mod-aws-compliance and steampipe-mod-aws-perimeter.

## Files

- Native predicates:
  - `peaso/checks/claude_aws_b_storage.py`: FSx, API Gateway v2, Glacier, Glue, Firehose, Kinesis, MediaStore, Storage Gateway, WorkSpaces.
  - `peaso/checks/claude_aws_b_db.py`: RDS, Neptune, Redshift and Redshift Serverless, MemoryDB, OpenSearch.
  - `peaso/checks/claude_aws_b_messaging.py`: MQ, MSK, MSK Connect, SNS, SQS, SES, Step Functions, Transfer Family.
  - `peaso/checks/claude_aws_b_compute.py`: Lambda, Lightsail, SageMaker.
  - `peaso/checks/claude_aws_b_security.py`:
    - Inspector2, Macie, RAM, Resource Explorer, Roles Anywhere, Route 53.
    - Secrets Manager, Service Catalog, Shield, SSM, Incident Manager.
    - Trusted Advisor, WAF Classic, WAFv2, Well-Architected.
- Shared helpers: `peaso/checks/claude_aws_b_common.py`.
- Merge, manual and reject tables: `peaso/checks/claude_aws_b.py`. It also loads every submodule.
- Review shards:
  - `peaso/rulepacks/reviewed_claude_aws_b.json`: 364 rows (ported, merged, rejected).
  - `peaso/rulepacks/reviewed_claude_aws_b_manual.json`: 3 manual attestations.
- Tests: `tests/test_peaso_checks_claude_aws_b.py`.

## Counts

| Disposition | Rows |
|---|---|
| ported | 338 |
| merged into existing natives | 19 |
| manual attestation | 3 |
| rejected, intrusive secret-content scanners | 5 |
| rejected, invalid upstream predicate (replacement native provided) | 2 |
| **total** | **367** |

There are 284 unique native predicates (`aws.cb.*`). Rows that ask the same question with the same threshold share one predicate. For example, these pairs each share a predicate:
- WAF Classic Prowler and steampipe rule, rule-group, web ACL and logging rows.
- Route 53 domain privacy and transfer lock.
- WAFv2 logging.

Rows with different thresholds or semantics keep separate predicates. Examples:
- Secrets Manager unused for 90 days: the Prowler version uses a timedelta and the steampipe version uses calendar days.
- WAFv2 "with rules": Prowler counts Firewall Manager groups and steampipe does not.
- SageMaker endpoint variants: more than one versus not exactly one.
- RAM trusted accounts, organizations and OUs.

| Service | Predicates | Rows |
|---|---|---|
| apigatewayv2 | 1 | 1 |
| firehose | 1 | 1 |
| fsx | 9 | 9 |
| glacier | 3 | 3 |
| glue | 18 | 23 |
| inspector2 | 7 | 7 |
| kafka / msk / mskconnect | 10 | 13 |
| kinesis | 4 | 5 |
| lambda | 7 | 7 |
| lightsail | 8 | 8 |
| macie | 2 | 2 |
| mediastore | 1 | 1 |
| memorydb | 2 | 2 |
| mq | 5 | 6 |
| neptune | 12 | 19 |
| opensearch | 16 | 22 |
| ram | 3 | 3 |
| rds | 50 | 52 |
| redshift / redshiftserverless | 23 | 31 |
| resourceexplorer2 | 1 | 1 |
| rolesanywhere | 1 | 1 |
| route53 | 7 | 10 |
| sagemaker | 22 | 34 |
| secretsmanager | 12 | 12 |
| servicecatalog | 2 | 2 |
| ses | 2 | 2 |
| sfn / stepfunctions | 3 | 3 |
| shield | 6 | 6 |
| sns | 7 | 8 |
| sqs | 5 | 5 |
| ssm / ssmincidents | 7 | 7 |
| storagegateway | 2 | 2 |
| transfer | 4 | 5 |
| trustedadvisor | 2 | 2 |
| waf / wafregional / wafv2 | 14 | 22 |
| wellarchitected | 1 | 1 |
| workspaces | 4 | 5 |

The service column totals 343 row mappings, not 338. A few rows map to two predicates, for example a provisioned and a serverless variant.

### Merged rows

Each merged row maps to an existing native that asks the same question:

| Rows | Existing native |
|---|---|
| Prowler `rds_cluster_*` (6 rows) | aws.rds.cluster_copy_snapshot_tags, aws.b.rds_cluster.nondefault_admin, aws.rds.cluster_deletion_protection, aws.rds.cluster_iam_authentication, aws.rds.cluster_multi_az, aws.rds.cluster_encryption |
| steampipe `rds_db_instance_*` (5 rows) | aws.rds.auto_minor_upgrade, aws.rds.cloudwatch_log_exports, aws.rds.vpc_configuration (x2), aws.rds.no_public_endpoint |
| mq_broker_auto_minor_version_upgrades | aws.b.mq.automatic_minor_upgrade |
| sns_topic_encrypted_at_rest | aws.sns.kms_encryption |
| sqs_queue_encrypted_at_rest | aws.sqs.encryption |
| lambda DLQ, lambda in VPC (C and X), lambda restrict public URL | aws.lambda.* |
| secretsmanager_automatic_rotation_enabled | aws.secretsmanager.rotation |

### Rejected rows

**Secret-content scanners (`intrusive_unsuitable`).** These rows run detect-secrets over payloads that PEASO deliberately does not collect:
- glue_catalog_connection_no_secrets
- glue_etl_jobs_no_secrets_in_arguments
- sagemaker_notebook_instance_no_secrets
- ssm_document_secrets
- stepfunctions_statemachine_no_secrets_in_definition

**Invalid upstream predicates (`invalid_predicate`).**
- **opensearch_domain_audit_logging_enabled:** both CASE branches return `ok`, so the control can never alarm.
  - Replacement: `aws.cb.opensearch.audit_logs_enabled`.
  - Docs: https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html
- **opensearch_domain_https_required:** compares TLSSecurityPolicy with the literal `tlsPolicies`, which is not a valid value. It therefore alarms on every domain.
  - Replacement: `aws.cb.opensearch.enforce_https`.
  - Docs: https://docs.aws.amazon.com/opensearch-service/latest/APIReference/API_DomainEndpointOptions.html

### Manual attestations

These rows keep the exact question and their framework mappings:
- **route53_dangling_ip_subdomain_takeover:** needs an account-wide EIP/ENI join plus the AWS ip-ranges feed.
- **secretsmanager_has_restrictive_resource_policy:** depends on an organisation-specific principal allowlist.
- **rolesanywhere_profile_restricts_session_permissions:** depends on workload-specific least privilege.

### Corrected or narrowed semantics

These are documented in each check's review notes in the shard. They exist to avoid false positives.

- **SSM block public sharing:** PASS requires `SettingValue == "Disable"`. The pinned SQL treats `Enable` as ok, which is inverted per the AWS docs (documents-ssm-sharing.html#block-public-access).
- **Inspector2 enabled:** only resource types (EC2, ECR, Lambda) that have resources in the region are required. A region with none of them is NOT_APPLICABLE.
- **Macie enabled:** FAIL only in regions that hold S3 buckets, matching Prowler with scan_unused_services off.
- **Well-Architected:** a RiskCounts HIGH or MEDIUM key with a zero count is not counted as a risk.
- **RAM perimeter trusted lists:** these have no configured allowlist, so principals of the relevant type produce MANUAL with the principals to review. They never FAIL.
- **Secrets rotated_as_scheduled:** a secret that rotated within its schedule is PASS. Upstream returns a NULL status for that case.

## Behaviour contract

Every predicate follows these rules:
- **Missing data.** Missing, denied, partial or malformed facts give UNKNOWN. That covers an item `_coverage` entry, a `collection_status` other than collected/empty, or an incomplete `collections[kind]` envelope.
- **Not-found markers.** A documented API not-found marker (`{"collection_status": "empty", "absent": true}`) is treated as "not configured" only where AWS documents that meaning. Examples:
  - Macie GetMacieSession.
  - WAF GetLoggingConfiguration WAFNonexistentItemException.
  - Lambda or Secrets Manager resource policy not found.
- **Applicability.** Applicability is respected, for example: private hosted zones, replica secrets, image-package Lambda, internal ALBs, Shield without a subscription, and regions without SageMaker models.

Each predicate has PASS, FAIL (or MANUAL), UNKNOWN, missing, None and denied fixtures, plus NOT_APPLICABLE fixtures where relevant. The tests also assert that fixtures are not mutated.

## COLLECTOR FACTS NEEDED

The predicates exist, but they return UNKNOWN until the Codex-owned collector gathers these facts. All are read-only APIs.

Conventions for the collector:
- **Detail responses:** store each one with `"collection_status": "collected"`.
- **Not-found codes:** for documented not-found codes, store `{"collection_status": "empty", "absent": true, "error": {...}}`.
- **Inventory envelopes:** inventory kinds need `collections[kind]` envelopes. Use `empty` when the list call succeeded with zero items.
- **Region:** unless a kind is marked global, it is regional.

### New inventory kinds

| Kind | API calls | Fields read |
|---|---|---|
| acmpca_certificate_authority | acm-pca ListCertificateAuthorities | Arn, Status, CertificateAuthorityConfiguration.KeyAlgorithm |
| elastic_ip | ec2 DescribeAddresses | AllocationId, PublicIp, Domain |
| firehose_delivery_stream | firehose ListDeliveryStreams + DescribeDeliveryStream | DeliveryStreamARN, DeliveryStreamEncryptionConfiguration.Status |
| glacier_vault | glacier ListVaults + GetVaultAccessPolicy (ResourceNotFoundException = absent) | VaultARN, Policy.policy.Policy |
| globalaccelerator_accelerator (global, us-west-2 endpoint) | globalaccelerator ListAccelerators | AcceleratorArn, Name |
| glue_connection | glue GetConnections (HidePassword=true) | Name, ConnectionType, ConnectionProperties.JDBC_ENFORCE_SSL only (allowlist; never store credentials) |
| glue_data_catalog | glue GetDataCatalogEncryptionSettings + GetResourcePolicy | EncryptionSettings.DataCatalogEncryptionSettings.{EncryptionAtRest.CatalogEncryptionMode, ConnectionPasswordEncryption.ReturnConnectionPasswordEncrypted}, ResourcePolicy.PolicyInJson |
| glue_dev_endpoint | glue GetDevEndpoints | EndpointName, SecurityConfiguration |
| glue_ml_transform | glue GetMLTransforms | TransformId, TransformEncryption.MlUserDataEncryption.MlUserDataEncryptionMode |
| glue_table | glue GetDatabases + GetTables | Name (inventory presence) |
| inspector2_account_status | inspector2 BatchGetAccountStatus | accountId, State.status, ResourceState.{ec2,ecr,lambda,lambdaCode}.status |
| inspector2_finding | inspector2 ListFindings (findingStatus=ACTIVE) + BatchGetFindingDetails | findingArn, firstObservedAt, packageVulnerabilityDetails.vulnerabilityId, Details.cisaData.{dateAdded,dateDue} |
| inspector2_coverage | inspector2 ListCoverage | resourceId, resourceType, scanStatus.{statusCode,reason}, lastScannedAt |
| kafka_version | kafka ListKafkaVersions | Version, Status |
| kinesis_stream | kinesis ListStreams + DescribeStreamSummary | StreamARN, EncryptionType, KeyId, RetentionPeriodHours |
| lightsail_instance | lightsail GetInstances | arn, name, addOns, ipv6Addresses, publicIpAddress, networking.ports |
| lightsail_database | lightsail GetRelationalDatabases | arn, name, publiclyAccessible |
| lightsail_static_ip | lightsail GetStaticIps | arn, name, isAttached |
| macie_session | macie2 GetMacieSession (not enabled = absent) + GetAutomatedDiscoveryConfiguration | accountId, Session.status, AutomatedDiscovery.status |
| media_store_container | mediastore ListContainers + GetContainerPolicy | ARN, Policy.Policy |
| msk_cluster | kafka ListClustersV2 | ClusterArn, ClusterType, Provisioned.{EncryptionInfo, ClientAuthentication, BrokerNodeGroupInfo.ConnectivityInfo.PublicAccess.Type, CurrentBrokerSoftwareInfo.KafkaVersion, EnhancedMonitoring}, Serverless.VpcConfigs |
| mskconnect_connector | kafkaconnect ListConnectors + DescribeConnector | connectorArn, kafkaClusterEncryptionInTransit.encryptionType, logDelivery.workerLogDelivery.cloudWatchLogs.{enabled,logGroup} |
| organization (global) | organizations DescribeOrganization (AWSOrganizationsNotInUseException = empty inventory) | Organization.{Id,Arn} |
| ram_resource_share | ram GetResourceShares(resourceOwner=SELF) + GetResourceShareAssociations (PRINCIPAL and RESOURCE) | resourceShareArn, name, status, PrincipalAssociations.resourceShareAssociations[{associatedEntity,status}], ResourceAssociations.resourceShareAssociations[...] |
| rds_db_subnet_group | rds DescribeDBSubnetGroups | DBSubnetGroupName, VpcId, Subnets[].SubnetAvailabilityZone |
| rds_engine_version | rds DescribeDBEngineVersions | Engine, EngineVersion |
| redshift_subnet_group | redshift DescribeClusterSubnetGroups | ClusterSubnetGroupName, Subnets |
| redshiftserverless_namespace | redshift-serverless ListNamespaces | namespaceArn, adminUsername, dbName, logExports |
| redshiftserverless_workgroup | redshift-serverless ListWorkgroups | workgroupArn, publiclyAccessible, enhancedVpcRouting, configParameters |
| resourceexplorer2_index | resource-explorer-2 ListIndexes | Arn, Region, Type |
| rolesanywhere_trust_anchor | rolesanywhere ListTrustAnchors | trustAnchorArn, source.sourceType, source.sourceData.acmPcaArn (never store certificate bodies) |
| route53_domain (global, us-east-1) | route53domains ListDomains + GetDomainDetail | DomainName, Detail.{AutoRenew, AdminPrivacy, StatusList, ExpirationDate} (contact PII not needed) |
| sagemaker_notebook_instance | sagemaker ListNotebookInstances + DescribeNotebookInstance | NotebookInstanceArn, DirectInternetAccess, KmsKeyId, SubnetId, RootAccess, PlatformIdentifier |
| sagemaker_model | sagemaker ListModels + DescribeModel | ModelArn, EnableNetworkIsolation, VpcConfig.{Subnets,SecurityGroupIds} |
| sagemaker_training_job | sagemaker ListTrainingJobs + DescribeTrainingJob | TrainingJobArn, EnableInterContainerTrafficEncryption, EnableNetworkIsolation, OutputDataConfig.KmsKeyId, ResourceConfig.VolumeKmsKeyId, VpcConfig.Subnets |
| sagemaker_endpoint_config | sagemaker ListEndpointConfigs + DescribeEndpointConfig | EndpointConfigArn, KmsKeyId, ProductionVariants |
| sagemaker_domain | sagemaker ListDomains + DescribeDomain | DomainArn, AuthMode, SingleSignOnApplicationArn |
| sagemaker_monitoring_schedule | sagemaker ListMonitoringSchedules | MonitoringScheduleName, MonitoringScheduleStatus |
| sagemaker_model_package_group | sagemaker ListModelPackageGroups + ListModelPackages(ModelApprovalStatus=Approved) | ModelPackageGroupName, ApprovedPackages (count) |
| sagemaker_processing_job | sagemaker ListProcessingJobs + DescribeProcessingJob | ProcessingJobName, AppSpecification.ImageUri |
| servicecatalog_portfolio | servicecatalog ListPortfolios + DescribePortfolioShares (Type ACCOUNT, ORGANIZATION, ORGANIZATIONAL_UNIT, ORGANIZATION_MEMBER_ACCOUNT) | Id, ARN, Shares.<TYPE>.PortfolioShareDetails[].PrincipalId |
| ses_email_identity | sesv2 ListEmailIdentities + GetEmailIdentity | IdentityName, Identity.{IdentityType, DkimAttributes.{SigningEnabled,Status}, Policies} |
| sfn_state_machine | stepfunctions ListStateMachines + DescribeStateMachine (definition not stored) | stateMachineArn, loggingConfiguration.level, encryptionConfiguration.{type,kmsKeyId} |
| shield_subscription (global) | shield DescribeSubscription / GetSubscriptionState | SubscriptionState |
| shield_protection (global) | shield ListProtections | Id, ResourceArn |
| sns_subscription | sns ListSubscriptions | SubscriptionArn, TopicArn, Protocol |
| ssm_resource_compliance_summary | ssm ListResourceComplianceSummaries | ResourceId, ResourceType, ComplianceType, Status |
| ssmincidents_account (global per replication region) | ssm-incidents ListReplicationSets + GetReplicationSet + ListResponsePlans | AccountId, ReplicationSets.items[{arn,status}], ResponsePlans.items[{arn}] |
| storagegateway_gateway | storagegateway ListGateways + DescribeGatewayInformation | GatewayARN, HostEnvironment |
| storagegateway_file_share | storagegateway ListFileShares + DescribeNFS/SMBFileShares | FileShareARN, KMSEncrypted |
| transfer_server | transfer ListServers + DescribeServer | ServerId, Server.{Arn, Protocols, SecurityPolicyName} |
| transfer_connector | transfer ListConnectors + DescribeConnector | ConnectorId, Connector.{Arn, LoggingRole} |
| trustedadvisor_support (global) | support DescribeServices (SubscriptionRequiredException = PremiumSupport false) | AccountId, PremiumSupport |
| trustedadvisor_check (global) | support DescribeTrustedAdvisorChecks + DescribeTrustedAdvisorCheckResult | id, name, Result.status |
| waf_rule / waf_rule_group / waf_web_acl (global) | waf ListRules+GetRule, ListRuleGroups+ListActivatedRulesInRuleGroup, ListWebACLs+GetWebACL+GetLoggingConfiguration (WAFNonexistentItemException = absent) | RuleId, Rule.Predicates; RuleGroupId, ActivatedRules.ActivatedRules; WebACLId, WebACL.{WebACLArn,Rules}, LoggingConfiguration.LoggingConfiguration.LogDestinationConfigs |
| wafregional_rule / wafregional_rule_group / wafregional_web_acl | waf-regional same calls + ListResourcesForWebACL | as above + ResourceArns.ResourceArns |
| wafv2_web_acl (REGIONAL per region, CLOUDFRONT global) | wafv2 ListWebACLs + GetWebACL + GetLoggingConfiguration | ARN, Name, Id, WebACL.{Rules[].VisibilityConfig, PreProcess/PostProcessFirewallManagerRuleGroups}, LoggingConfiguration.LoggingConfiguration.LogDestinationConfigs |
| wafv2_rule_group | wafv2 ListRuleGroups + GetRuleGroup | ARN, RuleGroup.VisibilityConfig.CloudWatchMetricsEnabled |
| wellarchitected_workload | wellarchitected ListWorkloads | WorkloadArn, RiskCounts |
| workspaces_workspace | workspaces DescribeWorkspaces | WorkspaceId, SubnetId, RootVolumeEncryptionEnabled, UserVolumeEncryptionEnabled |

### New fields on existing kinds

| Kind | API call | Field |
|---|---|---|
| route53_zone | route53 ListQueryLoggingConfigs(HostedZoneId) | QueryLoggingConfigs.QueryLoggingConfigs[].CloudWatchLogsLogGroupArn |
| ssm_managed_instance | ssm ListComplianceItems(ResourceIds=[instance], ResourceTypes=[ManagedInstance]) | ComplianceItems.ComplianceItems[{ComplianceType, Status}] |
| ssm_service_settings | ssm GetServiceSetting(/ssm/automation/customer-script-log-destination) | a second row: ServiceSetting.{SettingId, SettingValue} |
| rds_cluster | rds DescribeDBClusterParameters (cluster parameter group) | ClusterParameterGroupValues, allowlisted non-secret parameters (server_audit_logging, server_audit_events, rds.force_ssl, require_secure_transport, …) |
| rds_instance | rds DescribeDBParameters (each attached parameter group) | ParameterGroupValues, allowlisted non-secret parameters (rds.force_ssl, require_secure_transport, log_*, …) |
| redshift_cluster | redshift DescribeLoggingStatus; DescribeClusterParameters | LoggingStatus.LoggingEnabled; ParameterGroupValues.require_ssl (allowlisted) |
| glue_job | glue GetJobs | DefaultArgumentFlags, an allowlist of non-secret boolean/enum flags (--encryption-type, --enable-continuous-cloudwatch-log, --enable-spark-ui, …). DefaultArguments themselves stay stripped. |
| lambda_function | lambda ListFunctions | pass through KMSKeyArn, LoggingConfig and VpcConfig if not already kept |
| cloudtrail | cloudtrail GetEventSelectors | EventSelectors / AdvancedEventSelectors (Lambda data events) |
| subnet | ec2 DescribeSubnets | AvailabilityZoneId (pass-through) |

## Lead actions

- Add `reviewed_claude_aws_b.json` and `reviewed_claude_aws_b_manual.json` to `peaso/rulepacks/active_reviews.json`.
- Regenerate the manifest with `scripts/peaso_review_catalog.py --write --sources-root …`. This attaches framework mappings to the `aws.cb.*` natives and rebuilds the runtime and native catalogs.
- Registry line (already appended): `from . import claude_aws_b  # noqa: E402,F401` in `peaso/checks/__init__.py`.
