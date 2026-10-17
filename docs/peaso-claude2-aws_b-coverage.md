# PEASO claude2_aws_b coverage (AWS-B rows taken over from stalled Codex workers)

The partition is `peaso/rulepacks/port_partitions_claude2.json` → `partitions.claude2_aws_b`: 536 upstream rows (308 steampipe-mod-aws-compliance, 211 Prowler, 17 steampipe-mod-aws-perimeter). 301 rows had service `unknown` and were classified from the pinned query and dependencies.

## Files

- Native predicates (one module per service group):
  - `peaso/checks/claude2_aws_b_compute.py`: Lambda, ECS, EKS, Auto Scaling, AppStream, Elastic Beanstalk, Batch.
  - `peaso/checks/claude2_aws_b_edge.py`: CloudFront, ELBv2, Classic ELB, API Gateway REST/v2, AppSync, Direct Connect.
  - `peaso/checks/claude2_aws_b_data.py`: DynamoDB, DAX, Application Auto Scaling, Backup, ElastiCache, DocumentDB, DMS, Athena, DataSync, DLM, DRS.
  - `peaso/checks/claude2_aws_b_analytics.py`: EFS, EMR, Elasticsearch, Firehose, RDS snapshot encryption.
  - `peaso/checks/claude2_aws_b_identity.py`: ACM, Private CA, Cognito, Connect, Directory Service, Firewall Manager, Bedrock, Amplify, Data Pipeline.
  - `peaso/checks/claude2_aws_b_devtools.py`: CodeBuild, CodeArtifact, CodeCommit, CodePipeline, CodeDeploy, CloudFormation, EventBridge, ECR.
- Shared helpers: `peaso/checks/claude2_aws_b_common.py` (own provenance registries; generic policy/routing helpers re-used read-only from `claude_aws_b_common`).
- Aggregator: `peaso/checks/claude2_aws_b.py` (loads the groups, query-identical merges `AUTO`, `HELD_ELSEWHERE`, `ported()`, `dispositions()`).
- Review shards: `peaso/rulepacks/reviewed_claude2_aws_b.json` (ported, merged, rejected) and `peaso/rulepacks/reviewed_claude2_aws_b_manual.json` (manual attestations).
- Tests: `tests/test_peaso_checks_claude2_aws_b.py` plus `tests/test_peaso_checks_claude2_aws_b_{compute,edge,data,analytics,identity,devtools}.py`.

## Counts

| Disposition | Rows |
|---|---|
| ported | 360 |
| merged into existing natives | 126 |
| manual attestation | 5 |
| rejected, intrusive secret-content scanners | 12 |
| rejected, invalid upstream predicate (replacement native provided) | 13 |
| dropped, held as ported by another active shard | 20 |
| **total** | **536** |

There are 265 unique native predicates (`aws.c2b.*`). Rows asking the same question with the same threshold share one predicate; different thresholds keep separate predicates (each predicate's review note in the shard records the semantics and any deliberate deviation from upstream).

Dropped rows (addendum rule, already ported in an active shard): `reviewed_aws_b_cognito.json`: 12; `reviewed_aws_b_redshift.json`: 8. `aws-compliance.control.rds_db_snapshot_encrypted_at_rest` was pending in `reviewed_aws.json`; its entry carries `supersedes`.

| Group | Ported | Merged | Manual | Rejected | Predicates |
|---|---|---|---|---|---|
| compute | 80 | 5 | 0 | 5 | 51 |
| edge | 71 | 14 | 0 | 6 | 56 |
| data | 82 | 7 | 0 | 6 | 55 |
| analytics | 52 | 10 | 0 | 0 | 38 |
| identity | 36 | 1 | 3 | 2 | 32 |
| devtools | 39 | 2 | 2 | 4 | 33 |
| query-identical (aggregator) | 0 | 87 | 0 | 2 | 0 |

## Merged

87 steampipe rows use a pinned `query_id` byte-identical to one already ported in an active shard (mostly `aws.cb.*`); they merge to the same natives (`AUTO` in the aggregator). The remaining merges, each verified against the native source:

- `aws-compliance.control.cloudfront_distribution_non_s3_origins_encryption_in_transit_enabled` → `aws.b.cloudfront.custom_origin_encryption`: Same predicate: custom origins with http-only, or match-viewer while the default or any additional behavior allows HTTP, alarm; S3 origins are skipped.
- `aws-compliance.control.dynamodb_table_deletion_protection_enabled` → `aws.b.dynamodb.deletion_protection`: Identical predicate: steampipe alarms unless Table.DeletionProtectionEnabled is true, as the native does.
- `aws-compliance.control.es_domain_cognito_authentication_enabled` → `aws.cb.opensearch.cognito_dashboards_auth`: CognitoOptions.Enabled true; identical to the pinned opensearch_domain_cognito_authentication_enabled_for_kibana query on the same domains.
- `aws-compliance.control.es_domain_data_nodes_min_3` → `aws.cb.opensearch.data_node_fault_tolerance`: Zone awareness enabled and at least three data nodes (ElasticsearchClusterConfig = OpenSearch ClusterConfig).
- `aws-compliance.control.es_domain_dedicated_master_nodes_min_3` → `aws.cb.opensearch.dedicated_master_nodes`: DedicatedMasterEnabled true and DedicatedMasterCount >= 3 (ElasticsearchClusterConfig = OpenSearch ClusterConfig).
- `aws-compliance.control.es_domain_encryption_at_rest_enabled` → `aws.cb.opensearch.encryption_at_rest`: EncryptionAtRestOptions.Enabled true.
- `aws-compliance.control.es_domain_node_to_node_encryption_enabled` → `aws.cb.opensearch.node_to_node_encryption_region_skip`: NodeToNodeEncryptionOptions.Enabled true with the same af-south-1/eu-south-1/cn-north-1/cn-northwest-1 skip list.
- `aws-compliance.control.foundational_security_dynamodb_6` → `aws.b.dynamodb.deletion_protection`: Identical predicate: same query as dynamodb_table_deletion_protection_enabled (DeletionProtectionEnabled true).
- `aws-compliance.control.foundational_security_es_1` → `aws.cb.opensearch.encryption_at_rest`: EncryptionAtRestOptions.Enabled true.
- `aws-compliance.control.foundational_security_es_3` → `aws.cb.opensearch.node_to_node_encryption_region_skip`: NodeToNodeEncryptionOptions.Enabled true with the same af-south-1/eu-south-1/cn-north-1/cn-northwest-1 skip list.
- `aws-compliance.control.foundational_security_es_6` → `aws.cb.opensearch.data_node_fault_tolerance`: Zone awareness enabled and at least three data nodes (ElasticsearchClusterConfig = OpenSearch ClusterConfig).
- `aws-compliance.control.foundational_security_es_7` → `aws.cb.opensearch.dedicated_master_nodes`: DedicatedMasterEnabled true and DedicatedMasterCount >= 3 (ElasticsearchClusterConfig = OpenSearch ClusterConfig).
- `aws-perimeter.control.dms_replication_instance_not_publicly_accessible` → `aws.b.dms.no_public_instance`: Identical predicate: aws-perimeter alarms when the replication instance has PubliclyAccessible true, as the native does.
- `prowler.aws.apigateway_restapi_client_certificate_enabled` → `aws.b.apigateway.client_certificate`: Both fail a REST stage without clientCertificateId.
- `prowler.aws.apigateway_restapi_tracing_enabled` → `aws.b.apigateway.rest_xray`: Both fail a REST stage whose tracingEnabled is false.
- `prowler.aws.apigateway_restapi_waf_acl_attached` → `aws.b.apigateway.waf_reference`: Both fail a REST stage without webAclArn.
- `prowler.aws.apigatewayv2_api_access_logging_enabled` → `aws.cb.apigatewayv2.stage_access_logging`: Both fail an HTTP/WebSocket stage whose AccessLogSettings is absent or empty.
- `prowler.aws.awslambda_function_vpc_multi_az` → `aws.cb.lambda.vpc_multiple_az`: VPC-attached function subnets span at least two Availability Zones (lambda_min_azs default 2). Prowler reports non-VPC functions only when awslambda_function_inside_vpc did not already fail them; that case is reported by aws.lambda.vpc_configuration, so the native is NOT_APPLICABLE for them.
- `prowler.aws.backup_vaults_exist` → `aws.b.backup_vault.regional_presence`: Identical predicate: prowler FAILs a region whose complete backup vault inventory is empty; the native scope check does the same.
- `prowler.aws.cloudfront_distributions_default_root_object` → `aws.b.cloudfront.default_root_object`: Pinned prowler predicate reads the same DistributionConfig field with the same empty-value failure as aws.b.cloudfront.default_root_object (DefaultRootObject == '' fails).
- `prowler.aws.cloudfront_distributions_field_level_encryption_enabled` → `aws.b.cloudfront.field_level_encryption`: Pinned prowler predicate reads the same DistributionConfig field with the same empty-value failure as aws.b.cloudfront.field_level_encryption (DefaultCacheBehavior.FieldLevelEncryptionId).
- `prowler.aws.cloudfront_distributions_geo_restrictions_enabled` → `aws.b.cloudfront.geo_restrictions`: Both fail exactly when Restrictions.GeoRestriction.RestrictionType is 'none'.
- `prowler.aws.cloudfront_distributions_using_waf` → `aws.b.cloudfront.waf_reference`: Pinned prowler predicate reads the same DistributionConfig field with the same empty-value failure as aws.b.cloudfront.waf_reference (WebACLId == '' fails).
- `prowler.aws.codebuild_project_logging_enabled` → `aws.b.codebuild.logs_enabled`: CloudWatch or S3 logs status ENABLED; omitted log blocks are DISABLED, as prowler's defaults.
- `prowler.aws.cognito_identity_pool_guest_access_disabled` → `aws.b.cognito.no_guest_identities`: Identity pool AllowUnauthenticatedIdentities false; Prowler reads the same DescribeIdentityPool member.
- `prowler.aws.ecr_repositories_scan_images_on_push_enabled` → `aws.ecr.scan_on_push`: Repository imageScanningConfiguration.scanOnPush true, as prowler's repository.scan_on_push.
- `prowler.aws.ecs_task_definitions_containers_readonly_access` → `aws.b.ecs.all_readonly_roots`: Every container declares readonlyRootFilesystem true (absent = false).
- `prowler.aws.ecs_task_definitions_host_namespace_not_shared` → `aws.b.ecs.no_host_pid`: Task definition pidMode is not host.
- `prowler.aws.ecs_task_definitions_no_privileged_containers` → `aws.b.ecs.no_privileged_containers`: No container sets privileged true (absent = false).
- `prowler.aws.efs_encryption_at_rest_enabled` → `aws.b.efs.at_rest_encryption`: File system Encrypted true (DescribeFileSystems).
- `prowler.aws.eks_cluster_private_nodes_enabled` → `aws.eks.private_endpoint`: Cluster resourcesVpcConfig.endpointPrivateAccess is true.
- `prowler.aws.elasticache_redis_cluster_automatic_failover_enabled` → `aws.b.elasticache.automatic_failover`: Identical predicate: prowler PASSes replication groups whose AutomaticFailover is enabled, as the native does.
- `prowler.aws.elasticache_redis_cluster_in_transit_encryption_enabled` → `aws.b.elasticache.in_transit`: Identical predicate: prowler PASSes replication groups with TransitEncryptionEnabled true, as the native does.
- `prowler.aws.elasticache_redis_cluster_rest_encryption_enabled` → `aws.b.elasticache.at_rest`: Identical predicate: prowler PASSes replication groups with AtRestEncryptionEnabled true, as the native does.
- `prowler.aws.elb_connection_draining_enabled` → `aws.b.classic_elb.connection_draining`: Both read Attributes.LoadBalancerAttributes.ConnectionDraining.Enabled.
- `prowler.aws.elb_cross_zone_load_balancing_enabled` → `aws.b.classic_elb.cross_zone`: Both read Attributes.LoadBalancerAttributes.CrossZoneLoadBalancing.Enabled.
- `prowler.aws.elb_desync_mitigation_mode` → `aws.b.classic_elb.desync_mode`: Both pass for elb.http.desyncmitigationmode defensive/strictest and fail for monitor.
- `prowler.aws.elb_is_in_multiple_az` → `aws.b.classic_elb.multiple_az`: Both require more than one entry in AvailabilityZones.
- `prowler.aws.elb_logging_enabled` → `aws.b.classic_elb.access_logs`: Both read Attributes.LoadBalancerAttributes.AccessLog.Enabled.

## Rejected

- `aws-compliance.control.autoscaling_ec2_launch_configuration_no_sensitive_data` (intrusive_unsuitable): Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot.
- `aws-compliance.control.cloudformation_stack_output_no_secrets` (intrusive_unsuitable): Upstream runs a secret-content scanner over the payload (detect-secrets/Kingfisher or regex heuristics on values). PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting stack output values, plaintext variable values or repository file contents to grep for credentials is intrusive and unsuitable for the snapshot.
- `aws-compliance.control.dms_endpoint_mongo_db_authentication_enabled` (invalid_predicate): The pinned query (source endpoints with MongoDbSettings) alarms when AuthMechanism is 'default' and passes otherwise, without reading AuthType. AWS documents 'default' as a valid mechanism (SCRAM_SHA_1 on MongoDB 3.x+, unused when AuthType is no) and authentication itself as AuthType (no | password), so password-authenticated endpoints alarm and AuthType=no endpoints can pass. Corrected native predicate: AuthType is not 'no'. Replacement: `aws.c2b.dms.mongodb_auth`.
- `aws-compliance.control.dms_endpoint_redis_tls_enabled` (invalid_predicate): The pinned query (target endpoints with RedisSettings) passes only when SslCaCertificateArn is set. AWS documents SslCaCertificateArn as optional ('If an ARN isn't given for a CA, DMS uses the Amazon root CA'), so TLS endpoints trusting the Amazon root CA are flagged. Corrected native predicate: SslSecurityProtocol is ssl-encryption (the documented default). Replacement: `aws.c2b.dms.redis_tls`.
- `aws-compliance.control.docdb_cluster_instance_logging_enabled` (invalid_predicate): The pinned query requires instance EnabledCloudwatchLogsExports to contain 'error' and 'slowquery', which are not DocumentDB log types: DocumentDB exports audit and profiler logs at cluster level, and Security Hub DocumentDB.4 checks that the cluster publishes audit logs. Corrected native predicate: cluster exports audit and profiler. Replacement: `aws.c2b.documentdb.cluster_log_exports`.
- `aws-compliance.control.elb_listener_use_secure_ssl_cipher` (invalid_predicate): Only ELBSecurityPolicy-TLS-1-2-2017-01 and ELBSecurityPolicy-TLS-1-1-2017-01 pass, and every listener without an SslPolicy (HTTP/TCP) alarms. AWS recommends ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 (the console default) and all TLS13 policies alarm, while the TLS 1.1 policy passes. Replacement: aws.c2b.elbv2.insecure_ssl_ciphers. Replacement: `aws.c2b.elbv2.insecure_ssl_ciphers`.
- `aws-compliance.control.elb_network_lb_tls_listener_security_policy_configured` (invalid_predicate): Accepted TLS policies are ELBSecurityPolicy-2016-08 (supports TLS 1.0 and 1.1 per AWS), a misspelled 'ELBSecurityPolicy-FS-2018-0' and two TLS13 policies; the AWS-recommended ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09 alarms while a TLS 1.0 policy passes. Replacement: aws.c2b.elbv2.recommended_tls_policy (NLB TLS listeners). Replacement: `aws.c2b.elbv2.recommended_tls_policy`.
- `aws-compliance.control.elb_tls_listener_protocol_version` (invalid_predicate): The query alarms when an HTTPS listener's SslPolicy is like 'Protocol-SSLv3' or 'Protocol-TLSv1'. ELBv2 SslPolicy values are predefined ELBSecurityPolicy-* names (no policy is named Protocol-*), so it never alarms. Replacement: aws.c2b.elbv2.insecure_ssl_ciphers. Replacement: `aws.c2b.elbv2.insecure_ssl_ciphers`.
- `aws-compliance.control.foundational_security_cloudfront_13` (invalid_predicate): The control is 'CloudFront distributions should use origin access control', but the pinned query alarms when S3OriginConfig.OriginAccessIdentity is ''. AWS requires an empty OriginAccessIdentity when OAC is used, so the query alarms on exactly the compliant configuration. Corrected predicate: aws.c2b.cloudfront.s3_origin_access_control. Replacement: `aws.c2b.cloudfront.s3_origin_access_control`.
- `aws-compliance.control.foundational_security_dms_11` (invalid_predicate): The pinned query (source endpoints with MongoDbSettings) alarms when AuthMechanism is 'default' and passes otherwise, without reading AuthType. AWS documents 'default' as a valid mechanism (SCRAM_SHA_1 on MongoDB 3.x+, unused when AuthType is no) and authentication itself as AuthType (no | password), so password-authenticated endpoints alarm and AuthType=no endpoints can pass. Corrected native predicate: AuthType is not 'no'. Replacement: `aws.c2b.dms.mongodb_auth`.
- `aws-compliance.control.foundational_security_dms_12` (invalid_predicate): The pinned query (target endpoints with RedisSettings) passes only when SslCaCertificateArn is set. AWS documents SslCaCertificateArn as optional ('If an ARN isn't given for a CA, DMS uses the Amazon root CA'), so TLS endpoints trusting the Amazon root CA are flagged. Corrected native predicate: SslSecurityProtocol is ssl-encryption (the documented default). Replacement: `aws.c2b.dms.redis_tls`.
- `aws-compliance.control.foundational_security_docdb_4` (invalid_predicate): The pinned query requires instance EnabledCloudwatchLogsExports to contain 'error' and 'slowquery', which are not DocumentDB log types: DocumentDB exports audit and profiler logs at cluster level, and Security Hub DocumentDB.4 checks that the cluster publishes audit logs. Corrected native predicate: cluster exports audit and profiler. Replacement: `aws.c2b.documentdb.cluster_log_exports`.
- `aws-compliance.control.foundational_security_opensearch_5` (invalid_predicate): Uses the same pinned query as opensearch_domain_audit_logging_enabled: both CASE branches return 'ok', so the control can never alarm. AWS documents audit logs as LogPublishingOptions.AUDIT_LOGS (Enabled + CloudWatch log group); the corrected native predicate is aws.cb.opensearch.audit_logs_enabled. Replacement: `aws.cb.opensearch.audit_logs_enabled`.
- `aws-compliance.control.foundational_security_opensearch_8` (invalid_predicate): Uses the same pinned query as opensearch_domain_https_required, which compares DomainEndpointOptions.TLSSecurityPolicy with the literal 'tlsPolicies' (not a valid value: Policy-Min-TLS-1-0-2019-07, Policy-Min-TLS-1-2-2019-07, Policy-Min-TLS-1-2-PFS-2023-10), so it alarms on every EnforceHTTPS domain. Corrected native predicate: aws.cb.opensearch.enforce_https. Replacement: `aws.cb.opensearch.enforce_https`.
- `prowler.aws.amplify_app_no_secrets_in_environment` (intrusive_unsuitable): Upstream runs a secret-content scanner (detect-secrets) over the decoded payload. PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting full environment variables, build specs or pipeline definitions to grep for credentials is intrusive and unsuitable for the snapshot.
- `prowler.aws.apigateway_restapi_no_secrets_in_stage_variables` (intrusive_unsuitable): Secret scanning of stage variable values: the collector deliberately strips stage 'variables' and PEASO does not read or retain secret material.
- `prowler.aws.autoscaling_find_secrets_ec2_launch_configuration` (intrusive_unsuitable): Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot.
- `prowler.aws.batch_job_definition_no_secrets` (intrusive_unsuitable): Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot.
- `prowler.aws.cloudformation_stack_outputs_find_secrets` (intrusive_unsuitable): Upstream runs a secret-content scanner over the payload (detect-secrets/Kingfisher or regex heuristics on values). PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting stack output values, plaintext variable values or repository file contents to grep for credentials is intrusive and unsuitable for the snapshot.
- `prowler.aws.cloudfront_distributions_multiple_origin_failover_configured` (invalid_predicate): Prowler computes origin_failover = all(group.Members.Quantity >= 2 for group in OriginGroups.Items). AWS documents that an origin group always has exactly two origins (primary and secondary), and all([]) is True when there are no origin groups, so the check can never FAIL. aws.b.cloudfront.origin_group_metadata fails distributions without origin groups. Replacement: `aws.b.cloudfront.origin_group_metadata`.
- `prowler.aws.codebuild_project_no_secrets_in_variables` (intrusive_unsuitable): Upstream runs a secret-content scanner over the payload (detect-secrets/Kingfisher or regex heuristics on values). PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting stack output values, plaintext variable values or repository file contents to grep for credentials is intrusive and unsuitable for the snapshot. Replacement: `aws.c2b.codebuild.no_plaintext_sensitive_env_names`.
- `prowler.aws.codecommit_repository_no_secrets` (intrusive_unsuitable): Upstream runs a secret-content scanner over the payload (detect-secrets/Kingfisher or regex heuristics on values). PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting stack output values, plaintext variable values or repository file contents to grep for credentials is intrusive and unsuitable for the snapshot. This check also downloads every file of the default branch (GetFile/GetBlob).
- `prowler.aws.datapipeline_pipeline_no_secrets_in_definition` (intrusive_unsuitable): Upstream runs a secret-content scanner (detect-secrets) over the decoded payload. PEASO is a read-only configuration CSPM that does not collect or scan secret material; collecting full environment variables, build specs or pipeline definitions to grep for credentials is intrusive and unsuitable for the snapshot.
- `prowler.aws.ecs_task_definitions_no_environment_secrets` (intrusive_unsuitable): Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot. Replacement: `aws.c2b.ecs.no_credential_named_env_vars`.
- `prowler.aws.elasticbeanstalk_environment_no_secrets_in_configuration` (intrusive_unsuitable): Upstream runs a secret-content scanner over the decoded payload (detect-secrets / Kingfisher or substring and password-regex matching). PEASO is a read-only configuration CSPM that does not collect or scan secret material; the collector deliberately discards user data, environment values, commands and option values, and collecting them to grep for credentials is intrusive and unsuitable for the snapshot.

## Manual

- `prowler.aws.bedrock_agent_role_least_privilege`: Does every Amazon Bedrock agent execution role avoid AWS-managed *FullAccess policies, administrative or privilege-escalation permissions, and have a permissions boundary?
- `prowler.aws.bedrock_agent_role_not_shared_across_agents`: Does every Amazon Bedrock agent (draft and every version routed by an active alias) use an execution role that no other agent in the account uses?
- `prowler.aws.bedrock_api_key_no_administrative_privileges`: Do the IAM users that own Amazon Bedrock API keys lack administrative privileges, privilege-escalation paths and full Bedrock service access?
- `prowler.aws.codebuild_project_uses_allowed_github_organizations`: Does every CodeBuild project with a GitHub or GitHub Enterprise source (whose service role trusts codebuild.amazonaws.com) build only from a GitHub organization on your approved list?
- `prowler.aws.codepipeline_project_repo_private`: Are the GitHub/GitLab repositories used as CodeStarSourceConnection sources by CodePipeline pipelines private?

## Behaviour contract

- Missing, denied, partial or malformed facts are UNKNOWN, never FAIL. Child lists are only used when their envelope is `collected`/`empty`; a detail call's documented not-found is the `absent` marker.
- Resources outside the upstream applicability (engine, protocol, listener type, no cache, no clients, never-issued certificates, ...) are NOT_APPLICABLE.
- No secret material is collected or scanned; secret-content scanner rows are rejected as intrusive_unsuitable.
- Every predicate carries HackTricks Cloud Best Practices plus all upstream framework mappings of its rows (via the catalog), and has PASS, FAIL (or MANUAL), UNKNOWN fixtures.

## COLLECTOR FACTS NEEDED

The collector (Codex-owned) was not edited. Until these read-only facts are collected, the listed predicates return UNKNOWN (or evaluate an empty inventory as no resources).

### compute

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `lambda_function` | lambda:ListFunctions (existing) | Environment.VariableCount (number of Environment.Variables keys; values discarded) | `aws.c2b.lambda.env_vars_cmk` |
| `autoscaling_group` | autoscaling:DescribeAutoScalingGroups | AutoScalingGroupARN, AvailabilityZones, LoadBalancerNames, TargetGroupARNs, HealthCheckType, CapacityRebalance, LaunchConfigurationName, LaunchTemplate, MixedInstancesPolicy.LaunchTemplate (LaunchTemplateSpecification, Overrides[].InstanceType/InstanceRequirements), SuspendedProcesses, Tags[].PropagateAtLaunch, Instances[].AvailabilityZone/InstanceType | `aws.c2b.autoscaling.*` |
| `launch_configuration` | autoscaling:DescribeLaunchConfigurations | LaunchConfigurationARN, LaunchConfigurationName, AssociatePublicIpAddress, MetadataOptions.HttpTokens/HttpEndpoint/HttpPutResponseHopLimit (UserData discarded) | `aws.c2b.autoscaling.lc_no_public_ip`, `aws.c2b.autoscaling.lc_imdsv2_required`, `aws.c2b.autoscaling.lc_hop_limit`, `aws.c2b.autoscaling.group_lc_no_public_ip`, `aws.c2b.autoscaling.group_lc_imdsv2` |
| `ecs_service` | ecs:ListServices + ecs:DescribeServices | serviceArn, clusterArn, launchType, platformVersion, platformFamily, taskDefinition, networkConfiguration.awsvpcConfiguration.assignPublicIp, loadBalancers | `aws.c2b.ecs.service_no_public_ip`, `aws.c2b.ecs.awsvpc_service_no_public_ip`, `aws.c2b.ecs.fargate_latest_platform`, `aws.c2b.ecs.service_load_balancer_attached` |
| `ecs_task_set` | ecs:DescribeTaskSets (per service) | taskSetArn, networkConfiguration.awsvpcConfiguration.assignPublicIp | `aws.c2b.ecs.task_set_no_public_ip` |
| `ecs_container_instance` | ecs:ListContainerInstances + ecs:DescribeContainerInstances (per cluster) | containerInstanceArn, clusterArn (the cluster queried), ec2InstanceId, agentConnected, status | `aws.c2b.ecs.container_instance_agents_connected`, `aws.c2b.ecs.cluster_instance_volumes_encrypted`, `aws.c2b.ecs.container_instance_in_vpc` |
| `ecs_account_setting` | ecs:ListAccountSettings(name=defaultLogDriverMode, effectiveSettings=true) | name, value | `aws.c2b.ecs.logging_non_blocking` |
| `ecs_task_definition` | ecs:DescribeTaskDefinition (existing) | containerDefinitions[].environment[].name (names only; values discarded) | `aws.c2b.ecs.no_credential_named_env_vars` |
| `eks_cluster` | eks:DescribeAddon(clusterName, addonName=vpc-cni) stored as VpcCniAddon (ResourceNotFoundException = absent marker) | addon.configurationValues (only enableNetworkPolicy is needed) | `aws.c2b.eks.vpc_cni_network_policy` |
| `appstream_fleet` | appstream:DescribeFleets | Arn, EnableDefaultInternetAccess, MaxUserDurationInSeconds, DisconnectTimeoutInSeconds, IdleDisconnectTimeoutInSeconds | `aws.c2b.appstream.*` |
| `elastic_beanstalk_environment` | elasticbeanstalk:DescribeEnvironments + DescribeConfigurationSettings stored as Configuration | EnvironmentArn, Configuration.ConfigurationSettings[].OptionSettings[] restricted to aws:elasticbeanstalk:cloudwatch:logs/StreamLogs, aws:elasticbeanstalk:managedactions/ManagedActionsEnabled, aws:elasticbeanstalk:healthreporting:system/SystemType (other option values discarded) | `aws.c2b.elasticbeanstalk.*` |

### edge

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `cloudfront_distribution` | logs:DescribeDeliverySources + logs:DescribeDeliveries (us-east-1) | LogDeliveries.deliveries[].deliverySourceName (sources whose resourceArns contain the distribution ARN) | `aws.c2b.cloudfront.logging_any` |
| `cloudfront_distribution` | s3:HeadBucket (origin buckets absent from the account bucket inventory) | OriginBucketProbes.results[].Bucket, OriginBucketProbes.results[].HttpStatusCode | `aws.c2b.cloudfront.s3_origin_bucket_exists` |
| `load_balancer` | elbv2:DescribeRules(ListenerArn) for HTTP listeners | Listeners.items[].Rules.items[].Actions[].Type, Listeners.items[].Rules.items[].Actions[].RedirectConfig.Protocol | `aws.c2b.elbv2.http_listeners_redirect_https` |
| `wafv2_web_acl` | wafv2:ListWebACLs(Scope=REGIONAL) + wafv2:ListResourcesForWebACL(ResourceType=APPLICATION_LOAD_BALANCER) | ARN, ResourceArns.ResourceArns | `aws.c2b.elbv2.alb_waf_attached`, `aws.c2b.elbv2.alb_wafv2_attached` |
| `wafregional_web_acl` | waf-regional:ListWebACLs + waf-regional:ListResourcesForWebACL(ResourceType=APPLICATION_LOAD_BALANCER) | WebACLId, ResourceArns.ResourceArns | `aws.c2b.elbv2.alb_waf_attached` |
| `apigateway_domain_name` | apigateway:GetDomainNames | domainName, securityPolicy, endpointConfiguration.types | `aws.c2b.apigateway.domain_pqc_tls` |
| `rest_api` | apigateway:GetAuthorizers(restApiId) | Authorizers.items[].id, Authorizers.items[].type | `aws.c2b.apigateway.authorizers_or_authorized_methods`, `aws.c2b.apigateway.public_rest_api_authorizer`, `aws.c2b.apigateway.rest_api_has_authorizer` |
| `rest_api` | apigateway:GetResources(restApiId, embed=methods) | Resources.items[].path, Resources.items[].resourceMethods.<verb>.authorizationType, Resources.items[].resourceMethods.<verb>.requestValidatorId | `aws.c2b.apigateway.authorizers_or_authorized_methods`, `aws.c2b.apigateway.methods_authorization_type`, `aws.c2b.apigateway.methods_request_validator` |
| `http_api` | apigatewayv2:GetAuthorizers(ApiId) | Authorizers.items[].AuthorizerId | `aws.c2b.apigatewayv2.api_has_authorizer` |
| `http_api` | apigatewayv2:GetRoutes(ApiId) | Routes.items[].RouteId, Routes.items[].AuthorizationType, Routes.items[].AuthorizerId | `aws.c2b.apigatewayv2.routes_authorization_type`, `aws.c2b.apigatewayv2.routes_authorizer` |
| `appsync_graphql_api` | appsync:ListGraphqlApis + appsync:GetApiCache(apiId) | apiId, apiType, authenticationType, logConfig.fieldLogLevel, ApiCache.apiCache.atRestEncryptionEnabled, ApiCache.apiCache.transitEncryptionEnabled | `aws.c2b.appsync.field_level_logging`, `aws.c2b.appsync.graphql_no_api_key`, `aws.c2b.appsync.no_api_key_auth`, `aws.c2b.appsync.cache_at_rest_encryption`, `aws.c2b.appsync.cache_in_transit_encryption` |
| `directconnect_connection` | directconnect:DescribeConnections | connectionId, location | `aws.c2b.directconnect.connection_redundancy` |
| `directconnect_virtual_interface` | directconnect:DescribeVirtualInterfaces | virtualInterfaceId, connectionId, virtualGatewayId, directConnectGatewayId | `aws.c2b.directconnect.virtual_interface_redundancy` |

### data

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `athena_workgroup` | athena:ListWorkGroups + athena:GetWorkGroup | Name, State, WorkGroup.WorkGroup.{Name, State, Configuration.{ResultConfiguration.EncryptionConfiguration.EncryptionOption, EnforceWorkGroupConfiguration, PublishCloudWatchMetricsEnabled, ManagedQueryResultsConfiguration.Enabled}} | `aws.c2b.athena.results_encrypted`, `aws.c2b.athena.results_encrypted_prowler`, `aws.c2b.athena.enforce_configuration`, `aws.c2b.athena.enforce_configuration_prowler`, `aws.c2b.athena.cloudwatch_metrics`, `aws.c2b.athena.cloudwatch_metrics_prowler` |
| `backup_vault` | backup:GetBackupVaultAccessPolicy | Policy.Policy, ResourceNotFoundException stored as the ABSENT marker (today it becomes an error status) | `aws.c2b.backup.vault_policy_denies_recovery_point_deletion`, `aws.c2b.backup.vault_policy_not_public` |
| `backup_recovery_point` | backup:ListRecoveryPointsByBackupVault (every vault) | RecoveryPointArn, BackupVaultName, IsEncrypted, Lifecycle.DeleteAfterDays | `aws.c2b.backup.recovery_point_encrypted`, `aws.c2b.backup.recovery_point_retention_35` |
| `datasync_task` | datasync:ListTasks + datasync:DescribeTask | TaskArn, Task.{TaskArn, CloudWatchLogGroupArn, Options.LogLevel} | `aws.c2b.datasync.task_log_group`, `aws.c2b.datasync.task_logging_level` |
| `dax_cluster` | dax:DescribeClusters | ClusterArn, SSEDescription.Status, ClusterEndpointEncryptionType, Nodes[].AvailabilityZone | `aws.c2b.dax.encryption_at_rest`, `aws.c2b.dax.encryption_in_transit`, `aws.c2b.dax.multi_az` |
| `dlm_lifecycle_policy` | dlm:GetLifecyclePolicies | PolicyId, State, PolicyType | `aws.c2b.dlm.policy_exists_with_snapshots`, `aws.c2b.dlm.ebs_snapshot_policy_with_snapshots` |
| `dms_endpoint` | dms:DescribeEndpoints | EndpointArn, EngineName, SslMode, MongoDbSettings.AuthType, NeptuneSettings.IamAuthEnabled, RedisSettings.{ServerName, SslSecurityProtocol} | `aws.c2b.dms.endpoint_ssl`, `aws.c2b.dms.mongodb_auth`, `aws.c2b.dms.neptune_iam_auth`, `aws.c2b.dms.redis_tls` |
| `dms_replication_task` | dms:DescribeReplicationTasks | ReplicationTaskArn, ReplicationTaskSettings (JSON: Logging.EnableLogging, Logging.LogComponents[].{Id, Severity}) | `aws.c2b.dms.task_source_logging`, `aws.c2b.dms.task_target_logging` |
| `dms_certificate` | dms:DescribeCertificates | CertificateArn, ValidToDate | `aws.c2b.dms.certificate_not_expired` |
| `docdb_cluster` | rds:DescribeDBClusterParameters (cluster parameter group of each docdb cluster) | ClusterParameterGroupValues.tls | `aws.c2b.docdb.cluster_tls_required` |
| `rds_cluster_snapshot` | rds:DescribeDBClusterSnapshotAttributes | Attributes.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes[].{AttributeName, AttributeValues} | `aws.c2b.docdb.snapshot_restore_not_all_exact`, `aws.c2b.docdb.snapshot_not_public_prowler` |
| `drs_job` | drs:DescribeJobs | JobID, UninitializedAccountException stored as an empty inventory | `aws.c2b.drs.region_has_job` |
| `appautoscaling_target` | application-autoscaling:DescribeScalableTargets (ServiceNamespace=dynamodb) | ServiceNamespace, ResourceId, ScalableDimension | `aws.c2b.dynamodb.capacity_autoscaling` |
| `dynamodb_table` | dynamodb:GetResourcePolicy + dynamodb:ListTagsOfResource | ResourcePolicy.Policy (PolicyNotFoundException stored as the ABSENT marker), Tags.items[].{Key, Value} | `aws.c2b.dynamodb.policy_not_cross_account`, `aws.c2b.dynamodb.table_in_backup_selection_or_tag` |
| `elasticache_subnet_group` | elasticache:DescribeCacheSubnetGroups | CacheSubnetGroupName, Subnets[].SubnetIdentifier | `aws.c2b.elasticache.cluster_public_subnet_prowler`, `aws.c2b.elasticache.cluster_public_subnet` |

### analytics

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `efs_file_system (existing)` | efs:DescribeBackupPolicy, efs:DescribeFileSystemPolicy | BackupPolicy.BackupPolicy.Status; Policy.Policy. Record error PolicyNotFound as the absent marker (absent=('PolicyNotFound',)) instead of an unknown read | `aws.c2b.efs.backup_not_disabled`, `aws.c2b.efs.automatic_backups_enabled`, `aws.c2b.efs.policy_not_open_to_vpc_clients`, `aws.c2b.efs.policy_enforces_ssl`, `aws.c2b.efs.policy_no_wildcard_allow`, `aws.c2b.efs.policy_prohibit_public_access` |
| `efs_access_point` | efs:DescribeAccessPoints (paginated, no filter = all access points in the region) | AccessPointId, AccessPointArn, FileSystemId, RootDirectory.Path, PosixUser | `aws.c2b.efs.access_point_root_directory`, `aws.c2b.efs.access_point_user_identity`, `aws.c2b.efs.access_points_no_root_directory`, `aws.c2b.efs.access_points_posix_user` |
| `efs_mount_target` | efs:DescribeMountTargets (per FileSystemId, paginated) | MountTargetId, FileSystemId, SubnetId | `aws.c2b.efs.mount_target_subnet_no_auto_public_ip`, `aws.c2b.efs.no_public_mount_targets` |
| `emr_cluster` | elasticmapreduce:ListClusters (paginated, all states) + elasticmapreduce:DescribeCluster (per Id, stored under 'Cluster') | Id, ClusterArn, Status.State; Cluster.Cluster.{Id, SecurityConfiguration, KerberosAttributes (presence only, never KdcAdminPassword/CrossRealmTrustPrincipalPassword/ADDomainJoinPassword), MasterPublicDnsName, Ec2InstanceAttributes.{Ec2SubnetId, EmrManagedMasterSecurityGroup, EmrManagedSlaveSecurityGroup, AdditionalMasterSecurityGroups, AdditionalSlaveSecurityGroups}} | `aws.c2b.emr.cluster_*`, `aws.c2b.emr.master_*`, `aws.c2b.emr.cluster_not_publicly_accessible` |
| `emr_security_configuration` | elasticmapreduce:ListSecurityConfigurations + elasticmapreduce:DescribeSecurityConfiguration (per Name, stored under 'Configuration') | Name; Configuration.SecurityConfiguration (JSON: EncryptionConfiguration.{EnableAtRestEncryption, EnableInTransitEncryption, AtRestEncryptionConfiguration.{S3EncryptionConfiguration.EncryptionMode, LocalDiskEncryptionConfiguration.EncryptionKeyProviderType}}) | `aws.c2b.emr.security_configuration_*`, `aws.c2b.emr.cluster_*_encryption*` |
| `emr_block_public_access_configuration` | elasticmapreduce:GetBlockPublicAccessConfiguration (one per region) | BlockPublicAccessConfiguration.{BlockPublicSecurityGroupRules, PermittedPublicSecurityGroupRuleRanges[].{MinRange, MaxRange}} | `aws.c2b.emr.block_public_access_enabled`, `aws.c2b.emr.block_public_access_only_port_22` |
| `firehose_delivery_stream` | firehose:ListDeliveryStreams + firehose:DescribeDeliveryStream (DeliveryStreamDescription flattened) | DeliveryStreamARN, DeliveryStreamType, DeliveryStreamEncryptionConfiguration.Status | `aws.c2b.firehose.encrypted_at_rest_or_msk_source` |

### identity

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `acmpca_certificate_authority` | acm-pca ListCertificateAuthorities | Arn, Type, Status, CertificateAuthorityConfiguration.KeyAlgorithm | `aws.c2b.acmpca.root_ca_disabled`, `aws.c2b.acmpca.pqc_key_algorithm` |
| `cognito_user_pool (detail WebAcl)` | wafv2 GetWebACLForResource(ResourceArn=UserPool.Arn) | WebACL.{Name, ARN} or omitted | `aws.c2b.cognito.waf_web_acl_associated` |
| `connect_instance` | connect ListInstances + DescribeInstanceAttribute(AttributeType=CONTACTFLOW_LOGS) as ContactflowLogs | Id, Arn, ContactflowLogs.Attribute.{AttributeType, Value} | `aws.c2b.connect.contact_flow_logs` |
| `directory_service_directory` | ds DescribeDirectories + DescribeEventTopics (EventTopics) + ListLogSubscriptions (LogSubscriptions) + GetSnapshotLimits (SnapshotLimits) + ListCertificates (Certificates) + DescribeSharedDirectories(OwnerDirectoryId) (SharedDirectories) | DirectoryId, Type, RadiusSettings.AuthenticationProtocol, RadiusStatus; EventTopics[].TopicName; LogSubscriptions[].LogGroupName; SnapshotLimits.{ManualSnapshotsLimit, ManualSnapshotsCurrentCount, ManualSnapshotsLimitReached}; Certificates[].{CertificateId, ExpiryDateTime}; SharedDirectories[].SharedAccountId (child lists as {collection_status, items}; never RADIUS shared secrets) | `aws.c2b.directoryservice.*` |
| `fms_policy` | fms ListPolicies + ListComplianceStatus(PolicyId) as ComplianceStatus | PolicyId, PolicyName, PolicyArn; ComplianceStatus.items[].{MemberAccount, EvaluationResults[].ComplianceStatus} | `aws.c2b.fms.policies_compliant` |
| `bedrock_guardrail` | bedrock ListGuardrails + GetGuardrail(guardrailIdentifier) as Guardrail | id, arn; Guardrail.{guardrailId, contentPolicy.filters[].{type, inputStrength}, sensitiveInformationPolicy (presence only), contextualGroundingPolicy.filters[].{type, threshold, action, enabled}} | `aws.c2b.bedrock.guardrail_*`, `aws.c2b.bedrock.guardrails_configured`, `aws.c2b.bedrock.vpc_endpoints` |
| `bedrock_agent` | bedrock-agent ListAgents | agentId, agentName, guardrailConfiguration.guardrailIdentifier | `aws.c2b.bedrock.agent_guardrail`, `aws.c2b.bedrock.vpc_endpoints` |
| `bedrock_custom_model` | bedrock ListCustomModels(isOwned=true) + GetCustomModel as Model | modelArn, Model.{modelArn, modelKmsKeyArn} | `aws.c2b.bedrock.custom_model_cmk` |
| `bedrock_prompt` | bedrock-agent ListPrompts + GetPrompt as Prompt | id, arn, Prompt.{id, customerEncryptionKeyArn} (never prompt text) | `aws.c2b.bedrock.prompt_cmk`, `aws.c2b.bedrock.prompt_management_exists` |
| `bedrock_knowledge_base` | bedrock-agent ListKnowledgeBases + ListDataSources (DataSources) + GetDataSource as DataSources[].Detail | knowledgeBaseId; DataSources.items[].Detail.dataSource.{dataSourceId, serverSideEncryptionConfiguration.kmsKeyArn} (no data source credentials) | `aws.c2b.bedrock.knowledge_base_data_sources_cmk` |
| `bedrock_model_invocation_logging` | bedrock GetModelInvocationLoggingConfiguration (one row per region) | loggingConfig.{cloudWatchConfig.logGroupName, s3Config.bucketName} or omitted | `aws.c2b.bedrock.model_invocation_logging`, `aws.c2b.bedrock.invocation_logs_encrypted`, `aws.c2b.bedrock.vpc_endpoints` |
| `iam_service_specific_credential` | iam ListUsers + ListServiceSpecificCredentials(UserName, ServiceName=bedrock.amazonaws.com) | ServiceSpecificCredentialId, UserName, ServiceName, Status, CreateDate, ExpirationDate (never the credential secret) | `aws.c2b.bedrock.api_key_long_term_expired` |

### devtools

| Kind | Read-only API | Fields | Checks |
|---|---|---|---|
| `codebuild_project (Builds child list)` | codebuild:ListBuildsForProject(projectName, sortOrder=DESCENDING) + codebuild:BatchGetBuilds(ids) | Builds = {collection_status, items:[{id, buildStatus, startTime, endTime}]} in ListBuildsForProject order | `aws.c2b.codebuild.invoked_last_90_days`, `aws.c2b.codebuild.built_within_90_days` |
| `codebuild_project (Configuration projects[].environment.environmentVariables)` | codebuild:BatchGetProjects (already called) | environment.environmentVariables[].{name, type} only; the value member must stay dropped (today the whole list is omitted) | `aws.c2b.codebuild.no_plaintext_sensitive_env_names` |
| `codebuild_source_credential` | codebuild:ListSourceCredentials | sourceCredentialsInfos[].{arn, serverType, authType} | `aws.c2b.codebuild.source_repo_oauth` |
| `codebuild_report_group` | codebuild:ListReportGroups + codebuild:BatchGetReportGroups | reportGroups[].{arn, name, exportConfig.exportConfigType, exportConfig.s3Destination.{bucket, encryptionKey, encryptionDisabled}} | `aws.c2b.codebuild.report_group_export_encrypted` |
| `cloudformation_stack` | cloudformation:DescribeStacks | Stacks[].{StackName, StackId, NotificationARNs, DisableRollback, EnableTerminationProtection, DriftInformation.StackDriftStatus, ParentId, RootId}; Outputs only for StackName == CDKToolkit and only the BootstrapVersion OutputKey/OutputValue | `aws.c2b.cloudformation.drift_in_sync`, `aws.c2b.cloudformation.notifications`, `aws.c2b.cloudformation.rollback_enabled`, `aws.c2b.cloudformation.termination_protection_all_stacks`, `aws.c2b.cloudformation.termination_protection_root_stacks`, `aws.c2b.cloudformation.cdktoolkit_bootstrap_version` |
| `codedeploy_deployment_group` | codedeploy:ListApplications + codedeploy:ListDeploymentGroups + codedeploy:BatchGetDeploymentGroups | deploymentGroupsInfo[].{applicationName, deploymentGroupName, deploymentGroupId, computePlatform, deploymentConfigName} | `aws.c2b.codedeploy.lambda_not_all_at_once` |
| `ecr_repository (Images child list)` | ecr:DescribeImages(repositoryName) [+ ecr:DescribeImageScanFindings summary when imageScanStatus is absent] | Images = {collection_status, items:[{imageDigest, imageTags, imagePushedAt, artifactMediaType, imageScanStatus.status, imageScanFindingsSummary.findingSeverityCounts}]} | `aws.c2b.ecr.latest_image_no_medium_plus_findings` |
| `eventbridge_bus` | events:ListEventBuses (+ events:DescribeEventBus) | EventBuses[].{Name, Arn, Policy} | `aws.c2b.eventbridge.custom_bus_policy_attached`, `aws.c2b.eventbridge.bus_policy_not_public`, `aws.c2b.eventbridge.bus_policy_no_cross_account`, `aws.c2b.eventbridge.bus_policy_prohibit_public_perimeter` |
| `eventbridge_endpoint` | events:ListEndpoints | Endpoints[].{Name, Arn, ReplicationConfig.State} | `aws.c2b.eventbridge.global_endpoint_replication` |
| `eventbridge_schema_registry` | schemas:ListRegistries + schemas:GetResourcePolicy(RegistryName) (NotFoundException = absent marker) | Registries[].{RegistryName, RegistryArn}, Policy = {Policy, RevisionId} | `aws.c2b.eventbridge.schema_registry_no_cross_account` |
| `codeartifact_domain` | codeartifact:ListDomains + codeartifact:GetDomainPermissionsPolicy(domain) (ResourceNotFoundException = absent marker) | domains[].{name, arn, owner}, Policy = {policy.document} | `aws.c2b.codeartifact.domain_policy_prohibit_public_perimeter` |
| `codeartifact_repository` | codeartifact:ListRepositories + codeartifact:GetRepositoryPermissionsPolicy (ResourceNotFoundException = absent marker) + codeartifact:ListPackages + codeartifact:ListPackageVersions(sortBy=PUBLISHED_TIME, maxResults=1) | repositories[].{name, arn, domainName, domainOwner}, Policy = {policy.document}, Packages = {collection_status, items:[{format, namespace, package, originConfiguration.restrictions.{publish, upstream}, LatestVersion:{collection_status, versions:[{version, status, origin.originType}]}}]} | `aws.c2b.codeartifact.repository_policy_prohibit_public_perimeter`, `aws.c2b.codeartifact.internal_packages_block_upstream` |
