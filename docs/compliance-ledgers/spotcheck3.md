# Third independent compliance-ledger spot-check

Judgments were completed against `inputs/<slice>.json`, `inputs/check-index.json` (its `source:line` fields), and evaluator code **before** opening `spotcheck2.md`. The second report was read only after the third sample was fixed. Proposed check IDs were treated as valid by design. All rates below describe the original sampled entries, before these fixes.

## Sampling and acceptance

A local `random.Random(20261012)` stream selected 12 distinct requirement offsets per ledger, in the ledger’s flattened framework order, then 15 distinct offsets per provider in file order. This fixed sample has 60 ledger rows and 60 proposed controls. A ledger passes when errors/12 is at most 10%; thus one error passes and two errors fail. Proposed-control quality counts entries whose predicate is concrete and correct and whose stated data source exists and supplies the required fields. `UNKNOWN` is acceptable for incomplete evidence; an unsupported PASS is not.

| Ledger | Errors / 12 | Error rate | ≤10% |
|---|---:|---:|---|
| `aws-nist-ffiec-nydfs` | 3/12 | 25.0% | FAIL |
| `azure-cis` | 1/12 | 8.3% | PASS |
| `gcp-other` | 0/12 | 0.0% | PASS |
| `gcp-cis-cft` | 0/12 | 0.0% | PASS |
| `k8s-other` | 1/12 | 8.3% | PASS |

| Provider | Sound / 15 | Quality rate | Defects |
|---|---:|---:|---:|
| `aws` | 14/15 | 93.3% | 1 |
| `azure` | 12/15 | 80.0% | 3 |
| `gcp` | 13/15 | 86.7% | 2 |
| `k8s` | 14/15 | 93.3% | 1 |

## Ledger requirement judgments

`Index evidence` gives the `source:line` stored for each selected native check in `inputs/check-index.json`; `—` means no native evaluator was claimed. For manual and proposed rows, the original control text was checked in the named `inputs/<slice>.json`. `FIXED` is counted as an original-sample error.

### `aws-nist-ffiec-nydfs`

| Offset | Framework / requirement | Original decision | Index evidence | Judgment |
|---:|---|---|---|---|
| 832 | `aws-compliance.benchmark.fedramp_moderate_rev_4` / `aws-compliance.control.vpc_flow_logs_enabled` | `MAPPED` | `peaso/checks/__init__.py:476` | **OK** — Evaluator signal: VPC owned by the account has active flow logs. |
| 16 | `fedramp_low_revision_4_aws` / `sc-12` | `PARTIAL` | `peaso/checks/__init__.py:68`, `peaso/checks/__init__.py:394` | **OK** — Evaluator signal: In-use ACM certificate expires in more than 7 days; Enabled symmetric customer managed KMS key has rotation enabled (Prowler). |
| 1616 | `aws-compliance.benchmark.nist_csf` / `aws-compliance.control.redshift_cluster_enhanced_vpc_routing_enabled` | `MAPPED` | `peaso/checks/__init__.py:564` | **OK** — Evaluator signal: Redshift cluster EnhancedVpcRouting is True. |
| 103 | `ffiec_aws` / `d3-pc-am-b-12` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: No indexed AWS evaluator tests this complete activity: All passwords are encrypted in storage and in transit.. Verify cryptog… |
| 2 | `fedramp_low_revision_4_aws` / `ac-17` | `PARTIAL` | `peaso/checks/__init__.py:808`, `peaso/checks/__init__.py:141`, `peaso/checks/__init__.py:447` | **OK** — Evaluator signal: Classic ELB listeners use HTTPS or SSL only; In-use security group does not expose TCP 22 to 0.0.0.0/0 or ::/0; S3 bucket policy denies every req. |
| 1988 | `aws-compliance.benchmark.nydfs_23` / `aws-compliance.control.s3_bucket_restrict_public_read_access` | `MAPPED` | `peaso/checks/__init__.py:434` | **FIXED** — Reason named only PolicyStatus, while evaluator also tests stored ACL grants and policy statements; corrected. |
| 88 | `ffiec_aws` / `d2-ti-ti-b-2` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: No indexed AWS evaluator tests this complete activity: Threat information is used to monitor threats and vulnerabilities.. Ve… |
| 1150 | `aws-compliance.benchmark.nist_800_171_rev_2` / `aws-compliance.control.es_domain_node_to_node_encryption_enabled` | `MAPPED` | `peaso/checks/__init__.py:1181` | **OK** — Evaluator signal: OpenSearch domain enables node-to-node encryption (source region exceptions). |
| 1672 | `aws-compliance.benchmark.nist_csf` / `aws-compliance.control.ecs_task_definition_container_environment_no_secret` | `MAPPED` | `peaso/checks/__init__.py:333` | **FIXED** — Credential-name heuristic does not cover arbitrary secrets in ECS environment; MAPPED changed to PARTIAL. |
| 1557 | `aws-compliance.benchmark.nist_csf` / `aws-compliance.control.rds_db_instance_backup_enabled` | `MAPPED` | `peaso/checks/__init__.py:400` | **OK** — Evaluator signal: RDS instance automated backup retention is at least one day. |
| 1087 | `aws-compliance.benchmark.nist_800_171_rev_2` / `aws-compliance.control.cloudtrail_security_trail_enabled` | `MAPPED` | `peaso/checks/__init__.py:268` | **FIXED** — Reason named only HomeRegion, while evaluator requires logging, global and multi-Region, validation, KMS and management selectors; corrected. |
| 1369 | `aws-compliance.benchmark.nist_800_53_rev_5` / `aws-compliance.control.rds_db_instance_prohibit_public_access` | `MAPPED` | `peaso/checks/__init__.py:26` | **OK** — Evaluator signal: RDS instance avoids a public endpoint. |

### `azure-cis`

| Offset | Framework / requirement | Original decision | Index evidence | Judgment |
|---:|---|---|---|---|
| 281 | `cis_2.1_azure` / `8.1` | `MAPPED` | `peaso/checks/__init__.py:944` | **FIXED** — Reason cited rotation-policy fields, but evaluator tests attributes.exp on enabled RBAC-vault keys; corrected. |
| 911 | `azure-compliance.benchmark.cis_v130` / `azure-compliance.control.cis_v130_2_9` | `MAPPED` | `peaso/checks/__init__.py:115` | **OK** — Evaluator signal: Defender declares WDATP integration enabled. |
| 1613 | `azure-compliance.benchmark.cis_v300` / `azure-compliance.control.cis_v300_3_1_6_1` | `MAPPED` | `peaso/checks/__init__.py:71` | **OK** — Evaluator signal: Defender AppServices pricing is Standard in the selected subscription. |
| 205 | `cis_2.1_azure` / `2.1.21` | `MAPPED` | `peaso/checks/__init__.py:141` | **OK** — Evaluator signal: Defender WDATP setting exists and is enabled. |
| 699 | `cis_5.0_azure` / `8.1.3.4` | `NEW_CHECK` | — | **OK** — No native evaluator; proposal tests azure.cis.agentless_scanning_machines_component_status. |
| 941 | `azure-compliance.benchmark.cis_v130` / `azure-compliance.control.cis_v130_4_3_3` | `NEW_CHECK` | — | **OK** — No native evaluator; proposal tests azure.cis.postgresql_single_log_checkpoints. |
| 954 | `azure-compliance.benchmark.cis_v130` / `azure-compliance.control.cis_v130_5_2_2` | `MAPPED` | `peaso/checks/__init__.py:239`, `peaso/checks/__init__.py:58` | **OK** — Evaluator signal: Subscription-scoped activity log alert exists for Delete Policy Assignment; Subscription declares an enabled global alert for Microsoft.Authoriza. |
| 305 | `cis_3.0_azure` / `2.8` | `PARTIAL` | `peaso/checks/__init__.py:20` | **OK** — Evaluator signal: Entra ID enforces the custom banned password list. |
| 1293 | `azure-compliance.benchmark.cis_v200` / `azure-compliance.control.cis_v200_2_1_9` | `MAPPED` | `peaso/checks/__init__.py:71` | **OK** — Evaluator signal: Defender CosmosDbs pricing is Standard in the selected subscription. |
| 1791 | `azure-compliance.benchmark.cis_v400` / `azure-compliance.control.cis_v400_6_7` | `PARTIAL` | `peaso/checks/__init__.py:20` | **OK** — Evaluator signal: Entra ID smart lockout duration is at least 60 seconds. |
| 469 | `cis_4.0_azure` / `9.1.15` | `MAPPED` | `peaso/checks/__init__.py:109` | **OK** — Evaluator signal: Defender contact receives attack-path notifications at High risk or lower. |
| 523 | `cis_4.0_azure` / `7.1.2.1` | `PARTIAL` | `peaso/checks/__init__.py:257` | **OK** — Evaluator signal: Enabled activity log alert exists for Create Policy Assignment. |

### `gcp-other`

| Offset | Framework / requirement | Original decision | Index evidence | Judgment |
|---:|---|---|---|---|
| 170 | `ccc_gcp` / `CCC.SvlsComp.CN01.AR01` | `PARTIAL` | `peaso/checks/__init__.py:151` | **OK** — Evaluator signal: function internal ingress declaration. |
| 702 | `gcp-compliance.benchmark.hipaa` / `gcp-compliance.control.sql_instance_sql_contained_database_authentication_database_flag_off` | `MAPPED` | `peaso/checks/__init__.py:173` | **OK** — Evaluator signal: Cloud SQL reviews explicit contained database authentication configuration. |
| 565 | `rbi_cyber_security_framework_gcp` / `annex_i_6` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Requirement: Put in place systems and processes to identify, track, manage and monitor the status of patches to servers, oper… |
| 923 | `gcp-compliance.benchmark.nist_csf_v2` / `gcp-compliance.control.compute_firewall_allow_connections_proxied_by_iap` | `PARTIAL` | `peaso/checks/__init__.py:164` | **OK** — Evaluator signal: firewall iap tcp proxy source restriction. |
| 128 | `ccc_gcp` / `CCC.IAM.CN02.AR01` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Requirement: When an identity policy for a non-administrative principal is evaluated, it MUST NOT grant permissions for creat… |
| 596 | `secnumcloud_3.2_gcp` / `10.1` | `PARTIAL` | `peaso/checks/__init__.py:35`, `peaso/checks/__init__.py:28`, `peaso/checks/__init__.py:132` | **OK** — Evaluator signal: Every VM disk uses a customer-supplied encryption key (CSEK); BigQuery dataset declares a customer-managed default encryption key; bigquery table. |
| 194 | `ens_rd2022_gcp` / `op.exp.4.gcp.ma.1` | `NEW_CHECK` | — | **OK** — No native evaluator; proposal tests gcp_compute_os_patch_compliance. |
| 180 | `ens_rd2022_gcp` / `opc.acc.4.gcp.iam.1` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Requirement: Proceso de gestión de derechos de acceso The removed evaluators (GKE nodes do not use the Compute Engine default… |
| 800 | `gcp-compliance.benchmark.nist_csf_v10` / `gcp-compliance.control.logging_metric_alert_project_ownership_assignment` | `MAPPED` | `peaso/checks/__init__.py:35` | **OK** — Evaluator signal: Log metric and enabled alert exist for project ownership changes. |
| 937 | `gcp-compliance.benchmark.nist_csf_v2` / `gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_smtp_port_25` | `MAPPED` | `peaso/checks/__init__.py:35` | **OK** — Evaluator signal: Firewall rule does not allow internet ingress to TCP/UDP 25. |
| 689 | `soc2_gcp` / `pi_1_4` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Requirement evidence: The entity implements controls to ensure system outputs are delivered to authorized recipients in the c… |
| 147 | `ccc_gcp` / `CCC.GenAI.CN04.AR01` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: The requirement calls for When data is ingested for training, fine-tuning or conversion to vector embeddings, it MUST be vali… |

### `gcp-cis-cft`

| Offset | Framework / requirement | Original decision | Index evidence | Judgment |
|---:|---|---|---|---|
| 299 | `cis_5.0_gcp` / `3.10` | `MAPPED` | `peaso/checks/__init__.py:82` | **OK** — Evaluator signal: Subnet explicitly enables VPC Flow Logs. |
| 627 | `gcp-compliance.benchmark.cis_v300` / `gcp-compliance.control.cis_v300_1_7` | `MAPPED` | `peaso/checks/__init__.py:33` | **OK** — Evaluator signal: iam service account key age 90. |
| 34 | `cis_2.0_gcp` / `3.2` | `MAPPED` | `peaso/checks/__init__.py:97` | **OK** — Evaluator signal: Network avoids the legacy IPv4Range model. |
| 5 | `cis_2.0_gcp` / `1.12` | `PARTIAL` | — | **OK** — Evaluator signal: . |
| 756 | `gcp-compliance.benchmark.cis_v400` / `gcp-compliance.control.cis_v400_4_9` | `MAPPED` | `peaso/checks/__init__.py:108` | **OK** — Evaluator signal: VM interface inventory avoids declared external addresses. |
| 129 | `cis_3.0_gcp` / `4.3` | `MAPPED` | `peaso/checks/__init__.py:196` | **OK** — Evaluator signal: VM explicitly blocks project-wide SSH keys. |
| 415 | `gcp-compliance.benchmark.cis_v120` / `gcp-compliance.control.cis_v120_4_8` | `MAPPED` | `peaso/checks/__init__.py:86` | **OK** — Evaluator signal: VM explicitly enables both vTPM and integrity monitoring. |
| 328 | `cis_5.0_gcp` / `6.3.2` | `MAPPED` | `peaso/checks/__init__.py:21` | **OK** — Evaluator signal: reference sqlserver cross db ownership chaining. |
| 582 | `gcp-compliance.benchmark.cis_v200` / `gcp-compliance.control.cis_v200_4_2` | `MAPPED` | `peaso/checks/__init__.py:39` | **OK** — Evaluator signal: VM reviews default identity attachment with full OAuth API scope. |
| 541 | `gcp-compliance.benchmark.cis_v200` / `gcp-compliance.control.cis_v200_1_5` | `PARTIAL` | `peaso/checks/__init__.py:42` | **OK** — Evaluator signal: User-managed service account holds no admin, editor or owner role. |
| 157 | `cis_3.0_gcp` / `6.3.2` | `MAPPED` | `peaso/checks/__init__.py:21` | **OK** — Evaluator signal: reference sqlserver cross db ownership chaining. |
| 420 | `gcp-compliance.benchmark.cis_v120` / `gcp-compliance.control.cis_v120_5_2` | `MAPPED` | `peaso/checks/__init__.py:346` | **OK** — Evaluator signal: Bucket uses uniform bucket-level access. |

### `k8s-other`

| Offset | Framework / requirement | Original decision | Index evidence | Judgment |
|---:|---|---|---|---|
| 957 | `pci_4.0_kubernetes` / `3.5.1.21` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if Kubernetes persistent volumes are encrypted at rest with server-side encryption. No portable Kubernetes API field i… |
| 1449 | `pci_4.0_kubernetes` / `8.3.2.29` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if Kubernetes Ingress resources are configured to use TLS certificates provided by a certificate manager. To use this … |
| 1845 | `kubernetes-compliance.benchmark.nsa_cisa_v1` / `kubernetes-compliance.control.network_policy_default_deny_ingress` | `PARTIAL` | `peaso/checks/__init__.py:167` | **OK** — Evaluator signal: Review network policy default deny ingress. |
| 152 | `pci_4.0_kubernetes` / `1.2.8.44` | `NEW_CHECK` | — | **OK** — No native evaluator; proposal tests k8s_networkpolicy_has_ingress_or_egress_rules. |
| 601 | `pci_4.0_kubernetes` / `10.2.1.27` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if logging is enabled for your Kubernetes Pods. No portable Kubernetes API field in the proposed source establishes th… |
| 1702 | `prowler_threatscore_kubernetes` / `1.2.10` | `MAPPED` | `peaso/checks/__init__.py:201` | **OK** — Evaluator signal: pod reviewed container argument kube controller manager service account credentials enabled. |
| 1027 | `pci_4.0_kubernetes` / `3.7.4.3` | `MANUAL` | — | **FIXED** — Ingress TLS Secret association is available from spec.tls and Secret metadata; MANUAL changed to NEW_CHECK. |
| 82 | `iso27001_2022_kubernetes` / `A.8.24` | `PARTIAL` | `peaso/checks/__init__.py:201` | **OK** — Evaluator signal: pod reviewed container encryption providers configured. |
| 1809 | `kubernetes-compliance.benchmark.nsa_cisa_v1` / `kubernetes-compliance.control.deployment_cpu_limit` | `MAPPED` | `peaso/checks/__init__.py:231` | **OK** — Evaluator signal: deployment cpu limit. |
| 820 | `pci_4.0_kubernetes` / `11.6.1.4` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if Kubernetes Audit Logs are configured to send logs to a specified logging service. The audit logging is NON_COMPLIAN… |
| 1065 | `pci_4.0_kubernetes` / `4.2.1.1.12` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if Kubernetes Redis pods have encryption-in-transit enabled. No portable Kubernetes API field in the proposed source e… |
| 522 | `pci_4.0_kubernetes` / `10.2.1.5.30` | `MANUAL` | — | **OK** — No indexed evaluator establishes the full control. Input: Checks if logging is enabled on Kubernetes Ingress resources. No portable Kubernetes API field in the proposed source establi… |

## Proposed-control judgments

All sampled IDs exist in the new-check files. `FIXED` entries count as defective in the original sample. The source and predicate for every sampled control were reviewed; the short `OK` note records what was checked.

### `aws`

| Offset | Check ID | Judgment |
|---:|---|---|
| 177 | `aws_securityhub_findings_alerted` | **OK** — Source: events:ListRules/DescribeRule/ListTargetsByRule; EventPattern.source, EventPattern.detail.findings.Severity.Label, ; predicate: PASS iff an ENABLED EventBridge rule has source aws.securityhub and matches both HIGH and CRITICAL Security Hub findings, with at least one nonem… |
| 20 | `aws.pci.iam.role_required_managed_policies` | **OK** — Source: collected iam_role.AttachedManagedPolicies[].PolicyArn; configured required_policy_arns; predicate: Every in-scope IAM role has every configured managed policy ARN attached |
| 57 | `aws_backup_restore_tests_recent` | **FIXED** — ListRestoreJobs has SourceResourceArn, not ResourceArn; corrected source and restore-testing predicate. |
| 81 | `aws_cis_lightsail_bucket_private` | **OK** — Source: lightsail:GetBuckets buckets[].name,accessRules.getObject,accessRules.allowPublicOverrides; s3control:GetPublicAcce; predicate: FAIL if a bucket has accessRules.getObject=public and effective BlockPublicPolicy/RestrictPublicBuckets do not block it, or any enumerated object… |
| 49 | `aws_api_customer_log_delivery` | **OK** — Source: apigateway:GetStages; methodSettings.*.loggingLevel, accessLogSettings.destinationArn, accessLogSettings.format; predicate: PASS iff each in-scope REST API stage has effective loggingLevel=INFO or ERROR and a nonempty accessLogSettings.destinationArn and format contain… |
| 202 | `aws_wafv2_managed_rule_groups` | **OK** — Source: wafv2:GetWebACL WebACL.Rules[].Statement.ManagedRuleGroupStatement.VendorName, Name, OverrideAction plus approved b; predicate: For every inventoried WebACL ARN, PASS iff a managed rule group with vendor/name outside its baseline inventory is present and its OverrideAction… |
| 15 | `aws.pci.iam.configured_password_policy` | **OK** — Source: iam:GetAccountPasswordPolicy PasswordPolicy.MinimumPasswordLength, RequireSymbols, RequireNumbers, RequireUppercase; predicate: PASS iff iam:GetAccountPasswordPolicy PasswordPolicy.MinimumPasswordLength, RequireSymbols, RequireNumbers, RequireUppercaseCharacters, RequireLo… |
| 27 | `aws.pci.lambda.expected_configuration` | **OK** — Source: existing collected type lambda_function + Configuration.Runtime, Role, Timeout, MemorySize; caller supplied expecte; predicate: For each in-scope Lambda function, Runtime, Role, Timeout and MemorySize equal its approved expected values |
| 92 | `aws_cloudfront_origin_failover_configured` | **OK** — Source: existing collected cloudfront_distribution.Config.DistributionConfig.OriginGroups from cloudfront:GetDistributionCo; predicate: PASS when every in-scope distribution has an OriginGroup with two distinct existing member origin IDs and nonempty FailoverCriteria.StatusCodes.I… |
| 110 | `aws_detective_ai_account_graph_enabled` | **OK** — Source: detective:ListGraphs GraphList[].Arn and GraphList[].CreatedTime in each in-scope account and region; predicate: FAIL if an in-scope AI workload account/region has zero returned Detective GraphList entries with a nonempty Arn; UNKNOWN if the account/region i… |
| 135 | `aws_guardduty_suppression_filters` | **OK** — Source: new read-only guardduty:ListFilters, guardduty:GetFilter; predicate: PASS iff each required detector has an ARCHIVE filter matching the approved low-value finding criteria |
| 10 | `aws.pci.cloudwatch.resource_metric_alarm` | **OK** — Source: cloudwatch:DescribeAlarms and caller-supplied resource type, dimension and metric name; predicate: Each in-scope resource has an enabled alarm for the requested namespace, metric and resource dimension |
| 180 | `aws_securityhub_standards_control_baseline` | **OK** — Source: existing securityhub_hub collector: GetEnabledStandards; new read-only securityhub:DescribeStandardsControls; predicate: PASS iff enabled standards and each enabled/disabled control status equal the configured organizational baseline |
| 122 | `aws_ecr_scan_findings_metric_export` | **OK** — Source: new read-only events:ListRules, events:ListTargetsByRule, cloudwatch:ListMetrics; predicate: PASS iff an enabled rule forwards ECR/Inspector image scan findings to the configured metric ingestion target and the resulting metric is present |
| 47 | `aws_account_non_eu_resource_region_detected` | **OK** — Source: ec2:DescribeRegions (Regions[].RegionName, OptInStatus), s3:ListAllMyBuckets/GetBucketLocation (Buckets[].Name, Loc; predicate: For each listed resource, pass iff its region is in approved_region_names; fail for any resource outside that set; UNKNOWN if approved_region_nam… |

### `azure`

| Offset | Check ID | Judgment |
|---:|---|---|
| 175 | `azure.other.entra_identity_audit_events` | **FIXED** — Graph event reads do not prove approved-sink retention; predicate now returns UNKNOWN without separate export evidence. |
| 211 | `azure.other.monitor_dashboard_access` | **OK** — Source: ARM LIST Microsoft.Portal/dashboards and Microsoft.Insights/workbooks LIST, joined to Microsoft.Authorization/roleA; predicate: FAIL if a dashboard exposing degraded-service state grants read access to an unapproved principal or broad group |
| 86 | `azure.gap.iam_no_custom_subscription_owner_roles_created` | **FIXED** — Role definitions alone cannot prove a custom administrator role is assigned; added role assignments and custom-role type. |
| 370 | `azure_storage_account_monitor_storage_account_with_activity_logs_is_private_d12dda1` | **OK** — Source: Collected storage_account.items[].id joined to collected diagnostic_setting.items[].scope; diagnostic_setting.items; predicate: FAIL iff a storage blob service has no diagnostic setting with StorageRead, StorageWrite and StorageDelete all enabled and a nonempty workspaceId… |
| 247 | `azure_api_management_appinsights_ensure_is_configured_42aac6a` | **OK** — Source: ARM Microsoft.ApiManagement/service/loggers List and /diagnostics List 2024-05-01; inspect loggerType=applicationIn; predicate: FAIL iff an APIM service has no logger with loggerType == applicationInsights referenced by a diagnostics loggerId; UNKNOWN when required invento… |
| 97 | `azure.gap.logic_app_integration_service_environment_encrypted_with_cmk` | **OK** — Source: ARM GET Microsoft.Logic/integrationServiceEnvironments; inspect customer-managed encryption key configuration; predicate: FAIL if an applicable Integration Service Environment has no customer-managed Key Vault key configured for data at rest; UNKNOWN if the service o… |
| 309 | `azure_firewall_policy_1_2_8_42_cacbd9e` | **OK** — Source: Existing collected type web_application_firewall_policy.items[] (ARM GET Microsoft.Network/ApplicationGatewayWebApp; predicate: FAIL iff a WAF policy has empty customRules and empty managedRules.managedRuleSets; UNKNOWN when required inventory, linked resources or named pa… |
| 41 | `azure.cis.private_endpoint_should_mariadb_servers` | **OK** — Source: ARM GET Microsoft.DBforMariaDB/servers with properties.privateEndpointConnections[].properties.privateLinkServiceCo; predicate: FAIL when no private endpoint connection has status Approved; PASS when at least one is Approved. |
| 196 | `azure.other.message_namespace_cmk` | **OK** — Source: existing collected eventhub_namespace and servicebus_namespace properties.encryption.keySource and keyVaultProperti; predicate: FAIL if a scoped messaging namespace does not use a configured customer-managed Key Vault key |
| 44 | `azure.cis.public_network_access_should_mysql_servers` | **OK** — Source: ARM GET Microsoft.DBforMySQL/flexibleServers with properties.network.publicNetworkAccess and firewallRules; predicate: FAIL when properties.network.publicNetworkAccess is Enabled; PASS when Disabled; UNKNOWN when absent on an applicable database generation. |
| 296 | `azure_directory_user_10_6_3_21_d013932` | **FIXED** — Predicate referred to enabled users but source omitted accountEnabled; added it. |
| 261 | `azure_c5_am_09_01b` | **OK** — Source: Microsoft.ResourceGraph/resources (2022-10-01): id, type, tags["data-classification"]; scanner configuration: class; predicate: For every Resource Graph resource whose type is in classified_resource_types[], FAIL if tags["data-classification"] is absent or empty; PASS if e… |
| 46 | `azure.cis.resource_manager_delete_locks_applied_storage_accounts` | **OK** — Source: Microsoft.Storage/storageAccounts:list id; Microsoft.Authorization/locks:listByScope name,properties.level,scope fo; predicate: FAIL if any storage account has no effective lock with properties.level=CanNotDelete or ReadOnly at its own or ancestor scope; PASS if every stor… |
| 14 | `azure.cis.exclusionary_device_code_flow_policy_considered` | **OK** — Source: collected conditional_access_policy: state, conditions.authenticationFlows.transferMethods, conditions.users.includ; predicate: FAIL if no enabled policy with deviceCodeFlow in transferMethods, All in includeUsers, empty excludeUsers, and block in builtInControls exists; P… |
| 164 | `azure.other.clock_sync` | **OK** — Source: Collected vm.items[].guestConfigurationAssignments[].properties.complianceStatus,configurationParameter and assignm; predicate: FAIL if a scoped VM reports NonCompliant against the approved time-sync guest-configuration policy; UNKNOWN if no such guest assignment or curren… |

### `gcp`

| Offset | Check ID | Judgment |
|---:|---|---|
| 42 | `gcp_c5_malware_telemetry` | **OK** — Source: OS Config projects.locations.instances.inventories.get: name, updateTime, items.installedPackages; Compute instance; predicate: FAIL when an in-scope VM requires approved_agent_package and a current OS Config inventories.get items.installedPackages list does not contain it… |
| 59 | `gcp_certificate_rotation_90_days` | **FIXED** — Certificate resource createTime is not certificate issuance; parse leaf X.509 notBefore from pemCertificate. |
| 36 | `gcp_c5_kms_hsm` | **OK** — Source: Existing collected type kms_key.primary.protectionLevel from Cloud KMS cryptoKeys.get; designated HSM key scope as ; predicate: FAIL when a designated HSM key has primary.protectionLevel other than HSM or EXTERNAL_VPC where approved; UNKNOWN without a designated key scope. |
| 67 | `gcp_cloudcdn_cookie_ttl` | **OK** — Source: new read-only Compute:BackendServices.list with sessionAffinity,affinityCookieTtlSec; CDN fields are unrelated; predicate: FAIL when GENERATED_COOKIE or HTTP_COOKIE affinity has affinityCookieTtlSec above 1800 seconds; UNKNOWN when cookie TTL is absent. Absolute affin… |
| 120 | `gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6` | **OK** — Source: Cloud SQL instances.list; inspect databaseVersion and settings.databaseFlags[].name/value.; predicate: FAIL iff a PostgreSQL instance lacks cloudsql.iam_authentication=on or a MySQL instance lacks cloudsql_iam_authentication=on in settings.database… |
| 116 | `gcp_pubsub_topic_cmek` | **OK** — Source: existing collected type pubsub_topic + kmsKeyName; predicate: FAIL when kmsKeyName is empty for an in-scope topic; UNKNOWN when topic metadata is missing. |
| 65 | `gcp_cloudbuild_trigger_trust` | **OK** — Source: existing collected type cloudbuild_trigger + triggerTemplate,github,repositoryEventConfig,serviceAccount,disabled; predicate: FAIL when an enabled cloudbuild_trigger triggerTemplate/github/repositoryEventConfig repository or serviceAccount is outside approved_repositorie… |
| 6 | `gcp.identity.super_admin_recovery_group` | **OK** — Source: Existing workspace_role_assignment roleId,assignedTo and workspace_role roleName; new read-only Admin SDK Directory; predicate: FAIL if a non-suspended super-admin user has recoveryEmail absent, or the address does not resolve to a Directory group, or the resolved group ha… |
| 39 | `gcp_c5_log_isolation` | **FIXED** — Sink destination is storage.googleapis.com/BUCKET, not the bare bucket name; corrected normalization. |
| 56 | `gcp_c5_workforce_federation` | **OK** — Source: IAM workforcePools.list: name, state; workforcePools.providers.list: name, state, oidc.issuerUri, oidc.allowedAudie; predicate: FAIL when an in-scope workforcePools.list state or workforcePools.providers.list state is not ACTIVE, or provider oidc.issuerUri/oidc.allowedAudi… |
| 108 | `gcp_pci_bucket_7dc6cb8c2e05` | **OK** — Source: Cloud Storage buckets.list, buckets.getIamPolicy (existing) and bucketAccessControls.list (new read); inspect bucke; predicate: FAIL when bucket.name is not in excludedPublicBuckets and buckets.getIamPolicy bindings or bucketAccessControls.list entries grant allUsers/allAu… |
| 7 | `gcp.identity.super_admin_separation` | **OK** — Source: Existing workspace_role_assignment roleId,assignedTo and workspace_role roleName joined to Cloud IAM policies bindi; predicate: FAIL if an assigned super-admin primaryEmail appears as a direct user: member of an IAM binding with role roles/owner, roles/editor, or a role ID… |
| 118 | `gcp_resource_label_inventory` | **OK** — Source: new read-only Cloud Asset Inventory:SearchAllResources with name,assetType,labels; predicate: FAIL when an in-scope asset lacks required owner,criticality,data_classification labels; UNKNOWN when policy keys are not supplied. |
| 3 | `gcp.bigquery.table_classification_tags` | **OK** — Source: Existing BigQuery tables.get schema.fields[].name and schema.fields[].policyTags.names; join an operator supplied i; predicate: FAIL if a column listed in the required classification inventory has no intersection between schema.fields[].policyTags.names and the approved ta… |
| 29 | `gcp_c5_cloudbuild_gate` | **OK** — Source: Cloud Build triggers.list: id, approvalConfig.approvalRequired, build.steps, filename; builds.list/get: triggerId, ; predicate: FAIL when an in-scope production trigger approvalConfig.approvalRequired=false where approval is required, or its build.steps/filename definition… |

### `k8s`

| Offset | Check ID | Judgment |
|---:|---|---|
| 102 | `k8s_service_services_type_specified_rule_parameter_86993f7594` | **OK** — Source: Collected service.spec.type; mandatory serviceType policy input.; predicate: For each service, spec.type equals required serviceType; UNKNOWN when the mandatory parameter or inventory is unavailable. |
| 7 | `k8s.cis.admission_hostnetwork` | **OK** — Source: Collected admission_policy: spec.matchConstraints.resourceRules/operations, spec.validations[].expression, binding.; predicate: For each namespace, an admission_policy ValidatingAdmissionPolicyBinding with validationActions containing Deny, matching namespaceSelector/objec… |
| 21 | `k8s.cis.file_admin_conf_owner` | **OK** — Source: Collected file_metadata: path, node, uid, gid, _coverage for /etc/kubernetes/admin.conf.; predicate: For every applicable file_metadata entry whose path matches "/etc/kubernetes/admin.conf", uid=0 and gid=0; UNKNOWN without complete per-node path… |
| 2 | `k8s.cis.admission_capabilities_add` | **OK** — Source: Collected admission_policy: spec.matchConstraints.resourceRules/operations, spec.validations[].expression, binding.; predicate: For each namespace, an admission_policy ValidatingAdmissionPolicyBinding with validationActions containing Deny, matching namespaceSelector/objec… |
| 17 | `k8s.cis.cronjob_effective_runtime_default_seccomp` | **OK** — Source: Collected cronjob: spec.jobTemplate.spec.template.spec.securityContext.seccompProfile.type, spec.jobTemplate.spec.t; predicate: For every container and initContainer in cronjob, coalesce spec.jobTemplate.spec.template.spec.containers[*].securityContext.seccompProfile.type … |
| 25 | `k8s.cis.file_etc_cni_net_d_owner` | **OK** — Source: Collected file_metadata: path, node, uid, gid, _coverage for /etc/cni/net.d/*.; predicate: For every applicable file_metadata entry whose path matches "/etc/cni/net.d/*", uid=0 and gid=0; UNKNOWN without complete per-node path coverage. |
| 96 | `k8s_privileged_utility_access` | **OK** — Source: Collected role/clusterrole.rules[].resources/verbs, rolebinding/clusterrolebinding.subjects/roleRef, pod.metadata.n; predicate: For each effective RBAC binding, grants on pods/exec:create and pods/ephemeralcontainers:update belong to authorized_subjects; each privileged ut… |
| 98 | `k8s_secret_no_deletion_timestamp` | **OK** — Source: Collected secret_metadata.metadata.deletionTimestamp/name/namespace from metadata-only LIST /api/v1/secrets.; predicate: For each secret_metadata, metadata.deletionTimestamp is null or absent; UNKNOWN if metadata-only Secret inventory is incomplete. |
| 52 | `k8s.cis.pod_effective_runtime_default_seccomp` | **OK** — Source: Collected pod: spec.securityContext.seccompProfile.type, spec.containers[*].securityContext.seccompProfile.type, sp; predicate: For every container and initContainer in pod, coalesce spec.containers[*].securityContext.seccompProfile.type with spec.securityContext.seccompPr… |
| 23 | `k8s.cis.file_controller_manager_conf_owner` | **OK** — Source: Collected file_metadata: path, node, uid, gid, _coverage for /etc/kubernetes/controller-manager.conf.; predicate: For every applicable file_metadata entry whose path matches "/etc/kubernetes/controller-manager.conf", uid=0 and gid=0; UNKNOWN without complete … |
| 63 | `k8s_approved_image_installation` | **OK** — Source: Collected pod: spec.containers/initContainers/ephemeralContainers[*].image; admission_policy: spec.validations[].ex; predicate: For every pod, each spec.containers/initContainers/ephemeralContainers[*].image matches an approved registry and digest; an applicable admission_… |
| 1 | `k8s.cis.admission_allowprivilegeescalation` | **OK** — Source: Collected admission_policy: spec.matchConstraints.resourceRules/operations, spec.validations[].expression, binding.; predicate: For each namespace, an admission_policy ValidatingAdmissionPolicyBinding with validationActions containing Deny, matching namespaceSelector/objec… |
| 78 | `k8s_networkpolicy_cluster_has_network_policies_that_24d2fc90b0` | **FIXED** — Port-only NetworkPolicy check ignored public peers and omitted ports, which mean all ports; corrected peer and port semantics. |
| 70 | `k8s_ingress_backend_https` | **OK** — Source: Collected ingress: spec.ingressClassName, spec.tls, spec.rules[].http.paths[].backend.service.name, metadata.annota; predicate: For each nginx ingress with nonempty spec.tls and a resolved backend Service, metadata.annotations["nginx.ingress.kubernetes.io/backend-protocol"… |
| 75 | `k8s_namespace_has_rolebinding` | **OK** — Source: Collected namespace.metadata.name and rolebinding.metadata.namespace; mandatory target_namespace policy input.; predicate: Count(rolebinding where metadata.namespace=target_namespace) >= 1; UNKNOWN without target_namespace or complete RoleBinding inventory. |

## Corrections and evidence

- AWS ECS environment mapping is now `PARTIAL`; the evaluator checks credential-named variables at `peaso/checks/claude2_aws_b_compute.py:333`. S3 and CloudTrail rationales now reflect their actual predicates (`peaso/checks/claude_aws_a_s3.py:434`, `peaso/checks/aws_gap_core.py:268`).
- Azure RBAC Key Vault expiry rationale now cites `properties.attributes.exp`, which is evaluated at `peaso/checks/claude_azure_identity.py:944–962`.
- Kubernetes Ingress TLS control `pci_4.0_kubernetes:3.7.4.3` now proposes `k8s_ingress_tls_configured`; the proposal requires a same-namespace TLS Secret and a TLS entry even when no host is declared. The collector includes `ingress` and metadata-only `secret_metadata` (`peaso/collectors/k8s.py:82`, `:105`, `:713–718`).
- AWS Backup’s [ListRestoreJobs response](https://docs.aws.amazon.com/cli/latest/reference/backup/list-restore-jobs.html) supplies `SourceResourceArn`, not `ResourceArn`.
- The [Certificate Manager Certificate API](https://docs.cloud.google.com/certificate-manager/docs/reference/certificate-manager/rpc/google.cloud.certificatemanager.v1) separates resource `create_time` from `pem_certificate`; the revised check parses the leaf certificate issuance date. The [Cloud Logging sink API](https://docs.cloud.google.com/logging/docs/reference/v2/rest/v2/folders.sinks) formats a Storage destination as `storage.googleapis.com/BUCKET`.
- Azure custom-role assessment now joins role assignments; Entra group membership reads `accountEnabled` before filtering users; event observations no longer claim to establish approved-sink retention. The Kubernetes public-port proposal now accounts for peers and omitted ports.

The two decision changes were reflected in the ledger summaries. No runtime evaluator or collector code was changed; these are mappings and proposed checks, so the revised proposals still need implementation before they can emit findings.
