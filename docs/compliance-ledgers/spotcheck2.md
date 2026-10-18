# Second independent compliance-ledger spot-check

Judgments and edits were made before reading any prior `spotcheck2.md` (none existed at the destination). This review used the frozen requirement text in `inputs/<slice>.json`, the ledger decision and rationale, and the named native evaluator implementation. Proposed IDs were accepted as valid; their predicates and runtime tagging were judged.

## Sampling and redo decision

Deterministic SHA-256 ordering selected eight requirements per ledger using `slice|framework|requirement_id|spotcheck2`. The target strata were two `MAPPED`, two `PARTIAL` or `NEW_CHECK`, two `MANUAL` or `NOT_APPLICABLE`, and two `MAPPING_FIX`; remaining slots were filled from available strata. AWS C5, AWS KISA/ENS/SecNum/NIS2, Azure C5, and GCP C5 have no `MAPPED` rows, so their eight samples use available decisions. The 40 description IDs were selected by SHA-256 of `spotcheck2-desc|check_id` across description chunks, excluding verifier problem files. Error rates use the eight original sampled entries per ledger, including a wrong predicate or invalid runtime tag as an error.

| Ledger | Sampled requirement IDs in selection order | Errors / 8 | Result |
|---|---|---:|---|
| `aws-c5` | `PSS-04.01B`, `OPS-13.01B`, `AM-09.04AC`, `PS-06.01AC`, `OPS-14.03B`, `OPS-22.01AC`, `IAM-08.07B`, `OPS-30.01B` | 0/8 (0.0%) | Sample accepted after fixes |
| `aws-cis` | `aws-compliance.control.cis_v300_2_3_3`, `aws-compliance.control.cis_v600_3_3_1`, `aws-compliance.control.cis_v150_3_3`, `aws-compliance.control.cis_v140_3_3`, `aws-compliance.control.cis_compute_service_v100_3_12`, `aws-compliance.control.cis_v140_1_3`, `aws-compliance.control.cis_v600_2_19`, `aws-compliance.control.cis_v150_1_20` | 0/8 (0.0%) | Sample accepted after fixes |
| `aws-fsbp-wellarch-ftr` | `aws-compliance.control.s3_bucket_restrict_public_read_access`, `aws-compliance.control.foundational_security_es_5`, `EC2.14`, `Enable/disable additional standards and controls`, `RES-001`, `IAM-004`, `IAM.26`, `ElastiCache.4` | 0/8 (0.0%) | Sample accepted after fixes |
| `aws-kisa-ens-secnum-nis2` | `2.6.1`, `11.6.1`, `2.4.5`, `3.1.1`, `2.9.3`, `2.8.5`, `11.8`, `12.3` | 0/8 (0.0%) | Sample accepted after fixes |
| `aws-nist-ffiec-nydfs` | `aws-compliance.control.redshift_cluster_kms_enabled`, `aws-compliance.control.dax_cluster_encryption_at_rest_enabled`, `au_10`, `ac_4_26`, `ds_8`, `si_7_7`, `aws-compliance.benchmark.nist_800_53_rev_5:aws-compliance.control.rds_db_snapshot_prohibit_public_access`, `aws-compliance.benchmark.fedramp_moderate_rev_4:aws-compliance.control.rds_db_snapshot_prohibit_public_access` | 2/8 (25.0%) | **REDO REQUIRED** |
| `aws-other` | `aws-compliance.control.elb_application_lb_deletion_protection_enabled`, `aws-compliance.control.iam_root_user_hardware_mfa_enabled`, `CCC.LB.CN01.AR01`, `CCC.Monitor.CN04.AR01`, `A.8.30`, `AISF-AGENT-05`, `aws-compliance.control.rds_db_snapshot_prohibit_public_access`, `aws-compliance.control.efs_file_system_in_backup_plan` | 0/8 (0.0%) | Sample accepted after fixes |
| `aws-pci` | `aws-compliance.control.s3_public_access_block_account`, `3.3.1.3.5`, `2.2.4`, `6.3.2.b`, `1.2.2.b`, `1.2.2`, `8.2.7.18`, `4.2.1.1.4` | 0/8 (0.0%) | Sample accepted after fixes |
| `azure-c5` | `OPS-25.02B`, `IAM-04.02B`, `IAM-01.01B`, `OPS-11.02B`, `IAM-08.05B`, `OPS-17.01B`, `IAM-07.02B`, `PSS-04.03B` | 0/8 (0.0%) | Sample accepted after fixes |
| `azure-cis` | `azure-compliance.control.cis_v210_4_5_1`, `2.1.13`, `4.4.3`, `azure-compliance.control.postgres_server_private_link_used`, `8.1.5.2`, `azure-compliance.control.cis_v150_1_5`, `8.3.11`, `2.25` | 2/8 (25.0%) | **REDO REQUIRED** |
| `azure-nist-hipaa-rbi-soc2` | `azure-compliance.control.storage_account_default_network_access_rule_denied`, `azure-compliance.control.storage_sync_private_link_used`, `azure-compliance.control.compute_vm_container_security_configurations_vulnerabilities_remediated`, `cc_8_1`, `azure-compliance.control.datalake_analytics_account_logging_enabled`, `164_310_d_1`, `azure-compliance.control.mysql_db_server_geo_redundant_backup_enabled`, `azure-compliance.control.sql_server_and_databases_va_enabled` | 1/8 (12.5%) | Sample accepted after fixes |
| `azure-other` | `3.1.9`, `3.1.7`, `17.5`, `A.6.7`, `11.4`, `A.5.20`, `4.1.2`, `A.6.5` | 0/8 (0.0%) | Sample accepted after fixes |
| `azure-pci` | `4.2.1.19`, `azure-compliance.control.automation_account_variable_encryption_enabled`, `A3.5.1.9`, `11.5.2.5`, `7.2.1.4`, `1.4.2.10`, `1.3.2.15`, `10.2.1.5.7` | 1/8 (12.5%) | Sample accepted after fixes |
| `gcp-c5` | `CRY-09.01B`, `COS-08.02B`, `OPS-32.01B`, `PS-03.06B`, `OPS-22.01AC`, `SP-03.02B`, `IAM-06.04B`, `CRY-01.01B` | 0/8 (0.0%) | Sample accepted after fixes |
| `gcp-cis-cft` | `gcp-compliance.control.cis_v300_1_7`, `6.2.5`, `gcp-compliance.control.sql_world_readable`, `gcp-compliance.control.cis_v120_6_5`, `gcp-compliance.control.cis_v130_1_3`, `gcp-compliance.control.cis_v300_1_3`, `gcp-compliance.control.cis_v130_6_6`, `gcp-compliance.control.cis_v120_6_2_7` | 0/8 (0.0%) | Sample accepted after fixes |
| `gcp-other` | `gcp-compliance.control.only_my_domain`, `gcp-compliance.control.sql_instance_not_publicly_accessible`, `6.2`, `11.4.2.c`, `A.8.25`, `11.5`, `gcp-compliance.control.sql_instance_sql_user_connections_database_flag_configured`, `gcp-perimeter.control.cloud_run_not_publicly_accessible` | 2/8 (25.0%) | **REDO REQUIRED** |
| `gcp-pci` | `gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_port_9200_9300`, `gcp-compliance.control.compute_firewall_rule_ingress_access_restricted_to_tcp_udp_port_389`, `10.2.1.18`, `1.3.1.39`, `10.3.3.17`, `7.2.1.14`, `10.2.1.7.29`, `4.2.1.11` | 0/8 (0.0%) | Sample accepted after fixes |
| `k8s-cis` | `1.2.7`, `4.2.10`, `5.1.9`, `1.1.12`, `cis_1.11_kubernetes:5.3.1`, `cis_2.0.1_kubernetes:5.3.1`, `cis_1.10_kubernetes:4.2.7`, `cis_2.0.1_kubernetes:4.2.7` | 0/8 (0.0%) | Sample accepted after fixes |
| `k8s-other` | `kubernetes-compliance.control.pod_immutable_container_filesystem`, `3.2.3`, `1.5.1.28`, `10.2.2.20`, `1.3.1.11`, `3.5.1.3.21`, `kubernetes-compliance.control.network_policy_default_dont_allow_ingress`, `kubernetes-compliance.control.network_policy_default_dont_allow_egress` | 0/8 (0.0%) | Sample accepted after fixes |

**Redo required:** `aws-nist-ffiec-nydfs` (2/8), `azure-cis` (2/8), and `gcp-other` (2/8). Each exceeds 15%; the sampled fixes do not establish that the rest of those ledgers is sound.

## Ledger findings and fixes

1. `aws-nist-ffiec-nydfs`, `nist_800_53_revision_5_aws:au_10` (`PARTIAL` → `MANUAL`): `aws.cb.opensearch.slow_logs_enabled` tests slow-log publication (`peaso/checks/claude_aws_b_db.py:1216`), not irrefutable evidence for organization-defined actions. Removed the unrelated native tag and recorded control-specific manual evidence.
2. `aws-nist-ffiec-nydfs`, `nist_800_53_revision_5_aws:ac_4_26` (`PARTIAL` → `MANUAL`): generic CloudTrail, load-balancer, API, and other logs do not test recording or auditing cross-domain *content-filtering actions and results*. Removed all 11 unrelated native tags; operational filtering evidence is required (`peaso/checks/aws_a_cloudtrail.py:31`, `peaso/checks/aws_b_core.py:39`).
3. `azure-cis`, `cis_2.1_azure:4.4.3` (`NEW_CHECK`, tag fix): proposed `azure.cis.mysql_single_audit_log_enabled` was also in `native_checks` despite being absent from `inputs/check-index.json`. Cleared the native tag so the proposal cannot yield an automated pass; its read-only single-server configuration predicate remains.
4. `azure-cis`, `azure-compliance.benchmark.cis_v400:azure-compliance.control.postgres_server_private_link_used` (`NEW_CHECK`, tag fix): proposed `azure.gap.postgres_server_private_link_used` likewise appeared as a native check without an evaluator. Cleared the native tag; its approved-private-endpoint predicate remains a proposal.
5. `azure-nist-hipaa-rbi-soc2`, `azure-compliance.benchmark.nist_sp_800_171_rev_2:azure-compliance.control.sql_server_and_databases_va_enabled` (`MAPPING_FIX` → `PARTIAL`, predicate fix): VA presence alone can pass while recurring scans are disabled. Added `azure.claude.sql_va_recurring_scans`, which checks `properties.recurringScans.isEnabled` for classic VA. That evaluator returns `NOT_APPLICABLE` for Express VA, so full recurring-scan coverage remains unverified (`peaso/checks/claude_azure_data.py:605,619-640`).
6. `azure-pci`, `pci_4.0_azure:11.5.2.5` (`NEW_CHECK`, predicate fix): the proposal quantified over existing subscriptions and could pass a storage account with *no* Event Grid subscription. Corrected it to fail absence and require a subscription covering the expected events and approved destination for every in-scope storage account. Updated the matching proposal in `new-checks-azure.json`.
7. `gcp-other`, `gcp-compliance.benchmark.nist_csf_v2:gcp-compliance.control.only_my_domain` (`MAPPED` → `PARTIAL`): the evaluator checks only direct `user:` members of a project-root IAM policy against configured domains; other principal kinds and inherited grants are outside its predicate (`peaso/checks/gcp_ports_iam.py:81-105`).
8. `gcp-other`, `nis2_gcp:11.4.2.c` (`PARTIAL` → `MANUAL`): service-account activity, admin roles, keys, separation of duties, and KMS checks do not test authentication and encryption of system administration access. Removed all seven unrelated native tags; administration entry points and enforcement need direct evidence (`peaso/checks/claude_gcp_k8s_iam.py:280`, `peaso/checks/gcp_gap_cis.py:42`).

## Additional consistency finding

The sampled Azure CIS tag error led to a full native-ID consistency scan. `azure-cis` had 318 unindexed `native_checks` references, `gcp-cis-cft` had 62, and `k8s-other` had 104. Every such ID was already listed in the same row’s `new_checks`. I removed all 484 proposed IDs from `native_checks` while keeping their proposals and decisions. The sample rates above remain based on the eight independently selected rows per ledger; this structural finding also warrants a verifier rerun for `gcp-cis-cft` and `k8s-other`.

## Description sample

All 40 entries below were compared with evaluator code. `OK` means the sampled description, evaluated fields, pass/fail and applicable non-applicable behavior matched; `FIXED` records a mismatch. Three of 40 had errors (7.5%).

| # | Description chunk and check ID | Judgment |
|---:|---|---|
| 1 | `desc-k8s-2.json` · `k8s.ports.job.container_argument_audit_log_maxbackup_greater_than_10` | OK |
| 2 | `desc-k8s-2.json` · `k8s.ports.job.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | OK |
| 3 | `desc-azure-2.json` · `azure.port.keyvault_secret_expiration_set` | OK |
| 4 | `desc-k8s-1.json` · `k8s.daemonset.no_host_network` | OK |
| 5 | `desc-gcp-1.json` · `gcp.claude.logging.metric_alert_bucket_iam_changes` | OK |
| 6 | `desc-aws-2.json` · `aws.cb.rds.cluster_snapshot_shared_accounts_review` | OK |
| 7 | `desc-azure-1.json` · `azure.claude.nsg_internet_icmp` | OK |
| 8 | `desc-aws-4.json` · `aws.iam.restrict_public_trust` | OK |
| 9 | `desc-gcp-1.json` · `gcp.claude.logging.metric_alert_route_changes` | OK |
| 10 | `desc-aws-4.json` · `aws.gap.cloudtrail.bedrock_api_logging` | OK |
| 11 | `desc-azure-1.json` · `azure.claude.nsg_internet_udp_445` | OK |
| 12 | `desc-k8s-3.json` · `k8s.ports.replicationcontroller.container_argument_audit_log_maxsize_greater_than_100` | OK |
| 13 | `desc-k8s-2.json` · `k8s.ports.deployment.container_argument_authorization_mode_rbac` | OK |
| 14 | `desc-aws-3.json` · `aws.claude_a.ec2.launch_template_no_public_ip` | **FIXED** |
| 15 | `desc-gcp-1.json` · `gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off` | OK |
| 16 | `desc-azure-1.json` · `azure.claude.activity_log_alert_subscription_public_ip_write` | OK |
| 17 | `desc-gcp-1.json` · `gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off` | OK |
| 18 | `desc-azure-1.json` · `azure.claude.postgresql_flexible_log_disconnections` | OK |
| 19 | `desc-k8s-1.json` · `k8s.ports.cronjob.container_argument_protect_kernel_defaults_enabled` | OK |
| 20 | `desc-aws-4.json` · `aws.gap.ec2.instance_no_iam_role_with_security_group_write_access` | **FIXED** |
| 21 | `desc-gcp-1.json` · `gcp.iam.data_access_audit` | OK |
| 22 | `desc-gcp-1.json` · `gcp.htbp.gke.kubelet_readonly_port_disabled` | OK |
| 23 | `desc-aws-4.json` · `aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access` | **FIXED** |
| 24 | `desc-azure-2.json` · `azure.port.monitor_log_alert_delete_sql_servers_firewall_rule` | OK |
| 25 | `desc-azure-2.json` · `azure.network.nic_no_ip_forwarding` | OK |
| 26 | `desc-aws-1.json` · `aws.b.docdb.seven_day_backups` | OK |
| 27 | `desc-k8s-3.json` · `k8s.ports.replicaset.container_argument_etcd_certfile_and_keyfile_configured` | OK |
| 28 | `desc-aws-4.json` · `aws.claude_a.networkfirewall.policy_has_rule_groups` | OK |
| 29 | `desc-gcp-1.json` · `gcp.claude.gke.monitoring_enabled` | OK |
| 30 | `desc-azure-1.json` · `azure.claude.defender_assessment_endpoint_protection` | OK |
| 31 | `desc-k8s-3.json` · `k8s.ports.replicaset.no_host_ports` | OK |
| 32 | `desc-k8s-2.json` · `k8s.ports.deployment.container_runtime_default_seccomp` | OK |
| 33 | `desc-k8s-3.json` · `k8s.ports.statefulset.container_argument_authorization_mode_node` | OK |
| 34 | `desc-gcp-1.json` · `gcp.compute.secure_boot` | OK |
| 35 | `desc-aws-1.json` · `aws.b.codebuild.s3_log_encryption` | OK |
| 36 | `desc-k8s-1.json` · `k8s.namespace.restricted_admission` | OK |
| 37 | `desc-k8s-2.json` · `k8s.ports.pod.container_strong_kubelet_cryptographic_ciphers` | OK |
| 38 | `desc-azure-2.json` · `azure.claude2.vm_nic_ip_forwarding_disabled` | OK |
| 39 | `desc-azure-1.json` · `azure.claude.keyvault_key_rotation_policy` | OK |
| 40 | `desc-aws-1.json` · `aws.b.redshift.snapshots_seven_days` | OK |

Description findings:

- `aws.claude_a.ec2.launch_template_no_public_ip`: the old pass text omitted the UNKNOWN path for an existing ENI reference whose public address is not joined. Corrected pass text and description (`peaso/checks/claude_aws_a_ec2.py:1030-1045`).
- `aws.gap.ec2.instance_no_iam_role_with_security_group_write_access` and `aws.gap.ec2.instance_no_iam_role_with_destruction_kms_access`: both described *effective* permission. The evaluator matches declared Allow actions, unconditional all-resource Deny and boundary actions; it does not resolve resource scope, conditions, SCPs or session policies. Corrected both descriptions and pass/fail text (`peaso/checks/aws_gap_ec2.py:126-199`).

## Change counts and verification

- Decision transitions: `PARTIAL → MANUAL`: 3; `MAPPED → PARTIAL`: 1; `MAPPING_FIX → PARTIAL`: 1. No other decision type changed.
- Other sampled fixes: 484 duplicate proposed-ID references removed from `native_checks` across three ledgers (including the two sampled Azure CIS rows); one native evaluator added to the corrected `PARTIAL` row; one proposed Event Grid predicate corrected in the ledger and proposal list; three description entries corrected.
- Ledger summaries were updated for each decision transition. `manifest.json` was not edited; per `README.md`, only the supervisor writes the manifest after verifier review.
