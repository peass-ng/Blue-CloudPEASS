# Fourth independent compliance-ledger spot-check

Sampled the **original** 20 AWS requirements and 20 Azure proposed controls with separate `random.Random(2026101204).sample(range(n), 20)` calls in flattened framework/file order. Seed differs from prior reports. Error rates count defects in the original sampled entries before correction. A proposal is sound only if its predicate and named data source can support PASS, FAIL and UNKNOWN as stated. Proposed IDs are evaluated as proposals, not claimed runtime checks.

| Sample | Original errors | Error rate | Threshold ≤10% |
|---|---:|---:|---|
| AWS requirements | 2/20 | 10% | PASS |
| Azure proposed controls | 11/20 | 55% | FAIL |

## AWS requirement judgments

Frozen text: `inputs/aws-nist-ffiec-nydfs.json`. Native check IDs were resolved through `inputs/check-index.json` and their implementations under `peaso/checks/`. `FIXED` is counted as an original error.

| Offset | Requirement | Original decision | Judgment and evaluator evidence |
|---:|---|---|---|
| 1151 | `aws-compliance.benchmark.nist_800_171_rev_2` / `aws-compliance.control.apigateway_rest_api_stage_use_ssl_certificate` | `PARTIAL` | **OK** — Contradictory source wording is flagged PARTIAL; clientCertificateId checks presence only. `aws.b.apigateway.client_certificate`. |
| 274 | `nist_800_53_revision_5_aws` / `ac_3_13` | `MANUAL` | **OK** — ABAC assignments and enforcement need organization evidence. `no native check`. |
| 2029 | `aws-compliance.benchmark.nydfs_23` / `aws-compliance.control.cloudwatch_log_group_retention_period_365` | `MAPPED` | **OK** — CloudWatch retentionInDays >=365 matches. `aws.a.cloudwatch.finite_retention_365`. |
| 169 | `nist_800_171_revision_2_aws` / `3_14_1` | `MANUAL` | **OK** — Flaw identification and reporting extend beyond GuardDuty/Security Hub. `no native check`. |
| 1825 | `aws-compliance.benchmark.nist_csf_v2` / `aws-compliance.control.sns_topic_encrypted_at_rest` | `MAPPED` | **OK** — SNS KMS key declaration matches. `aws.sns.kms_encryption`. |
| 76 | `fedramp_moderate_revision_4_aws` / `si-4-5` | `MANUAL` | **OK** — Configured alert recipients and custom compromise indicators need policy and response evidence. `no native check`. |
| 218 | `nist_800_53_revision_4_aws` / `sc_2` | `MANUAL` | **OK** — Separation of management and user functions is architectural. `no native check`. |
| 582 | `nist_csf_2.0_aws` / `oc_1` | `MANUAL` | **OK** — Supply-chain role communication is organizational. `no native check`. |
| 384 | `nist_800_53_revision_5_aws` / `cp_10_2` | `MANUAL` | **OK** — Transaction recovery requires application recovery proof. `no native check`. |
| 1964 | `aws-compliance.benchmark.nydfs_23` / `aws-compliance.control.ec2_instance_not_publicly_accessible` | `PARTIAL` | **OK** — IPv4-only public IP test is properly PARTIAL for IPv6. `aws.claude_a.ec2.instance_no_public_ip`. |
| 1455 | `aws-compliance.benchmark.nist_800_53_rev_5` / `aws-compliance.control.guardduty_finding_archived` | `MAPPED` | **OK** — Service.Archived boolean matches named finding control. `aws.claude_a.guardduty.finding_archived`. |
| 490 | `nist_800_53_revision_5_aws` / `si_2_a` | `MANUAL` | **OK** — Identify, report, correct flaws needs process evidence. `no native check`. |
| 1987 | `aws-compliance.benchmark.nydfs_23` / `aws-compliance.control.s3_bucket_policy_restrict_public_access` | `MAPPED` | **FIXED** — Source requires restriction to provided principals, users, IPs or VPCs; evaluator only rejects unconditioned wildcard Allow. Changed MAPPED to PARTIAL. `aws.claude_a.s3.policy_restrict_public_access`. |
| 841 | `aws-compliance.benchmark.fedramp_moderate_rev_4` / `aws-compliance.control.elastic_beanstalk_enhanced_health_reporting_enabled` | `MAPPED` | **OK** — Enhanced-health option matches. `aws.c2b.elasticbeanstalk.enhanced_health`. |
| 427 | `nist_800_53_revision_5_aws` / `ra_3_a_1` | `MANUAL` | **OK** — Threat assessment is organizational. `no native check`. |
| 640 | `nist_csf_2.0_aws` / `pt_4` | `PARTIAL` | **OK** — Selected network checks do not prove all control networks; PARTIAL is appropriate. `aws.cb.redshift.internet_exposed, aws.claude_a.vpc.nacl_no_world_all_ports, aws.claude_a.vpc.sg_no_world_ssh, aws.claude_a.vpc.sg_no_world_all_traffic`. |
| 1091 | `aws-compliance.benchmark.nist_800_171_rev_2` / `aws-compliance.control.ssm_managed_instance_compliance_association_compliant` | `MAPPED` | **OK** — Association ComplianceItems status is the named signal. `aws.cb.ssm.instance_association_compliant`. |
| 1375 | `aws-compliance.benchmark.nist_800_53_rev_5` / `aws-compliance.control.s3_public_access_block_bucket` | `MAPPED` | **FIXED** — Source has excludedPublicBuckets parameter; evaluator ignores exclusions. Changed MAPPED to PARTIAL. `aws.claude_a.s3.bucket_public_access_block_all`. |
| 1896 | `aws-compliance.benchmark.nist_csf_v2` / `aws-compliance.control.autoscaling_group_multiple_az_configured` | `MAPPED` | **OK** — AvailabilityZones count >1 matches. `aws.c2b.autoscaling.multiple_az`. |
| 108 | `ffiec_aws` / `d3-pc-am-b-3` | `MANUAL` | **OK** — Admin privilege limitations and stronger controls require combined organizational evidence. `no native check`. |

## Azure proposed-control judgments

Compared the source field paths with `peaso/collectors/azure.py` for collected types, frozen `inputs/azure-*.json` control descriptions, and the stated ARM/Graph sources. `FIXED` counts an original error.

| Offset | Proposed control | Judgment and source/evaluator evidence |
|---:|---|---|
| 287 | `azure_cdn_profile_1_2_8_5_ed953a0` | **FIXED** — Default CDN certificate is Cdn, not AzureKeyVault; source path was also under profile instead of endpoint custom domain. |
| 68 | `azure.gap.compute_vm_malware_agent_automatic_upgrade_enabled` | **FIXED** — Signature-update claim lacked concrete settings and did not fail a missing extension. |
| 42 | `azure.cis.privileged_role_assignments_periodically_reviewed` | **FIXED** — Existential review check could PASS while other privileged assignments remain unreviewed. |
| 19 | `azure.cis.intune_logs_captured_sent_log_analytics` | **OK** — Intune diagnostic logs and workspace destination are concrete. |
| 54 | `azure.gap.asset_inventory_required_metadata` | **OK** — Inventory tags and requiredTagKeys are named; incomplete inventory yields UNKNOWN. |
| 145 | `azure.other.attack_t1606` | **OK** — Scheduled query, event table, fragments and action group are explicit. |
| 96 | `azure.gap.log_profile_enabled_for_all_subscription` | **FIXED** — Subscription diagnostic settings are a separate collection, not nested in subscription.items[]. |
| 363 | `azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a` | **FIXED** — PublicNetworkAccess=Enabled alone does not establish unrestricted internet ingress; firewall rules needed. |
| 122 | `azure.other.attack_t1049` | **OK** — Scheduled query, event table, fragments and action group are explicit. |
| 210 | `azure.other.monitor_alert_ack_authorization` | **FIXED** — Assignments alone do not establish effective actions; role definitions, inheritance, groups and approved responder set needed. |
| 106 | `azure.gap.mysql_server_private_link_used` | **OK** — Approved MySQL private endpoint status is direct. |
| 160 | `azure.other.build_private_network` | **FIXED** — Pool and service endpoints do not reveal agent network ingress. |
| 272 | `azure_c5_ops_13_01b` | **OK** — Subscription setting Administrative and Security categories plus destination are explicit. |
| 343 | `azure_recovery_vault_10_3_3_2_5313a3c` | **FIXED** — Vault GET alone does not supply backup policies; workload-specific schedules and retention need normalization. |
| 27 | `azure.cis.multifactor_authentication_policy_exists_administrative_groups` | **FIXED** — One MFA policy covering all roles is overly narrow and ignored effective exclusions/conditions; assess coverage per role. |
| 9 | `azure.cis.defender_external_attack_surface_monitoring_easm` | **OK** — Provisioned EASM workspace is a concrete presence signal. |
| 357 | `azure_security_pricing_compute_vm_security_configuration_vulnerabilities_remediated_64c8b1c` | **OK** — VM assessment Unhealthy for configured baseline is a direct signal. |
| 338 | `azure_pci_3_5_1_29` | **FIXED** — Compared key display name with full key ID and did not require encryption enabled. |
| 330 | `azure_pci_10_2_1_1_25` | **FIXED** — Audit OFF passed because FAIL applied only when audit was ON; both generation and export are required. |
| 126 | `azure.other.attack_t1087` | **OK** — Scheduled query, event table, fragments and action group are explicit. |

## Corrections and verification

- Changed AWS offsets 1987 and 1375 from `MAPPED` to `PARTIAL`, updated their reasons, and adjusted the ledger summary by two.
- Corrected the 11 sampled Azure proposals in `new-checks-azure.json`: source paths, data requirements, quantifiers, policy inputs, and PASS/FAIL/UNKNOWN logic. The sampled Azure population still fails the original-error threshold; fixing rows does not retroactively change the measured rate.
- API checks: [CDN custom domain certificate source](https://learn.microsoft.com/en-us/rest/api/cdn/custom-domains/get), [Azure Activity Log categories](https://learn.microsoft.com/en-us/azure/azure-monitor/fundamentals/activity-log-schema), [Recovery Services backup policy list](https://learn.microsoft.com/en-us/rest/api/backup/backup-policies/list), [Managed DevOps Pool networking](https://learn.microsoft.com/en-us/azure/devops/managed-devops-pools/configure-networking), [Synapse workspace key identity](https://learn.microsoft.com/en-us/cli/azure/synapse/workspace/key).

Verification: both JSON files parse, sample offsets are reproducible, and the AWS summary counts sum to the 2,041 requirements.
