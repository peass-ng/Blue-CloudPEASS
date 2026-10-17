# Independent compliance-ledger spot-check

Sample date: 2026-10-12. Deterministic random seed: `20261012`. Each of the 18 ledgers contributed eight requirements: two `MAPPED`/`MAPPING_FIX`, three `PARTIAL`/`NEW_CHECK`, and three `MANUAL`/`NOT_APPLICABLE` where available. For ledgers with no mapped decisions, four were drawn from each of the latter two groups. The four ledgers with no mapped decisions are `aws-c5`, `aws-kisa-ens-secnum-nis2`, `azure-c5`, and `gcp-c5`. Forty descriptions were drawn independently across description chunks, excluding verifier problem files.

I compared requirement text in the frozen slice inputs with ledger decisions, native check implementation and proposed-check predicates. A sample is an error if any recorded decision, mapping, proposed predicate or rationale materially misstates coverage, including tagging an unimplemented ID as native. Manual and out-of-scope samples have no native evaluator; their rationale was checked against the requirement and provider scope. Error rates are errors / 8. The sample is a triage signal, not a complete validation of any ledger.

## Ledger results

| Ledger | Errors / 8 | Error rate | Action |
|---|---:|---:|---|
| aws-c5 | 3/8 | 37.5% | **Redo entire ledger** |
| aws-cis | 2/8 | 25.0% | **Redo entire ledger** |
| aws-fsbp-wellarch-ftr | 2/8 | 25.0% | **Redo entire ledger** |
| aws-kisa-ens-secnum-nis2 | 2/8 | 25.0% | **Redo entire ledger** |
| aws-nist-ffiec-nydfs | 1/8 | 12.5% | No threshold trigger |
| aws-other | 2/8 | 25.0% | **Redo entire ledger** |
| aws-pci | 1/8 | 12.5% | No threshold trigger |
| azure-c5 | 4/8 | 50.0% | **Redo entire ledger** |
| azure-cis | 3/8 | 37.5% | **Redo entire ledger** |
| azure-nist-hipaa-rbi-soc2 | 0/8 | 0.0% | No threshold trigger |
| azure-other | 0/8 | 0.0% | No threshold trigger |
| azure-pci | 1/8 | 12.5% | No threshold trigger |
| gcp-c5 | 2/8 | 25.0% | **Redo entire ledger** |
| gcp-cis-cft | 2/8 | 25.0% | **Redo entire ledger** |
| gcp-other | 2/8 | 25.0% | **Redo entire ledger** |
| gcp-pci | 4/8 | 50.0% | **Redo entire ledger** |
| k8s-cis | 0/8 | 0.0% | No threshold trigger |
| k8s-other | 2/8 | 25.0% | **Redo entire ledger** |

The 12 ledgers marked **Redo entire ledger** exceed the requested 15% threshold. Corrections below fix only sampled entries; each marked ledger still needs a full re-review.

## All ledger findings

| Ledger / framework / requirement | Original → corrected | Finding |
|---|---|---|
| aws-c5 / c5_aws / SSO-05.02AC | PARTIAL → PARTIAL | Config recorder does not report violations; unauthorized-API alarm is only a technical subset. |
| aws-c5 / c5_aws / HR-05.02B | NEW_CHECK → PARTIAL | Offboarding procedure and checklist are not fully automatable. |
| aws-c5 / c5_aws / OPS-07.01AC | PARTIAL → MANUAL | Backup report-plan presence does not show customer self-service portal availability. |
| aws-cis / cis_7.0_aws / 6.1.2 | MAPPED → PARTIAL | EC2 security-group check only excludes world-open CIFS; it does not validate all trusted networks or other access paths. |
| aws-cis / cisa_aws / your-data-4 | PARTIAL → PARTIAL | RDS deletion protection does not test backups or redundancy. |
| aws-fsbp-wellarch-ftr / aws_foundational_technical_review_aws / CAA-002 | PARTIAL → NEW_CHECK | Service-principal SourceAccount check does not inspect sts:ExternalId in customer cross-account role trust. |
| aws-fsbp-wellarch-ftr / aws_account_security_onboarding_aws / Create analyzers in each active regions | PARTIAL → MAPPED | The scope evaluator fails when a region has no analyzer or any analyzer is inactive. |
| aws-kisa-ens-secnum-nis2 / ens_rd2022_aws / op.acc.3.aws.iam.4 | PARTIAL → PARTIAL | Console MFA does not test segregation of duties. |
| aws-kisa-ens-secnum-nis2 / secnumcloud_3.2_aws / 8.3 | MANUAL → MANUAL | Manual evidence type incorrectly cites training records for information protection needs. |
| aws-nist-ffiec-nydfs / ffiec_aws / d3-pc-am-b-10 | PARTIAL → MANUAL | World-open NACL/SSH checks do not establish separation of production and nonproduction environments. |
| aws-other / iso27001_2013_aws / A.9.4.G | PARTIAL → MAPPED | The named requirement is exactly the IAM uppercase password-policy setting tested by the evaluator. |
| aws-other / asd_essential_eight_aws / E8-1.3 | PARTIAL → PARTIAL | Absence of active Inspector findings does not show that a scanner runs daily. |
| aws-pci / pci_4.0_aws / 11.3.1.2.1 | MAPPED → MAPPED | Scan-on-push alone misses repositories covered by enhanced registry scanning. |
| azure-c5 / c5_azure / OPS-26.03B | PARTIAL → MANUAL | VM baseline checks do not verify hardening at immutable-image creation. |
| azure-c5 / c5_azure / IAM-07.03AS | PARTIAL → MANUAL | Resource encryption and Owner role checks do not prove pre-service contractual disclosure of plaintext access. |
| azure-c5 / c5_azure / SSO-02.01AC | MANUAL → MANUAL | Supplier-control rationale cites unrelated personnel records. |
| azure-c5 / c5_azure / PS-03.06B | MANUAL → MANUAL | Facility-maintenance records do not prove personnel ingress/egress response training. |
| azure-cis / cis_5.0_azure / 8.1.3.5 | NEW_CHECK → NEW_CHECK | Proposed check ID is absent from the catalogue and cannot be a native runtime tag. |
| azure-cis / cis_3.0_azure / 8.9 | NEW_CHECK → NEW_CHECK | Proposed check ID is absent from the catalogue and cannot be a native runtime tag. |
| azure-cis / azure-compliance.benchmark.cis_v500 / azure-compliance.control.cis_v500_2_1_3 | NEW_CHECK → NEW_CHECK | Proposed check ID is absent from the catalogue and cannot be a native runtime tag. |
| azure-pci / pci_4.0_azure / 1.5.1.40 | NEW_CHECK → NEW_CHECK | Proposed check ID/title says SSH while the rule covers parameterized authorized ports. |
| gcp-c5 / c5_gcp / DEV-09.01B | NEW_CHECK → MANUAL | Cloud Build security gate does not prove use or secure configuration of a version-control system. |
| gcp-c5 / c5_gcp / DEV-06.02B | NEW_CHECK → MANUAL | Build gates and provenance do not establish risk classification or mitigation before high-risk changes. |
| gcp-cis-cft / gcp-compliance.benchmark.cis_v400 / gcp-compliance.control.cis_v400_4_12 | NEW_CHECK → NEW_CHECK | Proposed check ID is absent from the catalogue and cannot be a native runtime tag. |
| gcp-cis-cft / cis_2.0_gcp / 1.12 | PARTIAL → PARTIAL | Proposed check ID is absent from the catalogue and cannot be a native runtime tag. |
| gcp-other / ccc_gcp / CCC.Build.CN01.AR01 | PARTIAL → PARTIAL | Proposed check ID is not native; approved-source configuration also cannot prove a rejected runtime attempt. |
| gcp-other / secnumcloud_3.2_gcp / 18.3 | PARTIAL → MANUAL | Audit logging configuration does not establish periodic review of compliance with policies and standards. |
| gcp-pci / pci_4.0_gcp / 10.3.2.21 | MAPPING_FIX → PARTIAL | Uniform bucket-level access does not establish absence of public IAM grants or evaluate excludedPublicBuckets. |
| gcp-pci / pci_4.0_gcp / 1.2.8.10 | NEW_CHECK → MANUAL | Proposed predicate merely repeats the source text and its Cloud Asset data source has no specified Config Connector status field. |
| gcp-pci / pci_4.0_gcp / 10.2.1.23 | NEW_CHECK → MANUAL | The proposal repeats “any log types” without defining engine-specific required logs or fields. |
| gcp-pci / pci_4.0_gcp / 8.4.3.3 | NEW_CHECK → NOT_APPLICABLE | GCP has no AWS-style root user or root virtual MFA device. |
| k8s-other / pci_4.0_kubernetes / 7.2.2.27 | NEW_CHECK → NEW_CHECK | Proposed check ID is not native and the generated predicate is tautological. |
| k8s-other / iso27001_2022_kubernetes / A.5.12 | PARTIAL → PARTIAL | Proposed classification-label check ID is not native. |
| descriptions / `azure.claude.activity_log_storage_cmk` | corrected description | The original text omitted the subscription diagnostic-setting join and incorrectly said `NOT_APPLICABLE` never occurs. The evaluator returns it when no diagnostic setting exports to a storage account (`peaso/checks/claude_azure_network.py:417`). |

## Requirement sample and evaluator evidence

Verdict `correct` means the sampled entry was sound; `fixed` identifies a finding above. The decision shown is the original sampled decision. Source references point to evaluator registration or generating predicate; proposed checks have no implementation.

### aws-c5

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| c5_aws | SSO-05.02AC | PARTIAL | fixed | peaso/checks/aws_a_regional.py:33 |
| c5_aws | HR-05.02B | NEW_CHECK | fixed | proposed (no evaluator) |
| c5_aws | OPS-07.01AC | PARTIAL | fixed | peaso/checks/aws_b_regional.py:27 |
| c5_aws | OIS-04.03B | PARTIAL | correct | peaso/checks/aws_gap_core.py:253, peaso/checks/aws_gap_metrics.py:267 |
| c5_aws | OIS-08.02B | MANUAL | correct | none (manual / out of scope) |
| c5_aws | SIM-03.05B | MANUAL | correct | none (manual / out of scope) |
| c5_aws | SSO-05.06B | MANUAL | correct | none (manual / out of scope) |
| c5_aws | PSS-03.05B | MANUAL | correct | none (manual / out of scope) |

### aws-cis

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| cis_2.0_aws | 3.2 | MAPPED | correct | peaso/checks/aws.py:14 |
| cis_7.0_aws | 6.1.2 | MAPPED | fixed | peaso/checks/claude_aws_a_ec2.py:940 |
| cisa_aws | your-data-4 | PARTIAL | fixed | peaso/checks/aws_b_core.py:81, peaso/checks/claude2_aws_b_analytics.py:130, peaso/checks/claude_aws_b_db.py:915, peaso/checks/aws.py:127, peaso/checks/aws.py:11, peaso/checks/aws.py:33 |
| cis_1.5_aws | 1.7 | PARTIAL | correct | peaso/checks/aws_gap_core.py:519 |
| cis_5.0_aws | 1.6 | PARTIAL | correct | peaso/checks/aws_gap_core.py:519 |
| aws-compliance.benchmark.cis_compute_service_v100 | aws-compliance.control.cis_compute_service_v100_4_12 | MANUAL | correct | none (manual / out of scope) |
| aws-compliance.benchmark.cis_v400 | aws-compliance.control.cis_v400_1_3 | MANUAL | correct | none (manual / out of scope) |
| cis_1.5_aws | 1.3 | MANUAL | correct | none (manual / out of scope) |

### aws-fsbp-wellarch-ftr

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| aws-compliance.benchmark.foundational_security | aws-compliance.control.foundational_security_redshiftserverless_5 | MAPPED | correct | peaso/checks/claude2_aws_b.py:69 |
| aws-compliance.benchmark.foundational_security | aws-compliance.control.foundational_security_opensearch_1 | MAPPED | correct | peaso/checks/claude2_aws_b.py:43 |
| aws_foundational_technical_review_aws | CAA-002 | PARTIAL | fixed | peaso/checks/claude_aws_a_iam_prowler.py:387 |
| aws_well_architected_framework_security_pillar_aws | SEC05-BP04 | PARTIAL | correct | peaso/checks/claude2_aws_b_edge.py:949 |
| aws_account_security_onboarding_aws | Create analyzers in each active regions | PARTIAL | fixed | peaso/checks/aws_a_accessanalyzer.py:23 |
| aws_well_architected_framework_security_pillar_aws | SEC10-BP01 | MANUAL | correct | none (manual / out of scope) |
| aws_foundational_technical_review_aws | WAFR-002 | MANUAL | correct | none (manual / out of scope) |
| aws_account_security_onboarding_aws | CFD + ALB + secret rotation architecture | MANUAL | correct | none (manual / out of scope) |

### aws-kisa-ens-secnum-nis2

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| ens_rd2022_aws | mp.com.2.aws.vpn.1 | PARTIAL | correct | proposed (no evaluator) |
| ens_rd2022_aws | op.acc.3.aws.iam.4 | PARTIAL | fixed | peaso/checks/claude_aws_a.py:27, peaso/checks/__init__.py:228 |
| nis2_aws | 4.2.2.f | PARTIAL | correct | peaso/checks/claude2_aws_b_data.py:291 |
| nis2_aws | 3.2.3.g | PARTIAL | correct | peaso/checks/aws_a_regional.py:13, peaso/checks/aws.py:15 |
| secnumcloud_3.2_aws | 15.1 | MANUAL | correct | none (manual / out of scope) |
| secnumcloud_3.2_aws | 8.3 | MANUAL | fixed | none (manual / out of scope) |
| nis2_aws | 2.1.2.d | MANUAL | correct | none (manual / out of scope) |
| secnumcloud_3.2_aws | 6.3 | MANUAL | correct | none (manual / out of scope) |

### aws-nist-ffiec-nydfs

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| aws-compliance.benchmark.fedramp_moderate_rev_4 | aws-compliance.control.cloudwatch_alarm_action_enabled | MAPPED | correct | peaso/checks/aws_a_cloudwatch.py:33 |
| aws-compliance.benchmark.nist_800_53_rev_4 | aws-compliance.control.s3_public_access_block_bucket_account | MAPPED | correct | peaso/checks/aws_a_s3.py:52 |
| ffiec_aws | d3-pc-am-b-10 | PARTIAL | fixed | peaso/checks/claude_aws_a_network.py:422, peaso/checks/claude_aws_a_network.py:298 |
| ffiec_aws | d3-dc-an-b-4 | PARTIAL | correct | peaso/checks/aws_a_cloudtrail.py:31, peaso/checks/aws_b_loadbalancing.py:215, peaso/checks/claude2_aws_b_edge.py:979, peaso/checks/claude_aws_b_db.py:1216, peaso/checks/claude_aws_b_db.py:879, peaso/checks/claude2_aws_a_cloudtrail.py:120, peaso/checks/claude_aws_a_network.py:491, peaso/checks/aws_extended.py:154, peaso/checks/aws_gap_core.py:317, peaso/checks/aws_gap_core.py:317, peaso/checks/aws_extended.py:89, peaso/checks/aws.py:43 |
| nist_800_53_revision_5_aws | sc_5_b | PARTIAL | correct | peaso/checks/aws_a_regional.py:13 |
| nist_csf_1.1_aws | ip_2 | MANUAL | correct | none (manual / out of scope) |
| nist_csf_2.0_aws | ov_1 | MANUAL | correct | none (manual / out of scope) |
| nist_800_53_revision_5_aws | si_2_d | MANUAL | correct | none (manual / out of scope) |

### aws-other

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| prowler_threatscore_aws | 3.3.7 | MAPPED | correct | peaso/checks/aws_gap_metrics.py:277 |
| aws-compliance.benchmark.hipaa_final_omnibus_security_rule_2013 | aws-compliance.control.ec2_instance_ssm_managed | MAPPED | correct | peaso/checks/claude_aws_a_ec2.py:726 |
| iso27001_2013_aws | A.9.4.G | PARTIAL | fixed | peaso/checks/aws_extended.py:32 |
| asd_essential_eight_aws | E8-3.1 | PARTIAL | correct | peaso/checks/claude2_aws_b_identity.py:419, peaso/checks/claude_aws_a_iam.py:792, peaso/checks/claude_aws_a_iam.py:697, peaso/checks/claude_aws_a_iam.py:812, peaso/checks/aws_gap_metrics.py:269, peaso/checks/__init__.py:228, peaso/checks/aws.py:138 |
| asd_essential_eight_aws | E8-1.3 | PARTIAL | fixed | peaso/checks/claude_aws_b_security.py:74, peaso/checks/claude_aws_b_security.py:127 |
| ccc_aws | CCC.RDMS.CN02.AR01 | MANUAL | correct | none (manual / out of scope) |
| asd_essential_eight_aws | E8-7.2 | MANUAL | correct | none (manual / out of scope) |
| iso27001_2022_aws | A.5.8 | MANUAL | correct | none (manual / out of scope) |

### aws-pci

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| pci_4.0_aws | 11.3.1.2.1 | MAPPED | fixed | peaso/checks/aws.py:18 |
| pci_4.0_aws | 8.2.7.1 | MAPPED | correct | peaso/checks/aws_a_account.py:37 |
| pci_4.0_aws | 3.5.1.36 | NEW_CHECK | correct | proposed (no evaluator) |
| pci_3.2.1_aws | 8.2.1.c | PARTIAL | correct | peaso/checks/claude2_aws_b_edge.py:808, peaso/checks/claude2_aws_b_edge.py:549 |
| pci_4.0_aws | 10.2.1.24 | PARTIAL | correct | peaso/checks/claude_aws_b_db.py:879 |
| pci_3.2.1_aws | 8.2.1.b | MANUAL | correct | none (manual / out of scope) |
| pci_3.2.1_aws | 6.5 | MANUAL | correct | none (manual / out of scope) |
| pci_3.2.1_aws | 1.2.2 | NOT_APPLICABLE | correct | none (manual / out of scope) |

### azure-c5

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| c5_azure | OPS-26.03B | PARTIAL | fixed | peaso/checks/claude_azure_compute.py:304, peaso/checks/claude_azure_compute.py:306 |
| c5_azure | PSS-02.01B | PARTIAL | correct | peaso/checks/claude_azure_data.py:605, peaso/checks/claude_azure_data.py:344 |
| c5_azure | IAM-07.03AS | PARTIAL | fixed | peaso/checks/__init__.py:567, peaso/checks/azure_ports_storage.py:12, peaso/checks/azure_extended.py:17, peaso/checks/azure_extended.py:164 |
| c5_azure | AM-06.02B | PARTIAL | correct | peaso/checks/claude_azure_network.py:385, peaso/checks/azure_ports_storage.py:12 |
| c5_azure | IAM-09.04B | MANUAL | correct | none (manual / out of scope) |
| c5_azure | SSO-02.01AC | MANUAL | fixed | none (manual / out of scope) |
| c5_azure | PS-03.06B | MANUAL | fixed | none (manual / out of scope) |
| c5_azure | PSS-07.02B | MANUAL | correct | none (manual / out of scope) |

### azure-cis

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| cis_2.1_azure | 4.1.3 | MAPPED | correct | peaso/checks/claude_azure_data.py:652, peaso/checks/azure_extended.py:164 |
| cis_5.0_azure | 5.25 | MAPPING_FIX | correct | peaso/checks/azure_ports_iam.py:40 |
| cis_5.0_azure | 8.1.3.5 | NEW_CHECK | fixed | proposed (no evaluator) |
| cis_3.0_azure | 8.9 | NEW_CHECK | fixed | proposed (no evaluator) |
| azure-compliance.benchmark.cis_v500 | azure-compliance.control.cis_v500_2_1_3 | NEW_CHECK | fixed | proposed (no evaluator) |
| cis_2.1_azure | 1.5 | MANUAL | correct | none (manual / out of scope) |
| cis_2.1_azure | 1.1.4 | MANUAL | correct | none (manual / out of scope) |
| azure-compliance.benchmark.cis_v130 | azure-compliance.control.cis_v130_1_10 | MANUAL | correct | none (manual / out of scope) |

### azure-nist-hipaa-rbi-soc2

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| azure-compliance.benchmark.nist_sp_800_53_rev_5 | azure-compliance.control.securitycenter_azure_defender_on_for_keyvault | MAPPED | correct | peaso/checks/azure_ports_defender.py:12 |
| azure-compliance.benchmark.nist_sp_800_53_rev_5 | azure-compliance.control.securitycenter_security_alerts_to_owner_enabled | MAPPED | correct | peaso/checks/claude_azure_data.py:158 |
| hipaa_azure | 164_308_a_4_ii_c | PARTIAL | correct | peaso/checks/claude_azure_identity.py:377, peaso/checks/claude_azure_identity.py:277, peaso/checks/claude_azure_identity.py:275, peaso/checks/claude_azure_identity.py:552, peaso/checks/claude_azure_identity.py:533 |
| azure-compliance.benchmark.nist_sp_800_53_rev_5 | azure-compliance.control.mysql_server_infrastructure_encryption_enabled | NEW_CHECK | correct | proposed (no evaluator) |
| azure-compliance.benchmark.nist_sp_800_171_rev_2 | azure-compliance.control.postgres_sql_server_encrypted_at_rest_using_cmk | NEW_CHECK | correct | proposed (no evaluator) |
| azure-compliance.benchmark.fedramp_high | azure-compliance.control.datalake_store_account_logging_enabled | NOT_APPLICABLE | correct | none (manual / out of scope) |
| azure-compliance.benchmark.nist_sp_800_171_rev_2 | azure-compliance.control.arc_compute_machine_windows_log_analytics_agent_installed | NOT_APPLICABLE | correct | none (manual / out of scope) |
| azure-compliance.benchmark.nist_sp_800_53_rev_5 | azure-compliance.control.storage_account_uses_azure_resource_manager | NOT_APPLICABLE | correct | none (manual / out of scope) |

### azure-other

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| prowler_threatscore_azure | 2.2.10 | MAPPED | correct | peaso/checks/claude_azure_data.py:509 |
| azure-perimeter.benchmark.network_access | azure-perimeter.control.network_interface_not_attached_to_public_ip | MAPPED | correct | peaso/checks/claude_azure_network.py:838 |
| iso27001_2022_azure | A.8.16 | PARTIAL | correct | peaso/checks/claude2_azure_network.py:381 |
| secnumcloud_3.2_azure | 17.3 | PARTIAL | correct | peaso/checks/claude_azure_compute.py:534, peaso/checks/claude_azure_network.py:1083 |
| ccc_azure | CCC.RDMS.CN05.AR01 | NEW_CHECK | correct | proposed (no evaluator) |
| secnumcloud_3.2_azure | 18.1 | MANUAL | correct | none (manual / out of scope) |
| ccc_azure | CCC.Vector.CN06.AR01 | NOT_APPLICABLE | correct | none (manual / out of scope) |
| nis2_azure | 3.1.1 | MANUAL | correct | none (manual / out of scope) |

### azure-pci

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| pci_4.0_azure | 1.3.1.19 | MAPPED | correct | peaso/checks/azure_gap_nsg.py:28 |
| pci_4.0_azure | 6.4.2.1 | MAPPING_FIX | correct | peaso/checks/claude2_azure_network.py:314 |
| pci_4.0_azure | 8.2.7.3 | NEW_CHECK | correct | proposed (no evaluator) |
| pci_4.0_azure | 1.5.1.40 | NEW_CHECK | fixed | proposed (no evaluator) |
| pci_4.0_azure | 1.3.1.27 | NEW_CHECK | correct | proposed (no evaluator) |
| pci_4.0_azure | 3.7.6.2 | NOT_APPLICABLE | correct | none (manual / out of scope) |
| pci_4.0_azure | 10.2.1.31 | NOT_APPLICABLE | correct | none (manual / out of scope) |
| pci_4.0_azure | 3.3.1.1.7 | NOT_APPLICABLE | correct | none (manual / out of scope) |

### gcp-c5

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| c5_gcp | OPS-16.02B | PARTIAL | correct | peaso/checks/gcp_ports_logging.py:8 |
| c5_gcp | IAM-04.01B | NEW_CHECK | correct | proposed (no evaluator) |
| c5_gcp | DEV-09.01B | NEW_CHECK | fixed | proposed (no evaluator) |
| c5_gcp | DEV-06.02B | NEW_CHECK | fixed | proposed (no evaluator) |
| c5_gcp | PS-06.04AC | MANUAL | correct | none (manual / out of scope) |
| c5_gcp | OIS-03.05B | MANUAL | correct | none (manual / out of scope) |
| c5_gcp | HR-06.05B | MANUAL | correct | none (manual / out of scope) |
| c5_gcp | PS-03.04B | MANUAL | correct | none (manual / out of scope) |

### gcp-cis-cft

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| gcp-compliance.benchmark.cis_v200 | gcp-compliance.control.cis_v200_1_15 | MAPPED | correct | peaso/checks/gcp_ports_keys.py:53 |
| cis_2.0_gcp | 4.5 | MAPPED | correct | peaso/checks/gcp_ports_compute.py:25 |
| gcp-compliance.benchmark.cis_v300 | gcp-compliance.control.cis_v300_1_1 | PARTIAL | correct | peaso/checks/gcp_ports_iam.py:105 |
| gcp-compliance.benchmark.cis_v400 | gcp-compliance.control.cis_v400_4_12 | NEW_CHECK | fixed | proposed (no evaluator) |
| cis_2.0_gcp | 1.12 | PARTIAL | fixed | proposed (no evaluator) |
| cis_5.0_gcp | 1.4 | MANUAL | correct | none (manual / out of scope) |
| cis_3.0_gcp | 1.3 | MANUAL | correct | none (manual / out of scope) |
| cis_2.0_gcp | 1.3 | MANUAL | correct | none (manual / out of scope) |

### gcp-other

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| gcp-compliance.benchmark.hipaa | gcp-compliance.control.logging_metric_alert_storage_iam_permission_changes | MAPPED | correct | peaso/checks/claude_gcp_k8s_iam.py:420 |
| prowler_threatscore_gcp | 1.3.1 | MAPPED | correct | peaso/checks/claude_gcp_k8s_iam.py:223 |
| ccc_gcp | CCC.ObjStor.CN04.AR02 | PARTIAL | correct | peaso/checks/claude_gcp_k8s_iam.py:91 |
| ccc_gcp | CCC.Build.CN01.AR01 | PARTIAL | fixed | proposed (no evaluator) |
| secnumcloud_3.2_gcp | 18.3 | PARTIAL | fixed | peaso/checks/claude_gcp_k8s_iam.py:189 |
| secnumcloud_3.2_gcp | 17.1 | MANUAL | correct | none (manual / out of scope) |
| secnumcloud_3.2_gcp | 14.3 | MANUAL | correct | none (manual / out of scope) |
| iso27001_2022_gcp | A.7.5 | MANUAL | correct | none (manual / out of scope) |

### gcp-pci

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| pci_4.0_gcp | 10.3.2.21 | MAPPING_FIX | fixed | peaso/checks/gcp_ports_services.py:48 |
| gcp-compliance.benchmark.pci_dss_v321 | gcp-compliance.control.enable_network_flow_logs | MAPPED | correct | peaso/checks/gcp_ports_services.py:46 |
| pci_4.0_gcp | 1.2.8.10 | NEW_CHECK | fixed | proposed (no evaluator) |
| pci_4.0_gcp | 10.2.1.23 | NEW_CHECK | fixed | proposed (no evaluator) |
| pci_4.0_gcp | 8.4.3.3 | NEW_CHECK | fixed | proposed (no evaluator) |
| pci_4.0_gcp | 3.5.1.24 | NOT_APPLICABLE | correct | none (manual / out of scope) |
| pci_4.0_gcp | 5.3.4.1 | NOT_APPLICABLE | correct | none (manual / out of scope) |
| pci_4.0_gcp | 10.2.1.7.2 | NOT_APPLICABLE | correct | none (manual / out of scope) |

### k8s-cis

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| cis_1.11_kubernetes | 2.4 | MAPPED | correct | peaso/checks/k8s_ports_components.py:58 |
| cis_1.12_kubernetes | 1.2.8 | MAPPED | correct | peaso/checks/k8s_ports_reference_config.py:15 |
| cis_2.0.1_kubernetes | 1.1.20 | NEW_CHECK | correct | proposed (no evaluator) |
| kubernetes-compliance.benchmark.cis_kube_v120 | kubernetes-compliance.control.cis_kube_v120_v100_5_2_1 | PARTIAL | correct | peaso/checks/k8s_ports_cluster.py:213 |
| cis_1.8_kubernetes | 5.1.12 | PARTIAL | correct | peaso/checks/claude_gcp_k8s_k8s.py:875 |
| cis_1.8_kubernetes | 3.1.2 | MANUAL | correct | none (manual / out of scope) |
| cis_1.12_kubernetes | 3.1.1 | MANUAL | correct | none (manual / out of scope) |
| cis_1.12_kubernetes | 5.3.1 | MANUAL | correct | none (manual / out of scope) |

### k8s-other

| Framework | Requirement | Original decision | Verdict | Evaluator code |
|---|---|---|---|---|
| kubernetes-compliance.benchmark.nsa_cisa_v1 | kubernetes-compliance.control.cronjob_container_privilege_escalation_disabled | MAPPED | correct | peaso/checks/k8s_ports_workloads.py:25 |
| prowler_threatscore_kubernetes | 1.1.2 | MAPPED | correct | peaso/checks/k8s_ports_reference_config.py:16 |
| pci_4.0_kubernetes | 7.2.2.27 | NEW_CHECK | fixed | proposed (no evaluator) |
| pci_4.0_kubernetes | 10.6.3.30 | PARTIAL | correct | peaso/checks/k8s_ports_components.py:33 |
| iso27001_2022_kubernetes | A.5.12 | PARTIAL | fixed | proposed (no evaluator) |
| iso27001_2022_kubernetes | A.5.8 | MANUAL | correct | none (manual / out of scope) |
| iso27001_2022_kubernetes | A.5.21 | MANUAL | correct | none (manual / out of scope) |
| iso27001_2022_kubernetes | A.8.26 | MANUAL | correct | none (manual / out of scope) |

## Description sample

One error was found and corrected (1/40, 2.5%). `evaluated`, `pass_when`, `fail_when`, and `not_applicable_when` were compared with the implementation.

| Description file | Check ID | Verdict | Evaluator code |
|---|---|---|---|
| desc-aws-1.json | aws.b.acm.no_wildcard_domain | correct | peaso/checks/aws_b_loadbalancing.py:157 |
| desc-k8s-1.json | k8s.ports.cronjob.container_argument_insecure_port_0 | correct | peaso/checks/k8s_ports_components.py:42 |
| desc-aws-3.json | aws.claude_a.guardduty.finding_archived | correct | peaso/checks/claude_aws_a_security.py:156 |
| desc-azure-2.json | azure.port.security_center_defender_for_cloudposture_enabled | correct | peaso/checks/azure_ports_defender.py:20 |
| desc-k8s-2.json | k8s.ports.podtemplate.container_argument_kube_controller_manager_root_ca_file_configured | correct | peaso/checks/k8s_ports_reference_config.py:28 |
| desc-k8s-1.json | k8s.claude.daemonset.dashboard_not_deployed | correct | peaso/checks/claude_gcp_k8s_k8s.py:369 |
| desc-azure-2.json | azure.vault.soft_delete | correct | peaso/checks/azure.py:10 |
| desc-aws-3.json | aws.cb.route53.domain_not_expired | correct | peaso/checks/claude_aws_b_security.py:412 |
| desc-azure-1.json | azure.claude.cosmos_virtual_network_filter | correct | peaso/checks/claude_azure_compute.py:806 |
| desc-k8s-1.json | k8s.ports.configmap_metadata.config_map_default_namespace_used | correct | peaso/checks/k8s_ports_cluster.py:26 |
| desc-k8s-3.json | k8s.ports.statefulset.container_argument_security_context_deny_enabled | correct | peaso/checks/k8s_ports_components.py:71 |
| desc-azure-2.json | azure.claude2.web_app_failed_request_tracing | correct | peaso/checks/claude2_azure_app.py:261 |
| desc-gcp-1.json | gcp.claude.firewall.public_ingress_tcp_port_137_to_139 | correct | peaso/checks/claude_gcp_k8s_compute.py:36 |
| desc-k8s-2.json | k8s.ports.pod.no_sys_admin | correct | peaso/checks/k8s_ports_workloads.py:118 |
| desc-k8s-1.json | k8s.ports.cronjob.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured | correct | peaso/checks/k8s_ports_reference_config.py:26 |
| desc-azure-1.json | azure.claude.activity_log_storage_cmk | fixed | peaso/checks/claude_azure_network.py:459 |
| desc-azure-2.json | azure.claude2.entra_ca_mfa_all_users_or_roles | correct | peaso/checks/claude2_azure_identity.py:99 |
| desc-aws-1.json | aws.b.elasticache.automatic_failover | correct | peaso/checks/aws_b_compute.py:68 |
| desc-azure-1.json | azure.claude.iam_no_custom_role | correct | peaso/checks/claude_azure_identity.py:574 |
| desc-aws-2.json | aws.cb.lightsail.instance_auto_snapshot | correct | peaso/checks/claude_aws_b_compute.py:338 |
| desc-k8s-2.json | k8s.ports.podtemplate.container_argument_api_server_anonymous_auth_disabled | correct | peaso/checks/k8s_ports_components.py:27 |
| desc-aws-2.json | aws.c2b.elasticache.cluster_no_default_subnet_group | correct | peaso/checks/claude2_aws_b_data.py:978 |
| desc-azure-2.json | azure.port.monitor_log_alert_create_update_security_solution | correct | peaso/checks/azure_ports_monitor.py:16 |
| desc-aws-3.json | aws.cb.servicecatalog.no_account_shares | correct | peaso/checks/claude_aws_b_security.py:620 |
| desc-aws-4.json | aws.claude_a.iam.user_long_lived_keys_only_iam_sts | correct | peaso/checks/claude_aws_a_iam.py:835 |
| desc-gcp-1.json | gcp.claude.image.policy_shared_access | correct | peaso/checks/gcp_ports_perimeter.py:60 |
| desc-aws-1.json | aws.b.aurora.mysql_audit_export | correct | peaso/checks/aws_b_storage.py:50 |
| desc-k8s-3.json | k8s.ports.statefulset.container_argument_kube_scheduler_bind_address_127_0_0_1 | correct | peaso/checks/k8s_ports_reference_config.py:33 |
| desc-aws-2.json | aws.cb.fsx.lustre_copy_tags_to_backups | correct | peaso/checks/claude_aws_b_storage.py:69 |
| desc-gcp-1.json | gcp.ports.apikeys_api_restricted_with_gemini_api | correct | peaso/checks/gcp_ports_configuration.py:132 |
| desc-azure-2.json | azure.claude2.entra_lockout_threshold_max_10 | correct | peaso/checks/claude2_azure_identity.py:78 |
| desc-aws-2.json | aws.c2b.dms.task_source_logging | correct | peaso/checks/claude2_aws_b_data.py:105 |
| desc-k8s-3.json | k8s.ports.statefulset.readiness_probe | correct | peaso/checks/k8s_ports_workloads.py:137 |
| desc-azure-2.json | azure.claude2.entra_lockout_duration_min_60 | correct | peaso/checks/claude2_azure_identity.py:73 |
| desc-aws-3.json | aws.claude_a.ec2.instance_ami_not_deprecated | correct | peaso/checks/claude_aws_a_ec2.py:761 |
| desc-aws-2.json | aws.c2b.eks.vpc_cni_network_policy | correct | peaso/checks/claude2_aws_b_compute.py:718 |
| desc-aws-2.json | aws.c2b.ecs.service_no_public_ip | correct | peaso/checks/claude2_aws_b_compute.py:513 |
| desc-aws-4.json | aws.claude_a.securityhub.prowler_delegated_admin_region | correct | peaso/checks/claude_aws_a_security.py:608 |
| desc-k8s-1.json | k8s.ports.daemonset.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured | correct | peaso/checks/k8s_ports_components.py:52 |
| desc-aws-1.json | aws.a.cloudtrail.home_multiregion_cloudwatch_date | correct | peaso/checks/claude2_aws_a.py:52 |

## Verification

The modified JSON files parse, sampled proposed IDs no longer appear in `native_checks`, and changed ledger summaries match their requirement decisions. Description JSON parses. This spot-check does not establish correctness of unsampled entries.
