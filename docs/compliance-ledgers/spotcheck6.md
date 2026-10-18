# Sixth independent Azure compliance-ledger spot-check

Seed `2026101206`; Python `random.Random(seed).sample(range(population), n)`. The control sample was drawn first from the 369-entry pre-correction proposal list; the same RNG then drew five flattened requirements per ledger in filename order. Offsets are zero based. Defect rates use the original rows, before corrections. A proposed check is a specification, not an implemented runtime evaluator.

| Population | Original defects | Rate | ≤10% |
|---|---:|---:|---|
| Proposed controls | 6/25 | 24% | **FAIL** |
| Ledger requirements | 2/25 | 8% | PASS |
| Combined (informational) | 8/50 | 16% | **FAIL** |

## Proposed-control sample

Each linked API reference was fetched over the network (HTTP 200) on 2026-10-12. The cited reference, frozen source requirement, `peaso/collectors/azure.py`, and relevant evaluator/Graph schema were compared; `FIXED` denotes an original defect. For manual/API-inaccessible evidence, UNKNOWN remains required.

| Offset | ID | Judgment | REST evidence and finding |
|---:|---|---|---|
| 332 | `azure.gap.databox_job_double_encryption_enabled` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/databox/jobs/list?view=rest-databox-2025-07-01). Data Box detail expansion and Enabled enum; new paged collector. |
| 341 | `azure.other.blob_uniform_access` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/list?view=rest-storagerp-2023-05-01). Container ACL and HNS path scope explicit; issued SAS remains UNKNOWN. |
| 264 | `azure_c5_ops_30_01ac` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-compute-2024-07-01). VM securityProfile and vTPM with explicit classified IDs. |
| 8 | `azure.gap.compute_vm_image_builder_uses_private_link` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/imagebuilder/virtual-machine-image-templates/list). Subnet selection was claimed as Private Link proof; narrowed to PARTIAL. |
| 134 | `azure_route_table_network_http_internet_access_restricted_5cd2484` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/route-tables/get?view=rest-virtualnetwork-2023-09-01). Approved appliance default route was wrongly allowed despite frozen rule rejecting 0/0; corrected. |
| 197 | `azure.gap.machine_learning_workspace_private_link_used` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/azureml/private-endpoint-connections/list?view=rest-azureml-2024-04-01). Approved workspace private endpoint child connection and paging. |
| 89 | `azure_role_assignment_iam_user_with_write_permission_on_subscription_mfa_enabled_d1806c1` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?view=rest-authorization-2022-04-01). Effective writers, group/PIM and Conditional Access exclusions remain required. |
| 291 | `azure.other.attack_t1082` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/monitor/scheduled-query-rules/list-by-subscription?view=rest-monitor-2021-08-01). Scheduled query rule, workspace scope and action group. |
| 331 | `azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-scale-set-vms/list?view=rest-compute-2024-07-01). VMSS instance list and stable per-instance Defender assessment join. |
| 173 | `azure_c5_ops_20_01b` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-03-01). ClassificationReason was universally required despite optional API field; corrected. |
| 144 | `azure.cis.postgresql_single_log_disconnections` | OK | [Official reference](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/postgresql/resource-manager/Microsoft.DBforPostgreSQL/stable/2017-12-01/postgresql.json). Legacy PostgreSQL Single Server configuration value. |
| 0 | `azure.cis.access_review_up_external_users_in_entra_privileged_identity_694482` | OK | [Official reference](https://learn.microsoft.com/en-us/graph/api/accessreviewset-list-definitions). Graph review definitions, instances and decisions require role/principal join. |
| 351 | `azure_aks_cluster_aks_cluster_rbac_enabled_fc209e3` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters/get?view=rest-aks-2024-05-01). AKS KMS key and effective access; legacy ID is misleading but frozen rule asks for secret encryption. |
| 343 | `azure.other.entra_app_secret_age_90` | OK | [Official reference](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0). Graph credential startDateTime requires collector projection change. |
| 151 | `azure.gap.logic_app_integration_service_environment_encrypted_with_cmk` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/logic/integration-service-environments/get?view=rest-logic-2019-05-01). ISE encryption key reference schema and approval input. |
| 339 | `azure.other.attack_t1562` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/monitor/scheduled-query-rules/list-by-subscription?view=rest-monitor-2021-08-01). Reviewed query hash and action group avoid keyword-only detection. |
| 287 | `azure.gap.kubernetes_cluster_https_enabled` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters/get?view=rest-aks-2024-05-01). HTTPS/HTTP API probe and private endpoint uncertainty. |
| 263 | `azure_c5_ops_08_01b` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/backup/backup-jobs/list?view=rest-backup-2024-04-01). Assumed universal backup-job entityId, absent for IaaS VM jobs; corrected stable-join rule. |
| 46 | `azure_vault_keyvault_key_expiration_set_in_non_rbac_a7d99d3` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/keyvault/certificates/get-certificates/get-certificates). Key Vault certificate expiry and current-version reads. |
| 177 | `azure_firewall_policy_6_4_1_7_a7975fc` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/application-gateway/web-application-firewall-policies/get?view=rest-application-gateway-2026-01-01). WAF policy state defaults Enabled; omitted state must not block PASS. |
| 288 | `azure.gap.monitor_log_cluster_encrypted_with_cmk` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/loganalytics/clusters/get?view=rest-loganalytics-2023-09-01). Log Analytics cluster CMK identity and Key Vault access. |
| 241 | `azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/guestconfiguration/guest-configuration-assignments/list?view=rest-guestconfiguration-2024-04-05). Guest assignment report contains thumbprint evidence. |
| 310 | `azure_cosmos_account_10_2_1_1_23_e04a63d` | **FIXED** | [Official reference](https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview). Diagnostic setting workspaceId was nested under logs; corrected to setting level. |
| 278 | `azure.cis.file_integrity_monitoring_component_status` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/get?view=rest-defenderforcloud-2024-01-01). Defender pricing extension isEnabled is a string. |
| 72 | `azure.other.ml_compute_file_download_restricted` | OK | [Official reference](https://learn.microsoft.com/en-us/rest/api/azureml/compute/list?view=rest-azureml-2024-04-01). AML artifact authorization needs role and data-plane joins. |

## Requirement sample: `azure-c5.json`

| Offset | Framework / requirement | Original decision | Judgment and evidence |
|---:|---|---|---|
| 274 | `c5_azure` / `OPS-31.01B` | MANUAL | OK — Remote attestation offering needs service/customer evidence. |
| 403 | `c5_azure` / `COS-06.01AC` | MANUAL | OK — Physical or encrypted network separation needs facility/provider evidence. |
| 407 | `c5_azure` / `COS-07.04B` | MANUAL | OK — Annual topology review is an operational record. |
| 73 | `c5_azure` / `HR-03.04AC` | MANUAL | OK — Personnel measurement is organizational evidence. |
| 605 | `c5_azure` / `PSS-12.04B` | MANUAL | OK — Advance customer notice needs dated communications. |

## Requirement sample: `azure-cis.json`

| Offset | Framework / requirement | Original decision | Judgment and evidence |
|---:|---|---|---|
| 732 | `cis_5.0_azure` / `9.1.1` | MAPPED | OK — [API](https://learn.microsoft.com/en-us/rest/api/storagerp/file-services/get-service-properties?view=rest-storagerp-2023-05-01); Storage account file-service shareDeleteRetentionPolicy is the relevant collector/evaluator signal. |
| 1231 | `azure-compliance.benchmark.cis_v150` / `azure-compliance.control.cis_v150_7_6` | NEW_CHECK | OK — [API](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2023-05-01); Unmanaged VHD URI can join to storage-account Blob encryption; new read-only check remains proposal. |
| 1860 | `azure-compliance.benchmark.cis_v400` / `azure-compliance.control.cis_v400_9_1_12` | MAPPED | OK — [API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/security-contacts/list?view=rest-defenderforcloud-2023-12-01-preview); Defender security contact alertsToAdmins and Owner role signal. |
| 1000 | `azure-compliance.benchmark.cis_v140` / `azure-compliance.control.cis_v140_1_10` | MANUAL | OK — Legacy gallery-app Access Panel tenant switch has no verified Graph field; manual is appropriate. |
| 1006 | `azure-compliance.benchmark.cis_v140` / `azure-compliance.control.cis_v140_1_16` | MAPPING_FIX | OK — [API](https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0); Graph authorizationPolicy allowedToCreateSecurityGroups matches the native evaluator. |

## Requirement sample: `azure-nist-hipaa-rbi-soc2.json`

| Offset | Framework / requirement | Original decision | Judgment and evidence |
|---:|---|---|---|
| 774 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.application_gateway_waf_enabled` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/application-gateway/web-application-firewall-policies/get?view=rest-application-gateway-2026-01-01); Linked WAF policy state is not read by evaluator; PARTIAL is accurate. |
| 690 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.sql_server_azure_defender_enabled` | MAPPING_FIX | OK — [API](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/get?view=rest-defenderforcloud-2024-01-01); Defender SqlServers pricingTier Standard directly tests plan. |
| 715 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.servicebus_namespace_logging_enabled` | MAPPED | OK — [API](https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview); Service Bus diagnostic setting log categories/enablement tested. |
| 294 | `azure-compliance.benchmark.hipaa_hitrust_v92` / `azure-compliance.control.postgres_sql_ssl_enabled` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/postgresql/configurations/list-by-server?view=rest-postgresql-2024-08-01); Flexible PostgreSQL secure transport omits legacy Single Server. |
| 470 | `azure-compliance.benchmark.nist_sp_800_171_rev_2` / `azure-compliance.control.appservice_web_app_cors_no_star` | MAPPED | OK — [API](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get?view=rest-appservice-2024-11-01); App Service CORS allowedOrigins rejects wildcard. |

## Requirement sample: `azure-other.json`

| Offset | Framework / requirement | Original decision | Judgment and evidence |
|---:|---|---|---|
| 187 | `ens_rd2022_azure` / `op.acc.6.r1.az.eid.3` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0); Admin MFA and capability are narrow password-policy signals. |
| 376 | `mitre_attack_azure` / `T1486` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/backup/backup-protected-items/list?view=rest-backup-2024-04-01); VM backup is a partial ransomware resilience signal. |
| 129 | `ccc_azure` / `CCC.IAM.CN02.AR02` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/authorization/role-assignments/list-for-scope?view=rest-authorization-2022-04-01); UAA/wildcard-role tests do not prove policy creation restrictions. |
| 534 | `prowler_threatscore_azure` / `3.3.13` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/application-insights/components/list?view=rest-application-insights-2015-05-01); One App Insights component does not prove every app instrumented. |
| 457 | `nis2_azure` / `9.2.c.iv` | PARTIAL | OK — [API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/get-keys/get-keys); Key Vault/SQL/storage signals leave key access process unproved. |

## Requirement sample: `azure-pci.json`

| Offset | Framework / requirement | Original decision | Judgment and evidence |
|---:|---|---|---|
| 1518 | `pci_4.0_azure` / `A1.1.2.6` | NOT_APPLICABLE | OK — Azure Files has no EFS-style access-point root path. |
| 430 | `pci_4.0_azure` / `10.2.1.5.12` | NEW_CHECK | **FIXED** — [API](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-network-virtualnetworkgateways-logs); GatewayDiagnosticLog/TunnelDiagnosticLog do not establish P2S client logs; require P2SDiagnosticLog. |
| 780 | `pci_4.0_azure` / `11.6.1.6` | NOT_APPLICABLE | OK — Message delivery status is client behavior, not namespace logging. |
| 114 | `pci_4.0_azure` / `1.3.1.51` | NOT_APPLICABLE | OK — AWS Web ACL resource has no direct Azure analogue. |
| 1448 | `pci_4.0_azure` / `8.3.2.45` | NEW_CHECK | **FIXED** — [API](https://learn.microsoft.com/en-us/rest/api/synapse/resourcemanager/sql-pool-blob-auditing-policies/get?view=rest-synapse-resourcemanager-2021-06-01); Workspace GET lacks SQL pool auditing child; key name is not key ID. Added child GET and key resolution. |

## Corrections and verification

- Corrected six sampled proposals and propagated their specifications to every embedded Azure requirement copy. The Image Builder requirement is now PARTIAL because an approved subnet alone does not prove Private Link. Updated stale C5 rationale for incident and restore-job signals.
- Corrected the two sampled PCI proposals (VPN P2S diagnostic category; Synapse SQL-pool auditing child and CMK key resolution), including all shared proposal copies. The original 8/50 rate remains above threshold.
- Parsed all four changed JSON files; verified sample offsets, ledger summary counts, proposal references and the changed predicates and data sources in 54 embedded proposal copies. Network checks returned HTTP 200 for all 25 sampled proposal reference URLs. No live Azure tenant was queried; this is a source/API specification audit.

Additional primary references used for corrections: [diagnostic-setting schema](https://learn.microsoft.com/en-us/rest/api/monitor/diagnostic-settings/list?view=rest-monitor-2021-05-01-preview), [VPN gateway log categories](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-network-virtualnetworkgateways-logs), [Synapse SQL-pool audit GET](https://learn.microsoft.com/en-us/rest/api/synapse/resourcemanager/sql-pool-blob-auditing-policies/get?view=rest-synapse-resourcemanager-2021-06-01), [Image Builder template GET](https://learn.microsoft.com/en-us/rest/api/imagebuilder/virtual-machine-image-templates/get?view=rest-imagebuilder-2022-07-01), [Backup jobs LIST](https://learn.microsoft.com/en-us/rest/api/backup/backup-jobs/list?view=rest-backup-2024-04-01), [Sentinel incident LIST](https://learn.microsoft.com/en-us/rest/api/securityinsights/incidents/list?view=rest-securityinsights-2024-03-01).
