# Fifth independent Azure compliance-ledger spot-check

Fresh seed: `2026101205`. Sampled `random.Random(seed).sample(range(380), 25)` from the **pre-correction** `new-checks-azure.json`, then used the same RNG to sample five flattened requirements from each Azure ledger in filename order. Offsets are zero based. Judgments count original defects even when corrected here. A proposed check must be able to distinguish PASS, FAIL and UNKNOWN using its named API data, policy inputs, and inventory completeness. Proposed checks are specifications, not implemented runtime checks.

| Population | Original defects | Rate | ≤10% threshold |
|---|---:|---:|---|
| Proposed Azure controls | 11/25 | 44% | **FAIL** |
| Azure ledger requirements (five from each of five ledgers) | 3/25 | 12% | **FAIL** |
| Combined, informational only | 14/50 | 28% | **FAIL** |

## Proposed-control sample

`FIXED` means the original proposal was defective and has been corrected. The collector comparison uses `peaso/collectors/azure.py`: for example, it gathers selected ARM kinds, Conditional Access policies, and embedded Recovery Services backup items, while the proposed checks may require additional collection. API evidence is linked below.

| Offset | ID | Judgment | Evidence and disposition |
|---:|---|---|---|
| 282 | `azure_devops_project_6_5_5_2_2908a87` | OK | Pipeline/YAML expansion and organization stage limits are required; unresolved templates/revisions yield UNKNOWN. |
| 42 | `azure.cis.public_network_access_should_mysql_servers` | OK | Flexible Server `network.publicNetworkAccess` directly supports the declared predicate; legacy Single Server is separated. |
| 139 | `azure.other.attack_t1614` | OK | Scheduled-query rule, approved workspace, required query fragments and action groups are explicit policy inputs. |
| 5 | `azure.cis.auto_provision_vulnerability_assessment_machines` | **FIXED** | `selectedProvider=Qualys` was accepted although the current `azureServersSetting` schema permits `MdeTvm`; also require the documented `kind`. |
| 175 | `azure.other.gateway_affinity_cookie_timeout` | **FIXED** | An unmeasured affinity-enabled backend could be skipped under “every backend returns”; PASS now requires a measurement for every applicable backend. |
| 124 | `azure.other.attack_t1201` | OK | Query pattern, AuditLogs reference, workspace scope and enabled action group are named; missing policy/inventory yields UNKNOWN. |
| 361 | `azure_storage_file_share_10_3_3_18_d67ab34` | **FIXED** | Backup `sourceResourceId` identifies the **storage account**, so matching only it can credit the wrong share. The join now also uses `friendlyName` and item type. |
| 236 | `azure_api_management_app_http_logs_enabled_21c108d` | OK | Service diagnostics and loggers are child lists, absent from the current APIM parent collection; proposal correctly requests new collection. |
| 35 | `azure.cis.postgresql_single_log_disconnections` | OK | Legacy PostgreSQL Single Server configuration value supports on/off; the proposal scopes this retired generation explicitly. |
| 8 | `azure.cis.endpoint_protection_vms_installed` | **FIXED** | Assessment `resourceDetails.id` is under `properties`, and a localized `metadata.displayName` is an unstable selector. Stable assessment key and per-VM join are now required. |
| 305 | `azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a` | **FIXED** | “Access-log category” was underspecified across classic Front Door and CDN profiles. Correct resource-specific categories are now named. |
| 216 | `azure.other.snapshot_sharing_scope` | OK | Snapshot network export mode and effective RBAC are specified, with group/inheritance uncertainty yielding UNKNOWN. It does not claim to recover issued SAS recipients. |
| 115 | `azure.other.attack_t1049` | OK | The scheduled-query pattern and action group are explicit; unresolved inventory or policy yields UNKNOWN. |
| 212 | `azure.other.runtime_public_ip` | OK | AML compute `properties.properties.enableNodePublicIp` is a direct setting; compute types without it yield UNKNOWN. |
| 312 | `azure_management_group_7_2_1_1_af95df1` | OK | Management Group descendants contain subscription IDs; expected group and complete enumeration are required. |
| 111 | `azure.other.acr_untagged_retention` | OK | Premium registry retention policy exposes `status` and `days`; approved maximum is a policy input. |
| 2 | `azure.cis.agentless_scanning_machines_component_status` | **FIXED** | Pricing extension `isEnabled` is the string `"True"`, not JSON boolean `true`; predicate now states the actual response value. |
| 67 | `azure.gap.compute_vm_password_file_permissions_0644_linux` | **FIXED** | Assignment GET does not embed `latestAssignmentReport.resources`; the assignment gives `latestReportId` and the file evidence comes from the reports endpoint. |
| 370 | `azure_vault_keyvault_non_rbac_secret_expiration_set_a4923d7` | **FIXED** | Per-secret version GET alone cannot enumerate all secret names; added paged `/secrets` listing and explicit current-version uncertainty. Source requirement asks for recent rotation, despite the legacy check ID. |
| 276 | `azure_cdn_profile_1_2_8_5_ed953a0` | **FIXED** | The frozen source rejects the default CDN-managed certificate; the old predicate *passed* `certificateSource=Cdn`. It now requires `AzureKeyVault`. |
| 38 | `azure.cis.postgresql_single_ssl_enforcement` | OK | Single Server `sslEnforcement` is the field named by the older benchmark; missing field/inventory yields UNKNOWN. |
| 12 | `azure.cis.exclusionary_device_code_flow_policy_considered` | **FIXED** | User/app exclusions alone cannot establish a tenant-wide block: locations, platforms, device, risk and client-app conditions can narrow policy scope. |
| 113 | `azure.other.admin_network_separation` | OK | NSG priorities, both subnet associations and approved ports are required; unresolved effective paths yield UNKNOWN. |
| 182 | `azure.other.human_federated_signin` | **FIXED** | Original predicate did not identify successful sign-ins, a lookback window, or an empty observation set. Added `status.errorCode`, window and UNKNOWN handling. |
| 46 | `azure.cis.tenant_creator_role_assignments_periodically_reviewed` | OK | Per-assignment completed decisions and age threshold avoid an existential-review false PASS. |

## Requirement sample: `azure-c5.json`

| Offset | Requirement | Original decision | Judgment |
|---:|---|---|---|
| 266 | `c5_azure` / `OPS-28.01B` | MANUAL | OK — risk assessment and customer communication need operational records. |
| 436 | `c5_azure` / `DEV-07.02B` | MANUAL | OK — test scope matching risk assessment requires test records. |
| 534 | `c5_azure` / `COM-02.01B` | MANUAL | OK — a three-year audit programme is organizational evidence. |
| 311 | `c5_azure` / `IAM-06.01B` | PARTIAL | OK — Owner/custom-role checks are limited configuration signals for privileged-access assignment process. |
| 447 | `c5_azure` / `DEV-09.01AC` | MANUAL | OK — version-control restoration safeguards require process and test evidence. |

## Requirement sample: `azure-cis.json`

| Offset | Requirement | Original decision | Judgment |
|---:|---|---|---|
| 780 | `cis_6.0_azure` / `5.7` | MAPPING_FIX | **FIXED** — Owner evaluator counts direct principal IDs; it does not expand Owner groups to effective people. Changed to PARTIAL and corrected the inaccurate `accountEnabled` reason. |
| 1469 | `azure-compliance.benchmark.cis_v210` / `azure-compliance.control.cis_v210_3_6` | PARTIAL | OK — account SAS policy is a partial signal for all issued SAS tokens. |
| 1050 | `azure-compliance.benchmark.cis_v140` / `azure-compliance.control.cis_v140_4_3_1` | NEW_CHECK | OK — old Single Server SSL field is distinct from collected Flexible Server. |
| 1683 | `azure-compliance.benchmark.cis_v300` / `azure-compliance.control.cis_v300_6_2_9` | MAPPED | OK — mapped activity-log alert evaluators check the named Public IP write operation. |
| 1525 | `azure-compliance.benchmark.cis_v210` / `azure-compliance.control.cis_v210_6_2` | PARTIAL | OK — declared Internet SSH rule is narrower than effective access and review evidence. |

## Requirement sample: `azure-nist-hipaa-rbi-soc2.json`

| Offset | Requirement | Original decision | Judgment |
|---:|---|---|---|
| 248 | `azure-compliance.benchmark.hipaa_hitrust_v92` / `azure-compliance.control.iam_user_with_write_permission_on_subscription_mfa_enabled` | PARTIAL | OK — registration/policy presence alone does not prove MFA enforcement for every effective writer. |
| 928 | `azure-compliance.benchmark.rbi_itf_nbfc_v2017` / `azure-compliance.control.mysql_ssl_enabled` | MAPPING_FIX | **FIXED** — mapped evaluator checks only MySQL Flexible Server; generic MySQL server requirement can include legacy Single Server. Changed to PARTIAL. |
| 754 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.compute_vm_min_password_age_1_day_windows` | MAPPED | OK — Windows guest assignment specifically checks minimum password age. |
| 824 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.app_service_environment_internal_encryption_enabled` | MAPPED | OK — evaluator reads `InternalEncryption` cluster setting. |
| 507 | `azure-compliance.benchmark.nist_sp_800_171_rev_2` / `azure-compliance.control.securitycenter_automatic_provisioning_monitoring_agent_on` | NOT_APPLICABLE | OK — retired monitoring-agent auto-provisioning is a legacy service control. |

## Requirement sample: `azure-other.json`

| Offset | Requirement | Original decision | Judgment |
|---:|---|---|---|
| 38 | `ccc_azure` / `CCC.Core.CN04.AR03` | PARTIAL | OK — Key Vault audit settings cover only one data-plane service. |
| 433 | `nis2_azure` / `4.3.2.a` | MANUAL | OK — supplier agreements and service reviews are process evidence. |
| 621 | `secnumcloud_3.2_azure` / `14.3` | PARTIAL | OK — DevOps test records alone do not establish post-change technical review. |
| 605 | `secnumcloud_3.2_azure` / `12.4` | PARTIAL | OK — listed Defender checks are narrower than the malware-control requirement. |
| 141 | `ccc_azure` / `CCC.GenAI.CN01.AR01` | NOT_APPLICABLE | OK — per-request GenAI input validation is not exposed by Azure resource inventory. |

## Requirement sample: `azure-pci.json`

| Offset | Requirement | Original decision | Judgment |
|---:|---|---|---|
| 1207 | `pci_4.0_azure` / `7.2.2.25` | NOT_APPLICABLE | OK — the stated S3-style container resource policy has no Azure Blob equivalent. |
| 1160 | `pci_4.0_azure` / `7.2.1.7` | NEW_CHECK | **FIXED** — proposed root-filesystem check omitted init and ephemeral containers, which can also have writable roots. Expanded the shared proposal. |
| 1027 | `pci_4.0_azure` / `3.7.7.8` | NOT_APPLICABLE | OK — AWS-style inline IAM policies do not exist in Azure RBAC/Entra roles. |
| 890 | `pci_4.0_azure` / `3.5.1.3.13` | NEW_CHECK | OK — Application Gateway listener-to-SSL-certificate binding exposes `keyVaultSecretId`. |
| 1560 | `pci_4.0_azure` / `A1.1.3.26` | PARTIAL | OK — native Search checks require a private endpoint, while the source also allows a service endpoint. |

## Corrections and evidence

Corrected 12 proposed controls: 11 from the control sample plus the AKS proposal referenced by the sampled PCI requirement. Corrected two ledger decisions and their summary counts. No existing native evaluator or collector was changed; these rows remain proposals where `needs_new_collection` is true. The original sample rates remain above threshold.

Primary API references: [Defender VA setting](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/server-vulnerability-assessments-settings/get), [Azure Files protected item fields](https://learn.microsoft.com/en-us/rest/api/backup/backup-protected-items/list), [CDN custom-domain certificate source](https://learn.microsoft.com/en-us/rest/api/cdn/custom-domains/get), [Guest assignment reports](https://learn.microsoft.com/en-us/rest/api/guestconfiguration/guest-configuration-assignment-reports/list), [Key Vault secret versions](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret-versions/get-secret-versions), [Defender pricing extension](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/pricings/list), [classic Front Door logs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-network-frontdoors-logs), [CDN profile logs](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-logs/microsoft-cdn-profiles-logs), [Conditional Access authentication flows](https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccessauthenticationflows), [Graph sign-in status](https://learn.microsoft.com/en-us/graph/api/resources/signin), [Management Group descendants](https://learn.microsoft.com/en-us/rest/api/managementgroups/management-groups/get-descendants), [AML compute public IP](https://learn.microsoft.com/en-us/rest/api/azureml/compute/list), and [APIM service diagnostics](https://learn.microsoft.com/en-us/rest/api/apimanagement/diagnostic/list-by-service).

Validation: JSON parsing, exact sample offsets, ledger-summary totals and proposal-to-requirement references were checked after correction.
