# Seventh independent Azure compliance-ledger spot-check

Seed `2026101207`; Python `random.Random(seed).sample(range(population), n)`. Sampled 25 of 369 proposed controls first, then five flattened requirements from each of the five Azure ledgers in sorted filename order. Offsets are zero based. Rates count defects in the original sampled rows before these corrections. Proposed checks are specifications, not deployed runtime evaluators.

| Population | Original defects | Exact rate | Threshold ≤10% |
|---|---:|---:|---|
| Proposed controls | 2/25 | 8% | PASS |
| Ledger requirements | 0/25 | 0% | PASS |
| Combined (informational) | 2/50 | 4% | PASS |

## Proposed controls

Compared frozen source text, `peaso/collectors/azure.py`, relevant native evaluators, and official REST/Graph references retrieved over the network on 2026-10-12. The collector does not yet implement every proposed new collection; PASS requires complete evidence and unresolved inputs remain UNKNOWN. Manual operational controls have no single sufficient REST endpoint.

| Offset | ID | Judgment | Official reference and finding |
|---:|---|---|---|
| 67 | `azure.other.build_private_network` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/devopspools/pools/get?view=rest-devopspools-2025-09-20). Pool network profile is placement evidence; external probe and complete routing are still required. |
| 82 | `azure_c5_pi_01_02ac` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-auth-settings-v-2?view=rest-appservice-2025-03-01). authsettingsV2 provider and globalValidation fields do not prove the customer federation interface; test evidence remains required. |
| 231 | `azure_synapse_workspace_10_3_3_22_15e4d4e` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/synapse/resourcemanager/sql-pool-restore-points/list?view=rest-synapse-resourcemanager-2021-06-01). Restore-point LIST has dates/types, not configurable retention; seven-day service retention and policy bounds must be established. |
| 38 | `azure_frontdoor_app_minimum_tls_version_12_0512053` | **FIXED** | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/frontdoorservice/frontdoor/front-doors/get?view=rest-frontdoorservice-frontdoor-2019-05-01). FIXED: classic customHttpsConfiguration, CDN customHttpsParameters, and AFD tlsSettings are separate paths; AFD preset cipher suites may set effective TLS. |
| 129 | `azure_firewall_policy_6_4_1_6_2ad9039` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/application-gateway/web-application-firewall-policies/get?view=rest-application-gateway-2026-01-01). WAF custom-rule priority is not Firewall Manager rule-group rank; Azure GET alone remains UNKNOWN. |
| 265 | `azure_cosmos_account_10_2_1_1_13_5c115b0` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/cosmos-db-resource-provider/database-accounts/get?view=rest-cosmos-db-resource-provider-2024-05-15). Mongo account and vCore cluster are separate resources; diagnostic categories and sink are joined at the exact resource. |
| 219 | `azure_c5_ops_25_02b` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/assessments/list?view=rest-defenderforcloud-composite-stable). Assessment severity is optional metadata; C5 criteria and finding-to-criteria evidence are required. |
| 308 | `azure_c5_ops_13_01b` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/monitor/subscription-diagnostic-settings/list?view=rest-monitor-2021-05-01-preview). Subscription diagnostic settings cover Activity Log only; broader SIEM ingestion/correlation needs evidence. |
| 241 | `azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/guestconfiguration/guest-configuration-assignments/list?view=rest-guestconfiguration-2024-04-05). Guest assignment and current report must prove required trusted-root thumbprints, not just assignment presence. |
| 330 | `azure.gap.compute_vm_container_security_configurations_vulnerabilities_remediated` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01). Assessment status requires stable key and VM/container-host join; missing coverage remains UNKNOWN. |
| 287 | `azure.gap.kubernetes_cluster_https_enabled` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/aks/managed-clusters/get?view=rest-aks-2024-05-01). AKS ARM FQDN is insufficient; authorized HTTPS and plaintext HTTP behavior probes are required. |
| 124 | `azure_c5_ops_05_01ac` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01). Manual report and committee-review evidence; assessment statusChangeDate is not a scan/report timestamp. |
| 311 | `azure_directory_user_7_2_1_19_28e2aa7` | OK | [REST/Graph](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0). Graph role assignments plus PIM and ARM scope hierarchy must be complete before no-direct-grant PASS. |
| 286 | `azure.gap.container_registry_vulnerabilities_remediated` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01). Registry assessment needs subassessment/image-digest joins and current coverage; parent Healthy alone is insufficient. |
| 128 | `azure_directory_user_entra_privileged_user_has_mfa_6f6d584` | OK | [REST/Graph](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0). Conditional Access conditions/exclusions and security defaults must be resolved for each effective admin. |
| 292 | `azure.other.attack_t1491` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/monitor/scheduled-query-rules/list-by-subscription?view=rest-monitor-2021-08-01). Scheduled query fields need reviewed T1491 semantics and workspace ingestion, not keywords. |
| 244 | `azure.gap.network_subnet_protected_by_firewall` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/virtualnetwork/network-interfaces/get-effective-route-table?view=rest-virtualnetwork-2026-01-01). Declared routes do not show effective precedence; NIC effective-route and firewall identity are required. |
| 201 | `azure.other.attack_t1201` | **FIXED** | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/monitor/scheduled-query-rules/list-by-subscription?view=rest-monitor-2021-08-01). FIXED: approved query fragments could match a non-detecting rule; require reviewed event/result filters and firing criteria. |
| 274 | `azure_storage_account_storage_blob_public_access_level_is_disabled_4211794` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2023-05-01). Typed storage fields and documented defaults must be compared to explicit policy. |
| 276 | `azure_vm_1_4_5_1_d40be43` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/get?view=rest-compute-2024-07-01). VM NIC public IP and VMSS template publicIPAddressConfiguration are distinct joins; instance drift is separate. |
| 230 | `azure_storage_account_sqlserver_auditing_enabled_e4e4b28` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/synapse/resourcemanager/sql-pool-blob-auditing-policies/get?view=rest-synapse-resourcemanager-2021-06-01). SQL-pool child auditing GET has state and storageEndpoint; workspace-level GET is insufficient. |
| 216 | `azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/application-gateway/application-gateways/get). Listener, rule, path-map and redirect references must resolve to an HTTPS destination. |
| 53 | `azure.cis.public_network_access_should_mariadb_servers` | OK | [REST/Graph](https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/specification/mariadb/resource-manager/Microsoft.DBforMariaDB/stable/2018-06-01/mariadb.json). Legacy MariaDB optional publicNetworkAccess distinguishes Enabled, Disabled and omitted. |
| 1 | `azure.cis.endpoint_protection_vms_installed` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list). Assessment status must join each VM by resourceDetails.id and stable key; missing assessment is UNKNOWN. |
| 31 | `azure_azure_resource_1_3_1_46_b70e2c8` | OK | [REST/Graph](https://learn.microsoft.com/en-us/rest/api/network-gateway/virtual-network-gateways/list-connections?view=rest-network-gateway-2026-01-01). Gateway connection tunnelConnectionStatus has per-tunnel health; parent status is insufficient. |

## Requirements: `azure-c5.json`

| Offset | Framework / requirement | Decision | Judgment and evidence |
|---:|---|---|---|
| 577 | `c5_azure` / `PSS-04.05B` | MANUAL | OK — Activity Log settings alone cannot establish customer-controlled logging process; MANUAL. |
| 333 | `c5_azure` / `IAM-07.02AC` | MANUAL | OK — Owner assignment flag does not prove approval before data access; MANUAL. |
| 2 | `c5_azure` / `OIS-01.03B` | MANUAL | OK — ISMS scope and boundaries require provider records; MANUAL. |
| 383 | `c5_azure` / `CRY-17.01B` | MANUAL | OK — Key lifecycle procedures require records; MANUAL. |
| 246 | `c5_azure` / `OPS-22.03AC` | MANUAL | OK — Penetration-test annual/significant-change review needs dated records; MANUAL. |

## Requirements: `azure-cis.json`

| Offset | Framework / requirement | Decision | Judgment and evidence |
|---:|---|---|---|
| 1419 | `azure-compliance.benchmark.cis_v210` / `azure-compliance.control.cis_v210_1_15` | MAPPING_FIX | OK — Guest invite enum comparison matches native evaluator and Graph policy. [REST/Graph](https://learn.microsoft.com/en-us/graph/api/authorizationpolicy-get?view=graph-rest-1.0). |
| 1835 | `azure-compliance.benchmark.cis_v400` / `azure-compliance.control.cis_v400_7_1_1_8` | NEW_CHECK | OK — Entra Graph Activity Logs are tenant diagnostics, not subscription settings; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/azure/templates/microsoft.aadiam/2017-04-01/diagnosticsettings). |
| 813 | `cis_6.0_azure` / `7.9` | MAPPING_FIX | OK — VPN P2S auth list exactly AAD matches native evaluator. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/network-gateway/virtual-network-gateways/get?view=rest-network-gateway-2026-01-01). |
| 749 | `cis_5.0_azure` / `9.3.8` | MAPPED | OK — Account allowBlobPublicAccess=false matches native evaluator. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2023-05-01). |
| 1536 | `azure-compliance.benchmark.cis_v210` / `azure-compliance.control.cis_v210_7_6` | PARTIAL | OK — Assessment can miss a VM without a result; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01). |

## Requirements: `azure-nist-hipaa-rbi-soc2.json`

| Offset | Framework / requirement | Decision | Judgment and evidence |
|---:|---|---|---|
| 793 | `azure-compliance.benchmark.nist_sp_800_53_rev_5` / `azure-compliance.control.bot_service_encrypted_with_cmk` | NEW_CHECK | OK — Bot CMK requires Bot Service encryption field; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/azure/templates/microsoft.botservice/2022-09-15/botservices). |
| 351 | `azure-compliance.benchmark.nist_csf_v2` / `azure-compliance.control.iam_no_custom_subscription_owner_roles_created` | PARTIAL | OK — Custom wildcard/owner checks do not prove every equivalent permission grant; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/authorization/role-definitions/list?view=rest-authorization-2022-04-01). |
| 126 | `azure-compliance.benchmark.fedramp_high` / `azure-compliance.control.search_service_public_network_access_disabled` | MAPPED | OK — Search publicNetworkAccess Disabled matches collector/evaluator. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/searchmanagement/services/get?view=rest-searchmanagement-2025-05-01). |
| 366 | `azure-compliance.benchmark.nist_csf_v2` / `azure-compliance.control.securitycenter_azure_defender_on_for_keyvault` | MAPPED | OK — Defender KeyVaults pricing matches native signal. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/pricings/get?view=rest-defenderforcloud-2024-01-01). |
| 422 | `azure-compliance.benchmark.nist_sp_800_171_rev_2` / `azure-compliance.control.appservice_api_app_remote_debugging_disabled` | MAPPED | OK — API app web configuration remoteDebuggingEnabled=false matches native check. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get-configuration?view=rest-appservice-2024-11-01). |

## Requirements: `azure-other.json`

| Offset | Framework / requirement | Decision | Judgment and evidence |
|---:|---|---|---|
| 124 | `ccc_azure` / `CCC.CntrReg.CN01.AR01` | PARTIAL | OK — Registry assessment does not perform known-vulnerable image push; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud/assessments/list?view=rest-defenderforcloud-2020-01-01). |
| 170 | `ccc_azure` / `CCC.SvlsComp.CN01.AR01` | PARTIAL | OK — Function publicNetworkAccess setting does not prove an external attempt; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get?view=rest-appservice-2024-11-01). |
| 75 | `ccc_azure` / `CCC.ObjStor.CN03.AR02` | NEW_CHECK | OK — Immutable policy plus effective object denial is needed; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/storagerp/blob-containers/get-immutability-policy?view=rest-storagerp-2023-01-01). |
| 299 | `iso27001_2022_azure` / `A.6.7` | PARTIAL | OK — VM JIT is only a remote-work technical signal; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/jit-network-access-policies/get?view=rest-defenderforcloud-composite-preview). |
| 553 | `prowler_threatscore_azure` / `4.1.3` | MAPPED | OK — Storage minimumTlsVersion comparison matches native evaluator. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/storagerp/storage-accounts/get-properties?view=rest-storagerp-2023-05-01). |

## Requirements: `azure-pci.json`

| Offset | Framework / requirement | Decision | Judgment and evidence |
|---:|---|---|---|
| 1447 | `pci_4.0_azure` / `8.3.2.44` | NOT_APPLICABLE | OK — Generic Managed Instance encryption switch is absent; NOT_APPLICABLE. |
| 1266 | `pci_4.0_azure` / `7.3.1.13` | NEW_CHECK | OK — Direct Graph/PIM/ARM user-role joins match source; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/graph/api/rbacapplication-list-roleassignments?view=graph-rest-1.0). |
| 845 | `pci_4.0_azure` / `3.3.1.3.4` | NEW_CHECK | OK — Cosmos account backupPolicy retention covers mapped account scope; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/cosmos-db-resource-provider/database-accounts/get?view=rest-cosmos-db-resource-provider-2024-05-15). |
| 1643 | `pci_4.0_azure` / `A3.4.1.11` | PARTIAL | OK — Function public access omits effective private endpoint/access-rule proof; PARTIAL. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/appservice/web-apps/get?view=rest-appservice-2024-11-01). |
| 652 | `pci_4.0_azure` / `10.3.3.22` | NEW_CHECK | OK — Synapse SQL-pool restore-point listing and fixed service retention need policy bounds; NEW_CHECK. [REST/Graph](https://learn.microsoft.com/en-us/rest/api/synapse/resourcemanager/sql-pool-restore-points/list?view=rest-synapse-resourcemanager-2021-06-01). |

## Corrections and verification

- Corrected the Front Door TLS proposal and both embedded PCI copies: classic Front Door, CDN endpoint custom domains, and AFD profile custom domains use distinct REST paths and TLS fields. AFD preset cipher suites require effective TLS interpretation. The [classic Front Door](https://learn.microsoft.com/en-us/rest/api/frontdoorservice/frontdoor/front-doors/get?view=rest-frontdoorservice-frontdoor-2019-05-01), [CDN custom domain](https://learn.microsoft.com/en-us/rest/api/cdn/custom-domains/get?view=rest-cdn-2025-04-15), and [AFD custom domain](https://learn.microsoft.com/en-us/rest/api/frontdoor/azurefrontdoorstandardpremium/afd-custom-domains/get?view=rest-frontdoor-2025-04-15) references establish the separate schemas.
- Corrected T1201 alert proposal and its embedded Other-ledger copy: query fragments are insufficient; a reviewed query with event/result filters, firing criteria, workspace ingestion, and enabled action group is required. [Scheduled query rule schema](https://learn.microsoft.com/en-us/rest/api/monitor/scheduled-query-rules/list-by-subscription?view=rest-monitor-2021-08-01).
- Parsed all changed JSON, reselected both samples with the stated RNG, checked corrected embedded copies and collector/native-check paths. Official linked proposal references returned HTTP 200, including the added AFD reference. No live Azure tenant was queried; judgments are source/API specification checks.
