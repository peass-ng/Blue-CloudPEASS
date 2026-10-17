# PEASO Claude2 Azure partition coverage (claude2_azure)

Partition: `peaso/rulepacks/port_partitions_claude2.json` -> `partitions.claude2_azure` (468 Azure rows: azure-compliance, azure-perimeter, prowler.azure). The partition includes four leftovers from `claude_azure`. Three are ported here with no `supersedes`, because their `claude_azure` rejection is deferred and the predicates are coverage-aware: `network_sg_flowlog_enabled`, `network_sg_flowlog_retention_period_greater_than_90` and `nsg_network_watcher_flow_log_send_to_log_analytics`. `storage_account_encryption_at_rest_using_mmk` stays with the `reviewed_claude_azure.json` rejection, by supervisor ruling.

## Files

- Predicates: `peaso/checks/claude2_azure.py` (aggregator), `claude2_azure_common.py`, `claude2_azure_app.py`, `claude2_azure_identity.py`, `claude2_azure_network.py`, `claude2_azure_defender.py`. Ids are `azure.claude2.<slug>` (75 predicates).
- Review shards: `peaso/rulepacks/reviewed_claude2_azure.json` (333 rows) and `peaso/rulepacks/reviewed_claude2_azure_manual.json` (19 rows).
- Tests: `tests/test_peaso_checks_claude2_azure.py` (shard integrity and in-memory manifest validation) and `tests/test_peaso_checks_claude2_azure_behavior.py` (PASS/FAIL/UNKNOWN and applicability fixtures).
- Registry: `from . import claude2_azure  # noqa: E402,F401` in `peaso/checks/__init__.py`.

## Counts

| Disposition | Rows |
|---|---|
| ported | 141 |
| merged | 190 |
| manual attestation | 19 |
| rejected | 4 |
| dropped (owned by another active shard as ported, merged or rejected, including the MMK leftover) | 114 |
| **total** | **468** |

Nine rows are held only as `pending` by `reviewed_azure.json` and carry `"supersedes"`.

## Design rules

- Missing, denied or partial inventories produce UNKNOWN. Scope predicates (`target: scope`) need the complete inventory for their kind, and management-group anchors are NOT_APPLICABLE.
- Tenant predicates anchor on the ARM `tenant` item and only read directory inventories for that tenant.
- Built-in role definitions are tenant-wide. They are never evaluated per subscription: `iam_no_custom_owner_roles` is a subscription aggregate over custom roles only.
- NSG flow logs are retiring, and VNet flow logs (with a VNet, subnet or NIC target) are the supported successor. `nsg_flow_log_configured` passes when an NSG flow log targets the NSG, or when an enabled VNet flow log covers a subnet, VNet or NIC the NSG is attached to (NIC subnets are resolved through the NIC inventory). It fails only when neither exists, and unattached NSGs are NOT_APPLICABLE. `nsg_flow_log_retention_90` judges NSGs that only VNet flow logs cover on those logs. The NSG Log Analytics rows pass when a VNet flow log has Traffic Analytics.
- Defender plan rows are owned by the active `reviewed_azure_ports_legacy_plans.json` shard, which checks plans one at a time; this shard adds no plan predicates.
- App Service element filters follow the upstream tables. The web-app table excludes `functionapp` kinds, and the function-app table requires one. Upstream kind-element filters (`api`, `app`, `functionapp`, Linux) map to NOT_APPLICABLE.
- Where the pinned upstream predicate is inverted or reads a field that does not exist, the native implements the control title using the documented ARM fields. Each such row records this in `review_notes`: Application Insights public access, Application Gateway WAF mode, SQL `disabledAlerts`, and managed identity read from the site `identity` block.

## COLLECTOR FACTS NEEDED

These predicates are registered and stay UNKNOWN until the collector provides the data. All of it is available through read-only GET/list APIs.

| Fact | API | Predicates |
|---|---|---|
| `app_service_plan` kind (`Microsoft.Web/serverfarms`, `sku.name`) | GET `Microsoft.Web/serverfarms` list | `app_service_plan_minimum_sku` |
| `app_service_environment` kind (`clusterSettings`) | GET `Microsoft.Web/hostingEnvironments` list | `app_service_environment_internal_encryption` |
| `app_service_slot` kind (`httpsOnly`) | GET `Microsoft.Web/sites/{name}/slots` | `web_app_slot_https_only` |
| Site `logsConfiguration` (`failedRequestsTracing.enabled`) embedded on `app_service` | GET `Microsoft.Web/sites/{name}/config/logs` | `web_app_failed_request_tracing` |
| `automation_variable` kind (`isEncrypted`) | GET `Microsoft.Automation/automationAccounts/{name}/variables` | `automation_variable_encrypted` |
| `directory_role` kind (`roleTemplateId` of activated roles) | Graph GET `/directoryRoles` | `entra_ca_mfa_all_users_or_roles` (role-only policies) |
| `directory_device_registration_policy` kind (`multiFactorAuthConfiguration`) | Graph GET `/policies/deviceRegistrationPolicy` | `entra_device_join_requires_mfa` |
| `isMfaRegistered` and `userPrincipalName` on `user_registration_detail` (the current `$select` is `id,isMfaCapable`) | Graph GET `/reports/authenticationMethods/userRegistrationDetails` | `entra_user_mfa_registered` |

## Overlap with inactive Codex shards

These rows also appear in shards that are not in `active_reviews.json`, so they do not count as ownership: `reviewed_azure_ports_app` 21, `compute` 25, `directory_extra` 11, `invalid_app` 10, `invalid_ca` 10, `invalid_misc` 4, `invalid_sql` 5, `misc` 11, `network` 15, `sql` 23, `storage_extra` 29.

The `invalid_*` shards reject rows whose upstream predicate is defective. This shard ports those rows using the corrected documented semantics, as recorded in `review_notes`. A supervisor needs to reconcile the two if those shards are activated.

## Predicates

| Native check | Kind / target | Rows | Example row |
|---|---|---|---|
| `azure.claude2.activity_log_alert_service_health` | activity_log_alert / scope | 2 | `azure-compliance.control.cis_v400_7_1_2_11` |
| `azure.claude2.aks_azure_monitor_metrics_enabled` | aks_cluster / resource | 1 | `prowler.azure.aks_cluster_azure_monitor_enabled` |
| `azure.claude2.aks_private_cluster_nodes_without_public_ip` | aks_cluster / resource | 1 | `prowler.azure.aks_clusters_public_access_disabled` |
| `azure.claude2.api_app_client_certificates` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_client_certificates_on` |
| `azure.claude2.api_app_cors_no_wildcard` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_cors_no_star` |
| `azure.claude2.api_app_ftps_required` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_ftps_enabled` |
| `azure.claude2.api_app_https_only` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_use_https` |
| `azure.claude2.api_app_managed_identity` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_uses_managed_identity` |
| `azure.claude2.api_app_min_tls_12` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_latest_tls_version` |
| `azure.claude2.api_app_remote_debugging_disabled` | app_service / resource | 1 | `azure-compliance.control.appservice_api_app_remote_debugging_disabled` |
| `azure.claude2.apim_consumption_client_certificate` | api_management / resource | 1 | `azure-compliance.control.apimanagement_service_client_certificate_enabled` |
| `azure.claude2.app_gateway_http2_enabled` | application_gateway / resource | 2 | `azure-compliance.control.application_gateway_http2_enabled` |
| `azure.claude2.app_gateway_min_tls_12` | application_gateway / resource | 2 | `azure-compliance.control.application_gateway_min_tls_1_2` |
| `azure.claude2.app_gateway_waf_enabled` | application_gateway / resource | 2 | `azure-compliance.control.application_gateway_waf_enabled` |
| `azure.claude2.app_gateway_waf_mode_specified` | application_gateway / resource | 1 | `azure-compliance.control.application_gateway_waf_uses_specified_mode` |
| `azure.claude2.app_service_environment_internal_encryption` | app_service_environment / resource | 1 | `azure-compliance.control.app_service_environment_internal_encryption_enabled` |
| `azure.claude2.app_service_plan_minimum_sku` | app_service_plan / resource | 1 | `azure-compliance.control.appservice_plan_minimum_sku` |
| `azure.claude2.app_workers_more_than_one` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_worker_more_than_one` |
| `azure.claude2.application_insights_configured` | application_insights / scope | 6 | `azure-compliance.control.cis_v200_5_3_1` |
| `azure.claude2.application_insights_public_access_blocked` | application_insights / resource | 1 | `azure-compliance.control.application_insights_block_log_ingestion_and_querying_from_public` |
| `azure.claude2.application_insights_workspace_based` | application_insights / resource | 1 | `azure-compliance.control.application_insights_linked_to_log_analytics_workspace` |
| `azure.claude2.automation_variable_encrypted` | automation_variable / resource | 1 | `azure-compliance.control.automation_account_variable_encryption_enabled` |
| `azure.claude2.batch_account_customer_managed_key` | batch_account / resource | 1 | `azure-compliance.control.batch_account_encrypted_with_cmk` |
| `azure.claude2.batch_account_managed_identity` | batch_account / resource | 1 | `azure-compliance.control.batch_account_identity_provider_enabled` |
| `azure.claude2.batch_account_resource_logs` | batch_account / resource | 1 | `azure-compliance.control.batch_account_logging_enabled` |
| `azure.claude2.defender_attack_path_setting_and_alert_contacts` | security_setting / scope | 2 | `azure-compliance.control.cis_v400_9_1_15` |
| `azure.claude2.entra_ca_mfa_all_users_or_roles` | tenant / resource | 2 | `azure-compliance.control.ad_all_user_mfa_enabled` |
| `azure.claude2.entra_custom_banned_password_enforced` | tenant / resource | 2 | `azure-compliance.control.ad_custom_banned_password_enforced` |
| `azure.claude2.entra_device_join_requires_mfa` | tenant / resource | 2 | `azure-compliance.control.ad_require_mfa_for_device_join` |
| `azure.claude2.entra_global_admin_between_2_and_4` | tenant / resource | 4 | `azure-compliance.control.cis_v210_1_25` |
| `azure.claude2.entra_lockout_duration_min_60` | tenant / resource | 2 | `azure-compliance.control.ad_account_duration_min_60_seconds` |
| `azure.claude2.entra_lockout_threshold_max_10` | tenant / resource | 2 | `azure-compliance.control.ad_account_lockout_threshold_max_10` |
| `azure.claude2.entra_user_mfa_registered` | user_registration_detail / resource | 2 | `azure-compliance.control.ad_user_mfa_enabled` |
| `azure.claude2.function_app_authentication_enabled` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_authentication_on` |
| `azure.claude2.function_app_client_certificates` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_client_certificates_on` |
| `azure.claude2.function_app_ftps_required` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_ftps_enabled` |
| `azure.claude2.function_app_linux_http2` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_latest_http_version` |
| `azure.claude2.function_app_managed_identity` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_uses_managed_identity` |
| `azure.claude2.function_app_restrict_public_access` | app_service / resource | 1 | `azure-compliance.control.appservice_function_app_restrict_public_acces` |
| `azure.claude2.iam_no_custom_owner_roles` | role_definition / scope | 8 | `azure-compliance.control.cis_v130_1_21` |
| `azure.claude2.nsg_flow_log_configured` | nsg / resource | 1 | `azure-compliance.control.network_sg_flowlog_enabled` |
| `azure.claude2.nsg_flow_log_retention_90` | nsg / resource | 9 | `azure-compliance.control.cis_v130_6_4` |
| `azure.claude2.nsg_flow_logs_to_log_analytics` | flow_log / scope | 7 | `azure-compliance.control.cis_v150_5_1_6` |
| `azure.claude2.prowler_app_authentication` | app_service / resource | 1 | `prowler.azure.app_ensure_auth_is_set_up` |
| `azure.claude2.prowler_app_client_certificates_required` | app_service / resource | 1 | `prowler.azure.app_client_certificates_on` |
| `azure.claude2.prowler_app_http_logs` | app_service / resource | 1 | `prowler.azure.app_http_logs_enabled` |
| `azure.claude2.prowler_app_identity` | app_service / resource | 1 | `prowler.azure.app_register_with_identity` |
| `azure.claude2.prowler_function_ftp_ftps_disabled` | app_service / resource | 1 | `prowler.azure.app_function_ftps_deployment_disabled` |
| `azure.claude2.prowler_function_identity` | app_service / resource | 1 | `prowler.azure.app_function_identity_is_configured` |
| `azure.claude2.prowler_function_identity_not_admin` | app_service / resource | 1 | `prowler.azure.app_function_identity_without_admin_privileges` |
| `azure.claude2.prowler_function_not_public` | app_service / resource | 1 | `prowler.azure.app_function_not_publicly_accessible` |
| `azure.claude2.prowler_function_vnet_integration` | app_service / resource | 1 | `prowler.azure.app_function_vnet_integration_enabled` |
| `azure.claude2.sql_server_threat_detection_all_alerts` | sql_server / resource | 1 | `azure-compliance.control.sql_server_threat_detection_all_enabled` |
| `azure.claude2.vm_encryption_at_host` | vm / resource | 1 | `azure-compliance.control.compute_vm_and_sacle_set_encryption_at_host_enabled` |
| `azure.claude2.vm_linux_ssh_key_only_guest_config` | vm / resource | 1 | `azure-compliance.control.compute_vm_ssh_key_authentication_linux` |
| `azure.claude2.vm_nic_ip_forwarding_disabled` | vm / resource | 1 | `azure-compliance.control.network_interface_ip_forwarding_disabled` |
| `azure.claude2.vm_trusted_launch_secure_boot_vtpm` | vm / resource | 3 | `azure-compliance.control.cis_v210_7_9` |
| `azure.claude2.vmss_encryption_at_host` | vm_scale_set / resource | 1 | `azure-compliance.control.compute_vm_and_sacle_set_encryption_at_host_enabled` |
| `azure.claude2.vnet_flow_log_retention_90` | flow_log / resource | 2 | `azure-compliance.control.cis_v400_8_8` |
| `azure.claude2.vnet_flow_logs_to_log_analytics` | flow_log / scope | 2 | `azure-compliance.control.cis_v400_7_1_1_7` |
| `azure.claude2.vnet_with_app_gateway_ddos_protection` | vnet / resource | 2 | `azure-compliance.control.cis_v500_8_5` |
| `azure.claude2.web_app_always_on` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_always_on` |
| `azure.claude2.web_app_authentication_enabled` | app_service / resource | 7 | `azure-compliance.control.appservice_authentication_enabled` |
| `azure.claude2.web_app_client_certificates` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_client_certificates_on` |
| `azure.claude2.web_app_diagnostic_http_log_category` | app_service / resource | 6 | `azure-compliance.control.appservice_web_app_diagnostic_log_category_http_log_enabled` |
| `azure.claude2.web_app_diagnostic_logs_enabled` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_diagnostic_logs_enabled` |
| `azure.claude2.web_app_failed_request_tracing` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_failed_request_tracing_enabled` |
| `azure.claude2.web_app_ftps_required` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_ftps_enabled` |
| `azure.claude2.web_app_health_check` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_health_check_enabled` |
| `azure.claude2.web_app_incoming_client_cert` | app_service / resource | 5 | `azure-compliance.control.appservice_web_app_incoming_client_cert_on` |
| `azure.claude2.web_app_managed_identity` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_uses_managed_identity` |
| `azure.claude2.web_app_register_with_entra` | app_service / resource | 7 | `azure-compliance.control.appservice_web_app_register_with_active_directory_enabled` |
| `azure.claude2.web_app_remote_debugging_disabled` | app_service / resource | 2 | `azure-compliance.control.appservice_web_app_remote_debugging_disabled` |
| `azure.claude2.web_app_slot_https_only` | app_service_slot / resource | 1 | `azure-compliance.control.appservice_web_app_slot_use_https` |
| `azure.claude2.web_app_vnet_connection` | app_service / resource | 1 | `azure-compliance.control.appservice_web_app_use_virtual_service_endpoint` |

### Merged into existing natives

| Native check | Rows |
|---|---|
| `azure.app.cors_no_wildcards` | 3 |
| `azure.app.ftps_only` | 7 |
| `azure.app.https_only` | 2 |
| `azure.app.minimum_tls` | 1 |
| `azure.app.remote_debugging_off` | 1 |
| `azure.claude.activity_log_alert_subscription_nsg_rule_delete` | 2 |
| `azure.claude.activity_log_alert_subscription_nsg_rule_write` | 2 |
| `azure.claude.activity_log_alert_subscription_sql_server` | 2 |
| `azure.claude.aks_network_policy_configured` | 1 |
| `azure.claude.aks_node_public_ip_disabled` | 1 |
| `azure.claude.bastion_host_exists` | 5 |
| `azure.claude.databricks_diagnostic_log_delivery` | 2 |
| `azure.claude.databricks_subnet_nsg` | 2 |
| `azure.claude.disk_attached_customer_key` | 6 |
| `azure.claude.disk_unattached_customer_key` | 6 |
| `azure.claude.entra_ca_mfa_admin_portals` | 2 |
| `azure.claude.entra_ca_mfa_management_api` | 2 |
| `azure.claude.entra_ca_policy_requires_mfa` | 8 |
| `azure.claude.entra_m365_group_creation_restricted` | 2 |
| `azure.claude.entra_named_location_trusted` | 6 |
| `azure.claude.entra_users_cannot_create_tenants` | 1 |
| `azure.claude.iam_disabled_user_no_role_assignment` | 2 |
| `azure.claude.iam_no_user_access_administrator_assignment` | 2 |
| `azure.claude.iam_subscription_owner_between_2_and_3` | 1 |
| `azure.claude.iam_subscription_tenant_transfer_restricted` | 1 |
| `azure.claude.insights_activity_logs_container_byok` | 5 |
| `azure.claude.insights_activity_logs_container_private` | 1 |
| `azure.claude.insights_operational_logs_container_byok` | 3 |
| `azure.claude.insights_operational_logs_container_private` | 3 |
| `azure.claude.keyvault_certificate_validity_12_months` | 1 |
| `azure.claude.mysql_flexible_audit_log_connection` | 1 |
| `azure.claude.mysql_flexible_audit_log_enabled` | 1 |
| `azure.claude.mysql_flexible_min_tls_12` | 1 |
| `azure.claude.mysql_flexible_secure_transport` | 1 |
| `azure.claude.network_watcher_in_vnet_region` | 8 |
| `azure.claude.nsg_associated_with_subnet` | 1 |
| `azure.claude.postgresql_flexible_connection_throttling` | 1 |
| `azure.claude.postgresql_flexible_log_checkpoints` | 1 |
| `azure.claude.postgresql_flexible_log_retention_over_3_days` | 1 |
| `azure.claude.postgresql_flexible_no_zero_address_rule` | 1 |
| `azure.claude.postgresql_flexible_secure_transport` | 1 |
| `azure.claude.sql_firewall_no_internet_or_azure_services` | 6 |
| `azure.claude.sql_server_entra_admin` | 6 |
| `azure.claude.sql_tde_protector_cmk` | 6 |
| `azure.claude.sql_va_notify_admins` | 4 |
| `azure.claude.sql_va_recurring_scans` | 4 |
| `azure.claude.sql_va_report_emails` | 4 |
| `azure.claude.storage_blob_classic_logging` | 2 |
| `azure.claude.storage_blob_diagnostic_logging` | 4 |
| `azure.claude.storage_container_no_public_access` | 3 |
| `azure.claude.storage_file_share_soft_delete_1_365` | 2 |
| `azure.claude.storage_private_link_all_approved` | 6 |
| `azure.claude.storage_queue_classic_logging` | 2 |
| `azure.claude.storage_queue_diagnostic_logging` | 4 |
| `azure.claude.storage_table_classic_logging` | 2 |
| `azure.claude.storage_table_diagnostic_logging` | 4 |
| `azure.claude.subscription_diagnostic_setting_categories` | 8 |
| `azure.claude.subscription_diagnostic_setting_exists` | 1 |
| `azure.claude.vm_os_managed_disk` | 6 |
| `azure.claude.vnet_gateway_entra_only` | 1 |
| `azure.claude.waf_policy_bot_protection` | 1 |
| `azure.claude.waf_policy_request_body_inspection` | 1 |
| `azure.disk.entra_export_auth` | 1 |
| `azure.disk.private_export` | 1 |
| `azure.port.search_service_public_network_access_disabled` | 1 |
| `azure.sql.no_public_network` | 1 |
| `azure.sql.threat_detection` | 20 |
| `azure.storage.no_blob_public_access` | 3 |

### Rejected

- `azure-compliance.control.arc_compute_machine_linux_log_analytics_agent_installed`: The legacy Log Analytics agent (MMA/OMS) is deprecated: 'The legacy Log Analytics agent is deprecated as of August 31, 2024. Microsoft will no longer provide any support'; requiring it on Arc machines contradicts the migration to Azure Monitor Agent. (https://learn.microsoft.com/en-us/previous-versions/azure/azure-monitor/agents/log-analytics-agent)
- `azure-compliance.control.arc_compute_machine_windows_log_analytics_agent_installed`: The legacy Log Analytics agent (MMA/OMS) is deprecated: 'The legacy Log Analytics agent is deprecated as of August 31, 2024. Microsoft will no longer provide any support'; requiring it on Arc machines contradicts the migration to Azure Monitor Agent. (https://learn.microsoft.com/en-us/previous-versions/azure/azure-monitor/agents/log-analytics-agent)
- `azure-compliance.control.cis_v400_3_1_8`: Mirrors the claude_azure review: the pinned query reads a workspace parameter that does not express managed-services / disk CMK configuration in the documented ARM schema. (https://learn.microsoft.com/en-us/azure/templates/microsoft.databricks/2024-05-01/workspaces)
- `azure-compliance.control.cis_v500_2_1_8`: Mirrors the claude_azure review: the pinned query reads a workspace parameter that does not express managed-services / disk CMK configuration in the documented ARM schema. (https://learn.microsoft.com/en-us/azure/templates/microsoft.databricks/2024-05-01/workspaces)

### Manual attestation

- `azure-compliance.control.appservice_function_app_latest_java_version`: "Ensure that 'Java version' is the latest, if used as a part of the Function app"
- `azure-compliance.control.appservice_function_app_latest_python_version`: "Ensure that 'Python version' is the latest, if used as a part of the Function app"
- `azure-compliance.control.appservice_web_app_latest_dotnet_framework_version`: "Web app should use the latest 'Net Framework' version"
- `azure-compliance.control.appservice_web_app_latest_java_version`: "Ensure that 'Java version' is the latest, if used as a part of the Web app"
- `azure-compliance.control.appservice_web_app_latest_php_version`: "Ensure that 'PHP version' is the latest, if used as a part of the WEB app"
- `azure-compliance.control.appservice_web_app_latest_python_version`: "Ensure that 'Python version' is the latest, if used as a part of the Web app"
- `azure-compliance.control.cis_v210_9_5`: "9.5 Ensure That 'PHP version' is the Latest, If Used to Run the Web App"
- `azure-compliance.control.cis_v210_9_6`: "9.6 Ensure that 'Python version' is the Latest Stable Version, if Used to Run the Web App"
- `azure-compliance.control.cis_v210_9_7`: "9.7 Ensure that 'Java version' is the latest, if used to run the Web App"
- `azure-compliance.control.cis_v300_9_7`: "9.7 Ensure that 'PHP version' is currently supported (if in use)"
- `azure-compliance.control.cis_v300_9_8`: "9.8 Ensure that 'Python version' is currently supported (if in use)"
- `azure-compliance.control.cis_v300_9_9`: "9.9 Ensure that 'Java version' is currently supported (if in use)"
- `prowler.azure.apim_threat_detection_llm_jacking`: "No potential LLM Jacking attacks detected across all Azure API Management instances"
- `prowler.azure.app_ensure_java_version_is_latest`: "App Service web app uses the latest supported Java version or 17 by default"
- `prowler.azure.app_ensure_php_version_is_latest`: "App Service web app uses the latest supported PHP version or 8.2 by default"
- `prowler.azure.app_ensure_python_version_is_latest`: "App Service web app uses the latest supported Python version or 3.12 by default"
- `prowler.azure.app_function_access_keys_configured`: "Function app has function keys configured"
- `prowler.azure.app_function_application_insights_enabled`: "Function App has Application Insights configured"
- `prowler.azure.app_function_latest_runtime_version`: "Function app uses the latest supported runtime version (~4)"
