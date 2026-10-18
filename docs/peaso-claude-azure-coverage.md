# PEASO Claude Azure partition coverage (claude_azure)

Partition: `peaso/rulepacks/port_partitions_claude.json` -> `partitions.claude_azure` (496 Azure rows: azure-compliance, azure-perimeter, prowler.azure).

## Files

- Predicates: `peaso/checks/claude_azure.py` (aggregator), `claude_azure_common.py`, `claude_azure_compute.py`, `claude_azure_identity.py`, `claude_azure_network.py`, `claude_azure_data.py`. Ids are `azure.claude.<slug>`.
- Review shards: `peaso/rulepacks/reviewed_claude_azure.json`, `peaso/rulepacks/reviewed_claude_azure_manual.json`.
- Tests: `tests/test_peaso_checks_claude_azure.py` (shard integrity + in-memory manifest validation) and `tests/test_peaso_checks_claude_azure_{compute,identity,network,data}.py`.
- Registry: `from . import claude_azure  # noqa: E402,F401` in `peaso/checks/__init__.py`.

## Counts

| Disposition | Rows |
|---|---|
| ported | 386 |
| merged | 42 |
| manual (rejected as automated, manual_attestation) | 3 |
| rejected | 51 |
| already supported by other shards (not re-reviewed) | 14 |
| **total** | 496 |

Unique new predicates: 348. Existing native predicates reused by merged/conjunction rows: 22.

The 14 already-supported rows are the prowler `defender_ensure_*` plan/MCAS/WDATP/notification rows owned by `reviewed_accepted_history.json`. `prowler.azure.vm_ensure_using_managed_disks` supersedes its pending entry in `reviewed_azure.json`.

## Activation

Framework mappings attach to the native checks only after the lead adds `reviewed_claude_azure.json` and `reviewed_claude_azure_manual.json` to `peaso/rulepacks/active_reviews.json` and regenerates the central artifacts (`scripts/peaso_review_catalog.py --write --sources-root /tmp/peaso-review-sources`). Until then every check carries only HackTricks Cloud Best Practices.

## Rejected rows

| Row | Reason |
|---|---|
| `azure-compliance.control.compute_vm_attached_with_network` | Upstream bug: the EXISTS subquery is not correlated to the VM, so the status reflects whether any VM in the subscription has a NIC. Its intent (a VM has a network interface) is always true for ARM VMs, which cannot be created without a NIC, so it carries no security signal. |
| `azure-compliance.control.compute_vm_log_analytics_agent_installed` | Requires the Microsoft.EnterpriseCloud.Monitoring MicrosoftMonitoringAgent/OmsAgentForLinux extension. The Log Analytics agent is deprecated as of 31 August 2024 and unsupported; a PASS would reward an unsupported agent and a FAIL would flag VMs correctly migrated to Azure Monitor Agent. |
| `azure-compliance.control.compute_vm_log_analytics_agent_installed_windows` | Same retired Log Analytics agent (MMA) requirement, restricted to Windows; deprecated 31 August 2024. |
| `azure-compliance.control.compute_vm_scale_set_log_analytics_agent_installed` | Same retired Log Analytics agent (MicrosoftMonitoringAgent/OmsAgentForLinux) requirement on scale sets; deprecated 31 August 2024. |
| `azure-compliance.control.compute_vm_scale_set_logging_enabled` | Upstream bug: the query is a copy of the VM antimalware auto-upgrade query. It evaluates azure_compute_virtual_machine (IaaSAntimalware autoUpgradeMinorVersion), not scale sets, so it defines no scale-set logging semantics to port. The VM antimalware semantics are already ported as azure.claude.vm_antimalware_auto_upgrade. |
| `azure-compliance.control.compute_vm_uses_azure_resource_manager` | Upstream returns ok whenever resource_group is non-null, which is true for every inventoried ARM VM; classic (ASM) IaaS VMs were retired on 1 September 2023, so the row cannot fail. |
| `azure-compliance.control.compute_vm_vulnerability_assessment_solution_enabled` | Upstream requires both an MDE.Linux/MDE.Windows extension and the integrated Qualys agent (WindowsAgent/LinuxAgent.AzureSecurityCenter). The integrated Qualys scanner has been retired; Defender for Cloud now uses Microsoft Defender Vulnerability Management with agentless scanning on by default, so extension inventory cannot show whether a VM is assessed. |
| `azure-compliance.control.databricks_workspace_cmk_configured` | Upstream bug: it tests parameters -> 'customerManagedKeyId', which does not exist in Microsoft.Databricks/workspaces WorkspaceCustomParameters (amlWorkspaceId, customPrivateSubnetName, customPublicSubnetName, customVirtualNetworkId, enableNoPublicIp, encryption, loadBalancer*, natGatewayName, prepareEncryption, publicIpName, requireInfrastructureEncryption, storageAccount*, vnetAddressPrefix), so  |
| `azure-compliance.control.datalake_analytics_account_logging_enabled` | Obsolete service: Azure Data Lake Analytics retired on 29 February 2024 and its resources are no longer accessible, so no live resource can be evaluated. |
| `azure-compliance.control.datalake_store_account_encryption_enabled` | Obsolete service: Azure Data Lake Storage Gen1 retired on 29 February 2024 and its resources are no longer accessible, so no live resource can be evaluated. |
| `azure-compliance.control.datalake_store_account_logging_enabled` | Obsolete service: Azure Data Lake Storage Gen1 retired on 29 February 2024 and its resources are no longer accessible, so no live resource can be evaluated. |
| `azure-compliance.control.eventgrid_topic_local_auth_enabled` | Upstream query reads azure_eventgrid_domain (not topics) and alarms when disableLocalAuth is true, i.e. it rewards enabling key/SAS local authentication. Microsoft guidance and the built-in Azure Policy ('Azure Event Grid topics should have local authentication methods disabled') require the opposite; porting it would mark the hardened state as a failure. |
| `azure-compliance.control.log_profile_enabled_for_all_subscription` | Rejected as obsolete: activity-log Log Profiles are a retired legacy collection method (creation blocked since 15 Sep 2025, retirement 15 Sep 2026); subscription diagnostic settings replace them and are ported as subscription_diagnostic_setting_* checks. |
| `azure-compliance.control.mariadb_server_geo_redundant_backup_enabled` | Rejected as obsolete: Azure Database for MariaDB was retired on 19 September 2025; servers can no longer be created or run, so the control has no live resource to evaluate. |
| `azure-compliance.control.mariadb_server_private_link_used` | Rejected as obsolete: Azure Database for MariaDB was retired on 19 September 2025; servers can no longer be created or run, so the control has no live resource to evaluate. |
| `azure-compliance.control.mariadb_server_public_network_access_disabled` | Rejected as obsolete: Azure Database for MariaDB was retired on 19 September 2025; servers can no longer be created or run, so the control has no live resource to evaluate. |
| `azure-compliance.control.mariadb_server_ssl_enabled` | Rejected as obsolete: Azure Database for MariaDB was retired on 19 September 2025; servers can no longer be created or run, so the control has no live resource to evaluate. |
| `azure-compliance.control.monitor_log_profile_enabled_for_all_categories` | Rejected as obsolete: activity-log Log Profiles are a retired legacy collection method (creation blocked since 15 Sep 2025, retirement 15 Sep 2026); subscription diagnostic settings replace them and are ported as subscription_diagnostic_setting_* checks. |
| `azure-compliance.control.monitor_log_profile_enabled_for_all_regions` | Rejected as obsolete: activity-log Log Profiles are a retired legacy collection method (creation blocked since 15 Sep 2025, retirement 15 Sep 2026); subscription diagnostic settings replace them and are ported as subscription_diagnostic_setting_* checks. |
| `azure-compliance.control.monitor_log_profile_retention_365_days` | Rejected as obsolete: activity-log Log Profiles are a retired legacy collection method (creation blocked since 15 Sep 2025, retirement 15 Sep 2026); subscription diagnostic settings replace them and are ported as subscription_diagnostic_setting_* checks. |
| `azure-compliance.control.mysql_db_server_geo_redundant_backup_enabled` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_audit_logging_enabled` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_audit_logging_events_connection_set` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_encrypted_at_rest_using_cmk` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_infrastructure_encryption_enabled` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_min_tls_1_2` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_private_link_used` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_server_public_network_access_disabled` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.mysql_ssl_enabled` | Rejected as obsolete: Azure Database for MySQL Single Server (Microsoft.DBforMySQL/servers) was retired on 16 September 2024; the equivalent flexible-server controls are ported separately. |
| `azure-compliance.control.network_sg_flowlog_enabled` | Rejected as obsolete: NSG flow logs are retiring (30 Sep 2027) and new NSG flow log creation is no longer supported; Microsoft directs migration to virtual network flow logs. Flow-log enablement/retention/Traffic Analytics are evaluated generically by flow_log_enabled, flow_log_traffic_analytics and network_watcher_flow_logs_* checks. |
| `azure-compliance.control.network_sg_flowlog_retention_period_greater_than_90` | Rejected as obsolete: NSG flow logs are retiring (30 Sep 2027) and new NSG flow log creation is no longer supported; Microsoft directs migration to virtual network flow logs. Flow-log enablement/retention/Traffic Analytics are evaluated generically by flow_log_enabled, flow_log_traffic_analytics and network_watcher_flow_logs_* checks. |
| `azure-compliance.control.nsg_network_watcher_flow_log_send_to_log_analytics` | Rejected as obsolete: NSG flow logs are retiring (30 Sep 2027) and new NSG flow log creation is no longer supported; Microsoft directs migration to virtual network flow logs. Flow-log enablement/retention/Traffic Analytics are evaluated generically by flow_log_enabled, flow_log_traffic_analytics and network_watcher_flow_logs_* checks. |
| `azure-compliance.control.postgres_db_server_allow_access_to_azure_services_disabled` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_connection_throttling_on` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_geo_redundant_backup_enabled` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_latest_tls_version` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_log_checkpoints_on` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_log_connections_on` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_log_disconnections_on` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_log_duration_on` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_db_server_log_retention_days_3` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_server_private_link_used` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgres_sql_server_encrypted_at_rest_using_cmk` | Rejected as obsolete and wrong upstream logic: targets retired PostgreSQL Single Server (retired 28 March 2025) and the upstream query joins azure_mysql_server instead of PostgreSQL servers. |
| `azure-compliance.control.postgres_sql_ssl_enabled` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgresql_server_infrastructure_encryption_enabled` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.postgresql_server_public_network_access_disabled` | Rejected as obsolete: Azure Database for PostgreSQL Single Server (Microsoft.DBforPostgreSQL/servers) was retired on 28 March 2025; flexible-server equivalents are ported separately. |
| `azure-compliance.control.securitycenter_automatic_provisioning_monitoring_agent_on` | Monitoring agent auto-provisioning is retired and cannot be enabled. |
| `azure-compliance.control.securitycenter_container_image_scan_enabled` | Upstream alarms on every sub-assessment whose assessedResourceType is not ContainerRegistryVulnerability; that field is a type discriminator, not scan enablement. |
| `azure-compliance.control.storage_account_encryption_at_rest_using_mmk` | Alarms on accounts using customer-managed keys, the stronger configuration. |
| `azure-compliance.control.storage_account_uses_azure_resource_manager` | Tautological: every ARM-listed account has a resource group, so it can never alarm. |
| `prowler.azure.defender_auto_provisioning_log_analytics_agent_vms_on` | Log Analytics agent auto-provisioning is retired and can no longer be enabled; a FAIL would be unremediable. |

## Manual rows

| Row | Question |
|---|---|
| `prowler.azure.network_public_ip_shodan` | Have the subscription's public IP addresses been reviewed in an internet-exposure scanner (e.g. Shodan/Censys) for unexpected open services? |
| `prowler.azure.vm_desired_sku_size` | Are all virtual machines using a desired (approved) VM SKU size? |
| `prowler.azure.vm_ensure_using_approved_images` | Are all virtual machines created from organisation-approved machine images? |

## Row to native mapping

| Row | Disposition | Native checks |
|---|---|---|
| `azure-compliance.control.compute_disk_access_uses_private_link` | ported | `azure.claude.disk_access_private_link` |
| `azure-compliance.control.compute_disk_unattached_encrypted_with_cmk` | ported | `azure.claude.disk_unattached_cmk` |
| `azure-compliance.control.compute_os_and_data_disk_encrypted_with_cmk` | ported | `azure.claude.disk_attached_customer_key` |
| `azure-compliance.control.compute_os_and_data_disk_encrypted_with_cmk_and_platform_managed` | ported | `azure.claude.disk_attached_double_encryption` |
| `azure-compliance.control.compute_unattached_disk_encrypted_with_cmk` | ported | `azure.claude.disk_unattached_customer_key` |
| `azure-compliance.control.compute_vm_account_with_password_linux` | ported | `azure.claude.vm_linux_no_passwordless_accounts` |
| `azure-compliance.control.compute_vm_data_and_os_disk_uses_managed_disk` | merged | `azure.vm.managed_disks` |
| `azure-compliance.control.compute_vm_disaster_recovery_enabled` | ported | `azure.claude.vm_site_recovery_enabled` |
| `azure-compliance.control.compute_vm_guest_configuration_installed` | ported | `azure.claude.vm_guest_configuration_extension` |
| `azure-compliance.control.compute_vm_guest_configuration_installed_linux` | ported | `azure.claude.vm_guest_configuration_extension_linux` |
| `azure-compliance.control.compute_vm_guest_configuration_installed_windows` | ported | `azure.claude.vm_guest_configuration_extension_windows` |
| `azure-compliance.control.compute_vm_guest_configuration_with_no_managed_identity` | ported | `azure.claude.vm_guest_configuration_managed_identity` |
| `azure-compliance.control.compute_vm_guest_configuration_with_system_assigned_managed_identity` | ported | `azure.claude.vm_guest_configuration_system_identity` |
| `azure-compliance.control.compute_vm_guest_configuration_with_user_and_system_assigned_managed_identity` | ported | `azure.claude.vm_guest_configuration_user_and_system_identity` |
| `azure-compliance.control.compute_vm_jit_access_protected` | ported | `azure.claude.vm_jit_access` |
| `azure-compliance.control.compute_vm_malware_agent_automatic_upgrade_enabled` | ported | `azure.claude.vm_antimalware_auto_upgrade` |
| `azure-compliance.control.compute_vm_malware_agent_installed` | ported | `azure.claude.vm_antimalware_extension` |
| `azure-compliance.control.compute_vm_max_password_age_70_days_windows` | ported | `azure.claude.vm_windows_max_password_age` |
| `azure-compliance.control.compute_vm_meet_security_baseline_requirements_linux` | ported | `azure.claude.vm_linux_security_baseline` |
| `azure-compliance.control.compute_vm_meet_security_baseline_requirements_windows` | ported | `azure.claude.vm_windows_security_baseline` |
| `azure-compliance.control.compute_vm_min_password_age_1_day_windows` | ported | `azure.claude.vm_windows_min_password_age` |
| `azure-compliance.control.compute_vm_min_password_length_14_windows` | ported | `azure.claude.vm_windows_min_password_length` |
| `azure-compliance.control.compute_vm_network_traffic_data_collection_linux_agent_installed` | ported | `azure.claude.vm_dependency_agent_linux` |
| `azure-compliance.control.compute_vm_network_traffic_data_collection_windows_agent_installed` | ported | `azure.claude.vm_dependency_agent_windows` |
| `azure-compliance.control.compute_vm_password_complexity_setting_enabled_windows` | ported | `azure.claude.vm_windows_password_complexity` |
| `azure-compliance.control.compute_vm_passwords_stored_using_reversible_encryption_windows` | ported | `azure.claude.vm_windows_no_reversible_password_encryption` |
| `azure-compliance.control.compute_vm_remote_access_restricted_all_ports` | ported | `azure.claude.vm_nic_nsg_internet_tcp_ingress` |
| `azure-compliance.control.compute_vm_restrict_previous_24_passwords_resuse_windows` | ported | `azure.claude.vm_windows_password_history` |
| `azure-compliance.control.compute_vm_restrict_remote_connection_from_accounts_without_password_linux` | ported | `azure.claude.vm_linux_remote_requires_password` |
| `azure-compliance.control.compute_vm_scale_set_automatic_upgrade_enabled` | ported | `azure.claude.vmss_automatic_upgrade_mode` |
| `azure-compliance.control.compute_vm_scale_set_boot_diagnostics_enabled` | ported | `azure.claude.vmss_boot_diagnostics` |
| `azure-compliance.control.compute_vm_scale_set_ssh_key_authentication_linux` | ported | `azure.claude.vmss_linux_ssh_keys` |
| `azure-compliance.control.compute_vm_scale_set_uses_managed_disks` | ported | `azure.claude.vmss_managed_disks` |
| `azure-compliance.control.compute_vm_secure_communication_protocols_configured` | ported | `azure.claude.vm_windows_secure_protocol_tls13` |
| `azure-compliance.control.compute_vm_system_updates_installed` | ported | `azure.claude.vm_windows_automatic_updates` |
| `azure-compliance.control.compute_vm_tcp_udp_access_restricted_internet` | ported | `azure.claude.vm_nsg_internet_management_ports` |
| `azure-compliance.control.compute_vm_utilizing_managed_disk` | ported | `azure.claude.vm_os_managed_disk` |
| `azure-compliance.control.compute_vm_windows_defender_exploit_guard_enabled` | ported | `azure.claude.vm_windows_exploit_guard` |
| `azure-compliance.control.compute_windows_vm_secure_boot_enabled` | ported | `azure.claude.vm_windows_secure_boot` |
| `azure-compliance.control.container_instance_container_group_encrypted_using_cmk` | ported | `azure.claude.container_group_cmk` |
| `azure-compliance.control.container_instance_container_group_identity_provider_enabled` | ported | `azure.claude.container_group_managed_identity` |
| `azure-compliance.control.container_instance_container_group_in_virtual_network` | ported | `azure.claude.container_group_virtual_network` |
| `azure-compliance.control.container_instance_container_group_secured_environment_variable` | ported | `azure.claude.container_group_secure_environment_variables` |
| `azure-compliance.control.container_registry_admin_user_disabled` | ported | `azure.claude.acr_admin_user_disabled` |
| `azure-compliance.control.container_registry_encrypted_with_cmk` | ported | `azure.claude.acr_cmk` |
| `azure-compliance.control.container_registry_geo_replication_enabled` | ported | `azure.claude.acr_geo_replication` |
| `azure-compliance.control.container_registry_public_network_access_disabled` | ported | `azure.claude.acr_public_network_access_disabled` |
| `azure-compliance.control.container_registry_quarantine_policy_enabled` | ported | `azure.claude.acr_quarantine_policy` |
| `azure-compliance.control.container_registry_restrict_public_access` | ported | `azure.claude.acr_network_default_deny` |
| `azure-compliance.control.container_registry_retention_policy_enabled` | ported | `azure.claude.acr_retention_policy` |
| `azure-compliance.control.container_registry_trust_policy_enabled` | ported | `azure.claude.acr_trust_policy` |
| `azure-compliance.control.container_registry_use_virtual_service_endpoint` | ported | `azure.claude.acr_vnet_service_endpoint` |
| `azure-compliance.control.container_registry_uses_private_link` | ported | `azure.claude.acr_private_link_approved` |
| `azure-compliance.control.cosmosdb_account_encryption_at_rest_using_cmk` | ported | `azure.claude.cosmos_cmk` |
| `azure-compliance.control.cosmosdb_account_key_based_metadata_write_access_disabled` | ported | `azure.claude.cosmos_key_based_metadata_write_disabled` |
| `azure-compliance.control.cosmosdb_account_uses_aad_and_rbac` | ported | `azure.claude.cosmos_local_auth_disabled` |
| `azure-compliance.control.cosmosdb_account_uses_private_link` | merged | `azure.port.cosmosdb_account_uses_private_link` |
| `azure-compliance.control.cosmosdb_account_virtual_network_filter_enabled` | merged | `azure.port.cosmosdb_account_virtual_network_filter_enabled` |
| `azure-compliance.control.cosmosdb_account_with_firewall_rules` | ported | `azure.claude.cosmos_network_restricted` |
| `azure-compliance.control.cosmosdb_use_virtual_service_endpoint` | ported | `azure.claude.cosmos_vnet_service_endpoint` |
| `azure-compliance.control.databox_edge_device_double_encryption_enabled` | ported | `azure.claude.databox_edge_double_encryption` |
| `azure-compliance.control.databricks_workspace_deployed_in_custom_vnet` | merged | `azure.port.databricks_workspace_deployed_in_custom_vnet` |
| `azure-compliance.control.databricks_workspace_diagnostic_log_delivery_configured` | ported | `azure.claude.databricks_diagnostic_log_delivery` |
| `azure-compliance.control.databricks_workspace_no_public_ip_enabled` | merged | `azure.port.databricks_workspace_no_public_ip_enabled` |
| `azure-compliance.control.databricks_workspace_public_network_access_disabled` | merged | `azure.port.databricks_workspace_public_network_access_disabled` |
| `azure-compliance.control.databricks_workspace_subnet_with_nsg_configured` | ported | `azure.claude.databricks_subnet_nsg` |
| `azure-compliance.control.databricks_workspace_uses_private_endpoint` | merged | `azure.port.databricks_workspace_uses_private_endpoint` |
| `azure-compliance.control.eventgrid_domain_identity_provider_enabled` | ported | `azure.claude.eventgrid_domain_managed_identity` |
| `azure-compliance.control.eventgrid_domain_private_link_used` | ported | `azure.claude.eventgrid_domain_private_link` |
| `azure-compliance.control.eventgrid_domain_restrict_public_access` | ported | `azure.claude.eventgrid_domain_public_access_disabled` |
| `azure-compliance.control.eventgrid_topic_identity_provider_enabled` | ported | `azure.claude.eventgrid_topic_managed_identity` |
| `azure-compliance.control.eventgrid_topic_private_link_used` | ported | `azure.claude.eventgrid_topic_private_link` |
| `azure-compliance.control.eventhub_namespace_cmk_encryption_enabled` | ported | `azure.claude.eventhub_namespace_cmk` |
| `azure-compliance.control.eventhub_namespace_logging_enabled` | ported | `azure.claude.eventhub_namespace_logging` |
| `azure-compliance.control.eventhub_namespace_private_link_used` | ported | `azure.claude.eventhub_namespace_private_link` |
| `azure-compliance.control.eventhub_namespace_use_virtual_service_endpoint` | ported | `azure.claude.eventhub_namespace_vnet_rule` |
| `azure-compliance.control.frontdoor_waf_enabled` | ported | `azure.claude.frontdoor_waf_policy_linked` |
| `azure-compliance.control.hdinsight_cluster_encrypted_at_rest_with_cmk` | ported | `azure.claude.hdinsight_cmk` |
| `azure-compliance.control.hdinsight_cluster_encryption_at_host_enabled` | ported | `azure.claude.hdinsight_encryption_at_host` |
| `azure-compliance.control.hdinsight_cluster_encryption_in_transit_enabled` | ported | `azure.claude.hdinsight_encryption_in_transit` |
| `azure-compliance.control.healthcare_fhir_azure_api_encrypted_at_rest_with_cmk` | ported | `azure.claude.fhir_cmk` |
| `azure-compliance.control.healthcare_fhir_uses_private_link` | ported | `azure.claude.fhir_private_link` |
| `azure-compliance.control.hpc_cache_encrypted_with_cmk` | ported | `azure.claude.hpc_cache_cmk` |
| `azure-compliance.control.iam_conditional_access_mfa_enabled` | ported | `azure.claude.entra_ca_policy_requires_mfa` |
| `azure-compliance.control.iam_conditional_access_trusted_location_configured` | ported | `azure.claude.entra_named_location_trusted` |
| `azure-compliance.control.iam_deprecated_account` | ported | `azure.claude.iam_disabled_user_no_role_assignment` |
| `azure-compliance.control.iam_deprecated_account_with_owner_roles` | ported | `azure.claude.iam_disabled_user_no_owner` |
| `azure-compliance.control.iam_external_user_with_owner_role` | ported | `azure.claude.iam_external_user_no_owner` |
| `azure-compliance.control.iam_external_user_with_read_permission` | ported | `azure.claude.iam_external_user_no_reader` |
| `azure-compliance.control.iam_external_user_with_write_permission` | ported | `azure.claude.iam_external_user_no_write` |
| `azure-compliance.control.iam_no_custom_role` | ported | `azure.claude.iam_no_custom_role` |
| `azure-compliance.control.iam_no_custom_subscription_owner_roles_created` | ported | `azure.claude.iam_custom_role_no_wildcard_actions` |
| `azure-compliance.control.iam_subscription_owner_between_2_and_3` | ported | `azure.claude.iam_subscription_owner_between_2_and_3` |
| `azure-compliance.control.iam_subscription_owner_max_3` | ported | `azure.claude.iam_subscription_owner_max_3` |
| `azure-compliance.control.iam_subscription_owner_more_than_1` | ported | `azure.claude.iam_subscription_owner_more_than_1` |
| `azure-compliance.control.iam_subscription_tenant_transfer_restricted` | ported | `azure.claude.iam_subscription_tenant_transfer_restricted` |
| `azure-compliance.control.iam_subscriptions_with_custom_roles_no_overly_permissive` | ported | `azure.claude.iam_root_custom_role_no_wildcard` |
| `azure-compliance.control.iam_user_access_administrator_role_restricted` | ported | `azure.claude.iam_no_user_access_administrator_assignment` |
| `azure-compliance.control.iam_user_no_built_in_contributor_role` | ported | `azure.claude.iam_user_no_contributor_assignment` |
| `azure-compliance.control.iam_user_not_allowed_to_create_security_group` | ported | `azure.claude.entra_users_cannot_create_security_groups` |
| `azure-compliance.control.iam_user_not_allowed_to_create_tenants` | ported | `azure.claude.entra_users_cannot_create_tenants` |
| `azure-compliance.control.iam_user_not_allowed_to_register_application` | ported | `azure.claude.entra_users_cannot_create_apps` |
| `azure-compliance.control.iot_hub_logging_enabled` | ported | `azure.claude.iot_hub_logging` |
| `azure-compliance.control.iot_hub_private_link_used` | ported | `azure.claude.iot_hub_private_link` |
| `azure-compliance.control.keyvault_certificate_validity_period_less_equal_12_months` | ported | `azure.claude.keyvault_certificate_validity_12_months` |
| `azure-compliance.control.keyvault_firewall_enabled` | ported | `azure.claude.keyvault_firewall_ip_rules` |
| `azure-compliance.control.keyvault_key_automatic_rotation_enabled` | ported | `azure.claude.keyvault_key_automatic_rotation_after_create` |
| `azure-compliance.control.keyvault_key_expiration_set` | ported | `azure.claude.keyvault_key_expiration_set` |
| `azure-compliance.control.keyvault_logging_enabled` | ported | `azure.claude.keyvault_audit_and_alllogs_groups` |
| `azure-compliance.control.keyvault_managed_hms_logging_enabled` | ported | `azure.claude.managed_hsm_audit_logging` |
| `azure-compliance.control.keyvault_managed_hms_purge_protection_enabled` | ported | `azure.claude.managed_hsm_purge_protection` |
| `azure-compliance.control.keyvault_purge_protection_enabled` | merged | `azure.vault.purge_protection` |
| `azure-compliance.control.keyvault_rbac_enabled` | merged | `azure.vault.rbac` |
| `azure-compliance.control.keyvault_soft_delete_enabled` | merged | `azure.vault.soft_delete` |
| `azure-compliance.control.keyvault_vault_public_network_access_disabled` | merged | `azure.vault.default_deny` |
| `azure-compliance.control.keyvault_vault_recoverable` | merged | `azure.port.keyvault_vault_recoverable` |
| `azure-compliance.control.keyvault_vault_use_virtual_service_endpoint` | ported | `azure.claude.keyvault_vnet_service_endpoint` |
| `azure-compliance.control.keyvault_with_non_rbac_key_expiration_set` | ported | `azure.claude.keyvault_non_rbac_key_expiration_set` |
| `azure-compliance.control.keyvault_with_non_rbac_secret_expiration_set` | ported | `azure.claude.keyvault_non_rbac_secret_expiration_set` |
| `azure-compliance.control.keyvault_with_rbac_key_expiration_set` | ported | `azure.claude.keyvault_rbac_key_expiration_set` |
| `azure-compliance.control.keyvault_with_rbac_secret_expiration_set` | ported | `azure.claude.keyvault_rbac_secret_expiration_set` |
| `azure-compliance.control.kubernetes_cluster_add_on_azure_policy_enabled` | ported | `azure.claude.aks_azure_policy_addon` |
| `azure-compliance.control.kubernetes_cluster_addon_azure_policy_enabled` | ported | `azure.claude.aks_azure_policy_addon` |
| `azure-compliance.control.kubernetes_cluster_authorized_ip_range_defined` | ported | `azure.claude.aks_authorized_ip_ranges` |
| `azure-compliance.control.kubernetes_cluster_http_application_routing_disabled` | ported | `azure.claude.aks_http_application_routing_disabled` |
| `azure-compliance.control.kubernetes_cluster_key_vault_secret_rotation_enabled` | ported | `azure.claude.aks_secret_store_rotation` |
| `azure-compliance.control.kubernetes_cluster_logging_enabled` | ported | `azure.claude.aks_container_insights_logging` |
| `azure-compliance.control.kubernetes_cluster_max_pod_50` | ported | `azure.claude.aks_max_pods_at_least_50` |
| `azure-compliance.control.kubernetes_cluster_network_plugin_azure` | ported | `azure.claude.aks_network_plugin_azure` |
| `azure-compliance.control.kubernetes_cluster_network_policy_enabled` | ported | `azure.claude.aks_network_policy_configured` |
| `azure-compliance.control.kubernetes_cluster_node_restrict_public_access` | ported | `azure.claude.aks_node_public_ip_disabled` |
| `azure-compliance.control.kubernetes_cluster_os_and_data_disks_encrypted_with_cmk` | ported | `azure.claude.aks_disk_encryption_set` |
| `azure-compliance.control.kubernetes_cluster_restrict_public_access` | merged | `azure.aks.private_cluster` |
| `azure-compliance.control.kubernetes_cluster_sku_standard` | ported | `azure.claude.aks_paid_sku_tier` |
| `azure-compliance.control.kubernetes_cluster_temp_disks_and_agent_node_pool_cache_encrypted_at_host` | ported | `azure.claude.aks_encryption_at_host` |
| `azure-compliance.control.kubernetes_cluster_upgrade_channel` | merged | `azure.aks.auto_upgrade` |
| `azure-compliance.control.kubernetes_cluster_upgraded_with_non_vulnerable_version` | ported | `azure.claude.aks_version_not_cve_2019_9946` |
| `azure-compliance.control.kusto_cluster_disk_encryption_enabled` | ported | `azure.claude.kusto_disk_encryption` |
| `azure-compliance.control.kusto_cluster_double_encryption_enabled` | ported | `azure.claude.kusto_double_encryption` |
| `azure-compliance.control.kusto_cluster_encrypted_at_rest_with_cmk` | ported | `azure.claude.kusto_cmk` |
| `azure-compliance.control.kusto_cluster_sku_with_sla` | ported | `azure.claude.kusto_sku_with_sla` |
| `azure-compliance.control.log_analytics_workspace_block_log_ingestion_and_querying_from_public` | ported | `azure.claude.log_analytics_public_ingestion_query_disabled` |
| `azure-compliance.control.log_analytics_workspace_block_non_azure_ingestion` | ported | `azure.claude.log_analytics_local_auth_disabled` |
| `azure-compliance.control.logic_app_workflow_logging_enabled` | ported | `azure.claude.logic_app_workflow_diagnostic_logging` |
| `azure-compliance.control.machine_learning_workspace_encrypted_with_cmk` | ported | `azure.claude.ml_workspace_cmk` |
| `azure-compliance.control.monitor_diagnostic_settings_captures_proper_categories` | ported | `azure.claude.subscription_diagnostic_setting_categories` |
| `azure-compliance.control.monitor_diagnostic_settings_exists_for_subscription` | ported | `azure.claude.subscription_diagnostic_setting_exists` |
| `azure-compliance.control.monitor_log_alert_create_policy_assignment` | ported | `azure.claude.activity_log_alert_subscription_policy_assignment_write` |
| `azure-compliance.control.monitor_log_alert_create_update_nsg` | ported | `azure.claude.activity_log_alert_subscription_nsg_write` |
| `azure-compliance.control.monitor_log_alert_create_update_nsg_rule` | ported | `azure.claude.activity_log_alert_subscription_nsg_rule_write` |
| `azure-compliance.control.monitor_log_alert_create_update_public_ip_address` | ported | `azure.claude.activity_log_alert_subscription_public_ip_write` |
| `azure-compliance.control.monitor_log_alert_create_update_security_solution` | ported | `azure.claude.activity_log_alert_subscription_security_solution_write` |
| `azure-compliance.control.monitor_log_alert_create_update_sql_servers_firewall_rule` | ported | `azure.claude.activity_log_alert_subscription_sql_firewall_rule_write` |
| `azure-compliance.control.monitor_log_alert_delete_nsg` | ported | `azure.claude.activity_log_alert_subscription_nsg_delete` |
| `azure-compliance.control.monitor_log_alert_delete_nsg_rule` | ported | `azure.claude.activity_log_alert_subscription_nsg_rule_delete` |
| `azure-compliance.control.monitor_log_alert_delete_policy_assignment` | ported | `azure.claude.activity_log_alert_subscription_policy_assignment_delete` |
| `azure-compliance.control.monitor_log_alert_delete_public_ip_address` | ported | `azure.claude.activity_log_alert_subscription_public_ip_delete` |
| `azure-compliance.control.monitor_log_alert_delete_security_solution` | ported | `azure.claude.activity_log_alert_subscription_security_solution_delete` |
| `azure-compliance.control.monitor_log_alert_delete_sql_servers_firewall_rule` | ported | `azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete` |
| `azure-compliance.control.monitor_log_alert_for_administrative_operations` | ported | `azure.claude.activity_log_alert_subscription_administrative_operations` |
| `azure-compliance.control.monitor_log_alert_sql_firewall_rule` | ported | `azure.claude.activity_log_alert_subscription_sql_server` |
| `azure-compliance.control.monitor_logs_storage_container_insights_activity_logs_encrypted_with_byok` | ported | `azure.claude.insights_activity_logs_container_byok` |
| `azure-compliance.control.monitor_logs_storage_container_insights_activity_logs_not_public_accessible` | ported | `azure.claude.insights_activity_logs_container_private` |
| `azure-compliance.control.monitor_logs_storage_container_insights_operational_logs_encrypted_with_byok` | ported | `azure.claude.insights_operational_logs_container_byok` |
| `azure-compliance.control.monitor_logs_storage_container_insights_operational_logs_not_public_accessible` | ported | `azure.claude.insights_operational_logs_container_private` |
| `azure-compliance.control.mssql_managed_instance_encryption_at_rest_using_cmk` | ported | `azure.claude.mssql_managed_instance_tde_cmk` |
| `azure-compliance.control.mssql_managed_instance_vulnerability_assessment_enabled` | ported | `azure.claude.mssql_managed_instance_vulnerability_assessment` |
| `azure-compliance.control.mysql_flexible_server_audit_logging_enabled` | ported | `azure.claude.mysql_flexible_audit_log_enabled` |
| `azure-compliance.control.mysql_flexible_server_audit_logging_events_connection_set` | ported | `azure.claude.mysql_flexible_audit_log_connection` |
| `azure-compliance.control.mysql_flexible_server_min_tls_1_2` | ported | `azure.claude.mysql_flexible_min_tls_12` |
| `azure-compliance.control.mysql_flexible_server_ssl_enabled` | ported | `azure.claude.mysql_flexible_secure_transport` |
| `azure-compliance.control.network_bastion_host_min_1` | ported | `azure.claude.bastion_host_exists` |
| `azure-compliance.control.network_network_peering_connected` | ported | `azure.claude.vnet_peering_connected` |
| `azure-compliance.control.network_security_group_diagnostic_setting_deployed` | ported | `azure.claude.nsg_diagnostic_logging` |
| `azure-compliance.control.network_security_group_https_access_restricted` | ported | `azure.claude.nsg_internet_http` |
| `azure-compliance.control.network_security_group_https_port_80_443_access_restricted` | ported | `azure.claude.nsg_internet_http_https` |
| `azure-compliance.control.network_security_group_not_configured_gateway_subnets` | ported | `azure.claude.gateway_subnet_no_nsg` |
| `azure-compliance.control.network_security_group_outbound_access_restricted` | ported | `azure.claude.nsg_outbound_restricted` |
| `azure-compliance.control.network_security_group_rdp_access_restricted` | ported | `azure.claude.nsg_internet_rdp` |
| `azure-compliance.control.network_security_group_remote_access_restricted` | ported | `azure.claude.nsg_internet_remote_access` |
| `azure-compliance.control.network_security_group_restrict_inbound_icmp_port` | ported | `azure.claude.nsg_internet_icmp` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_135` | ported | `azure.claude.nsg_internet_tcp_135` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_1433` | ported | `azure.claude.nsg_internet_tcp_1433` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_20` | ported | `azure.claude.nsg_internet_tcp_20` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_21` | ported | `azure.claude.nsg_internet_tcp_21` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_23` | ported | `azure.claude.nsg_internet_tcp_23` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_25` | ported | `azure.claude.nsg_internet_tcp_25` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_3306` | ported | `azure.claude.nsg_internet_tcp_3306` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_4333` | ported | `azure.claude.nsg_internet_tcp_4333` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_445` | ported | `azure.claude.nsg_internet_tcp_445` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_53` | ported | `azure.claude.nsg_internet_tcp_53` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_5432` | ported | `azure.claude.nsg_internet_tcp_5432` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_5500` | ported | `azure.claude.nsg_internet_tcp_5500` |
| `azure-compliance.control.network_security_group_restrict_inbound_tcp_port_5900` | ported | `azure.claude.nsg_internet_tcp_5900` |
| `azure-compliance.control.network_security_group_restrict_inbound_udp_port_137` | ported | `azure.claude.nsg_internet_udp_137` |
| `azure-compliance.control.network_security_group_restrict_inbound_udp_port_138` | ported | `azure.claude.nsg_internet_udp_138` |
| `azure-compliance.control.network_security_group_restrict_inbound_udp_port_1434` | ported | `azure.claude.nsg_internet_udp_1434` |
| `azure-compliance.control.network_security_group_restrict_inbound_udp_port_445` | ported | `azure.claude.nsg_internet_udp_445` |
| `azure-compliance.control.network_security_group_restrict_inbound_udp_port_53` | ported | `azure.claude.nsg_internet_udp_53` |
| `azure-compliance.control.network_security_group_ssh_access_restricted` | ported | `azure.claude.nsg_internet_ssh` |
| `azure-compliance.control.network_security_group_subnet_associated` | ported | `azure.claude.nsg_associated_with_subnet` |
| `azure-compliance.control.network_security_group_udp_service_restricted` | ported | `azure.claude.nsg_internet_udp_services` |
| `azure-compliance.control.network_virtual_network_gateway_aad_only` | ported | `azure.claude.vnet_gateway_entra_only` |
| `azure-compliance.control.network_virtual_network_gateway_no_basic_sku` | ported | `azure.claude.vnet_gateway_no_basic_sku` |
| `azure-compliance.control.network_watcher_enabled` | ported | `azure.claude.network_watcher_in_vnet_region` |
| `azure-compliance.control.network_watcher_flow_log_enabled` | ported | `azure.claude.flow_log_enabled` |
| `azure-compliance.control.network_watcher_flow_log_traffic_analytics_enabled` | ported | `azure.claude.flow_log_traffic_analytics` |
| `azure-compliance.control.network_watcher_in_regions_with_virtual_network` | ported | `azure.claude.network_watcher_in_vnet_region` |
| `azure-compliance.control.postgres_flexible_server_allow_access_to_azure_services_disabled` | ported | `azure.claude.postgresql_flexible_no_zero_address_rule` |
| `azure-compliance.control.postgres_flexible_server_connection_throttling_on` | ported | `azure.claude.postgresql_flexible_connection_throttling` |
| `azure-compliance.control.postgres_flexible_server_log_checkpoints_on` | ported | `azure.claude.postgresql_flexible_log_checkpoints` |
| `azure-compliance.control.postgres_flexible_server_log_retention_days_3` | ported | `azure.claude.postgresql_flexible_log_retention_over_3_days` |
| `azure-compliance.control.postgres_sql_flexible_server_ssl_enabled` | ported | `azure.claude.postgresql_flexible_secure_transport` |
| `azure-compliance.control.recovery_service_vault_uses_managed_identity` | ported | `azure.claude.recovery_vault_managed_identity` |
| `azure-compliance.control.recovery_service_vault_uses_private_link` | ported | `azure.claude.recovery_vault_private_endpoint_site_recovery` |
| `azure-compliance.control.recovery_service_vault_uses_private_link_for_backup` | ported | `azure.claude.recovery_vault_private_endpoint_backup` |
| `azure-compliance.control.search_service_logging_enabled` | ported | `azure.claude.search_service_logging_enabled` |
| `azure-compliance.control.search_service_replica_count_3` | ported | `azure.claude.search_service_replica_count_above_3` |
| `azure-compliance.control.securitycenter_additional_email_configured` | ported | `azure.claude.defender_security_contact_email_configured` |
| `azure-compliance.control.securitycenter_asc_default_setting_not_disabled` | ported | `azure.claude.defender_default_initiative_no_disabled_effects` |
| `azure-compliance.control.securitycenter_azure_defender_on_for_containerregistry` | ported | `azure.claude.defender_container_registry_plan_standard` |
| `azure-compliance.control.securitycenter_azure_defender_on_for_dns` | ported | `azure.claude.defender_dns_plan_standard` |
| `azure-compliance.control.securitycenter_azure_defender_on_for_k8s` | ported | `azure.claude.defender_kubernetes_plan_standard` |
| `azure-compliance.control.securitycenter_email_configured` | ported | `azure.claude.defender_security_contact_email_configured` |
| `azure-compliance.control.securitycenter_notify_alerts_configured` | ported | `azure.claude.defender_alert_notifications_high` |
| `azure-compliance.control.securitycenter_pricing_standard` | ported | `azure.claude.defender_plan_standard_any` |
| `azure-compliance.control.securitycenter_security_alerts_to_owner_enabled` | ported | `azure.claude.defender_alerts_to_owner` |
| `azure-compliance.control.servicebus_name_space_private_link_used` | ported | `azure.claude.servicebus_namespace_private_link` |
| `azure-compliance.control.servicebus_namespace_azure_ad_authentication_enabled` | ported | `azure.claude.servicebus_namespace_local_auth_disabled` |
| `azure-compliance.control.servicebus_namespace_logging_enabled` | ported | `azure.claude.servicebus_namespace_logging_enabled` |
| `azure-compliance.control.servicebus_namespace_no_overly_permissive_network_access` | ported | `azure.claude.servicebus_namespace_network_restricted` |
| `azure-compliance.control.servicebus_premium_namespace_cmk_encrypted` | ported | `azure.claude.servicebus_premium_namespace_cmk` |
| `azure-compliance.control.servicebus_use_virtual_service_endpoint` | ported | `azure.claude.servicebus_premium_namespace_vnet_rules` |
| `azure-compliance.control.servicefabric_cluster_active_directory_authentication_enabled` | ported | `azure.claude.servicefabric_cluster_entra_auth` |
| `azure-compliance.control.servicefabric_cluster_protection_level_as_encrypt_and_sign` | ported | `azure.claude.servicefabric_cluster_encrypt_and_sign` |
| `azure-compliance.control.signalr_service_no_free_tier_sku` | ported | `azure.claude.signalr_service_no_free_tier` |
| `azure-compliance.control.signalr_service_private_link_used` | ported | `azure.claude.signalr_service_private_link` |
| `azure-compliance.control.spring_cloud_service_network_injection_enabled` | ported | `azure.claude.spring_cloud_service_vnet_injection` |
| `azure-compliance.control.sql_database_allow_internet_access` | ported | `azure.claude.sql_firewall_no_internet_or_azure_services` |
| `azure-compliance.control.sql_database_long_term_geo_redundant_backup_enabled` | ported | `azure.claude.sql_database_long_term_retention` |
| `azure-compliance.control.sql_database_vulnerability_findings_resolved` | ported | `azure.claude.sql_database_va_findings_resolved` |
| `azure-compliance.control.sql_db_active_directory_admin_configured` | ported | `azure.claude.sql_server_entra_admin` |
| `azure-compliance.control.sql_db_public_network_access_disabled` | merged | `azure.sql.no_public_network` |
| `azure-compliance.control.sql_server_and_databases_va_enabled` | merged | `azure.sql.threat_detection` |
| `azure-compliance.control.sql_server_atp_enabled` | merged | `azure.sql.threat_detection` |
| `azure-compliance.control.sql_server_auditing_on` | merged | `azure.sql.auditing` |
| `azure-compliance.control.sql_server_auditing_storage_account_destination_retention_90_days` | ported | `azure.claude.sql_audit_storage_retention_90` |
| `azure-compliance.control.sql_server_azure_ad_authentication_enabled` | ported | `azure.claude.sql_server_entra_admin` |
| `azure-compliance.control.sql_server_azure_defender_enabled` | merged | `azure.sql.threat_detection` |
| `azure-compliance.control.sql_server_tde_protector_cmk_encrypted` | ported | `azure.claude.sql_tde_protector_cmk` |
| `azure-compliance.control.sql_server_transparent_data_encryption_enabled` | merged | `azure.sql.tde_enabled` |
| `azure-compliance.control.sql_server_use_virtual_service_endpoint` | ported | `azure.claude.sql_server_vnet_rules` |
| `azure-compliance.control.sql_server_uses_private_link` | ported | `azure.claude.sql_server_private_link` |
| `azure-compliance.control.sql_server_va_setting_periodic_scan_enabled` | ported | `azure.claude.sql_va_recurring_scans`, `azure.sql.threat_detection` |
| `azure-compliance.control.sql_server_va_setting_reports_notify_admins` | ported | `azure.claude.sql_va_notify_admins`, `azure.sql.threat_detection` |
| `azure-compliance.control.sql_server_va_setting_scan_reports_configured` | ported | `azure.claude.sql_va_report_emails`, `azure.sql.threat_detection` |
| `azure-compliance.control.storage_account_access_keys_periodically_regenerated` | ported | `azure.claude.storage_access_keys_rotated_90` |
| `azure-compliance.control.storage_account_blob_and_container_soft_delete_enabled` | ported | `azure.claude.storage_blob_and_container_soft_delete_7_365` |
| `azure-compliance.control.storage_account_blob_containers_public_access_disabled` | ported | `azure.claude.storage_container_no_public_access`, `azure.storage.no_blob_public_access` |
| `azure-compliance.control.storage_account_blob_service_classic_logging_enabled` | ported | `azure.claude.storage_blob_classic_logging` |
| `azure-compliance.control.storage_account_blob_service_logging_enabled` | ported | `azure.claude.storage_blob_diagnostic_logging` |
| `azure-compliance.control.storage_account_block_public_access` | merged | `azure.storage.no_public_network` |
| `azure-compliance.control.storage_account_containing_vhd_os_disk_cmk_encrypted` | ported | `azure.claude.storage_vhd_accounts_cmk` |
| `azure-compliance.control.storage_account_default_network_access_deny` | merged | `azure.storage.default_deny` |
| `azure-compliance.control.storage_account_default_network_access_rule_denied` | merged | `azure.storage.default_deny` |
| `azure-compliance.control.storage_account_encryption_at_rest_using_cmk` | ported | `azure.claude.storage_account_cmk` |
| `azure-compliance.control.storage_account_encryption_scopes_encrypted_at_rest_with_cmk` | ported | `azure.claude.storage_encryption_scope_cmk` |
| `azure-compliance.control.storage_account_file_share_smb_channel_encryption_aes_256_gcm` | ported | `azure.claude.storage_smb_channel_encryption_aes_256_gcm` |
| `azure-compliance.control.storage_account_file_share_smb_protocol_version_3_1_1` | ported | `azure.claude.storage_smb_version_3_1_1` |
| `azure-compliance.control.storage_account_file_share_soft_delete_enabled` | ported | `azure.claude.storage_file_share_soft_delete_1_365` |
| `azure-compliance.control.storage_account_geo_redundant_enabled` | ported | `azure.claude.storage_account_geo_redundant` |
| `azure-compliance.control.storage_account_key_rotation_reminder_enabled` | ported | `azure.claude.storage_key_expiration_policy_90` |
| `azure-compliance.control.storage_account_queue_service_classic_logging_enabled` | ported | `azure.claude.storage_queue_classic_logging` |
| `azure-compliance.control.storage_account_queue_services_logging_enabled` | ported | `azure.claude.storage_queue_diagnostic_logging` |
| `azure-compliance.control.storage_account_restrict_network_access` | merged | `azure.storage.default_deny` |
| `azure-compliance.control.storage_account_secure_transfer_required_enabled` | merged | `azure.storage.https_only` |
| `azure-compliance.control.storage_account_soft_delete_enabled` | ported | `azure.claude.storage_blob_soft_delete_enabled` |
| `azure-compliance.control.storage_account_table_service_classic_logging_enabled` | ported | `azure.claude.storage_table_classic_logging` |
| `azure-compliance.control.storage_account_table_service_logging_enabled` | ported | `azure.claude.storage_table_diagnostic_logging` |
| `azure-compliance.control.storage_account_trusted_microsoft_services_enabled` | ported | `azure.claude.storage_trusted_azure_services_bypass` |
| `azure-compliance.control.storage_account_use_virtual_service_endpoint` | ported | `azure.claude.storage_vnet_service_endpoint_rules` |
| `azure-compliance.control.storage_account_uses_private_link` | ported | `azure.claude.storage_private_link_all_approved` |
| `azure-compliance.control.storage_sync_private_link_used` | ported | `azure.claude.storage_sync_private_link` |
| `azure-compliance.control.stream_analytics_job_logging_enabled` | ported | `azure.claude.stream_analytics_job_logging_enabled` |
| `azure-compliance.control.synapse_workspace_data_exfiltration_protection_enabled` | ported | `azure.claude.synapse_workspace_exfiltration_protection` |
| `azure-compliance.control.synapse_workspace_encryption_at_rest_using_cmk` | ported | `azure.claude.synapse_workspace_cmk` |
| `azure-compliance.control.synapse_workspace_private_link_used` | ported | `azure.claude.synapse_workspace_private_link` |
| `azure-compliance.control.synapse_workspace_vulnerability_assessment_enabled` | ported | `azure.claude.synapse_workspace_vulnerability_assessment` |
| `azure-compliance.control.web_application_firewall_policy_bot_protection_enabled` | ported | `azure.claude.waf_policy_bot_protection` |
| `azure-compliance.control.web_application_firewall_policy_request_body_inspection_enabled` | ported | `azure.claude.waf_policy_request_body_inspection` |
| `azure-perimeter.control.compute_vm_no_public_ip` | ported | `azure.claude.vm_no_public_ip` |
| `azure-perimeter.control.container_registry_restrict_public_network_access` | merged | `azure.claude.acr_public_network_access_disabled` |
| `azure-perimeter.control.cosmos_db_account_restrict_public_network_access` | ported | `azure.claude.cosmos_public_network_access_disabled` |
| `azure-perimeter.control.cosmosdb_account_cors_prohibit_public_access` | ported | `azure.claude.cosmos_cors_no_wildcard` |
| `azure-perimeter.control.kubernetes_cluster_private` | merged | `azure.aks.private_cluster` |
| `azure-perimeter.control.network_interface_not_attached_to_public_ip` | ported | `azure.claude.nic_no_public_ip` |
| `azure-perimeter.control.network_security_group_restrict_ingress_all_ports_tcp_udp_from_internet` | ported | `azure.claude.nsg_internet_all_ports_tcp_udp` |
| `azure-perimeter.control.network_security_group_restrict_ingress_common_ports_all` | ported | `azure.claude.nsg_internet_common_ports` |
| `azure-perimeter.control.sql_server_restrict_public_network_access` | merged | `azure.sql.no_public_network` |
| `azure-perimeter.control.storage_account_prohibit_blob_public_access` | merged | `azure.storage.no_blob_public_access` |
| `azure-perimeter.control.storage_account_restrict_public_network_access` | merged | `azure.storage.no_public_network` |
| `azure-perimeter.control.storage_container_prohibit_public_access` | ported | `azure.claude.storage_container_no_public_access` |
| `prowler.azure.containerregistry_admin_user_disabled` | merged | `azure.claude.acr_admin_user_disabled` |
| `prowler.azure.containerregistry_not_publicly_accessible` | merged | `azure.claude.acr_public_network_access_disabled` |
| `prowler.azure.containerregistry_uses_private_link` | ported | `azure.claude.acr_private_endpoint_present` |
| `prowler.azure.cosmosdb_account_automatic_failover_enabled` | ported | `azure.claude.cosmos_automatic_failover` |
| `prowler.azure.cosmosdb_account_backup_policy_continuous` | ported | `azure.claude.cosmos_continuous_backup` |
| `prowler.azure.cosmosdb_account_firewall_use_selected_networks` | ported | `azure.claude.cosmos_virtual_network_filter` |
| `prowler.azure.cosmosdb_account_minimum_tls_version` | ported | `azure.claude.cosmos_minimum_tls12` |
| `prowler.azure.cosmosdb_account_public_network_access_disabled` | ported | `azure.claude.cosmos_public_network_access_restricted` |
| `prowler.azure.cosmosdb_account_use_aad_and_rbac` | merged | `azure.claude.cosmos_local_auth_disabled` |
| `prowler.azure.cosmosdb_account_use_private_endpoints` | ported | `azure.claude.cosmos_private_endpoint_present` |
| `prowler.azure.databricks_workspace_cmk_encryption_enabled` | ported | `azure.claude.databricks_managed_disk_cmk` |
| `prowler.azure.databricks_workspace_no_public_ip_enabled` | merged | `azure.port.databricks_workspace_no_public_ip_enabled` |
| `prowler.azure.databricks_workspace_public_network_access_disabled` | merged | `azure.port.databricks_workspace_public_network_access_disabled` |
| `prowler.azure.databricks_workspace_vnet_injection_enabled` | ported | `azure.claude.databricks_vnet_injection_value` |
| `prowler.azure.defender_additional_email_configured_with_a_security_contact` | ported | `azure.claude.defender_contact_has_email` |
| `prowler.azure.defender_assessments_vm_endpoint_protection_installed` | ported | `azure.claude.defender_assessment_endpoint_protection` |
| `prowler.azure.defender_attack_path_notifications_properly_configured` | ported | `azure.claude.defender_attack_path_notifications` |
| `prowler.azure.defender_auto_provisioning_vulnerabilty_assessments_machines_on` | ported | `azure.claude.defender_assessment_vulnerability_solution` |
| `prowler.azure.defender_container_images_resolved_vulnerabilities` | ported | `azure.claude.defender_assessment_running_images_vulnerabilities` |
| `prowler.azure.defender_container_images_scan_enabled` | ported | `azure.claude.defender_container_registry_vulnerability_scanning` |
| `prowler.azure.defender_ensure_defender_for_databases_is_on` | ported | `azure.claude.defender_database_plans_standard` |
| `prowler.azure.defender_ensure_defender_for_dns_is_on` | ported | `azure.claude.defender_dns_plan_standard` |
| `prowler.azure.defender_ensure_iot_hub_defender_is_on` | ported | `azure.claude.defender_iot_security_solution_enabled` |
| `prowler.azure.defender_ensure_system_updates_are_applied` | ported | `azure.claude.defender_assessment_system_updates` |
| `prowler.azure.entra_app_registration_credential_not_expired` | ported | `azure.claude.entra_app_credential_not_expiring` |
| `prowler.azure.entra_authentication_methods_policy_strong_auth_enforced` | ported | `azure.claude.entra_auth_methods_strong_registration` |
| `prowler.azure.entra_conditional_access_policy_require_mfa_for_admin_portals` | ported | `azure.claude.entra_ca_mfa_admin_portals` |
| `prowler.azure.entra_conditional_access_policy_require_mfa_for_management_api` | ported | `azure.claude.entra_ca_mfa_management_api` |
| `prowler.azure.entra_global_admin_in_less_than_five_users` | ported | `azure.claude.entra_global_admin_fewer_than_five` |
| `prowler.azure.entra_non_privileged_user_has_mfa` | ported | `azure.claude.entra_non_privileged_user_mfa` |
| `prowler.azure.entra_policy_default_users_cannot_create_security_groups` | ported | `azure.claude.entra_users_cannot_create_security_groups` |
| `prowler.azure.entra_policy_ensure_default_user_cannot_create_apps` | ported | `azure.claude.entra_users_cannot_create_apps` |
| `prowler.azure.entra_policy_ensure_default_user_cannot_create_tenants` | ported | `azure.claude.entra_users_cannot_create_tenants` |
| `prowler.azure.entra_policy_guest_invite_only_for_admin_roles` | ported | `azure.claude.entra_guest_invites_admins_only` |
| `prowler.azure.entra_policy_guest_users_access_restrictions` | ported | `azure.claude.entra_guest_access_restricted` |
| `prowler.azure.entra_policy_restricts_user_consent_for_apps` | ported | `azure.claude.entra_user_consent_disabled` |
| `prowler.azure.entra_policy_user_consent_for_verified_apps` | ported | `azure.claude.entra_user_consent_not_legacy` |
| `prowler.azure.entra_privileged_user_has_mfa` | ported | `azure.claude.entra_privileged_user_mfa` |
| `prowler.azure.entra_security_defaults_enabled` | ported | `azure.claude.entra_security_defaults_enabled` |
| `prowler.azure.entra_trusted_named_locations_exists` | ported | `azure.claude.entra_trusted_named_location_exists` |
| `prowler.azure.entra_user_with_recent_sign_in` | ported | `azure.claude.entra_user_recent_sign_in` |
| `prowler.azure.entra_user_with_vm_access_has_mfa` | ported | `azure.claude.entra_vm_access_user_mfa` |
| `prowler.azure.entra_users_cannot_create_microsoft_365_groups` | ported | `azure.claude.entra_m365_group_creation_restricted` |
| `prowler.azure.iam_custom_role_has_permissions_to_administer_resource_locks` | ported | `azure.claude.iam_custom_role_administers_locks` |
| `prowler.azure.iam_role_user_access_admin_restricted` | ported | `azure.claude.iam_no_user_access_administrator_assignment` |
| `prowler.azure.iam_subscription_roles_owner_custom_not_created` | ported | `azure.claude.iam_custom_role_no_wildcard_actions` |
| `prowler.azure.keyvault_access_only_through_private_endpoints` | ported | `azure.claude.keyvault_private_endpoint_only_access` |
| `prowler.azure.keyvault_key_expiration_set_in_non_rbac` | ported | `azure.claude.keyvault_non_rbac_key_expiration_set` |
| `prowler.azure.keyvault_key_rotation_enabled` | ported | `azure.claude.keyvault_key_rotation_policy` |
| `prowler.azure.keyvault_logging_enabled` | ported | `azure.claude.keyvault_audit_logging` |
| `prowler.azure.keyvault_non_rbac_secret_expiration_set` | ported | `azure.claude.keyvault_non_rbac_secret_expiration_set` |
| `prowler.azure.keyvault_private_endpoints` | ported | `azure.claude.keyvault_private_endpoint_exists` |
| `prowler.azure.keyvault_rbac_key_expiration_set` | ported | `azure.claude.keyvault_rbac_key_expiration_set` |
| `prowler.azure.keyvault_rbac_secret_expiration_set` | ported | `azure.claude.keyvault_rbac_secret_expiration_set` |
| `prowler.azure.keyvault_recoverable` | merged | `azure.port.keyvault_vault_recoverable` |
| `prowler.azure.monitor_alert_create_policy_assignment` | ported | `azure.claude.activity_log_alert_policy_assignment_write` |
| `prowler.azure.monitor_alert_create_update_nsg` | ported | `azure.claude.activity_log_alert_nsg_write` |
| `prowler.azure.monitor_alert_create_update_public_ip_address_rule` | ported | `azure.claude.activity_log_alert_public_ip_write` |
| `prowler.azure.monitor_alert_create_update_security_solution` | ported | `azure.claude.activity_log_alert_security_solution_write` |
| `prowler.azure.monitor_alert_create_update_sqlserver_fr` | ported | `azure.claude.activity_log_alert_sql_firewall_rule_write` |
| `prowler.azure.monitor_alert_delete_nsg` | ported | `azure.claude.activity_log_alert_nsg_delete` |
| `prowler.azure.monitor_alert_delete_policy_assignment` | ported | `azure.claude.activity_log_alert_policy_assignment_delete` |
| `prowler.azure.monitor_alert_delete_public_ip_address_rule` | ported | `azure.claude.activity_log_alert_public_ip_delete` |
| `prowler.azure.monitor_alert_delete_security_solution` | ported | `azure.claude.activity_log_alert_security_solution_delete` |
| `prowler.azure.monitor_alert_delete_sqlserver_fr` | ported | `azure.claude.activity_log_alert_sql_firewall_rule_delete` |
| `prowler.azure.monitor_alert_service_health_exists` | ported | `azure.claude.activity_log_alert_service_health` |
| `prowler.azure.monitor_diagnostic_setting_with_appropriate_categories` | ported | `azure.claude.subscription_diagnostic_setting_any_categories` |
| `prowler.azure.monitor_diagnostic_settings_exists` | ported | `azure.claude.subscription_diagnostic_setting_exists` |
| `prowler.azure.monitor_storage_account_with_activity_logs_cmk_encrypted` | ported | `azure.claude.activity_log_storage_cmk` |
| `prowler.azure.monitor_storage_account_with_activity_logs_is_private` | ported | `azure.claude.activity_log_storage_private` |
| `prowler.azure.mysql_flexible_server_audit_log_connection_activated` | ported | `azure.claude.mysql_flexible_audit_log_connection` |
| `prowler.azure.mysql_flexible_server_audit_log_enabled` | ported | `azure.claude.mysql_flexible_audit_log_enabled` |
| `prowler.azure.mysql_flexible_server_geo_redundant_backup_enabled` | ported | `azure.claude.mysql_flexible_geo_redundant_backup` |
| `prowler.azure.mysql_flexible_server_high_availability_enabled` | ported | `azure.claude.mysql_flexible_high_availability` |
| `prowler.azure.mysql_flexible_server_minimum_tls_version_12` | ported | `azure.claude.mysql_flexible_min_tls_12` |
| `prowler.azure.mysql_flexible_server_ssl_connection_enabled` | ported | `azure.claude.mysql_flexible_secure_transport` |
| `prowler.azure.network_bastion_host_exists` | ported | `azure.claude.bastion_host_exists` |
| `prowler.azure.network_flow_log_captured_sent` | ported | `azure.claude.network_watcher_flow_logs_traffic_analytics` |
| `prowler.azure.network_flow_log_more_than_90_days` | ported | `azure.claude.network_watcher_flow_logs_retention_90` |
| `prowler.azure.network_http_internet_access_restricted` | ported | `azure.claude.nsg_internet_http` |
| `prowler.azure.network_rdp_internet_access_restricted` | ported | `azure.claude.nsg_internet_rdp` |
| `prowler.azure.network_ssh_internet_access_restricted` | ported | `azure.claude.nsg_internet_ssh` |
| `prowler.azure.network_subnet_nsg_associated` | ported | `azure.claude.subnet_nsg_associated` |
| `prowler.azure.network_udp_internet_access_restricted` | ported | `azure.claude.nsg_internet_udp_any` |
| `prowler.azure.network_watcher_enabled` | ported | `azure.claude.network_watcher_in_vnet_region` |
| `prowler.azure.policy_ensure_asc_enforcement_enabled` | ported | `azure.claude.defender_default_policy_enforced` |
| `prowler.azure.postgresql_flexible_server_allow_access_services_disabled` | ported | `azure.claude.postgresql_flexible_no_azure_services_rule` |
| `prowler.azure.postgresql_flexible_server_connection_throttling_on` | ported | `azure.claude.postgresql_flexible_connection_throttling` |
| `prowler.azure.postgresql_flexible_server_enforce_ssl_enabled` | ported | `azure.claude.postgresql_flexible_secure_transport` |
| `prowler.azure.postgresql_flexible_server_entra_id_authentication_enabled` | ported | `azure.claude.postgresql_flexible_entra_authentication` |
| `prowler.azure.postgresql_flexible_server_geo_redundant_backup_enabled` | ported | `azure.claude.postgresql_flexible_geo_redundant_backup` |
| `prowler.azure.postgresql_flexible_server_high_availability_enabled` | ported | `azure.claude.postgresql_flexible_high_availability` |
| `prowler.azure.postgresql_flexible_server_log_checkpoints_on` | ported | `azure.claude.postgresql_flexible_log_checkpoints` |
| `prowler.azure.postgresql_flexible_server_log_connections_on` | ported | `azure.claude.postgresql_flexible_log_connections` |
| `prowler.azure.postgresql_flexible_server_log_disconnections_on` | ported | `azure.claude.postgresql_flexible_log_disconnections` |
| `prowler.azure.postgresql_flexible_server_log_retention_days_greater_3` | ported | `azure.claude.postgresql_flexible_log_retention_over_3_days` |
| `prowler.azure.recovery_vault_backup_policy_retention_adequate` | ported | `azure.claude.recovery_vault_backup_retention_30_days` |
| `prowler.azure.recovery_vault_has_protected_items` | ported | `azure.claude.recovery_vault_has_protected_items` |
| `prowler.azure.sqlserver_auditing_enabled` | merged | `azure.sql.auditing` |
| `prowler.azure.sqlserver_auditing_retention_90_days` | ported | `azure.claude.sql_audit_retention_over_90` |
| `prowler.azure.sqlserver_azuread_administrator_enabled` | ported | `azure.claude.sql_server_entra_admin` |
| `prowler.azure.sqlserver_microsoft_defender_enabled` | merged | `azure.sql.threat_detection` |
| `prowler.azure.sqlserver_recommended_minimal_tls_version` | ported | `azure.claude.sql_server_minimal_tls_12` |
| `prowler.azure.sqlserver_tde_encrypted_with_cmk` | ported | `azure.claude.sql_tde_protector_cmk`, `azure.sql.tde_enabled` |
| `prowler.azure.sqlserver_unrestricted_inbound_access` | ported | `azure.claude.sql_firewall_no_full_range` |
| `prowler.azure.sqlserver_va_emails_notifications_admins_enabled` | ported | `azure.claude.sql_va_notify_admins` |
| `prowler.azure.sqlserver_va_periodic_recurring_scans_enabled` | ported | `azure.claude.sql_va_recurring_scans` |
| `prowler.azure.sqlserver_va_scan_reports_configured` | ported | `azure.claude.sql_va_reports_configured` |
| `prowler.azure.sqlserver_vulnerability_assessment_enabled` | ported | `azure.claude.sql_server_vulnerability_assessment_enabled` |
| `prowler.azure.storage_blob_public_access_level_is_disabled` | merged | `azure.storage.no_blob_public_access` |
| `prowler.azure.storage_ensure_azure_services_are_trusted_to_access_is_enabled` | ported | `azure.claude.storage_trusted_azure_services_bypass` |
| `prowler.azure.storage_ensure_encryption_with_customer_managed_keys` | ported | `azure.claude.storage_account_cmk` |
| `prowler.azure.storage_ensure_file_shares_soft_delete_is_enabled` | ported | `azure.claude.storage_file_share_soft_delete_enabled` |
| `prowler.azure.storage_ensure_private_endpoints_in_storage_accounts` | ported | `azure.claude.storage_private_endpoint_present` |
| `prowler.azure.storage_geo_redundant_enabled` | ported | `azure.claude.storage_account_geo_redundant` |
| `prowler.azure.storage_key_rotation_90_days` | ported | `azure.claude.storage_key_expiration_policy_max_90` |
| `prowler.azure.storage_smb_channel_encryption_with_secure_algorithm` | ported | `azure.claude.storage_smb_channel_encryption_aes_256_gcm` |
| `prowler.azure.storage_smb_protocol_version_is_latest` | ported | `azure.claude.storage_smb_version_3_1_1` |
| `prowler.azure.vm_backup_enabled` | ported | `azure.claude.vm_backup_protected` |
| `prowler.azure.vm_ensure_attached_disks_encrypted_with_cmk` | ported | `azure.claude.disk_attached_cmk` |
| `prowler.azure.vm_ensure_unattached_disks_encrypted_with_cmk` | merged | `azure.claude.disk_unattached_cmk` |
| `prowler.azure.vm_ensure_using_managed_disks` | merged | `azure.vm.managed_disks` |
| `prowler.azure.vm_jit_access_enabled` | merged | `azure.claude.vm_jit_access` |
| `prowler.azure.vm_scaleset_associated_with_load_balancer` | ported | `azure.claude.vmss_load_balancer_backend` |
| `prowler.azure.vm_scaleset_not_empty` | ported | `azure.claude.vmss_not_empty` |
| `prowler.azure.vm_sufficient_daily_backup_retention_period` | ported | `azure.claude.vm_backup_daily_retention_7_days` |

## COLLECTOR FACTS NEEDED

All APIs below are read-only (GET/list). Until a fact is collected the dependent predicate returns UNKNOWN (never FAIL).

Engine note: child collections (diagnostic_setting, subnet, sql_*, secret_metadata, ...) are scoped by parent resource id and are not visible to a subscription-scoped evaluation. Predicates that need per-resource diagnostic settings read an embedded `diagnosticSettings` list on the parent item (Microsoft.Insights/diagnosticSettings list, api-version 2021-05-01-preview). Subscription role-assignment checks that join tenant directory objects need the tenant directory collections exposed to the subscription index.

### Compute group


All calls are read-only GETs on ARM (`https://management.azure.com`). Items keep the ARM-native shape. A list call collects the `value[]` array. Until a fact is collected, the predicates that need it return UNKNOWN.

#### New subscription-scoped kinds (collection scope = subscription, so resource checks can see them)
| kind | API (GET) | api-version | fields read |
|---|---|---|---|
| `vm_scale_set` | `/subscriptions/{s}/providers/Microsoft.Compute/virtualMachineScaleSets` | 2024-07-01 | `sku.capacity`, `properties.upgradePolicy.mode`, `properties.virtualMachineProfile.{diagnosticsProfile.bootDiagnostics.enabled, osProfile.linuxConfiguration.disablePasswordAuthentication, storageProfile.osDisk.{osType,managedDisk,vhdContainers}, storageProfile.dataDisks[].managedDisk, networkProfile.networkInterfaceConfigurations[].properties.ipConfigurations[].properties.{subnet,loadBalancerBackendAddressPools[].id}}` |
| `container_group` | list `/subscriptions/{s}/providers/Microsoft.ContainerInstance/containerGroups`, then **GET each** `{id}` (the list may omit encryptionProperties/subnetIds) | 2023-05-01 | `identity.type`, `properties.encryptionProperties.{vaultBaseUrl,keyName}`, `properties.subnetIds[].id`, `properties.containers[].properties.environmentVariables[].{name,value,secureValue}`. Never persist `value` contents; replacing them with a redaction marker keeps the predicate working, because it only tests `value is not None`. |
| `disk_access` | `/subscriptions/{s}/providers/Microsoft.Compute/diskAccesses` | 2023-10-02 | `properties.privateEndpointConnections[].properties.privateLinkServiceConnectionState.status` |
| `databox_edge_device` | `/subscriptions/{s}/providers/Microsoft.DataBoxEdge/dataBoxEdgeDevices` | 2023-07-01 | `sku.name` |
| `jit_network_access_policy` | `/subscriptions/{s}/providers/Microsoft.Security/jitNetworkAccessPolicies` | 2020-01-01 | `name`, `properties.virtualMachines[].id` |
| `resource_link` | `/subscriptions/{s}/providers/Microsoft.Resources/links` | 2016-09-01 | `name` (ASR-Protect-*), `properties.sourceId`, `properties.targetId` |
| `backup_protected_item` | for each vault in `/subscriptions/{s}/providers/Microsoft.RecoveryServices/vaults` (2023-04-01): `{vaultId}/backupProtectedItems?$filter=backupManagementType eq 'AzureIaasVM'` | 2023-04-01 | `name`, `properties.workloadType` ("VM"), `properties.sourceResourceId`, `properties.policyId`, `properties.protectionState`. These must be emitted as a **subscription-scoped** collection: complete only when every vault was read. |
| `backup_policy` | `{vaultId}/backupPolicies?$filter=backupManagementType eq 'AzureIaasVM'` | 2023-04-01 | `id`, `properties.retentionPolicy.dailySchedule.retentionDuration.{count,durationType}`. Subscription-scoped, complete only when every vault was read. |

#### Embedded facts on existing kinds
| kind | embed key | API (GET) | api-version | fields read |
|---|---|---|---|---|
| `vm` | `resources` (always embed; `[]` when none) | `{vmId}/extensions` | 2023-09-01 | `name`, `properties.{publisher,type,provisioningState,autoUpgradeMinorVersion}` (settings are not read, so do not embed them) |
| `vm` | `guestConfigurationAssignments` (always embed; `[]` when none) | `{vmId}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments` | 2024-04-05 | `name`, `properties.complianceStatus`, `properties.guestConfiguration.{name,configurationParameter[].{name,value}}` |
| `vm` | `identity` (top-level; already in the VM GET) | — | — | `identity.type` |
| `container_registry` | `replications` (Premium only) | `{registryId}/replications` | 2023-07-01 | `location` |
| `container_registry` | `properties.networkRuleSet.virtualNetworkRules` | the registry GET with a preview api-version that still returns virtualNetworkRules (e.g. 2023-11-01-preview) | — | `id` |
| `databricks_workspace` | `diagnosticSettings` | `{workspaceId}/providers/Microsoft.Insights/diagnosticSettings` | 2021-05-01-preview | `properties.logs[].{category,categoryGroup,enabled}` |

#### Existing kinds and fields used as-is (already collected)
- `vm`: `id`, `properties.storageProfile.{osDisk.{osType,managedDisk,vhd,diffDiskSettings},imageReference.offer}`, `properties.securityProfile.{securityType,uefiSettings.secureBootEnabled}`, `properties.osProfile.windowsConfiguration.enableAutomaticUpdates`, `properties.networkProfile.networkInterfaces[].id`.
- `disk`: `properties.diskState`, `properties.encryption.type`.
- `nic`: `id`, `properties.networkSecurityGroup.id`, `properties.ipConfigurations[].properties.{privateIPAddress,subnet.id,publicIPAddress.id}`.
- `nsg`: `id`, `properties.securityRules`, `properties.subnets[].id`.
- `vnet`: `id`, `properties.subnets[].{name,properties.{addressPrefix,networkSecurityGroup.id}}`.
- `container_registry` 2023-07-01: `sku.name`, `properties.{adminUserEnabled,publicNetworkAccess,encryption.status,networkRuleSet.defaultAction,policies.{quarantinePolicy,retentionPolicy,trustPolicy}.status,privateEndpointConnections,loginServer}`.
- `cosmos_account` 2024-05-15: `properties.{publicNetworkAccess,enableAutomaticFailover,backupPolicy.type,isVirtualNetworkFilterEnabled,ipRules,virtualNetworkRules,disableKeyBasedMetadataWriteAccess,disableLocalAuth,minimalTlsVersion,keyVaultKeyUri,cors,privateEndpointConnections,databaseAccountOfferType}`.
- `databricks_workspace` 2024-05-01: `sku.name`, `properties.{managedResourceGroupId,encryption.entities.managedDisk.keyVaultProperties,parameters.{customVirtualNetworkId,customPrivateSubnetName,customPublicSubnetName}.value}`.

#### Dependencies declared on predicates (for collection planning)
- `vm_no_public_ip`: vm, nic.
- `vm_nic_nsg_internet_tcp_ingress` and `vm_nsg_internet_management_ports`: vm, nic, nsg.
- `vm_jit_access`: vm, jit_network_access_policy.
- `vm_site_recovery_enabled`: vm, resource_link.
- `vm_backup_protected`: vm, backup_protected_item.
- `vm_backup_daily_retention_7_days`: vm, backup_protected_item, backup_policy.
- `databricks_subnet_nsg`: databricks_workspace, vnet.

### Identity group


All of these are read-only GET/list calls. None of them reads a secret, key or certificate value. Until each fact below is collected, the predicates that depend on it evaluate to UNKNOWN.

#### New ARM resource kinds (subscription scope, add to `ENDPOINTS`)
| kind | resource type, api-version | fields read |
|---|---|---|
| `eventgrid_domain` | Microsoft.EventGrid/domains, 2022-06-15 | identity.type, properties.publicNetworkAccess, properties.privateEndpointConnections[].properties.privateLinkServiceConnectionState.status |
| `eventgrid_topic` | Microsoft.EventGrid/topics, 2022-06-15 | same as eventgrid_domain |
| `eventhub_namespace` | Microsoft.EventHub/namespaces, 2024-01-01 | sku.tier, properties.encryption.keySource, properties.privateEndpointConnections[...].status |
| `frontdoor` | Microsoft.Network/frontDoors, 2021-06-01 (Front Door classic) | properties.frontendEndpoints[].properties.webApplicationFirewallPolicyLink.id |
| `hdinsight_cluster` | Microsoft.HDInsight/clusters, 2021-06-01 | properties.provisioningState, properties.diskEncryptionProperties.{keyName,encryptionAtHost}, properties.encryptionInTransitProperties.isEncryptionInTransitEnabled |
| `healthcare_fhir_service` | Microsoft.HealthcareApis/services, 2021-11-11 (Azure API for FHIR) | properties.cosmosDbConfiguration.keyVaultKeyUri, properties.privateEndpointConnections |
| `hpc_cache` | Microsoft.StorageCache/caches, 2024-03-01 | properties.encryptionSettings.keyEncryptionKey.{keyUrl,sourceVault.id} |
| `iot_hub` | Microsoft.Devices/IotHubs, 2023-06-30 | sku.tier, properties.privateEndpointConnections |
| `managed_hsm` | Microsoft.KeyVault/managedHSMs, 2023-07-01 | properties.enablePurgeProtection |

#### New child kinds
- **`key_vault_key`**: the child of `vault`. Call `GET {vaultId}/keys?api-version=2023-07-01` and read `properties.attributes.{enabled,exp}` and `properties.rotationPolicy.lifetimeActions[].{trigger.timeAfterCreate,trigger.timeBeforeExpiry,action.type}`.
  - If the ARM list does not return `rotationPolicy`, fall back to the data plane: `GET {vaultUri}/keys/{name}/rotationpolicy?api-version=7.4`. This needs the `keys/getrotationpolicy` permission or Key Vault Reader. It reads metadata only.
  - Embed the parent vault flag as `vaultProperties.enableRbacAuthorization` (bool).
- **`secret_metadata`** (already collected): embed `vaultProperties.enableRbacAuthorization` from the parent vault. The engine cannot join a child kind scoped by vault rid to the vault.
- **`key_vault_certificate_policy`**: data plane. List with `GET {vaultUri}/certificates?api-version=7.4`, then call `GET {vaultUri}/certificates/{name}/policy?api-version=7.4` for each certificate. Read `x509_props.validity_months`.
  - Needs RBAC Key Vault Reader or Certificate User, or the access policy certificates list/get.
  - It does not read the private key or secret.

#### Embedded facts on existing or new kinds
- **`diagnosticSettings`** is the list result of `GET {resourceId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`. Embed it as the top-level `diagnosticSettings` on:
  - `vault`
  - `managed_hsm`
  - `eventhub_namespace`
  - `iot_hub`

  Fields read are `properties.logs[].{category,categoryGroup,enabled,retentionPolicy.{enabled,days}}` and `properties.storageAccountId`.
- **`networkRuleSet`** on `eventhub_namespace`: `GET {namespaceId}/networkRuleSets/default?api-version=2024-01-01`. Read `properties.virtualNetworkRules[].subnet.id`.

#### Entra ID / Microsoft Graph v1.0 (tenant scope `/tenants/<id>`)
| kind | endpoint | permission | fields |
|---|---|---|---|
| `conditional_access_policy` | GET /identity/conditionalAccess/policies | Policy.Read.All | id, state, conditions.users.includeUsers, conditions.applications.includeApplications, grantControls.builtInControls |
| `named_location` | GET /identity/conditionalAccess/namedLocations | Policy.Read.All | @odata.type, id, isTrusted, ipRanges |
| `user_registration_detail` | GET /reports/authenticationMethods/userRegistrationDetails | AuditLog.Read.All (plus a Reports Reader/Security Reader role) | id, isMfaCapable |
| `authentication_methods_policy` (singleton) | GET /policies/authenticationMethodsPolicy | Policy.Read.All | registrationEnforcement.authenticationMethodsRegistrationCampaign.state, authenticationMethodConfigurations[].{@odata.type,id,state} |
| `directory_setting` | GET /groupSettings | Directory.Read.All | displayName, values[].{name,value} |

Changes to existing directory `$select` lists:
- **`directory_user`**: add `signInActivity`. This needs AuditLog.Read.All and Entra ID P1. Read `signInActivity.lastSignInDateTime`.
- **`directory_application`**: add `passwordCredentials` and `keyCredentials`. Read `endDateTime` and `keyId` only; Graph never returns secret values here.
- `directory_authorization_policy` and `directory_security_defaults`: already collected. Fields read:
  - authorization policy: `defaultUserRolePermissions.{allowedToCreateApps,allowedToCreateSecurityGroups,allowedToCreateTenants,permissionGrantPoliciesAssigned}`, `allowInvitesFrom`, `guestUserRoleId`
  - security defaults: `isEnabled`
- `directory_role_assignment`: already collected. Fields read: `principalId`, `roleDefinitionId` (template id) and `directoryScopeId`.
- `tenant` (ARM /tenants, already collected): reads `tenantId`. Tenant aggregates are anchored on this item and use `index.context.scope`.

#### Tenant-level ARM singleton
- **`subscription_tenant_policy`**: `GET https://management.azure.com/providers/Microsoft.Subscription/policies/default?api-version=2021-10-01`. Read `properties.blockSubscriptionsIntoTenant` and `properties.blockSubscriptionsLeavingTenant`. Collect it at tenant scope.

#### Engine fact (not a collector call)
The subscription-scope checks below join subscription `role_assignment` to the tenant `directory_user`:
- `iam_external_user_no_owner`
- `iam_external_user_no_reader`
- `iam_external_user_no_write`
- `iam_disabled_user_no_role_assignment`
- `iam_disabled_user_no_owner`

`entra_vm_access_user_mfa` similarly joins subscription `role_assignment` to the tenant `user_registration_detail`.

These checks need the scoped index for a subscription to also expose the collections of the authenticated tenant's directory: the `/tenants/<id>` envelopes for those kinds. Until then the engine reports them as UNKNOWN with "required scoped inventory incomplete" (scope checks), or the join raises UNKNOWN (resource check).

### Network group


All of these are read-only ARM GETs. Until a fact is collected, the predicates that need it return UNKNOWN.

| Kind | Read-only API (ARM path, api-version) | Fields read |
|---|---|---|
| `nsg` (existing) | `Microsoft.Network/networkSecurityGroups` 2023-09-01 | `properties.securityRules[].properties.{priority,direction,access,protocol,sourceAddressPrefix(es),destinationPortRange(s),destinationAddressPrefix(es),destinationApplicationSecurityGroups}`, `properties.defaultSecurityRules[]` (same shape; ARM returns them by default, so keep them), `properties.subnets[].id`; **embed** `diagnosticSettings` = `GET {nsgId}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview` |
| `subnet` (existing child of vnet) | embedded `vnet.properties.subnets` | `name`, `properties.networkSecurityGroup.id` |
| `nic` (existing) | `Microsoft.Network/networkInterfaces` | `properties.ipConfigurations[].properties.publicIPAddress.id` |
| `vnet` (existing) | `Microsoft.Network/virtualNetworks` | `location`, `properties.virtualNetworkPeerings[].properties.peeringState` |
| `network_watcher` | `GET /subscriptions/{id}/providers/Microsoft.Network/networkWatchers?api-version=2023-09-01` (subscription scope, same scope as vnet) | `id`, `location`; **embed** `flowLogs` = `GET {watcherId}/flowLogs?api-version=2023-09-01` |
| `flow_log` | child of network_watcher: `GET {watcherId}/flowLogs?api-version=2023-09-01` | `properties.enabled`, `properties.targetResourceId`, `properties.retentionPolicy.{days,enabled}`, `properties.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration.{enabled,workspaceId,trafficAnalyticsInterval}` |
| `bastion_host` | `GET /subscriptions/{id}/providers/Microsoft.Network/bastionHosts?api-version=2023-09-01` | count, `id`, `name` |
| `virtual_network_gateway` | `GET /subscriptions/{id}/resourceGroups/{rg}/providers/Microsoft.Network/virtualNetworkGateways?api-version=2023-09-01` (per resource group; there is no subscription-level list) | `properties.gatewayType`, `properties.sku.name`, `properties.vpnClientConfiguration.vpnAuthenticationTypes` |
| `activity_log_alert` | `GET /subscriptions/{id}/providers/Microsoft.Insights/activityLogAlerts?api-version=2020-10-01` (scope = subscription) | `id`, `location`, `properties.enabled`, `properties.scopes[]`, `properties.condition.allOf[].{field,equals}` |
| `subscription_diagnostic_setting` | `GET /subscriptions/{id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview` (scope = subscription) | `name`, `properties.logs[].{category,categoryGroup,enabled}`, `properties.storageAccountId` |
| `storage_account` (existing) | — | `id`, `properties.encryption.keySource`, `properties.allowBlobPublicAccess`; **embed** `blobContainers` = `GET {accountId}/blobServices/default/containers?api-version=2023-05-01` → `[].{name,properties.publicAccess}` (container metadata only, no blob reads) |
| `log_analytics_workspace` | `GET /subscriptions/{id}/providers/Microsoft.OperationalInsights/workspaces?api-version=2023-09-01` | `properties.publicNetworkAccessForIngestion`, `properties.publicNetworkAccessForQuery`, `properties.features.disableLocalAuth` (do NOT call sharedKeys) |
| `logic_app_workflow` | `GET /subscriptions/{id}/providers/Microsoft.Logic/workflows?api-version=2019-05-01` | **embed** `diagnosticSettings` (as for nsg) |
| `ml_workspace` | `GET /subscriptions/{id}/providers/Microsoft.MachineLearningServices/workspaces?api-version=2024-04-01` | `properties.encryption.status` |
| `mssql_managed_instance` | `GET /subscriptions/{id}/providers/Microsoft.Sql/managedInstances?api-version=2023-08-01` | **embed** `encryptionProtectors` = `GET {miId}/encryptionProtector?api-version=2023-08-01` → `[].properties.{serverKeyType,uri}`; **embed** `vulnerabilityAssessments` = `GET {miId}/vulnerabilityAssessments?api-version=2023-08-01` → `[].{name,properties.recurringScans.isEnabled}` (storage SAS/keys are not read) |
| `mysql_flexible_server` | `GET /subscriptions/{id}/providers/Microsoft.DBforMySQL/flexibleServers?api-version=2023-12-30` | `sku.tier`, `properties.backup.geoRedundantBackup`, `properties.highAvailability.mode`; **embed** `configurations` = `GET {serverId}/configurations?api-version=2023-12-30` → `[].{name,properties.value}` (audit_log_enabled, audit_log_events, tls_version, require_secure_transport) |
| `postgresql_flexible_server` | `GET /subscriptions/{id}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2024-08-01` | `sku.tier`, `properties.backup.geoRedundantBackup`, `properties.highAvailability.mode`, `properties.network.publicNetworkAccess`, `properties.authConfig.activeDirectoryAuth`; **embed** `configurations` (`{serverId}/configurations`), `firewallRules` (`{serverId}/firewallRules` → `[].properties.{startIpAddress,endIpAddress}`), `administrators` (`{serverId}/administrators`), all at api-version 2024-08-01 |
| `recovery_vault` | `GET /subscriptions/{id}/providers/Microsoft.RecoveryServices/vaults?api-version=2024-04-01` | `identity.type`, `properties.privateEndpointStateForBackup`, `properties.privateEndpointStateForSiteRecovery`; **embed** `backupPolicies` = `GET {vaultId}/backupPolicies?api-version=2024-04-01` → `[].properties.retentionPolicy.dailySchedule.retentionDuration.count`; **embed** `backupProtectedItems` = `GET {vaultId}/backupProtectedItems?api-version=2024-04-01` |
| `policy_assignment` | `GET /subscriptions/{id}/providers/Microsoft.Authorization/policyAssignments?api-version=2023-04-01` (scope = subscription) | `name`, `properties.enforcementMode` |

Every embedded list must be a list. If the child call is denied, leave the key absent so the check reads UNKNOWN; never write `[]` in that case. Subscription-scope kinds need collection envelopes at scope `/subscriptions/<id>` with status collected/empty, so that `complete_items` can prove the inventory is complete.

### Data group


The collector (Codex-owned) does not gather the facts below yet. Until it does, the checks that read them return UNKNOWN. All facts come from read-only GET or List calls. Keep the ARM response shape unchanged. Child lists are embedded on the parent item, so an embedded list that is missing stays UNKNOWN, and an empty list `[]` is an explicit empty result.

#### New top-level kinds (subscription-scoped lists)
| kind | ARM list path | api-version | fields read |
|---|---|---|---|
| security_assessment | /subscriptions/{s}/providers/Microsoft.Security/assessments | 2020-01-01 | properties.displayName, properties.status.code (Healthy/Unhealthy/NotApplicable) |
| iot_security_solution | /subscriptions/{s}/providers/Microsoft.Security/iotSecuritySolutions | 2019-08-01 | properties.status (Enabled/Disabled) |
| policy_assignment | /subscriptions/{s}/providers/Microsoft.Authorization/policyAssignments | 2022-06-01 | name, properties.parameters.{k}.value |
| servicebus_namespace | /subscriptions/{s}/providers/Microsoft.ServiceBus/namespaces | 2022-10-01-preview | sku.tier, properties.status, disableLocalAuth, privateEndpointConnections[].properties.privateLinkServiceConnectionState.status, encryption.keySource (omitted when platform-managed) |
| service_fabric_cluster | /subscriptions/{s}/providers/Microsoft.ServiceFabric/clusters | 2021-06-01 | properties.azureActiveDirectory, properties.fabricSettings[].parameters[].value |
| signalr_service | /subscriptions/{s}/providers/Microsoft.SignalRService/signalR | 2023-02-01 | sku.tier, properties.privateEndpointConnections |
| spring_cloud_service | /subscriptions/{s}/providers/Microsoft.AppPlatform/Spring | 2023-12-01 | sku.tier, properties.networkProfile.serviceRuntimeSubnetId |
| storage_sync_service | /subscriptions/{s}/providers/Microsoft.StorageSync/storageSyncServices | 2022-06-01 | properties.incomingTrafficPolicy, properties.privateEndpointConnections |
| stream_analytics_job | /subscriptions/{s}/providers/Microsoft.StreamAnalytics/streamingjobs | 2020-03-01 | diagnosticSettings (embedded, see below) |
| synapse_workspace | /subscriptions/{s}/providers/Microsoft.Synapse/workspaces | 2021-06-01 | properties.managedVirtualNetworkSettings.preventDataExfiltration, properties.encryption.cmk.key.name, properties.privateEndpointConnections |
| web_application_firewall_policy | /subscriptions/{s}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies | 2023-09-01 | properties.managedRules.managedRuleSets[].{ruleSetType, ruleGroupOverrides[].rules[].state}, properties.policySettings.requestBodyCheck |

#### New child kinds (each item carries parent_id)
| kind | ARM path | api-version | fields |
|---|---|---|---|
| sql_database_ltr_policy | {database}/backupLongTermRetentionPolicies | 2023-08-01 | parent_id, properties.weeklyRetention/monthlyRetention/yearlyRetention |
| sql_vulnerability_assessment | {server}/vulnerabilityAssessments/default | 2023-08-01 | properties.storageContainerPath, properties.recurringScans.{isEnabled, emailSubscriptionAdmins, emails}; embed `expressVulnerabilityAssessment` = GET {server}/sqlVulnerabilityAssessments/default (2023-08-01-preview or later), properties.state |
| sql_encryption_protector | {server}/encryptionProtector/current | 2023-08-01 | properties.serverKeyType (AzureKeyVault/ServiceManaged) |
| storage_container | {account}/blobServices/default/containers | 2023-05-01 | properties.publicAccess (None/Blob/Container) |
| storage_encryption_scope | {account}/encryptionScopes | 2023-05-01 | properties.source |

#### Embedded facts on existing kinds
- **search_service, servicebus_namespace, stream_analytics_job → `diagnosticSettings`**: the list from {resource}/providers/Microsoft.Insights/diagnosticSettings (2021-05-01-preview), with properties.logs[].{category, categoryGroup, enabled}.
- **servicebus_namespace → `networkRuleSet`**: GET {ns}/networkRuleSets/default (2022-10-01-preview), with properties.{defaultAction, publicNetworkAccess, virtualNetworkRules[].subnet.id}.
- **sql_server → `serverAdministrators`**: {server}/administrators (2023-08-01), with properties.administratorType.
- **sql_server → `virtualNetworkRules`**: {server}/virtualNetworkRules (2023-08-01), with properties.virtualNetworkSubnetId.
- **sql_database → `vulnerabilityAssessmentScans`**: {db}/vulnerabilityAssessments/default/scans (2023-08-01), with properties.{endTime, numberOfFailedSecurityChecks}.
- **storage_account → `serviceAnalyticsLogging.{blob,queue,table}.{read,write,delete}`**: data-plane Get Service Properties, `?restype=service&comp=properties`, Logging element. This call requires the Storage Account Contributor / Reader-and-Data-Access role or OAuth data-plane read. Never read the account keys; if only key auth would work, leave the fact absent so the check stays UNKNOWN.
- **storage_account → `serviceDiagnosticSettings.{blob,queue,table}`**: diagnosticSettings on {account}/{blob|queue|table}Services/default (2021-05-01-preview).
- **storage_service (fileServices) → `shares`**: {account}/fileServices/default/shares (2023-05-01). Name only.
- **synapse_workspace → `sqlVulnerabilityAssessments`**: {ws}/sqlPools/{pool}/vulnerabilityAssessments, flattened across pools (2021-06-01), with properties.recurringScans.isEnabled.

#### Existing kinds and fields already relied on
- security_pricing: properties.{pricingTier, deprecated, replacedBy, extensions[].{name,isEnabled}}
- security_contact: properties.{emails, notificationsByRole.{state,roles}, notificationsSources[].{sourceType,minimalSeverity,minimalRiskLevel}}
- search_service: properties.replicaCount
- sql_firewall_rule, sql_audit (properties.state, retentionDays, storageEndpoint), sql_database (name)
- storage_account: properties.{keyCreationTime, keyPolicy, networkAcls.{bypass, defaultAction, virtualNetworkRules}, encryption.keySource, privateEndpointConnections}, sku, kind
- storage_service: type, properties.{deleteRetentionPolicy, containerDeleteRetentionPolicy, shareDeleteRetentionPolicy, protocolSettings.smb.{versions, channelEncryption}}
- vm: properties.storageProfile.osDisk.{managedDisk, vhd.uri}

