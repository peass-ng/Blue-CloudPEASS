/** Check-specific summaries of the reviewed native Azure evidence shapes.
 * Unknown/malformed facts return undefined for the uncertainty-aware fallback.
 * Full evidence remains independently available; this does not simulate access.
 */
export const REVIEWED_AZURE_EVIDENCE_CHECKS = [
  "azure.aks.api_server_restricted",
  "azure.aks.auto_upgrade",
  "azure.aks.azure_rbac",
  "azure.aks.defender_monitoring",
  "azure.aks.network_policy",
  "azure.aks.no_local_accounts",
  "azure.aks.private_cluster",
  "azure.aks.rbac",
  "azure.app.client_certificates",
  "azure.app.cors_no_wildcards",
  "azure.app.ftps_only",
  "azure.app.http2",
  "azure.app.https_only",
  "azure.app.minimum_tls",
  "azure.app.remote_debugging_off",
  "azure.app.request_logging",
  "azure.app.scm_minimum_tls",
  "azure.cis.agentless_scanning_machines_component_status",
  "azure.cis.app_service_entra_registration_enabled",
  "azure.cis.defender_external_attack_surface_monitoring_easm",
  "azure.cis.enforce_ssl_connection_mysql_server",
  "azure.cis.file_integrity_monitoring_component_status",
  "azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server",
  "azure.cis.legacy_vhds_encrypted",
  "azure.cis.mysql_flexible_cmk",
  "azure.cis.mysql_single_audit_log_enabled",
  "azure.cis.mysql_single_audit_log_events_connection",
  "azure.cis.postgresql_single_connection_throttling",
  "azure.cis.postgresql_single_log_checkpoints",
  "azure.cis.postgresql_single_log_connections",
  "azure.cis.postgresql_single_log_disconnections",
  "azure.cis.postgresql_single_log_retention_days",
  "azure.cis.postgresql_single_no_azure_services_rule",
  "azure.cis.postgresql_single_ssl_enforcement",
  "azure.cis.public_network_access_should_mariadb_servers",
  "azure.cis.public_network_access_should_mysql_servers",
  "azure.cis.public_network_access_should_postgresql_servers",
  "azure.cis.resource_manager_delete_locks_applied_storage_accounts",
  "azure.claude.acr_admin_user_disabled",
  "azure.claude.acr_cmk",
  "azure.claude.acr_geo_replication",
  "azure.claude.acr_network_default_deny",
  "azure.claude.acr_private_endpoint_present",
  "azure.claude.acr_private_link_approved",
  "azure.claude.acr_public_network_access_disabled",
  "azure.claude.acr_quarantine_policy",
  "azure.claude.acr_retention_policy",
  "azure.claude.acr_trust_policy",
  "azure.claude.acr_vnet_service_endpoint",
  "azure.claude.activity_log_alert_nsg_delete",
  "azure.claude.activity_log_alert_nsg_write",
  "azure.claude.activity_log_alert_policy_assignment_delete",
  "azure.claude.activity_log_alert_policy_assignment_write",
  "azure.claude.activity_log_alert_public_ip_delete",
  "azure.claude.activity_log_alert_public_ip_write",
  "azure.claude.activity_log_alert_security_solution_delete",
  "azure.claude.activity_log_alert_security_solution_write",
  "azure.claude.activity_log_alert_service_health",
  "azure.claude.activity_log_alert_sql_firewall_rule_delete",
  "azure.claude.activity_log_alert_sql_firewall_rule_write",
  "azure.claude.activity_log_alert_subscription_administrative_operations",
  "azure.claude.activity_log_alert_subscription_nsg_delete",
  "azure.claude.activity_log_alert_subscription_nsg_rule_delete",
  "azure.claude.activity_log_alert_subscription_nsg_rule_write",
  "azure.claude.activity_log_alert_subscription_nsg_write",
  "azure.claude.activity_log_alert_subscription_policy_assignment_delete",
  "azure.claude.activity_log_alert_subscription_policy_assignment_write",
  "azure.claude.activity_log_alert_subscription_public_ip_delete",
  "azure.claude.activity_log_alert_subscription_public_ip_write",
  "azure.claude.activity_log_alert_subscription_security_solution_delete",
  "azure.claude.activity_log_alert_subscription_security_solution_write",
  "azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete",
  "azure.claude.activity_log_alert_subscription_sql_firewall_rule_write",
  "azure.claude.activity_log_alert_subscription_sql_server",
  "azure.claude.activity_log_storage_cmk",
  "azure.claude.activity_log_storage_private",
  "azure.claude.aks_authorized_ip_ranges",
  "azure.claude.aks_azure_policy_addon",
  "azure.claude.aks_container_insights_logging",
  "azure.claude.aks_disk_encryption_set",
  "azure.claude.aks_encryption_at_host",
  "azure.claude.aks_http_application_routing_disabled",
  "azure.claude.aks_max_pods_at_least_50",
  "azure.claude.aks_network_plugin_azure",
  "azure.claude.aks_network_policy_configured",
  "azure.claude.aks_node_public_ip_disabled",
  "azure.claude.aks_paid_sku_tier",
  "azure.claude.aks_secret_store_rotation",
  "azure.claude.aks_version_not_cve_2019_9946",
  "azure.claude.bastion_host_exists",
  "azure.claude.container_group_cmk",
  "azure.claude.container_group_managed_identity",
  "azure.claude.container_group_secure_environment_variables",
  "azure.claude.container_group_virtual_network",
  "azure.claude.cosmos_automatic_failover",
  "azure.claude.cosmos_cmk",
  "azure.claude.cosmos_continuous_backup",
  "azure.claude.cosmos_cors_no_wildcard",
  "azure.claude.cosmos_key_based_metadata_write_disabled",
  "azure.claude.cosmos_local_auth_disabled",
  "azure.claude.cosmos_minimum_tls12",
  "azure.claude.cosmos_network_restricted",
  "azure.claude.cosmos_private_endpoint_present",
  "azure.claude.cosmos_public_network_access_disabled",
  "azure.claude.cosmos_public_network_access_restricted",
  "azure.claude.cosmos_virtual_network_filter",
  "azure.claude.cosmos_vnet_service_endpoint",
  "azure.claude.databox_edge_double_encryption",
  "azure.claude.databricks_diagnostic_log_delivery",
  "azure.claude.databricks_managed_disk_cmk",
  "azure.claude.databricks_subnet_nsg",
  "azure.claude.databricks_vnet_injection_value",
  "azure.claude.defender_alert_notifications_high",
  "azure.claude.defender_alerts_to_owner",
  "azure.claude.defender_assessment_endpoint_protection",
  "azure.claude.defender_assessment_running_images_vulnerabilities",
  "azure.claude.defender_assessment_system_updates",
  "azure.claude.defender_assessment_vulnerability_solution",
  "azure.claude.defender_attack_path_notifications",
  "azure.claude.defender_contact_has_email",
  "azure.claude.defender_container_registry_plan_standard",
  "azure.claude.defender_container_registry_vulnerability_scanning",
  "azure.claude.defender_database_plans_standard",
  "azure.claude.defender_default_initiative_no_disabled_effects",
  "azure.claude.defender_default_policy_enforced",
  "azure.claude.defender_dns_plan_standard",
  "azure.claude.defender_iot_security_solution_enabled",
  "azure.claude.defender_kubernetes_plan_standard",
  "azure.claude.defender_plan_standard_any",
  "azure.claude.defender_security_contact_email_configured",
  "azure.claude.disk_access_private_link",
  "azure.claude.disk_attached_cmk",
  "azure.claude.disk_attached_customer_key",
  "azure.claude.disk_attached_double_encryption",
  "azure.claude.disk_unattached_cmk",
  "azure.claude.disk_unattached_customer_key",
  "azure.claude.entra_app_credential_not_expiring",
  "azure.claude.entra_auth_methods_strong_registration",
  "azure.claude.entra_ca_mfa_admin_portals",
  "azure.claude.entra_ca_mfa_management_api",
  "azure.claude.entra_ca_policy_requires_mfa",
  "azure.claude.entra_global_admin_fewer_than_five",
  "azure.claude.entra_guest_access_restricted",
  "azure.claude.entra_guest_invites_admins_only",
  "azure.claude.entra_m365_group_creation_restricted",
  "azure.claude.entra_named_location_trusted",
  "azure.claude.entra_non_privileged_user_mfa",
  "azure.claude.entra_privileged_user_mfa",
  "azure.claude.entra_security_defaults_enabled",
  "azure.claude.entra_trusted_named_location_exists",
  "azure.claude.entra_user_consent_disabled",
  "azure.claude.entra_user_consent_not_legacy",
  "azure.claude.entra_user_recent_sign_in",
  "azure.claude.entra_users_cannot_create_apps",
  "azure.claude.entra_users_cannot_create_security_groups",
  "azure.claude.entra_users_cannot_create_tenants",
  "azure.claude.entra_vm_access_user_mfa",
  "azure.claude.eventgrid_domain_managed_identity",
  "azure.claude.eventgrid_domain_private_link",
  "azure.claude.eventgrid_domain_public_access_disabled",
  "azure.claude.eventgrid_topic_managed_identity",
  "azure.claude.eventgrid_topic_private_link",
  "azure.claude.eventhub_namespace_cmk",
  "azure.claude.eventhub_namespace_logging",
  "azure.claude.eventhub_namespace_private_link",
  "azure.claude.eventhub_namespace_vnet_rule",
  "azure.claude.fhir_cmk",
  "azure.claude.fhir_private_link",
  "azure.claude.flow_log_enabled",
  "azure.claude.flow_log_traffic_analytics",
  "azure.claude.frontdoor_waf_policy_linked",
  "azure.claude.gateway_subnet_no_nsg",
  "azure.claude.hdinsight_cmk",
  "azure.claude.hdinsight_encryption_at_host",
  "azure.claude.hdinsight_encryption_in_transit",
  "azure.claude.hpc_cache_cmk",
  "azure.claude.iam_custom_role_administers_locks",
  "azure.claude.iam_custom_role_no_wildcard_actions",
  "azure.claude.iam_disabled_user_no_owner",
  "azure.claude.iam_disabled_user_no_role_assignment",
  "azure.claude.iam_external_user_no_owner",
  "azure.claude.iam_external_user_no_reader",
  "azure.claude.iam_external_user_no_write",
  "azure.claude.iam_no_custom_role",
  "azure.claude.iam_no_user_access_administrator_assignment",
  "azure.claude.iam_root_custom_role_no_wildcard",
  "azure.claude.iam_subscription_owner_between_2_and_3",
  "azure.claude.iam_subscription_owner_max_3",
  "azure.claude.iam_subscription_owner_more_than_1",
  "azure.claude.iam_subscription_tenant_transfer_restricted",
  "azure.claude.iam_user_no_contributor_assignment",
  "azure.claude.insights_activity_logs_container_byok",
  "azure.claude.insights_activity_logs_container_private",
  "azure.claude.insights_operational_logs_container_byok",
  "azure.claude.insights_operational_logs_container_private",
  "azure.claude.iot_hub_logging",
  "azure.claude.iot_hub_private_link",
  "azure.claude.keyvault_audit_and_alllogs_groups",
  "azure.claude.keyvault_audit_logging",
  "azure.claude.keyvault_certificate_validity_12_months",
  "azure.claude.keyvault_firewall_ip_rules",
  "azure.claude.keyvault_key_automatic_rotation_after_create",
  "azure.claude.keyvault_key_expiration_set",
  "azure.claude.keyvault_key_rotation_policy",
  "azure.claude.keyvault_non_rbac_key_expiration_set",
  "azure.claude.keyvault_non_rbac_secret_expiration_set",
  "azure.claude.keyvault_private_endpoint_exists",
  "azure.claude.keyvault_private_endpoint_only_access",
  "azure.claude.keyvault_rbac_key_expiration_set",
  "azure.claude.keyvault_rbac_secret_expiration_set",
  "azure.claude.keyvault_vnet_service_endpoint",
  "azure.claude.kusto_cmk",
  "azure.claude.kusto_disk_encryption",
  "azure.claude.kusto_double_encryption",
  "azure.claude.kusto_sku_with_sla",
  "azure.claude.log_analytics_local_auth_disabled",
  "azure.claude.log_analytics_public_ingestion_query_disabled",
  "azure.claude.logic_app_workflow_diagnostic_logging",
  "azure.claude.managed_hsm_audit_logging",
  "azure.claude.managed_hsm_purge_protection",
  "azure.claude.ml_workspace_cmk",
  "azure.claude.mssql_managed_instance_tde_cmk",
  "azure.claude.mssql_managed_instance_vulnerability_assessment",
  "azure.claude.mysql_flexible_audit_log_connection",
  "azure.claude.mysql_flexible_audit_log_enabled",
  "azure.claude.mysql_flexible_geo_redundant_backup",
  "azure.claude.mysql_flexible_high_availability",
  "azure.claude.mysql_flexible_min_tls_12",
  "azure.claude.mysql_flexible_secure_transport",
  "azure.claude.network_watcher_flow_logs_retention_90",
  "azure.claude.network_watcher_flow_logs_traffic_analytics",
  "azure.claude.network_watcher_in_vnet_region",
  "azure.claude.nic_no_public_ip",
  "azure.claude.nsg_associated_with_subnet",
  "azure.claude.nsg_diagnostic_logging",
  "azure.claude.nsg_internet_all_ports_tcp_udp",
  "azure.claude.nsg_internet_common_ports",
  "azure.claude.nsg_internet_http",
  "azure.claude.nsg_internet_http_https",
  "azure.claude.nsg_internet_icmp",
  "azure.claude.nsg_internet_rdp",
  "azure.claude.nsg_internet_remote_access",
  "azure.claude.nsg_internet_ssh",
  "azure.claude.nsg_internet_tcp_135",
  "azure.claude.nsg_internet_tcp_1433",
  "azure.claude.nsg_internet_tcp_20",
  "azure.claude.nsg_internet_tcp_21",
  "azure.claude.nsg_internet_tcp_23",
  "azure.claude.nsg_internet_tcp_25",
  "azure.claude.nsg_internet_tcp_3306",
  "azure.claude.nsg_internet_tcp_4333",
  "azure.claude.nsg_internet_tcp_445",
  "azure.claude.nsg_internet_tcp_53",
  "azure.claude.nsg_internet_tcp_5432",
  "azure.claude.nsg_internet_tcp_5500",
  "azure.claude.nsg_internet_tcp_5900",
  "azure.claude.nsg_internet_udp_137",
  "azure.claude.nsg_internet_udp_138",
  "azure.claude.nsg_internet_udp_1434",
  "azure.claude.nsg_internet_udp_445",
  "azure.claude.nsg_internet_udp_53",
  "azure.claude.nsg_internet_udp_any",
  "azure.claude.nsg_internet_udp_services",
  "azure.claude.nsg_outbound_restricted",
  "azure.claude.postgresql_flexible_connection_throttling",
  "azure.claude.postgresql_flexible_entra_authentication",
  "azure.claude.postgresql_flexible_geo_redundant_backup",
  "azure.claude.postgresql_flexible_high_availability",
  "azure.claude.postgresql_flexible_log_checkpoints",
  "azure.claude.postgresql_flexible_log_connections",
  "azure.claude.postgresql_flexible_log_disconnections",
  "azure.claude.postgresql_flexible_log_retention_over_3_days",
  "azure.claude.postgresql_flexible_no_azure_services_rule",
  "azure.claude.postgresql_flexible_no_zero_address_rule",
  "azure.claude.postgresql_flexible_secure_transport",
  "azure.claude.recovery_vault_backup_retention_30_days",
  "azure.claude.recovery_vault_has_protected_items",
  "azure.claude.recovery_vault_managed_identity",
  "azure.claude.recovery_vault_private_endpoint_backup",
  "azure.claude.recovery_vault_private_endpoint_site_recovery",
  "azure.claude.search_service_logging_enabled",
  "azure.claude.search_service_replica_count_above_3",
  "azure.claude.servicebus_namespace_local_auth_disabled",
  "azure.claude.servicebus_namespace_logging_enabled",
  "azure.claude.servicebus_namespace_network_restricted",
  "azure.claude.servicebus_namespace_private_link",
  "azure.claude.servicebus_premium_namespace_cmk",
  "azure.claude.servicebus_premium_namespace_vnet_rules",
  "azure.claude.servicefabric_cluster_encrypt_and_sign",
  "azure.claude.servicefabric_cluster_entra_auth",
  "azure.claude.signalr_service_no_free_tier",
  "azure.claude.signalr_service_private_link",
  "azure.claude.spring_cloud_service_vnet_injection",
  "azure.claude.sql_audit_retention_over_90",
  "azure.claude.sql_audit_storage_retention_90",
  "azure.claude.sql_database_long_term_retention",
  "azure.claude.sql_database_va_findings_resolved",
  "azure.claude.sql_firewall_no_full_range",
  "azure.claude.sql_firewall_no_internet_or_azure_services",
  "azure.claude.sql_server_entra_admin",
  "azure.claude.sql_server_minimal_tls_12",
  "azure.claude.sql_server_private_link",
  "azure.claude.sql_server_vnet_rules",
  "azure.claude.sql_server_vulnerability_assessment_enabled",
  "azure.claude.sql_tde_protector_cmk",
  "azure.claude.sql_va_notify_admins",
  "azure.claude.sql_va_recurring_scans",
  "azure.claude.sql_va_report_emails",
  "azure.claude.sql_va_reports_configured",
  "azure.claude.storage_access_keys_rotated_90",
  "azure.claude.storage_account_cmk",
  "azure.claude.storage_account_geo_redundant",
  "azure.claude.storage_blob_and_container_soft_delete_7_365",
  "azure.claude.storage_blob_classic_logging",
  "azure.claude.storage_blob_diagnostic_logging",
  "azure.claude.storage_blob_soft_delete_enabled",
  "azure.claude.storage_container_no_public_access",
  "azure.claude.storage_encryption_scope_cmk",
  "azure.claude.storage_file_share_soft_delete_1_365",
  "azure.claude.storage_file_share_soft_delete_enabled",
  "azure.claude.storage_key_expiration_policy_90",
  "azure.claude.storage_key_expiration_policy_max_90",
  "azure.claude.storage_private_endpoint_present",
  "azure.claude.storage_private_link_all_approved",
  "azure.claude.storage_queue_classic_logging",
  "azure.claude.storage_queue_diagnostic_logging",
  "azure.claude.storage_smb_channel_encryption_aes_256_gcm",
  "azure.claude.storage_smb_version_3_1_1",
  "azure.claude.storage_sync_private_link",
  "azure.claude.storage_table_classic_logging",
  "azure.claude.storage_table_diagnostic_logging",
  "azure.claude.storage_trusted_azure_services_bypass",
  "azure.claude.storage_vhd_accounts_cmk",
  "azure.claude.storage_vnet_service_endpoint_rules",
  "azure.claude.stream_analytics_job_logging_enabled",
  "azure.claude.subnet_nsg_associated",
  "azure.claude.subscription_diagnostic_setting_any_categories",
  "azure.claude.subscription_diagnostic_setting_categories",
  "azure.claude.subscription_diagnostic_setting_exists",
  "azure.claude.synapse_workspace_cmk",
  "azure.claude.synapse_workspace_exfiltration_protection",
  "azure.claude.synapse_workspace_private_link",
  "azure.claude.synapse_workspace_vulnerability_assessment",
  "azure.claude.vm_antimalware_auto_upgrade",
  "azure.claude.vm_antimalware_extension",
  "azure.claude.vm_backup_daily_retention_7_days",
  "azure.claude.vm_backup_protected",
  "azure.claude.vm_dependency_agent_linux",
  "azure.claude.vm_dependency_agent_windows",
  "azure.claude.vm_guest_configuration_extension",
  "azure.claude.vm_guest_configuration_extension_linux",
  "azure.claude.vm_guest_configuration_extension_windows",
  "azure.claude.vm_guest_configuration_managed_identity",
  "azure.claude.vm_guest_configuration_system_identity",
  "azure.claude.vm_guest_configuration_user_and_system_identity",
  "azure.claude.vm_jit_access",
  "azure.claude.vm_linux_no_passwordless_accounts",
  "azure.claude.vm_linux_remote_requires_password",
  "azure.claude.vm_linux_security_baseline",
  "azure.claude.vm_nic_nsg_internet_tcp_ingress",
  "azure.claude.vm_no_public_ip",
  "azure.claude.vm_nsg_internet_management_ports",
  "azure.claude.vm_os_managed_disk",
  "azure.claude.vm_site_recovery_enabled",
  "azure.claude.vm_windows_automatic_updates",
  "azure.claude.vm_windows_exploit_guard",
  "azure.claude.vm_windows_max_password_age",
  "azure.claude.vm_windows_min_password_age",
  "azure.claude.vm_windows_min_password_length",
  "azure.claude.vm_windows_no_reversible_password_encryption",
  "azure.claude.vm_windows_password_complexity",
  "azure.claude.vm_windows_password_history",
  "azure.claude.vm_windows_secure_boot",
  "azure.claude.vm_windows_secure_protocol_tls13",
  "azure.claude.vm_windows_security_baseline",
  "azure.claude.vmss_automatic_upgrade_mode",
  "azure.claude.vmss_boot_diagnostics",
  "azure.claude.vmss_linux_ssh_keys",
  "azure.claude.vmss_load_balancer_backend",
  "azure.claude.vmss_managed_disks",
  "azure.claude.vmss_not_empty",
  "azure.claude.vnet_gateway_entra_only",
  "azure.claude.vnet_gateway_no_basic_sku",
  "azure.claude.vnet_peering_connected",
  "azure.claude.waf_policy_bot_protection",
  "azure.claude.waf_policy_request_body_inspection",
  "azure.claude2.activity_log_alert_service_health",
  "azure.claude2.aks_azure_monitor_metrics_enabled",
  "azure.claude2.aks_private_cluster_nodes_without_public_ip",
  "azure.claude2.api_app_client_certificates",
  "azure.claude2.api_app_cors_no_wildcard",
  "azure.claude2.api_app_ftps_required",
  "azure.claude2.api_app_https_only",
  "azure.claude2.api_app_managed_identity",
  "azure.claude2.api_app_min_tls_12",
  "azure.claude2.api_app_remote_debugging_disabled",
  "azure.claude2.apim_consumption_client_certificate",
  "azure.claude2.app_gateway_http2_enabled",
  "azure.claude2.app_gateway_min_tls_12",
  "azure.claude2.app_gateway_waf_enabled",
  "azure.claude2.app_gateway_waf_mode_specified",
  "azure.claude2.app_service_environment_internal_encryption",
  "azure.claude2.app_service_plan_minimum_sku",
  "azure.claude2.app_workers_more_than_one",
  "azure.claude2.application_insights_configured",
  "azure.claude2.application_insights_public_access_blocked",
  "azure.claude2.application_insights_workspace_based",
  "azure.claude2.automation_variable_encrypted",
  "azure.claude2.batch_account_customer_managed_key",
  "azure.claude2.batch_account_managed_identity",
  "azure.claude2.batch_account_resource_logs",
  "azure.claude2.defender_attack_path_setting_and_alert_contacts",
  "azure.claude2.entra_ca_mfa_all_users_or_roles",
  "azure.claude2.entra_custom_banned_password_enforced",
  "azure.claude2.entra_device_join_requires_mfa",
  "azure.claude2.entra_global_admin_between_2_and_4",
  "azure.claude2.entra_lockout_duration_min_60",
  "azure.claude2.entra_lockout_threshold_max_10",
  "azure.claude2.entra_user_mfa_registered",
  "azure.claude2.function_app_authentication_enabled",
  "azure.claude2.function_app_client_certificates",
  "azure.claude2.function_app_ftps_required",
  "azure.claude2.function_app_linux_http2",
  "azure.claude2.function_app_managed_identity",
  "azure.claude2.function_app_restrict_public_access",
  "azure.claude2.iam_no_custom_owner_roles",
  "azure.claude2.nsg_flow_log_configured",
  "azure.claude2.nsg_flow_log_retention_90",
  "azure.claude2.nsg_flow_logs_to_log_analytics",
  "azure.claude2.prowler_app_authentication",
  "azure.claude2.prowler_app_client_certificates_required",
  "azure.claude2.prowler_app_http_logs",
  "azure.claude2.prowler_app_identity",
  "azure.claude2.prowler_function_ftp_ftps_disabled",
  "azure.claude2.prowler_function_identity",
  "azure.claude2.prowler_function_identity_not_admin",
  "azure.claude2.prowler_function_not_public",
  "azure.claude2.prowler_function_vnet_integration",
  "azure.claude2.sql_server_threat_detection_all_alerts",
  "azure.claude2.vm_encryption_at_host",
  "azure.claude2.vm_linux_ssh_key_only_guest_config",
  "azure.claude2.vm_nic_ip_forwarding_disabled",
  "azure.claude2.vm_trusted_launch_secure_boot_vtpm",
  "azure.claude2.vmss_encryption_at_host",
  "azure.claude2.vnet_flow_log_retention_90",
  "azure.claude2.vnet_flow_logs_to_log_analytics",
  "azure.claude2.vnet_with_app_gateway_ddos_protection",
  "azure.claude2.web_app_always_on",
  "azure.claude2.web_app_authentication_enabled",
  "azure.claude2.web_app_client_certificates",
  "azure.claude2.web_app_diagnostic_http_log_category",
  "azure.claude2.web_app_diagnostic_logs_enabled",
  "azure.claude2.web_app_failed_request_tracing",
  "azure.claude2.web_app_ftps_required",
  "azure.claude2.web_app_health_check",
  "azure.claude2.web_app_incoming_client_cert",
  "azure.claude2.web_app_managed_identity",
  "azure.claude2.web_app_register_with_entra",
  "azure.claude2.web_app_remote_debugging_disabled",
  "azure.claude2.web_app_slot_https_only",
  "azure.claude2.web_app_vnet_connection",
  "azure.defender.standard_tier",
  "azure.disk.entra_export_auth",
  "azure.disk.private_export",
  "azure.gap.compute_vm_remote_access_restricted_all_ports",
  "azure.gap.compute_vm_tcp_udp_access_restricted_internet",
  "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled",
  "azure.gap.monitor_log_profile_retention_365_days",
  "azure.gap.nsg_declared_internet_http",
  "azure.gap.nsg_declared_internet_http_https",
  "azure.gap.nsg_declared_internet_rdp",
  "azure.gap.nsg_declared_internet_remote_access",
  "azure.gap.nsg_declared_internet_ssh",
  "azure.gap.nsg_declared_internet_udp_any",
  "azure.gap.nsg_declared_internet_udp_services",
  "azure.gap.postgres_db_server_log_duration_on",
  "azure.gap.web_pub_sub_private_link_used",
  "azure.htbp.acr.anonymous_pull_disabled",
  "azure.htbp.appconfig.local_auth_disabled",
  "azure.htbp.appservice.ftp_basic_auth_disabled",
  "azure.htbp.appservice.scm_basic_auth_disabled",
  "azure.htbp.appservice.scm_site_restricted_like_main",
  "azure.htbp.automation.webhook_expiry_bounded",
  "azure.htbp.batch.shared_key_auth_disabled",
  "azure.htbp.entra.app_fic_github_not_pull_request",
  "azure.htbp.entra.app_no_tier0_graph_application_permissions",
  "azure.htbp.entra.service_principal_no_password_credentials",
  "azure.htbp.entra.temporary_access_pass_one_time",
  "azure.htbp.eventgrid.domain_local_auth_disabled",
  "azure.htbp.eventgrid.topic_local_auth_disabled",
  "azure.htbp.eventhub.local_auth_disabled",
  "azure.htbp.iothub.local_auth_disabled",
  "azure.htbp.keyvault.template_deployment_disabled",
  "azure.htbp.logicapp.request_trigger_caller_restricted",
  "azure.htbp.managed_identity.fic_github_not_pull_request",
  "azure.htbp.postgresql.password_auth_disabled",
  "azure.htbp.redis.access_key_auth_disabled",
  "azure.htbp.search.api_key_auth_disabled",
  "azure.htbp.signalr.local_auth_disabled",
  "azure.htbp.sql.entra_only_authentication",
  "azure.htbp.storage.sftp_local_users_disabled",
  "azure.htbp.synapse.firewall_no_allow_all_internet",
  "azure.htbp.webpubsub.local_auth_disabled",
  "azure.iam.no_full_custom_role",
  "azure.iam.review_owner_assignment",
  "azure.network.ddos_configured",
  "azure.network.load_balancer_standard",
  "azure.network.nic_no_ip_forwarding",
  "azure.network.public_ip_standard",
  "azure.network.restrict_internet_ingress",
  "azure.other.entra_app_secret_age_90",
  "azure.port.ad_authorization_policy_guest_invite_restricted",
  "azure.port.ad_authorization_policy_guest_user_access_restricted",
  "azure.port.ad_authorization_policy_user_consent_disallowed",
  "azure.port.ad_authorization_policy_user_consent_verified_publishers_selected_permissions",
  "azure.port.ad_security_defaults_policy_enabled",
  "azure.port.apimanagement_service_with_virtual_network",
  "azure.port.app_configuration_encryption_enabled",
  "azure.port.app_configuration_private_link_used",
  "azure.port.app_configuration_sku_standard",
  "azure.port.cognitive_account_encrypted_with_cmk",
  "azure.port.cognitive_account_private_link_used",
  "azure.port.cognitive_account_public_network_access_disabled",
  "azure.port.cognitive_account_restrict_public_access",
  "azure.port.cognitive_service_local_auth_disabled",
  "azure.port.cosmosdb_account_uses_private_link",
  "azure.port.cosmosdb_account_virtual_network_filter_enabled",
  "azure.port.data_factory_encrypted_with_cmk",
  "azure.port.data_factory_public_network_access_disabled",
  "azure.port.data_factory_uses_git_repository",
  "azure.port.data_factory_uses_private_link",
  "azure.port.databricks_workspace_deployed_in_custom_vnet",
  "azure.port.databricks_workspace_no_public_ip_enabled",
  "azure.port.databricks_workspace_public_network_access_disabled",
  "azure.port.databricks_workspace_uses_private_endpoint",
  "azure.port.defender_alert_severity_contact",
  "azure.port.defender_notify_owner_contact",
  "azure.port.defender_required_mcas",
  "azure.port.defender_required_wdatp",
  "azure.port.iam_user_not_allowed_to_create_security_group",
  "azure.port.iam_user_not_allowed_to_register_application",
  "azure.port.keyvault_key_automatic_rotation_enabled",
  "azure.port.keyvault_key_expiration_set",
  "azure.port.keyvault_logging_enabled",
  "azure.port.keyvault_public_network_access_disabled",
  "azure.port.keyvault_secret_expiration_set",
  "azure.port.keyvault_vault_private_link_used",
  "azure.port.keyvault_vault_recoverable",
  "azure.port.keyvault_with_non_rbac_key_expiration_set",
  "azure.port.keyvault_with_non_rbac_secret_expiration_set",
  "azure.port.keyvault_with_rbac_key_expiration_set",
  "azure.port.keyvault_with_rbac_secret_expiration_set",
  "azure.port.monitor_log_alert_create_policy_assignment",
  "azure.port.monitor_log_alert_create_update_nsg",
  "azure.port.monitor_log_alert_create_update_public_ip_address",
  "azure.port.monitor_log_alert_create_update_security_solution",
  "azure.port.monitor_log_alert_create_update_sql_servers_firewall_rule",
  "azure.port.monitor_log_alert_delete_nsg",
  "azure.port.monitor_log_alert_delete_policy_assignment",
  "azure.port.monitor_log_alert_delete_public_ip_address",
  "azure.port.monitor_log_alert_delete_security_solution",
  "azure.port.monitor_log_alert_delete_sql_servers_firewall_rule",
  "azure.port.redis_cache_in_virtual_network",
  "azure.port.redis_cache_min_tls_1_2",
  "azure.port.redis_cache_no_basic_sku",
  "azure.port.redis_cache_ssl_enabled",
  "azure.port.redis_cache_uses_private_link",
  "azure.port.search_service_public_network_access_disabled",
  "azure.port.search_service_uses_managed_identity",
  "azure.port.search_service_uses_private_link",
  "azure.port.search_service_uses_sku_supporting_private_link",
  "azure.port.security_center_defender_for_api_enabled",
  "azure.port.security_center_defender_for_cloudposture_enabled",
  "azure.port.securitycenter_azure_defender_on_for_appservice",
  "azure.port.securitycenter_azure_defender_on_for_containerregistry",
  "azure.port.securitycenter_azure_defender_on_for_containers",
  "azure.port.securitycenter_azure_defender_on_for_cosmosdb",
  "azure.port.securitycenter_azure_defender_on_for_database",
  "azure.port.securitycenter_azure_defender_on_for_dns",
  "azure.port.securitycenter_azure_defender_on_for_k8s",
  "azure.port.securitycenter_azure_defender_on_for_keyvault",
  "azure.port.securitycenter_azure_defender_on_for_opensource_relational_db",
  "azure.port.securitycenter_azure_defender_on_for_resource_manager",
  "azure.port.securitycenter_azure_defender_on_for_server",
  "azure.port.securitycenter_azure_defender_on_for_sqldb",
  "azure.port.securitycenter_azure_defender_on_for_sqlservervm",
  "azure.port.securitycenter_azure_defender_on_for_storage",
  "azure.port.securitycenter_mcas_integration",
  "azure.port.securitycenter_wdatp_integration",
  "azure.port.storage_account_access_keys_periodically_regenerated",
  "azure.port.storage_account_blob_and_container_soft_delete_enabled",
  "azure.port.storage_account_blob_soft_delete_enabled",
  "azure.port.storage_account_blob_versioning_enabled",
  "azure.port.storage_account_container_soft_delete_enabled",
  "azure.port.storage_account_encryption_at_rest_using_cmk",
  "azure.port.storage_account_file_share_smb_channel_encryption_aes_256_gcm",
  "azure.port.storage_account_file_share_smb_protocol_version_3_1_1",
  "azure.port.storage_account_geo_redundant_enabled",
  "azure.port.storage_account_key_rotation_reminder_enabled",
  "azure.port.storage_account_soft_delete_enabled",
  "azure.port.storage_account_trusted_microsoft_services_enabled",
  "azure.sql.audit_retention",
  "azure.sql.auditing",
  "azure.sql.minimum_tls",
  "azure.sql.no_public_network",
  "azure.sql.restrict_firewall",
  "azure.sql.tde_enabled",
  "azure.sql.threat_alerts_all",
  "azure.sql.threat_detection",
  "azure.storage.blob_soft_delete_retention",
  "azure.storage.blob_versioning",
  "azure.storage.container_soft_delete",
  "azure.storage.cross_tenant_replication",
  "azure.storage.default_deny",
  "azure.storage.default_oauth",
  "azure.storage.https_only",
  "azure.storage.infrastructure_encryption",
  "azure.storage.minimum_tls",
  "azure.storage.no_blob_public_access",
  "azure.storage.no_public_network",
  "azure.storage.no_shared_key",
  "azure.vault.approved_private_endpoint",
  "azure.vault.default_deny",
  "azure.vault.no_public_network",
  "azure.vault.purge_protection",
  "azure.vault.rbac",
  "azure.vault.secret_expiration",
  "azure.vault.soft_delete",
  "azure.vm.encryption_at_host",
  "azure.vm.linux_ssh_keys",
  "azure.vm.managed_disks",
  "azure.vm.trusted_launch",
  "azure_api_management_appinsights_ensure_is_configured_42aac6a",
  "azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7",
  "azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28",
  "azure_firewall_policy_1_2_8_23_59ad733",
  "azure_firewall_policy_1_2_8_24_cc7cb8a",
  "azure_firewall_policy_1_2_8_42_cacbd9e",
  "azure_log_analytics_workspace_10_5_1_4_8c74ccb",
  "azure_pci_1_2_8_39",
  "azure_search_service_3_5_1_19_a3c75c0",
  "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5",
  "azure_vm_app_function_identity_is_configured_bdb10d4",
  "azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679"
];
const reviewedChecks = new Set(REVIEWED_AZURE_EVIDENCE_CHECKS);

const scalarSettings: Record<string, [string, string]> = {
  "azure.storage.no_shared_key": ["properties.allowSharedKeyAccess", "Shared Key authorization"],
  "azure.storage.default_oauth": ["properties.defaultToOAuthAuthentication", "Default Entra authorization"],
  "azure.storage.no_public_network": ["properties.publicNetworkAccess", "Public storage network access"],
  "azure.vault.purge_protection": ["properties.enablePurgeProtection", "Vault purge protection"],
  "azure.vault.rbac": ["properties.enableRbacAuthorization", "Vault Azure RBAC authorization"],
  "azure.vault.no_public_network": ["properties.publicNetworkAccess", "Public vault network access"],
  "azure.vault.default_deny": ["properties.networkAcls.defaultAction", "Default vault network action"],
  "azure.aks.no_local_accounts": ["properties.disableLocalAccounts", "Disabling local AKS accounts"],
  "azure.aks.azure_rbac": ["properties.aadProfile.enableAzureRBAC", "Azure RBAC for Kubernetes"],
  "azure.sql.minimum_tls": ["properties.minimalTlsVersion", "Minimum SQL TLS version"],
  "azure.sql.no_public_network": ["properties.publicNetworkAccess", "Public SQL network access"],
  "azure.storage.default_deny": ["properties.networkAcls.defaultAction", "Default storage network action"],
  "azure.storage.cross_tenant_replication": ["properties.allowCrossTenantReplication", "Cross-tenant replication"],
  "azure.storage.infrastructure_encryption": ["properties.encryption.requireInfrastructureEncryption", "Additional infrastructure encryption"],
  "azure.vm.encryption_at_host": ["properties.securityProfile.encryptionAtHost", "Host encryption"],
  "azure.network.nic_no_ip_forwarding": ["properties.enableIPForwarding", "NIC IP forwarding"],
  "azure.app.https_only": ["properties.httpsOnly", "HTTPS-only access"],
  "azure.app.http2": ["properties.http20Enabled", "HTTP/2"],
  "azure.app.request_logging": ["properties.httpLoggingEnabled", "HTTP request logging"],
  "azure.app.remote_debugging_off": ["properties.remoteDebuggingEnabled", "Remote debugging"],
};

const additionalScalarSettings: Record<string, {path: string; label: string; values: (string | boolean)[]; invert: boolean}> = {
  "azure.vault.soft_delete": {
    "path": "properties.enableSoftDelete",
    "label": "Vault soft delete",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.aks.rbac": {
    "path": "properties.enableRBAC",
    "label": "Kubernetes RBAC",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.aks.private_cluster": {
    "path": "properties.apiServerAccessProfile.enablePrivateCluster",
    "label": "Private Kubernetes API",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.sql.auditing": {
    "path": "properties.state",
    "label": "SQL auditing state",
    "values": [
      "Enabled",
      "Disabled"
    ],
    "invert": false
  },
  "azure.sql.threat_detection": {
    "path": "properties.state",
    "label": "SQL threat-detection state",
    "values": [
      "Enabled",
      "Disabled"
    ],
    "invert": false
  },
  "azure.disk.entra_export_auth": {
    "path": "properties.dataAccessAuthMode",
    "label": "Disk export authentication mode",
    "values": [
      "AzureActiveDirectory",
      "None"
    ],
    "invert": false
  },
  "azure.network.load_balancer_standard": {
    "path": "sku.name",
    "label": "Service SKU",
    "values": [
      "Standard",
      "Basic"
    ],
    "invert": false
  },
  "azure.network.public_ip_standard": {
    "path": "sku.name",
    "label": "Service SKU",
    "values": [
      "Standard",
      "Basic"
    ],
    "invert": false
  },
  "azure.network.ddos_configured": {
    "path": "properties.enableDdosProtection",
    "label": "DDoS protection",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.aks.defender_monitoring": {
    "path": "properties.securityProfile.defender.securityMonitoring.enabled",
    "label": "Defender cluster monitoring",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.port.databricks_workspace_no_public_ip_enabled": {
    "path": "properties.parameters.enableNoPublicIp.value",
    "label": "No-public-IP compute deployment",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.port.databricks_workspace_public_network_access_disabled": {
    "path": "properties.publicNetworkAccess",
    "label": "Public network access",
    "values": [
      "Disabled",
      "Enabled"
    ],
    "invert": false
  },
  "azure.claude.vmss_automatic_upgrade_mode": {
    "path": "properties.upgradePolicy.mode",
    "label": "Scale-set upgrade mode",
    "values": [
      "Automatic",
      "Manual",
      "Rolling"
    ],
    "invert": false
  },
  "azure.claude.vmss_boot_diagnostics": {
    "path": "properties.virtualMachineProfile.diagnosticsProfile.bootDiagnostics.enabled",
    "label": "Boot diagnostics",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.acr_admin_user_disabled": {
    "path": "properties.adminUserEnabled",
    "label": "Registry admin-user authentication",
    "values": [
      false,
      true
    ],
    "invert": false
  },
  "azure.claude.acr_cmk": {
    "path": "properties.encryption.status",
    "label": "Customer-managed encryption",
    "values": [
      "enabled",
      "disabled"
    ],
    "invert": false
  },
  "azure.claude.acr_public_network_access_disabled": {
    "path": "properties.publicNetworkAccess",
    "label": "Public network access",
    "values": [
      "Disabled",
      "Enabled"
    ],
    "invert": false
  },
  "azure.claude.acr_network_default_deny": {
    "path": "properties.networkRuleSet.defaultAction",
    "label": "Default network action",
    "values": [
      "Deny",
      "Allow"
    ],
    "invert": false
  },
  "azure.claude.acr_quarantine_policy": {
    "path": "properties.policies.quarantinePolicy.status",
    "label": "Registry quarantine policy",
    "values": [
      "enabled",
      "disabled"
    ],
    "invert": false
  },
  "azure.claude.acr_retention_policy": {
    "path": "properties.policies.retentionPolicy.status",
    "label": "Registry retention policy",
    "values": [
      "enabled",
      "disabled"
    ],
    "invert": false
  },
  "azure.claude.acr_trust_policy": {
    "path": "properties.policies.trustPolicy.status",
    "label": "Registry trust policy",
    "values": [
      "enabled",
      "disabled"
    ],
    "invert": false
  },
  "azure.claude.cosmos_public_network_access_disabled": {
    "path": "properties.publicNetworkAccess",
    "label": "Public network access",
    "values": [
      "Disabled",
      "Enabled",
      "SecuredByPerimeter"
    ],
    "invert": false
  },
  "azure.claude.cosmos_public_network_access_restricted": {
    "path": "properties.publicNetworkAccess",
    "label": "Public network access",
    "values": [
      "Disabled",
      "SecuredByPerimeter",
      "Enabled"
    ],
    "invert": false
  },
  "azure.claude.cosmos_automatic_failover": {
    "path": "properties.enableAutomaticFailover",
    "label": "Automatic failover",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.cosmos_continuous_backup": {
    "path": "properties.backupPolicy.type",
    "label": "Backup mode",
    "values": [
      "Continuous",
      "Periodic"
    ],
    "invert": false
  },
  "azure.claude.cosmos_virtual_network_filter": {
    "path": "properties.isVirtualNetworkFilterEnabled",
    "label": "Virtual-network filtering",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.cosmos_key_based_metadata_write_disabled": {
    "path": "properties.disableKeyBasedMetadataWriteAccess",
    "label": "Key-based metadata writes",
    "values": [
      true,
      false
    ],
    "invert": true
  },
  "azure.claude.cosmos_local_auth_disabled": {
    "path": "properties.disableLocalAuth",
    "label": "Local-key authentication",
    "values": [
      true,
      false
    ],
    "invert": true
  },
  "azure.claude.cosmos_minimum_tls12": {
    "path": "properties.minimalTlsVersion",
    "label": "Minimum TLS version",
    "values": [
      "Tls12",
      "Tls13",
      "Tls",
      "Tls11"
    ],
    "invert": false
  },
  "azure.claude.entra_users_cannot_create_security_groups": {
    "path": "defaultUserRolePermissions.allowedToCreateSecurityGroups",
    "label": "Default-user security-group creation",
    "values": [
      false,
      true
    ],
    "invert": false
  },
  "azure.claude.entra_users_cannot_create_apps": {
    "path": "defaultUserRolePermissions.allowedToCreateApps",
    "label": "Default-user application registration",
    "values": [
      false,
      true
    ],
    "invert": false
  },
  "azure.claude.entra_users_cannot_create_tenants": {
    "path": "defaultUserRolePermissions.allowedToCreateTenants",
    "label": "Default-user tenant creation",
    "values": [
      false,
      true
    ],
    "invert": false
  },
  "azure.claude.eventhub_namespace_cmk": {
    "path": "properties.encryption.keySource",
    "label": "Encryption key source",
    "values": [
      "Microsoft.KeyVault",
      "Microsoft.EventHub"
    ],
    "invert": false
  },
  "azure.claude.managed_hsm_purge_protection": {
    "path": "properties.enablePurgeProtection",
    "label": "Purge protection",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.aks_network_plugin_azure": {
    "path": "properties.networkProfile.networkPlugin",
    "label": "Kubernetes network plugin",
    "values": [
      "azure",
      "kubenet",
      "none"
    ],
    "invert": false
  },
  "azure.claude.kusto_disk_encryption": {
    "path": "properties.enableDiskEncryption",
    "label": "Cluster disk-encryption setting",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.kusto_double_encryption": {
    "path": "properties.enableDoubleEncryption",
    "label": "Additional double encryption",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.log_analytics_local_auth_disabled": {
    "path": "properties.features.disableLocalAuth",
    "label": "Local ingestion authentication",
    "values": [
      true,
      false
    ],
    "invert": true
  },
  "azure.claude.ml_workspace_cmk": {
    "path": "properties.encryption.status",
    "label": "Customer-managed encryption",
    "values": [
      "Enabled",
      "Disabled"
    ],
    "invert": false
  },
  "azure.claude.mysql_flexible_geo_redundant_backup": {
    "path": "properties.backup.geoRedundantBackup",
    "label": "Geo-redundant backup",
    "values": [
      "Enabled",
      "Disabled"
    ],
    "invert": false
  },
  "azure.claude.postgresql_flexible_geo_redundant_backup": {
    "path": "properties.backup.geoRedundantBackup",
    "label": "Geo-redundant backup",
    "values": [
      "Enabled",
      "Disabled"
    ],
    "invert": false
  },
  "azure.claude.vnet_gateway_no_basic_sku": {
    "path": "properties.sku.name",
    "label": "Gateway SKU",
    "values": [
      "VpnGw1",
      "VpnGw2",
      "VpnGw3",
      "VpnGw4",
      "VpnGw5",
      "VpnGw1AZ",
      "VpnGw2AZ",
      "VpnGw3AZ",
      "VpnGw4AZ",
      "VpnGw5AZ",
      "Standard",
      "HighPerformance",
      "UltraPerformance",
      "ErGw1AZ",
      "ErGw2AZ",
      "ErGw3AZ",
      "ErGwScale",
      "Basic"
    ],
    "invert": false
  },
  "azure.claude.flow_log_enabled": {
    "path": "properties.enabled",
    "label": "Flow logging",
    "values": [
      true,
      false
    ],
    "invert": false
  },
  "azure.claude.recovery_vault_private_endpoint_site_recovery": {
    "path": "properties.privateEndpointStateForSiteRecovery",
    "label": "Site Recovery private-endpoint state",
    "values": [
      "Enabled",
      "None"
    ],
    "invert": false
  },
  "azure.claude.recovery_vault_private_endpoint_backup": {
    "path": "properties.privateEndpointStateForBackup",
    "label": "Backup private-endpoint state",
    "values": [
      "Enabled",
      "None"
    ],
    "invert": false
  },
  "azure.claude.signalr_service_no_free_tier": {
    "path": "sku.tier",
    "label": "Service tier",
    "values": [
      "Standard",
      "Premium",
      "Free"
    ],
    "invert": false
  },
  "azure.claude.sql_tde_protector_cmk": {
    "path": "properties.serverKeyType",
    "label": "TDE protector key type",
    "values": [
      "AzureKeyVault",
      "ServiceManaged"
    ],
    "invert": false
  },
  "azure.claude.storage_account_cmk": {
    "path": "properties.encryption.keySource",
    "label": "Encryption key source",
    "values": [
      "Microsoft.Keyvault",
      "Microsoft.Storage"
    ],
    "invert": false
  },
  "azure.claude.storage_account_geo_redundant": {
    "path": "sku.name",
    "label": "Service SKU",
    "values": [
      "Standard_GRS",
      "Standard_RAGRS",
      "Standard_GZRS",
      "Standard_RAGZRS",
      "Standard_LRS",
      "Standard_ZRS",
      "Premium_LRS",
      "Premium_ZRS",
      "StandardV2_LRS",
      "StandardV2_ZRS",
      "PremiumV2_LRS",
      "PremiumV2_ZRS"
    ],
    "invert": false
  },
  "azure.claude.waf_policy_request_body_inspection": {
    "path": "properties.policySettings.requestBodyCheck",
    "label": "WAF request-body inspection",
    "values": [
      true,
      false
    ],
    "invert": false
  }
};

const list = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === "string");
const shortList = (values: string[]) => values.slice(0, 3).join(", ") + (values.length > 3 ? ` and ${values.length - 3} more` : "");
const finite = (value: unknown): value is number => typeof value === "number" && Number.isFinite(value);
const toggle = (name: string, value: unknown): string | undefined => typeof value === "boolean" ? `${name} is ${value ? "enabled" : "disabled"}.` : undefined;

export function explainAzureFindingEvidence(checkId: string, evidence: unknown, status: string): string | undefined {
  const observation = nativeAzureFindingEvidence(checkId, evidence, status);
  if (observation === undefined) return undefined;
  const meanings: Record<string, string> = {
    "Scale-set upgrade mode is Automatic.": "Scale-set instances are configured to upgrade automatically.",
    "Scale-set upgrade mode is Manual.": "Scale-set instance upgrades must be applied manually.",
    "Scale-set upgrade mode is Rolling.": "Scale-set upgrades are configured to run in batches.",
    "The container public-access ACL is None.": "The container ACL grants no anonymous access.",
    "The container public-access ACL is Container.": "The container ACL permits anonymous listing and blob reads.",
    "The container public-access ACL is Blob.": "The container ACL permits anonymous blob reads but not anonymous listing.",
    "The log container public-access ACL is None.": "The log container ACL grants no anonymous access.",
    "The log container public-access ACL is Container.": "The log container ACL permits anonymous listing and blob reads.",
    "The log container public-access ACL is Blob.": "The log container ACL permits anonymous blob reads but not anonymous listing.",
    "Backup private-endpoint state is None.": "Backup traffic is not configured to use a private endpoint.",
    "Site Recovery private-endpoint state is None.": "Site Recovery traffic is not configured to use a private endpoint.",
    "Disk export authentication mode is None.": "Disk exports do not require Microsoft Entra authentication.",
    "API Management virtual-network mode is None.": "API Management is not configured in a virtual network.",
    "Search identity type is SystemAssigned.": "Search has a system-assigned managed identity.",
    "Search identity type is UserAssigned.": "Search uses user-assigned managed identities.",
    "Search identity type is SystemAssigned, UserAssigned.": "Search has both system-assigned and user-assigned managed identities.",
    "Enabled vault log groups: allLogs.": "Vault diagnostics are configured to export all supported log categories.",
  };
  return meanings[observation] ?? observation;
}

function nativeAzureFindingEvidence(checkId: string, evidence: unknown, status: string): string | undefined {
  if (!reviewedChecks.has(checkId)) return undefined;
  if (!["PASS", "FAIL"].includes(status) || !evidence || typeof evidence !== "object" || Array.isArray(evidence)) return undefined;
  const e = evidence as Record<string, unknown>;
  const scalar = scalarSettings[checkId];
  if (scalar && e.field === scalar[0]) {
    const allowed = scalar[0].endsWith("publicNetworkAccess") ? ["Enabled", "Disabled"]
      : scalar[0].endsWith("defaultAction") ? ["Allow", "Deny"]
      : scalar[0].endsWith("minimalTlsVersion") ? ["1.0", "1.2"] : undefined;
    if (!allowed && typeof e.configured === "boolean") return checkId === "azure.aks.no_local_accounts"
      ? `Local AKS accounts are ${e.configured ? "disabled" : "enabled"}.` : toggle(scalar[1], e.configured);
    if (allowed && typeof e.configured === "string" && allowed.includes(e.configured)) return `${scalar[1]} is ${e.configured.toLowerCase()}.`;
    return undefined;
  }
  const strict = strictAzureEvidence(checkId, e, status);
  if (strict !== undefined) return strict;
  const dataIdentity = dataIdentityAzureEvidence(checkId, e);
  if (dataIdentity !== undefined) return dataIdentity;
  const legacy = legacyAzureEvidence(checkId, e);
  if (legacy !== undefined) return legacy;
  const declarations = declarationAzureEvidence(checkId, e);
  if (declarations !== undefined) return declarations;
  const successor = successorAzureEvidence(checkId, e);
  if (successor !== undefined) return successor;
  const standard = standardAzureEvidence(checkId, e);
  if (standard !== undefined) return standard;
  const hacktricks = hacktricksAzureEvidence(checkId, e);
  if (hacktricks !== undefined) return hacktricks;
  const adjacent = identityAdjacentAzureEvidence(checkId, e);
  if (adjacent !== undefined) return adjacent;
  const identity = identityAzureEvidence(checkId, e);
  if (identity !== undefined) return identity;
  const sourceFamily = sourceFamilyAzureEvidence(checkId, e, status);
  if (sourceFamily !== undefined) return sourceFamily;
  const additional = additionalAzureEvidence(checkId, e, status);
  if (additional !== undefined) return additional;
  if (!checkId.startsWith("azure.claude.") && !checkId.startsWith("azure.claude2.")) return undefined;
  const slug = checkId.replace(/^azure\.claude2?\./, "");
  if (slug.startsWith("nsg_internet_") || slug === "nsg_outbound_restricted") {
    if (!Array.isArray(e.exposed_rules)) return undefined;
    if (!e.exposed_rules.length) return "No matching public-source Allow rule was found.";
    const ports: string[] = [];
    for (const rule of e.exposed_rules) {
      if (!rule || typeof rule !== "object") return undefined;
      const { protocol, port } = rule as Record<string, unknown>;
      if (typeof protocol !== "string" || !/^(tcp|udp|icmp|\*)$/.test(protocol) || !/^(all|\d+(?:-\d+)?)$/.test(String(port))) return undefined;
      ports.push(protocol === "icmp" ? "ICMP" : protocol === "*" && port === "all" ? "all protocols and ports" : `${protocol === "*" ? "all protocols" : protocol}/${port}`);
    }
    return `${e.direction === "Outbound" ? "Outbound Allow rules cover" : "Internet-source ingress is allowed on"} ${shortList([...new Set(ports)])}.`;
  }
  if (slug.startsWith("activity_log_alert_")) {
    if (e.reason === "no matching enabled activity log alert") return "No enabled alert matches the required operation and conditions.";
    if (typeof e.alert === "string" && e.alert) return "An enabled alert matches the required operation and conditions.";
    return undefined;
  }
  if (slug === "subscription_diagnostic_setting_exists" && list(e.settings)) return e.settings.length ? "An activity-log export setting is configured." : "No activity-log export setting is configured.";
  if (slug === "subscription_diagnostic_setting_categories" && list(e.missing_categories)) return e.missing_categories.length ? `Activity-log categories are missing: ${shortList(e.missing_categories as string[])}.` : "All four required activity-log categories are enabled.";
  if (slug === "subscription_diagnostic_setting_any_categories") {
    if (e.reason === "no diagnostic setting captures all four categories") return "No single export setting enables all four required activity-log categories.";
    if (typeof e.setting === "string") return "One export setting enables all four required activity-log categories.";
  }
  const parameterLabels: Record<string, string> = { audit_log_enabled: "Audit logging", require_secure_transport: "Required TLS transport", "connection_throttle.enable": "Connection throttling", log_checkpoints: "Checkpoint logging", log_connections: "Connection logging", log_disconnections: "Disconnection logging" };
  const parameterKeys: Record<string, string> = {
    mysql_flexible_audit_log_enabled: "audit_log_enabled", mysql_flexible_secure_transport: "require_secure_transport",
    postgresql_flexible_secure_transport: "require_secure_transport", postgresql_flexible_connection_throttling: "connection_throttle.enable",
    postgresql_flexible_log_checkpoints: "log_checkpoints", postgresql_flexible_log_connections: "log_connections", postgresql_flexible_log_disconnections: "log_disconnections",
  };
  if (typeof e.parameter === "string" && parameterKeys[slug] === e.parameter && parameterLabels[e.parameter] && typeof e.value === "string" && /^(on|off)$/i.test(e.value)) return `${parameterLabels[e.parameter]} is ${e.value.toLowerCase() === "on" ? "enabled" : "disabled"}.`;
  if (slug === "mysql_flexible_audit_log_connection" && typeof e.audit_log_events === "string") return `MySQL audit events include ${e.audit_log_events.split(",").some(event => event.trim().toUpperCase() === "CONNECTION") ? "" : "no "}CONNECTION events.`;
  if (slug === "mysql_flexible_min_tls_12" && typeof e.tls_version === "string" && e.tls_version.length < 100) return `Allowed MySQL TLS versions: ${e.tls_version}.`;
  if (slug.endsWith("_flexible_high_availability") && typeof e.mode === "string") return `High availability is ${e.mode === "Disabled" ? "disabled" : e.mode}.`;
  if (slug === "postgresql_flexible_log_retention_over_3_days" && finite(e.retention_days)) return `PostgreSQL server logs are configured for ${e.retention_days} days of retention.`;
  if (["postgresql_flexible_no_azure_services_rule", "postgresql_flexible_no_zero_address_rule"].includes(slug)) {
    if (e.reason === "public network access disabled; firewall rules are inert") return "Public networking is disabled; the firewall rules are inactive.";
    if (list(e.rules)) return e.rules.length ? `${e.rules.length} firewall rule${e.rules.length === 1 ? " has" : "s have"} the flagged broad address setting.` : "No firewall rule has the flagged broad address setting.";
  }
  if (slug === "postgresql_flexible_entra_authentication" && typeof e.active_directory_auth === "string") return e.active_directory_auth === "Disabled" ? "Entra authentication is disabled." : finite(e.administrators) ? `Entra authentication is enabled with ${e.administrators} listed administrator${e.administrators === 1 ? "" : "s"}.` : undefined;
  if (slug === "bastion_host_exists" && finite(e.bastion_hosts)) return `${e.bastion_hosts} Bastion host${e.bastion_hosts === 1 ? " is" : "s are"} listed in the subscription.`;
  if (slug === "nic_no_public_ip" && list(e.public_ips)) return e.public_ips.length ? "The NIC references a public IP address." : "The NIC has no public-IP reference.";
  if (slug === "vnet_peering_connected" && list(e.peering_states)) return e.peering_states.includes("Disconnected") ? "At least one virtual-network peering is disconnected." : "No listed peering is disconnected.";
  if (slug === "subnet_nsg_associated" && Object.hasOwn(e, "nsg")) return e.nsg === null ? "The subnet has no NSG reference." : typeof e.nsg === "string" ? "The subnet references an NSG." : undefined;
  if (slug === "gateway_subnet_no_nsg" && Object.hasOwn(e, "nsg")) return e.nsg === null ? "GatewaySubnet has no NSG reference." : typeof e.nsg === "string" ? "GatewaySubnet references an NSG." : undefined;
  if (slug === "vnet_gateway_entra_only" && list(e.vpn_authentication_types)) return `Point-to-site authentication types: ${shortList(e.vpn_authentication_types as string[])}.`;
  if (slug === "network_watcher_in_vnet_region" && typeof e.region === "string") return `A Network Watcher ${status === "PASS" ? "was" : "was not"} found in ${e.region}.`;
  if (slug === "flow_log_traffic_analytics") {
    if (e.reason === "flow log disabled") return "The flow log is disabled.";
    if (e.reason === "traffic analytics disabled") return "Traffic Analytics is disabled.";
    if (finite(e.traffic_analytics_interval)) return `Traffic Analytics uses a ${e.traffic_analytics_interval}-minute processing interval.`;
  }
  if (slug === "network_watcher_flow_logs_traffic_analytics") {
    if (e.reason === "no flow logs configured") return "No flow logs are configured.";
    if (list(e.flow_logs)) return e.flow_logs.length ? `${e.flow_logs.length} flow log${e.flow_logs.length === 1 ? " is" : "s are"} disabled or lack Traffic Analytics.` : "All listed flow logs and Traffic Analytics are enabled.";
  }
  if (["servicebus_namespace_private_link", "sql_server_private_link", "synapse_workspace_private_link", "storage_private_link_all_approved", "storage_private_endpoint_present"].includes(slug) && list(e.connection_states)) return e.connection_states.length ? `Private endpoint connection states: ${shortList(e.connection_states as string[])}.` : "No private endpoint connections are listed.";
  if (slug === "servicebus_namespace_local_auth_disabled") return typeof e.disable_local_auth === "boolean" ? `Local SAS authentication is ${e.disable_local_auth ? "disabled" : "enabled"}.` : undefined;
  if (["servicebus_premium_namespace_vnet_rules", "storage_vnet_service_endpoint_rules"].includes(slug) && finite(e.virtual_network_rule_count)) return `${typeof e.default_action === "string" ? `Default network action is ${e.default_action.toLowerCase()}; ` : ""}${e.virtual_network_rule_count} virtual-network rule${e.virtual_network_rule_count === 1 ? " is" : "s are"} listed.`;
  if (["sql_firewall_no_internet_or_azure_services", "sql_firewall_no_full_range"].includes(slug) && typeof e.start_ip === "string" && typeof e.end_ip === "string") return e.start_ip === "0.0.0.0" && e.end_ip === "0.0.0.0" ? "The firewall rule allows connections from Azure services across tenants." : `The firewall rule allows the IPv4 range ${e.start_ip}–${e.end_ip}.`;
  if (slug === "sql_server_entra_admin" && list(e.administrator_types)) return e.administrator_types.includes("ActiveDirectory") ? "An Entra administrator is configured." : "No Entra administrator is listed.";
  if (slug === "sql_server_vnet_rules" && list(e.subnets)) return `${e.subnets.length} subnet rule${e.subnets.length === 1 ? " is" : "s are"} listed for the SQL server.`;
  if (["storage_key_expiration_policy_90", "storage_key_expiration_policy_max_90"].includes(slug) && Object.hasOwn(e, "key_expiration_period_days")) return e.key_expiration_period_days === null ? "No storage key-expiration policy is declared." : finite(e.key_expiration_period_days) ? `Storage key expiration is configured for ${e.key_expiration_period_days} days.` : undefined;
  if (slug === "storage_access_keys_rotated_90" && e.key_age_days && typeof e.key_age_days === "object") {
    const ages = Object.values(e.key_age_days);
    if (ages.length && ages.every(finite)) return `The oldest reported storage key is ${Math.max(...ages)} days old.`;
  }
  if (slug === "storage_blob_and_container_soft_delete_7_365") {
    const days = (value: unknown) => value === null ? "disabled" : finite(value) ? `${value} days` : undefined;
    const blob = days(e.blob_retention_days), container = days(e.container_retention_days);
    if (blob && container) return `Soft delete: blobs ${blob}; containers ${container}.`;
  }
  if (["storage_blob_soft_delete_enabled", "storage_file_share_soft_delete_enabled"].includes(slug)) return toggle(slug.includes("file") ? "File-share soft delete" : "Blob soft delete", e.enabled);
  if (slug === "storage_file_share_soft_delete_1_365" && Object.hasOwn(e, "retention_days")) return e.retention_days === null ? "File-share soft delete is disabled." : finite(e.retention_days) ? `File-share soft-delete retention is ${e.retention_days} days.` : undefined;
  if (["storage_smb_channel_encryption_aes_256_gcm", "storage_smb_version_3_1_1"].includes(slug)) return e.configured === null ? "The SMB restriction is unset; service defaults apply." : list(e.configured) ? `Allowed SMB ${slug.includes("encryption") ? "ciphers" : "versions"}: ${shortList(e.configured as string[])}.` : undefined;
  if (slug === "storage_container_no_public_access" && typeof e.public_access === "string") return `The container public-access ACL is ${e.public_access}.`;
  if (slug === "storage_encryption_scope_cmk" && typeof e.source === "string" && ["microsoft.storage", "microsoft.keyvault"].includes(e.source.toLowerCase())) return `The encryption scope uses ${e.source.toLowerCase() === "microsoft.storage" ? "a platform-managed storage key" : "a Key Vault key"}.`;
  if (slug === "storage_sync_private_link" && typeof e.incoming_traffic_policy === "string" && list(e.connection_states)) return `Incoming traffic policy is ${e.incoming_traffic_policy}; ${e.connection_states.includes("Approved") ? "an approved endpoint is listed" : "no approved endpoint is listed"}.`;
  if (slug === "synapse_workspace_exfiltration_protection") return e.prevent_data_exfiltration === null ? "Data-exfiltration protection is not declared." : toggle("Data-exfiltration protection", e.prevent_data_exfiltration);
  if (slug === "synapse_workspace_cmk" && Object.hasOwn(e, "cmk_key_name")) return e.cmk_key_name === null || typeof e.cmk_key_name === "string" ? `${typeof e.cmk_key_name === "string" && e.cmk_key_name.trim() ? "A" : "No"} customer-managed key name is declared.` : undefined;
  if (slug === "function_app_ftps_required" && typeof e.ftps_state === "string") return e.ftps_state === "AllAllowed" ? "Plain FTP publishing is allowed." : e.ftps_state === "Disabled" ? "FTP and FTPS publishing are disabled." : e.ftps_state === "FtpsOnly" ? "FTP publishing requires TLS." : undefined;
  if (slug === "function_app_linux_http2") return toggle("HTTP/2", e.http20_enabled);
  if (slug === "application_insights_workspace_based" && Object.hasOwn(e, "workspace_resource_id")) return e.workspace_resource_id === null || typeof e.workspace_resource_id === "string" ? `${e.workspace_resource_id ? "A" : "No"} Log Analytics workspace link is declared.` : undefined;
  return undefined;
}

function additionalAzureEvidence(checkId: string, e: Record<string, unknown>, status: string): string | undefined {
  const scalar = additionalScalarSettings[checkId];
  if (scalar && e.field === scalar.path) {
    if (!scalar.values.some(value => value === e.configured)) return undefined;
    if (typeof e.configured === "boolean") return toggle(scalar.label, scalar.invert ? !e.configured : e.configured);
    return `${scalar.label} is ${String(e.configured)}.`;
  }
  const slug = checkId.replace(/^azure\.(?:claude|port)\./, "");
  if (["logic_app_workflow_diagnostic_logging", "nsg_diagnostic_logging"].includes(slug)) return toggle("Diagnostic logging", e.diagnostic_logging_enabled);
  if (slug === "activity_log_alert_service_health") {
    if (e.reason === "no matching enabled activity log alert") return "No enabled alert matches Service Health incidents.";
    if (typeof e.alert === "string") return "An enabled alert matches Service Health incidents.";
  }
  if (["activity_log_storage_cmk", "activity_log_storage_private"].includes(slug) && list(e.storage_accounts)) return slug.endsWith("cmk")
    ? status === "FAIL" ? `${e.storage_accounts.length} activity-log storage destination${e.storage_accounts.length === 1 ? " uses" : "s use"} platform-managed keys.` : "Resolved activity-log storage destinations use Key Vault keys."
    : status === "FAIL" ? `${e.storage_accounts.length} activity-log storage destination${e.storage_accounts.length === 1 ? " permits" : "s permit"} blob public access.` : "Resolved activity-log storage destinations disable blob public access.";
  if (slug.startsWith("insights_") && slug.endsWith("_container_private")) {
    if (e.reason === "account disallows blob public access") return "The account blocks blob public access.";
    if (["None", "Container", "Blob"].includes(String(e.public_access))) return `The log container public-access ACL is ${e.public_access}.`;
  }
  if (slug === "log_analytics_public_ingestion_query_disabled" && typeof e.publicNetworkAccessForIngestion === "string" && typeof e.publicNetworkAccessForQuery === "string") return `Public ingestion is ${e.publicNetworkAccessForIngestion}; public query is ${e.publicNetworkAccessForQuery}.`;
  if (slug === "mssql_managed_instance_tde_cmk") {
    if (e.server_key_type === "AzureKeyVault") return "A Key Vault TDE protector with a key URI is declared.";
    if (list(e.server_key_types)) return `TDE protector types: ${shortList(e.server_key_types)}.`;
  }
  if (slug === "mssql_managed_instance_vulnerability_assessment") return toggle("Default vulnerability-assessment scan scheduling", e.recurring_scans_enabled);
  if (slug === "nsg_associated_with_subnet" && finite(e.subnets)) return `The NSG lists ${e.subnets} subnet association${e.subnets === 1 ? "" : "s"}.`;
  if (slug === "network_watcher_flow_logs_retention_90") {
    if (e.reason === "no flow logs configured") return "No flow logs are configured.";
    if (Array.isArray(e.flow_logs)) return e.flow_logs.length ? `${e.flow_logs.length} flow log${e.flow_logs.length === 1 ? " is" : "s are"} disabled or configured below 90 days of retention.` : "Listed flow logs are enabled with 90-day or unlimited retention.";
  }
  if (slug === "defender_default_policy_enforced" && list(e.modes)) return `Applicable initiative enforcement modes: ${shortList(e.modes)}.`;
  if (slug === "recovery_vault_managed_identity") return e.identity === null || e.identity_type === "None" ? "The vault declares no managed identity." : typeof e.identity_type === "string" ? `Vault identity type is ${e.identity_type}.` : undefined;
  if (slug === "recovery_vault_backup_retention_30_days") {
    if (e.reason === "no backup policies configured") return "No backup policies are configured.";
    if (Array.isArray(e.short_policies)) return `${e.short_policies.length} daily backup polic${e.short_policies.length === 1 ? "y has" : "ies have"} a retention count below 30.`;
    if (finite(e.evaluated_policies)) return `${e.evaluated_policies} daily backup polic${e.evaluated_policies === 1 ? "y meets" : "ies meet"} the retention-count threshold.`;
  }
  if (slug === "recovery_vault_has_protected_items" && finite(e.protected_items)) return `${e.protected_items} protected backup item${e.protected_items === 1 ? " is" : "s are"} listed.`;
  if (["redis_cache_ssl_enabled"].includes(slug)) return toggle("Non-TLS Redis port", e.non_ssl_port_enabled);
  if (slug === "redis_cache_min_tls_1_2" && typeof e.minimum_tls === "string") return `Declared Redis minimum TLS version is ${e.minimum_tls}.`;
  if (["redis_cache_no_basic_sku", "app_configuration_sku_standard", "search_service_uses_sku_supporting_private_link", "storage_account_geo_redundant_enabled"].includes(slug) && typeof e.sku === "string") return `Declared service SKU is ${e.sku}.`;
  if (slug === "redis_cache_in_virtual_network") return e.subnet_id === null ? "No Redis subnet ID is declared." : typeof e.subnet_id === "string" ? "A Redis subnet ID is declared." : undefined;
  if (slug === "cognitive_service_local_auth_disabled" && typeof e.local_auth_disabled === "boolean") return `Local-key authentication is ${e.local_auth_disabled ? "disabled" : "enabled"}.`;
  if (["cognitive_account_public_network_access_disabled", "data_factory_public_network_access_disabled", "search_service_public_network_access_disabled"].includes(slug) && typeof e.public_network_access === "string") return `Public networking is ${e.public_network_access.toLowerCase()}.`;
  if (slug === "cognitive_account_restrict_public_access") {
    if (typeof e.default_action === "string") return `The default network action is ${e.default_action.toLowerCase()}.`;
    if (list(e.capabilities) && !e.capabilities.includes("VirtualNetworks")) return "VirtualNetworks capability is absent; this conditional ACL check does not evaluate isolation.";
  }
  if (slug === "cognitive_account_encrypted_with_cmk" && list(e.capabilities) && !e.capabilities.includes("CustomerManagedKey")) return "CustomerManagedKey capability is absent; this conditional check does not evaluate a dedicated key.";
  if (["cognitive_account_private_link_used", "redis_cache_uses_private_link", "app_configuration_private_link_used", "data_factory_uses_private_link", "search_service_uses_private_link", "keyvault_vault_private_link_used"].includes(slug)) {
    if (slug === "keyvault_vault_private_link_used" && e.default_action === "Allow") return "The default vault network action is allow.";
    if (list(e.approval_states)) return `Private endpoint states: ${e.approval_states.length ? shortList(e.approval_states) : "no connections"}.${slug === "cognitive_account_private_link_used" && list(e.capabilities) ? ` Virtual-network capability is ${e.capabilities.includes("VirtualNetworks") ? "present" : "absent"}.` : ""}`;
  }
  if (["app_configuration_encryption_enabled", "data_factory_encrypted_with_cmk", "data_factory_uses_git_repository"].includes(slug)) {
    const [key, label] = slug === "app_configuration_encryption_enabled" ? ["key_identifier", "customer-managed key identifier"] : slug === "data_factory_encrypted_with_cmk" ? ["vault_base_url", "encryption vault URL"] : ["repository_name", "source-control repository name"];
    if (e[key] === null || typeof e[key] === "string") return `${e[key] === null ? "No" : "A"} ${label} is declared.`;
  }
  if (slug === "apimanagement_service_with_virtual_network" && typeof e.virtual_network_type === "string") return `API Management virtual-network mode is ${e.virtual_network_type}.`;
  if (slug === "search_service_uses_managed_identity" && typeof e.identity_type === "string") return `Search identity type is ${e.identity_type}.`;
  if (/^keyvault_(?:(?:with_rbac|with_non_rbac)_)?(?:key|secret)_expiration_set$/.test(slug)) return e.enabled === false ? "The object is disabled; this check does not require its expiration." : typeof e.expiration_configured === "boolean" ? `An expiration timestamp is ${e.expiration_configured ? "configured" : "not configured"}.` : undefined;
  if (slug === "keyvault_key_automatic_rotation_enabled" && list(e.rotate_after_create)) return e.rotate_after_create.length ? `Automatic rotation is scheduled ${shortList(e.rotate_after_create)} after creation.` : "No Rotate/timeAfterCreate schedule is configured.";
  if (slug === "keyvault_logging_enabled" && list(e.enabled_category_groups)) return `Enabled vault log groups: ${e.enabled_category_groups.length ? shortList(e.enabled_category_groups) : "none"}.`;
  if (slug === "keyvault_public_network_access_disabled" && typeof e.default_action === "string") return `The vault network ACL default action is ${e.default_action.toLowerCase()}.`;
  if (["storage_account_key_rotation_reminder_enabled"].includes(slug)) return e.key_policy === null ? "No key-expiration reminder policy is declared." : finite(e.configured_days) ? `The key-expiration reminder is configured for ${e.configured_days} days.` : undefined;
  if (slug === "storage_account_soft_delete_enabled") return toggle("Blob soft delete", e.enabled);
  if (["storage_account_blob_soft_delete_enabled", "storage_account_container_soft_delete_enabled"].includes(slug)) return e.enabled === false ? `${slug.includes("container") ? "Container" : "Blob"} soft delete is disabled.` : e.enabled === true && finite(e.days) ? `${slug.includes("container") ? "Container" : "Blob"} soft-delete retention is ${e.days} days.` : undefined;
  if (slug === "storage_account_blob_and_container_soft_delete_enabled") {
    const policy = (value: unknown) => {
      if (!value || typeof value !== "object") return undefined;
      const item = value as Record<string, unknown>;
      return item.enabled === false ? "disabled" : item.enabled === true && finite(item.days) ? `${item.days} days` : undefined;
    };
    const blob = policy(e.blob), container = policy(e.container);
    if (blob && container) return `Soft delete: blobs ${blob}; containers ${container}.`;
  }
  if (slug === "storage_account_blob_versioning_enabled") return toggle("Blob versioning", e.versioning_enabled);
  if (slug.startsWith("storage_account_file_share_smb_") && typeof e.configured === "string") return `Allowed SMB ${slug.includes("channel_encryption") ? "ciphers" : "versions"}: ${e.configured}.`;
  if (slug === "storage_account_access_keys_periodically_regenerated" && e.days_since_creation && typeof e.days_since_creation === "object") {
    const ages = Object.values(e.days_since_creation);
    if (ages.length && ages.every(finite)) return `The oldest reported storage key was created ${Math.ceil(Math.max(...ages) * 1000) / 1000} days before capture.`;
  }
  if (["search_service_logging_enabled", "servicebus_namespace_logging_enabled", "stream_analytics_job_logging_enabled"].includes(slug) && list(e.settings_with_enabled_logs)) return e.settings_with_enabled_logs.length ? "At least one diagnostic setting enables resource logs." : "No diagnostic setting enables resource logs.";
  if (slug === "search_service_replica_count_above_3" && finite(e.replica_count)) return `Search declares ${e.replica_count} replica${e.replica_count === 1 ? "" : "s"}.`;
  if (slug === "defender_contact_has_email" && finite(e.email_count)) return `The security contact has ${e.email_count} nonblank email entr${e.email_count === 1 ? "y" : "ies"}.`;
  if (slug === "defender_attack_path_notifications") return e.attack_path_source === false ? "No AttackPath notification source is configured." : typeof e.minimal_risk_level === "string" ? `The attack-path notification threshold is ${e.minimal_risk_level}.` : undefined;
  if (slug === "defender_security_contact_email_configured" && list(e.contacts)) return e.contacts.some(name => name !== "default") ? "A non-default security contact is configured; this check does not inspect its email." : typeof e.default_has_email === "boolean" ? `The default contact ${e.default_has_email ? "has" : "does not have"} a nonblank email.` : undefined;
  if (slug === "defender_alert_notifications_high" && typeof e.role_notifications_on === "boolean" && typeof e.alert_minimal_severity_high === "boolean") return `Role notifications are ${e.role_notifications_on ? "on" : "off"}; an exact High-severity alert source is ${e.alert_minimal_severity_high ? "configured" : "not configured"}.`;
  if (slug === "defender_alerts_to_owner" && typeof e.owner_notified === "boolean") return `Owner-role notifications are ${e.owner_notified ? "configured" : "not configured"}.`;
  if (["defender_container_registry_plan_standard", "defender_dns_plan_standard", "defender_kubernetes_plan_standard", "defender_plan_standard_any"].includes(slug) && typeof e.plan === "string" && typeof e.pricing_tier === "string") return `The ${e.plan} protection plan tier is ${e.pricing_tier}.`;
  if (slug === "defender_database_plans_standard" && e.pricing_tiers && typeof e.pricing_tiers === "object") {
    const entries = Object.entries(e.pricing_tiers);
    if (entries.every(([, tier]) => ["Free", "Standard"].includes(String(tier)))) {
      const free = entries.filter(([, tier]) => tier === "Free").map(([name]) => name);
      return free.length ? `Free database protection plans: ${shortList(free)}.` : "All four listed database protection plans are Standard.";
    }
  }
  if (slug === "defender_container_registry_vulnerability_scanning") return e.pricing_tier === "Free" ? "The Containers protection plan is Free." : list(e.extension_states) ? `Registry assessment extension states: ${e.extension_states.length ? shortList(e.extension_states) : "not configured"}.` : undefined;
  if (slug.startsWith("defender_assessment_") && e.unhealthy_counts && typeof e.unhealthy_counts === "object") {
    const counts = Object.values(e.unhealthy_counts);
    if (counts.every(finite)) return counts.length ? `${counts.reduce((total, count) => total + count, 0)} matching Defender assessment record${counts.reduce((total, count) => total + count, 0) === 1 ? " is" : "s are"} Unhealthy.` : "No matching Defender assessment record is Unhealthy.";
  }
  if (slug === "servicefabric_cluster_entra_auth" && typeof e.entra_configured === "boolean") return `An Entra configuration object is ${e.entra_configured ? "declared" : "not declared"}.`;
  if (slug === "servicefabric_cluster_encrypt_and_sign" && typeof e.encrypt_and_sign === "boolean") return `An EncryptAndSign parameter value was ${e.encrypt_and_sign ? "found" : "not found"} in the cluster settings.`;
  if (slug === "signalr_service_private_link" && list(e.connection_states)) return e.connection_states.length ? `Private endpoint states: ${shortList(e.connection_states)}.` : "No private endpoint connections are listed.";
  if (slug === "spring_cloud_service_vnet_injection") return e.service_runtime_subnet === null ? "No service-runtime subnet is declared." : typeof e.service_runtime_subnet === "string" ? "A service-runtime subnet is declared." : undefined;
  if (slug === "sql_database_long_term_retention" && e.retention && typeof e.retention === "object") {
    const periods = Object.entries(e.retention);
    if (periods.every(([, value]) => typeof value === "string")) {
      const nonzero = periods.filter(([, value]) => /[1-9]/.test(String(value)));
      return nonzero.length ? `Nonzero long-term retention intervals: ${shortList(nonzero.map(([name, value]) => `${name.replace("Retention", "")} ${value}`))}.` : "Weekly, monthly and yearly long-term retention are all disabled.";
    }
  }
  if (["sql_audit_storage_retention_90", "sql_audit_retention_over_90"].includes(slug)) return e.state === "Disabled" ? "SQL auditing is disabled." : finite(e.retention_days) ? e.retention_days === 0 ? "SQL audit retention is unlimited." : `SQL audit retention is ${e.retention_days} days.` : undefined;
  if (slug === "sql_va_recurring_scans") return toggle("Recurring vulnerability-assessment scans", e.recurring_scans);
  if (slug === "sql_va_notify_admins" && typeof e.email_subscription_admins === "boolean") return `Assessment emails to subscription administrators are ${e.email_subscription_admins ? "enabled" : "disabled"}.`;
  if (slug === "sql_va_report_emails" && finite(e.email_count)) return `${e.email_count} nonblank assessment-report recipient${e.email_count === 1 ? " is" : "s are"} configured.`;
  if (slug === "sql_va_reports_configured" && typeof e.email_subscription_admins === "boolean") return e.email_subscription_admins ? "Administrator assessment notifications are enabled." : status === "PASS" ? "Nonblank assessment-report recipients are configured." : "No administrator notifications or nonblank assessment-report recipients are configured.";
  if (slug === "storage_trusted_azure_services_bypass" && list(e.bypass)) return `The trusted Azure-services network bypass is ${e.bypass.includes("AzureServices") ? "configured" : "not configured"}.`;
  if (/^storage_(blob|queue|table)_(classic|diagnostic)_logging$/.test(slug) && [e.read, e.write, e.delete].every(value => typeof value === "boolean")) {
    const missing = ["read", "write", "delete"].filter(key => e[key] === false);
    return missing.length ? `${e.service} logging omits ${missing.join(", ")} operations.` : `${e.service} read, write and delete logging are enabled.`;
  }
  if (slug === "synapse_workspace_vulnerability_assessment" && Array.isArray(e.recurring_scans) && e.recurring_scans.every(value => typeof value === "boolean")) return e.recurring_scans.includes(true) ? "A Synapse SQL assessment has recurring scans enabled." : "No listed Synapse SQL assessment has recurring scans enabled.";
  if (slug === "servicebus_premium_namespace_cmk" || slug.endsWith("_container_byok") || ["cognitive_account_encrypted_with_cmk", "storage_account_encryption_at_rest_using_cmk"].includes(slug)) {
    if (e.key_source === null) return "No customer-managed key source is declared; the platform default applies.";
    if (typeof e.key_source === "string") return ["microsoft.keyvault", "azurekeyvault"].includes(e.key_source.toLowerCase()) ? "A Key Vault key source is declared." : `The declared key source is ${e.key_source}.`;
  }
  return undefined;
}

const nextAzureFamilyIds = new Set([
  "azure.claude.acr_geo_replication",
  "azure.claude.acr_private_endpoint_present",
  "azure.claude.acr_private_link_approved",
  "azure.claude.acr_vnet_service_endpoint",
  "azure.claude.container_group_cmk",
  "azure.claude.container_group_managed_identity",
  "azure.claude.container_group_secure_environment_variables",
  "azure.claude.container_group_virtual_network",
  "azure.claude.cosmos_cmk",
  "azure.claude.cosmos_cors_no_wildcard",
  "azure.claude.cosmos_network_restricted",
  "azure.claude.cosmos_private_endpoint_present",
  "azure.claude.cosmos_vnet_service_endpoint",
  "azure.claude.databox_edge_double_encryption",
  "azure.claude.databricks_diagnostic_log_delivery",
  "azure.claude.databricks_managed_disk_cmk",
  "azure.claude.databricks_subnet_nsg",
  "azure.claude.databricks_vnet_injection_value",
  "azure.claude.disk_access_private_link",
  "azure.claude.disk_attached_cmk",
  "azure.claude.disk_attached_customer_key",
  "azure.claude.disk_attached_double_encryption",
  "azure.claude.disk_unattached_cmk",
  "azure.claude.disk_unattached_customer_key",
  "azure.claude.vm_antimalware_auto_upgrade",
  "azure.claude.vm_antimalware_extension",
  "azure.claude.vm_backup_daily_retention_7_days",
  "azure.claude.vm_backup_protected",
  "azure.claude.vm_dependency_agent_linux",
  "azure.claude.vm_dependency_agent_windows",
  "azure.claude.vm_guest_configuration_extension",
  "azure.claude.vm_guest_configuration_extension_linux",
  "azure.claude.vm_guest_configuration_extension_windows",
  "azure.claude.vm_guest_configuration_managed_identity",
  "azure.claude.vm_guest_configuration_system_identity",
  "azure.claude.vm_guest_configuration_user_and_system_identity",
  "azure.claude.vm_jit_access",
  "azure.claude.vm_linux_no_passwordless_accounts",
  "azure.claude.vm_linux_remote_requires_password",
  "azure.claude.vm_linux_security_baseline",
  "azure.claude.vm_nic_nsg_internet_tcp_ingress",
  "azure.claude.vm_no_public_ip",
  "azure.claude.vm_nsg_internet_management_ports",
  "azure.claude.vm_os_managed_disk",
  "azure.claude.vm_site_recovery_enabled",
  "azure.claude.vm_windows_automatic_updates",
  "azure.claude.vm_windows_exploit_guard",
  "azure.claude.vm_windows_max_password_age",
  "azure.claude.vm_windows_min_password_age",
  "azure.claude.vm_windows_min_password_length",
  "azure.claude.vm_windows_no_reversible_password_encryption",
  "azure.claude.vm_windows_password_complexity",
  "azure.claude.vm_windows_password_history",
  "azure.claude.vm_windows_secure_boot",
  "azure.claude.vm_windows_secure_protocol_tls13",
  "azure.claude.vm_windows_security_baseline",
  "azure.claude.vmss_linux_ssh_keys",
  "azure.claude.vmss_load_balancer_backend",
  "azure.claude.vmss_managed_disks",
  "azure.claude.vmss_not_empty",
  "azure.claude2.activity_log_alert_service_health",
  "azure.claude2.api_app_client_certificates",
  "azure.claude2.api_app_cors_no_wildcard",
  "azure.claude2.api_app_ftps_required",
  "azure.claude2.api_app_https_only",
  "azure.claude2.api_app_managed_identity",
  "azure.claude2.api_app_min_tls_12",
  "azure.claude2.api_app_remote_debugging_disabled",
  "azure.claude2.app_service_environment_internal_encryption",
  "azure.claude2.app_service_plan_minimum_sku",
  "azure.claude2.app_workers_more_than_one",
  "azure.claude2.application_insights_configured",
  "azure.claude2.application_insights_public_access_blocked",
  "azure.claude2.defender_attack_path_setting_and_alert_contacts",
  "azure.claude2.function_app_authentication_enabled",
  "azure.claude2.function_app_client_certificates",
  "azure.claude2.function_app_managed_identity",
  "azure.claude2.function_app_restrict_public_access",
  "azure.claude2.iam_no_custom_owner_roles",
  "azure.claude2.nsg_flow_logs_to_log_analytics",
  "azure.claude2.prowler_app_authentication",
  "azure.claude2.prowler_app_client_certificates_required",
  "azure.claude2.prowler_app_http_logs",
  "azure.claude2.prowler_app_identity",
  "azure.claude2.prowler_function_ftp_ftps_disabled",
  "azure.claude2.prowler_function_identity",
  "azure.claude2.prowler_function_identity_not_admin",
  "azure.claude2.prowler_function_not_public",
  "azure.claude2.prowler_function_vnet_integration",
  "azure.claude2.vnet_flow_logs_to_log_analytics",
  "azure.claude2.web_app_always_on",
  "azure.claude2.web_app_authentication_enabled",
  "azure.claude2.web_app_client_certificates",
  "azure.claude2.web_app_diagnostic_http_log_category",
  "azure.claude2.web_app_diagnostic_logs_enabled",
  "azure.claude2.web_app_failed_request_tracing",
  "azure.claude2.web_app_ftps_required",
  "azure.claude2.web_app_health_check",
  "azure.claude2.web_app_incoming_client_cert",
  "azure.claude2.web_app_managed_identity",
  "azure.claude2.web_app_register_with_entra",
  "azure.claude2.web_app_remote_debugging_disabled",
  "azure.claude2.web_app_slot_https_only",
  "azure.claude2.web_app_vnet_connection",
  "azure.disk.private_export",
  "azure.port.ad_authorization_policy_guest_invite_restricted",
  "azure.port.ad_authorization_policy_guest_user_access_restricted",
  "azure.port.ad_authorization_policy_user_consent_disallowed",
  "azure.port.ad_authorization_policy_user_consent_verified_publishers_selected_permissions",
  "azure.port.ad_security_defaults_policy_enabled",
  "azure.port.cosmosdb_account_uses_private_link",
  "azure.port.cosmosdb_account_virtual_network_filter_enabled",
  "azure.port.databricks_workspace_deployed_in_custom_vnet",
  "azure.port.databricks_workspace_uses_private_endpoint",
  "azure.port.defender_alert_severity_contact",
  "azure.port.defender_notify_owner_contact",
  "azure.port.defender_required_mcas",
  "azure.port.defender_required_wdatp",
  "azure.port.iam_user_not_allowed_to_create_security_group",
  "azure.port.iam_user_not_allowed_to_register_application",
  "azure.port.keyvault_vault_recoverable",
  "azure.port.monitor_log_alert_create_policy_assignment",
  "azure.port.monitor_log_alert_create_update_nsg",
  "azure.port.monitor_log_alert_create_update_public_ip_address",
  "azure.port.monitor_log_alert_create_update_security_solution",
  "azure.port.monitor_log_alert_create_update_sql_servers_firewall_rule",
  "azure.port.monitor_log_alert_delete_nsg",
  "azure.port.monitor_log_alert_delete_policy_assignment",
  "azure.port.monitor_log_alert_delete_public_ip_address",
  "azure.port.monitor_log_alert_delete_security_solution",
  "azure.port.monitor_log_alert_delete_sql_servers_firewall_rule",
  "azure.port.security_center_defender_for_api_enabled",
  "azure.port.security_center_defender_for_cloudposture_enabled",
  "azure.port.securitycenter_azure_defender_on_for_appservice",
  "azure.port.securitycenter_azure_defender_on_for_containerregistry",
  "azure.port.securitycenter_azure_defender_on_for_containers",
  "azure.port.securitycenter_azure_defender_on_for_cosmosdb",
  "azure.port.securitycenter_azure_defender_on_for_database",
  "azure.port.securitycenter_azure_defender_on_for_dns",
  "azure.port.securitycenter_azure_defender_on_for_k8s",
  "azure.port.securitycenter_azure_defender_on_for_keyvault",
  "azure.port.securitycenter_azure_defender_on_for_opensource_relational_db",
  "azure.port.securitycenter_azure_defender_on_for_resource_manager",
  "azure.port.securitycenter_azure_defender_on_for_server",
  "azure.port.securitycenter_azure_defender_on_for_sqldb",
  "azure.port.securitycenter_azure_defender_on_for_sqlservervm",
  "azure.port.securitycenter_azure_defender_on_for_storage",
  "azure.port.securitycenter_mcas_integration",
  "azure.port.securitycenter_wdatp_integration",
  "azure.port.storage_account_trusted_microsoft_services_enabled"
]);
function sourceFamilyAzureEvidence(checkId: string, e: Record<string, unknown>, status: string): string | undefined {
  if (!nextAzureFamilyIds.has(checkId)) return undefined;
  const slug = checkId.replace(/^azure\.(?:claude2?|port)\./, "");
  if (checkId === "azure.disk.private_export" && typeof e.public_network_access === "string" && typeof e.network_access_policy === "string") return `Disk export public networking is ${e.public_network_access}; network policy is ${e.network_access_policy}.`;
  if (e.field && typeof e.configured === "boolean") {
    const names: Record<string, string> = { "properties.clientCertEnabled": "Incoming client certificates", "properties.httpsOnly": "HTTPS-only access", "defaultUserRolePermissions.allowedToCreateApps": "Default-user application registration", "defaultUserRolePermissions.allowedToCreateSecurityGroups": "Default-user security-group creation", isEnabled: "Security Defaults" };
    if (typeof e.field === "string" && names[e.field]) return `${names[e.field]} ${e.field === "properties.clientCertEnabled" ? "are" : "is"} ${e.configured ? "enabled" : "disabled"}.`;
  }
  if (typeof e.plan === "string" && typeof e.pricing_tier === "string") return `The ${e.plan} protection plan tier is ${e.pricing_tier}.${typeof e.replacement === "string" ? ` Its supported replacement is ${e.replacement}.` : ""}`;
  if (slug === "securitycenter_azure_defender_on_for_database" && e.pricing_tiers && typeof e.pricing_tiers === "object") {
    const entries = Object.entries(e.pricing_tiers);
    if (entries.every(([, tier]) => tier === null || ["Free", "Standard"].includes(String(tier)))) {
      const absent = entries.filter(([, tier]) => tier === null).map(([name]) => name);
      const free = entries.filter(([, tier]) => tier === "Free").map(([name]) => name);
      return [absent.length ? `No plan is listed for ${shortList(absent)}.` : "", free.length ? `Free protection plans: ${shortList(free)}.` : "", !absent.length && !free.length ? "All four listed database protection plans are Standard." : ""].filter(Boolean).join(" ");
    }
  }
  if (typeof e.setting === "string") return e.observed_count === 0 ? `No ${e.setting} integration setting is listed.` : typeof e.enabled === "boolean" ? `The ${e.setting} integration is ${e.enabled ? "enabled" : "disabled"}.` : undefined;
  if (slug === "defender_notify_owner_contact" && typeof e.notification_state === "string" && list(e.roles)) return `Role notifications are ${e.notification_state}; Owner is ${e.roles.includes("Owner") ? "included" : "not included"}.`;
  if (slug === "defender_alert_severity_contact") return e.minimal_severity === null ? "No non-null Alert minimum severity is declared." : typeof e.minimal_severity === "string" ? `The selected Alert notification threshold is ${e.minimal_severity}.` : undefined;
  if (["cosmosdb_account_uses_private_link", "databricks_workspace_uses_private_endpoint"].includes(slug) && list(e.approval_states)) return e.approval_states.length ? `Private endpoint states: ${shortList(e.approval_states)}.` : "No private endpoint connections are listed.";
  if (slug === "cosmosdb_account_virtual_network_filter_enabled") return e.public_network_access === "Disabled" ? "Public Cosmos DB networking is disabled." : typeof e.vnet_filter_enabled === "boolean" ? `Public Cosmos DB networking is enabled; VNet filtering is ${e.vnet_filter_enabled ? "enabled" : "disabled"}.` : undefined;
  if (slug === "databricks_workspace_deployed_in_custom_vnet" && typeof e.parameter_declared === "boolean") return `A custom-VNet parameter object is ${e.parameter_declared ? "declared" : "not declared"}.`;
  if (slug === "keyvault_vault_recoverable" && typeof e.soft_delete_enabled === "boolean" && typeof e.purge_protection_enabled === "boolean") return `Vault soft delete is ${e.soft_delete_enabled ? "enabled" : "disabled"}; purge protection is ${e.purge_protection_enabled ? "enabled" : "disabled"}.`;
  if (slug === "storage_account_trusted_microsoft_services_enabled" && typeof e.configured_bypass === "string") return `Storage network bypasses: ${e.configured_bypass}.`;
  if (slug === "ad_authorization_policy_guest_invite_restricted" && typeof e.allow_invites_from === "string") return `Guest invitations are configured for ${e.allow_invites_from}.`;
  if (slug === "ad_authorization_policy_guest_user_access_restricted" && typeof e.guest_user_role_id === "string") {
    const roles: Record<string, string> = { "2af84b1e-32c8-42b7-82bc-daa82404023b": "Restricted Guest User", "10dae51f-b6af-4016-8d66-8c2a99b929b3": "Guest User", "a0b1b346-4d3e-4e8b-98f8-753987be4970": "User" };
    if (roles[e.guest_user_role_id]) return `The default guest role template is ${roles[e.guest_user_role_id]}.`;
  }
  if (slug === "ad_authorization_policy_user_consent_disallowed" && list(e.self_consent_policies)) return e.self_consent_policies.length ? `${e.self_consent_policies.length} default-user self-consent polic${e.self_consent_policies.length === 1 ? "y is" : "ies are"} assigned.` : "No default-user self-consent policy is assigned.";
  if (slug === "ad_authorization_policy_user_consent_verified_publishers_selected_permissions" && list(e.permission_grant_policies)) return e.permission_grant_policies.length ? `Assigned consent policies: ${shortList(e.permission_grant_policies)}.` : "No consent policy is assigned; this exact low-risk-policy preference is not met.";
  if (Array.isArray(e.matching_alert_ids) && list(e.matching_alert_ids) && typeof e.operation === "string") return `${e.matching_alert_ids.length ? "An" : "No"} enabled Global subscription alert matches ${e.operation}.`;
  if (typeof e.encryption_type === "string" && typeof e.disk_state === "string") {
    const types: Record<string, string> = { EncryptionAtRestWithPlatformKey: "a platform-managed key", EncryptionAtRestWithCustomerKey: "a customer-managed key", EncryptionAtRestWithPlatformAndCustomerKeys: "platform and customer-managed keys" };
    if (types[e.encryption_type]) return `The ${e.disk_state.toLowerCase()} disk selects ${types[e.encryption_type]}.`;
  }
  if (["disk_access_private_link", "acr_private_link_approved"].includes(slug) && list(e.connection_states)) return e.connection_states.length ? `Private endpoint states: ${shortList(e.connection_states)}.` : "No private endpoint connections are listed.";
  if (list(e.matching_extensions)) return e.matching_extensions.length ? "A matching extension declaration is listed." : "No extension matches this check's publisher, type and state criteria.";
  if (list(e.identity_types)) return e.identity_types.length ? `Declared managed identity types: ${shortList(e.identity_types)}.` : "No managed identity type is declared.";
  if (typeof e.configuration === "string" && list(e.statuses)) return `Machine Configuration reports ${e.configuration}: ${shortList(e.statuses)}.`;
  if (slug === "vm_os_managed_disk") return e.unmanaged_os_disk === true ? "The OS disk declares an unmanaged VHD." : typeof e.managed_disk_id === "string" ? "A managed OS disk ID is declared." : undefined;
  if (slug === "vm_windows_automatic_updates") return toggle("Windows automatic updates", e.enable_automatic_updates);
  if (slug === "vm_windows_secure_boot") return e.security_type === "Standard" ? "The VM uses the Standard security profile." : typeof e.secure_boot === "boolean" ? `The VM uses ${e.security_type}; Secure Boot is ${e.secure_boot ? "enabled" : "disabled"}.` : undefined;
  if (slug === "vm_no_public_ip" && list(e.public_ip_ids)) return e.public_ip_ids.length ? "A VM NIC references a public IP address." : "No VM NIC public-IP reference is listed.";
  if (["vm_nic_nsg_internet_tcp_ingress", "vm_nsg_internet_management_ports"].includes(slug) && Array.isArray(e.internet_allow_rules)) {
    if (!e.internet_allow_rules.length) return "No matching internet-source Allow declaration is listed on the selected NSGs.";
    const ports: string[] = [];
    for (const rule of e.internet_allow_rules) {
      if (!rule || typeof rule !== "object") return undefined;
      const r = rule as Record<string, unknown>;
      if (!list(r.ports)) return undefined;
      ports.push(...r.ports);
    }
    return `NSG Allow declarations admit internet sources on ports ${shortList([...new Set(ports)])}.`;
  }
  if (slug === "vm_jit_access" && list(e.jit_policies)) return e.jit_policies.length ? "A listed just-in-time policy contains this VM ID." : "No listed just-in-time policy contains this VM ID.";
  if (slug === "vm_site_recovery_enabled" && list(e.asr_links)) return e.asr_links.length ? "A matching ASR-Protect resource link is listed." : "No matching ASR-Protect resource link is listed.";
  if (slug === "vm_backup_protected" && list(e.protected_items)) return e.protected_items.length ? "An Azure Backup protected-item record matches this VM." : "No Azure Backup protected-item record matches this VM.";
  if (slug === "vm_backup_daily_retention_7_days" && finite(e.retention_days)) return `The matched VM backup policy declares ${e.retention_days} days of daily retention.`;
  if (slug === "vmss_linux_ssh_keys" && typeof e.password_authentication_disabled === "boolean") return `Linux scale-set SSH password authentication is ${e.password_authentication_disabled ? "disabled" : "enabled"}.`;
  if (slug === "vmss_managed_disks") return e.unmanaged_os_disk === true ? "The scale-set OS disk declares unmanaged VHD containers." : finite(e.data_disk_count) ? "The scale set declares managed OS and data-disk objects." : undefined;
  if (slug === "vmss_load_balancer_backend" && list(e.backend_pools)) return e.backend_pools.length ? "A scale-set NIC configuration references a load-balancer backend pool." : "No scale-set NIC configuration references a load-balancer backend pool.";
  if (slug === "vmss_not_empty" && finite(e.capacity)) return `Declared scale-set capacity is ${e.capacity}.`;
  if (slug === "container_group_cmk" && typeof e.customer_key_configured === "boolean") return e.customer_key_configured ? "An encryption vault URL and key name are declared." : "No complete encryption vault-URL and key-name declaration is present.";
  if (slug === "container_group_virtual_network" && list(e.subnet_ids)) return e.subnet_ids.length ? "The container group declares a subnet attachment." : "The container group declares no subnet attachment.";
  if (slug === "container_group_secure_environment_variables" && list(e.plain_value_variables)) return e.plain_value_variables.length ? `${e.plain_value_variables.length} environment variable${e.plain_value_variables.length === 1 ? " uses" : "s use"} a plain value; values are not displayed.` : "No environment variable has a non-null plain value.";
  if (slug === "acr_geo_replication" && list(e.replication_regions)) return `Listed registry replication regions: ${e.replication_regions.length ? shortList(e.replication_regions) : "none"}.`;
  if (slug === "acr_vnet_service_endpoint") return e.default_action === "Allow" ? "The registry network default action is allow." : list(e.virtual_network_rules) ? `The registry defaults to deny and lists ${e.virtual_network_rules.length} subnet rule${e.virtual_network_rules.length === 1 ? "" : "s"}.` : undefined;
  if (["acr_private_endpoint_present", "cosmos_private_endpoint_present"].includes(slug) && list(e.private_endpoints)) return e.private_endpoints.length ? "A private endpoint ID is listed; approval is evaluated separately." : "No private endpoint ID is listed.";
  if (slug === "cosmos_cmk" && typeof e.key_vault_key_uri_present === "boolean") return `A Key Vault key URI is ${e.key_vault_key_uri_present ? "declared" : "not declared"}.`;
  if (slug === "cosmos_cors_no_wildcard" && list(e.wildcard_rules)) return e.wildcard_rules.length ? "A CORS rule allows every browser origin." : "No CORS rule contains the literal wildcard origin.";
  if (slug === "cosmos_network_restricted") return e.public_network_access === "Disabled" || e.public_network_access === "SecuredByPerimeter" ? `Public networking is ${e.public_network_access}.` : typeof e.virtual_network_filter === "boolean" && finite(e.ip_rule_count) ? `Public networking is enabled; VNet filtering is ${e.virtual_network_filter ? "enabled" : "disabled"}, with ${e.ip_rule_count} IP rule${e.ip_rule_count === 1 ? "" : "s"}.` : undefined;
  if (slug === "cosmos_vnet_service_endpoint" && list(e.virtual_network_rules)) return `${e.virtual_network_rules.length} Cosmos DB subnet rule${e.virtual_network_rules.length === 1 ? " is" : "s are"} listed.`;
  if (slug === "databox_edge_double_encryption" && typeof e.sku === "string") return `The device SKU is ${e.sku}.`;
  if (slug === "databricks_managed_disk_cmk") return e.encryption === null || e.managed_disk_encryption === null ? "No customer-managed disk-encryption object is declared." : typeof e.key_properties_present === "boolean" ? `The managed-disk key-properties object is ${e.key_properties_present ? "nonempty" : "empty"}.` : undefined;
  if (slug === "databricks_diagnostic_log_delivery" && list(e.missing_categories)) return e.missing_categories.length ? `Missing Databricks log categories: ${shortList(e.missing_categories)}.` : "All six required Databricks log categories are enabled.";
  if (slug === "databricks_subnet_nsg" && list(e.subnets_without_nsg)) return e.subnets_without_nsg.length ? `Databricks subnets without an NSG: ${shortList(e.subnets_without_nsg)}.` : "Both named Databricks subnets reference an NSG.";
  if (slug === "databricks_vnet_injection_value") return e.custom_vnet_id === null || e.custom_vnet_id === "" ? "No nonempty custom-VNet parameter value is declared." : typeof e.custom_vnet_id === "string" ? "A custom-VNet parameter value is declared." : undefined;
  if (typeof e.ftps_state === "string") return e.ftps_state === "AllAllowed" ? "Plain FTP publishing is allowed." : e.ftps_state === "FtpsOnly" ? "FTP publishing requires TLS." : e.ftps_state === "Disabled" ? "FTP and FTPS publishing are disabled." : undefined;
  if (typeof e.min_tls_version === "string") return `The declared inbound minimum TLS version is ${e.min_tls_version}.`;
  if (typeof e.remote_debugging_enabled === "boolean") return toggle("Remote debugging", e.remote_debugging_enabled);
  if (typeof e.identity_type === "string") return e.identity_type === "None" ? "No managed identity is declared." : `Declared managed identity type is ${e.identity_type}.`;
  if (typeof e.authentication_enabled === "boolean") return toggle("App Service Authentication", e.authentication_enabled);
  if (typeof e.always_on === "boolean") return toggle("Always On", e.always_on);
  if (slug === "web_app_diagnostic_logs_enabled" && [e.detailedErrorLoggingEnabled, e.httpLoggingEnabled, e.requestTracingEnabled].every(value => typeof value === "boolean")) {
    const disabled = [e.detailedErrorLoggingEnabled ? "" : "detailed errors", e.httpLoggingEnabled ? "" : "HTTP logs", e.requestTracingEnabled ? "" : "request tracing"].filter(Boolean);
    return disabled.length ? `Disabled Windows IIS logging: ${disabled.join(", ")}.` : "Detailed errors, HTTP logs and request tracing are enabled.";
  }
  if (typeof e.failed_requests_tracing === "boolean") return toggle("Windows IIS failed-request tracing", e.failed_requests_tracing);
  if (Object.hasOwn(e, "health_check_path")) return e.health_check_path === null ? "No health-check path is declared." : e.health_check_path === "" ? "The declared health-check path is an empty string." : typeof e.health_check_path === "string" ? `The health-check path is ${e.health_check_path}.` : undefined;
  if (slug === "web_app_vnet_connection" && list(e.vnet_connection_ids)) return typeof e.regional_subnet_id === "string" ? "A regional integration subnet ID is declared." : e.vnet_connection_ids.length ? "A native VNet connection reference is declared." : "No regional subnet ID or native VNet connection reference is declared.";
  if (["web_app_diagnostic_http_log_category", "prowler_app_http_logs"].includes(slug) && list(e.settings)) return e.settings.length ? "A diagnostic setting enables the selected HTTP-log category." : "No diagnostic setting enables the selected HTTP-log category.";
  if (finite(e.number_of_workers)) return `The app declares ${e.number_of_workers} worker${e.number_of_workers === 1 ? "" : "s"}.`;
  if (list(e.allow_any_rules)) return e.allow_any_rules.length ? "An access-restriction rule explicitly allows Any source." : "No access-restriction rule explicitly allows Any source.";
  if (typeof e.client_cert_enabled === "boolean" && typeof e.client_cert_mode === "string") return `Incoming client certificates are ${e.client_cert_enabled ? "enabled" : "disabled"}; mode is ${e.client_cert_mode}.`;
  if (Object.hasOwn(e, "virtual_network_subnet_id")) return e.virtual_network_subnet_id === null ? "No VNet integration subnet ID is declared." : typeof e.virtual_network_subnet_id === "string" ? "A VNet integration subnet ID is declared." : undefined;
  if (slug === "prowler_function_not_public" && ["Enabled", "Disabled"].includes(String(e.public_network_access))) return `Function public-network access is ${String(e.public_network_access).toLowerCase()}.`;
  if (list(e.admin_role_ids)) return e.admin_role_ids.length ? "A listed broad administrative role is assigned to a function managed-identity principal." : "No listed broad administrative role is assigned to the function managed-identity principals.";
  if (typeof e.sku_name === "string") return `The App Service plan SKU is ${e.sku_name}.`;
  if (typeof e.internal_encryption === "boolean") return toggle("The InternalEncryption cluster setting", e.internal_encryption);
  if (typeof e.https_only === "boolean") return toggle("HTTPS-only access", e.https_only);
  if (typeof e.ingestion === "string" && typeof e.query === "string") return `Public ingestion is ${e.ingestion}; public query is ${e.query}.`;
  if (finite(e.components)) return `${e.components} Application Insights component${e.components === 1 ? " is" : "s are"} listed in the subscription.`;
  if (list(e.custom_owner_roles)) return e.custom_owner_roles.length ? `${e.custom_owner_roles.length} custom role${e.custom_owner_roles.length === 1 ? " declares" : "s declare"} a literal all-actions wildcard.` : "No custom role declares a literal all-actions wildcard.";
  if (["vnet_flow_logs_to_log_analytics", "nsg_flow_logs_to_log_analytics"].includes(slug) && list(e.flow_logs)) return e.flow_logs.length ? "A matching flow-log declaration has a nonblank Traffic Analytics workspace ID." : "No matching flow-log declaration has a nonblank Traffic Analytics workspace ID.";
  if (slug === "activity_log_alert_service_health" && list(e.alerts)) return e.alerts.length ? "An enabled Global subscription health alert is listed." : "No matching Global subscription health alert is listed.";
  if (typeof e.attack_path_enabled === "boolean" && finite(e.contacts_with_alert_notifications)) return `AttackPath settings are ${e.attack_path_enabled ? "enabled" : "disabled"}; ${e.contacts_with_alert_notifications} contact${e.contacts_with_alert_notifications === 1 ? " has" : "s have"} alert notifications configured.`;
  if (Object.hasOwn(e, "allowed_origins")) return e.allowed_origins === null ? "No CORS origin list is declared." : list(e.allowed_origins) ? e.allowed_origins.includes("*") ? "CORS allows every browser origin." : "The declared CORS origin list has no literal wildcard." : undefined;
  if (e.cors === "not configured") return "CORS is not configured.";
  return undefined;
}

const identityAzureIds = new Set(["azure.claude.entra_security_defaults_enabled", "azure.claude.entra_guest_invites_admins_only", "azure.claude.entra_guest_access_restricted", "azure.claude.entra_user_consent_disabled", "azure.claude.entra_user_consent_not_legacy", "azure.claude.entra_auth_methods_strong_registration", "azure.claude.entra_ca_mfa_admin_portals", "azure.claude.entra_ca_mfa_management_api", "azure.claude.entra_global_admin_fewer_than_five", "azure.claude.entra_trusted_named_location_exists", "azure.claude.entra_m365_group_creation_restricted", "azure.claude.entra_ca_policy_requires_mfa", "azure.claude.entra_named_location_trusted", "azure.claude.entra_app_credential_not_expiring", "azure.claude.entra_user_recent_sign_in", "azure.claude.entra_privileged_user_mfa", "azure.claude.entra_non_privileged_user_mfa", "azure.claude.entra_vm_access_user_mfa", "azure.claude.iam_no_user_access_administrator_assignment", "azure.claude.iam_user_no_contributor_assignment", "azure.claude.iam_custom_role_no_wildcard_actions", "azure.claude.iam_root_custom_role_no_wildcard", "azure.claude.iam_no_custom_role", "azure.claude.iam_custom_role_administers_locks", "azure.claude.iam_subscription_owner_between_2_and_3", "azure.claude.iam_subscription_owner_max_3", "azure.claude.iam_subscription_owner_more_than_1", "azure.claude.iam_external_user_no_owner", "azure.claude.iam_external_user_no_reader", "azure.claude.iam_external_user_no_write", "azure.claude.iam_disabled_user_no_role_assignment", "azure.claude.iam_disabled_user_no_owner", "azure.claude.iam_subscription_tenant_transfer_restricted"]);

function identityAzureEvidence(checkId: string, e: Record<string, unknown>): string | undefined {
  if (!identityAzureIds.has(checkId)) return undefined;
  const slug = checkId.replace("azure.claude.", "");
  if (slug === "entra_security_defaults_enabled" && typeof e.security_defaults_enabled === "boolean") {
    if (e.security_defaults_enabled) return "Security Defaults is enabled.";
    if (finite(e.enabled_ca_policy_count)) return `Security Defaults is disabled; ${e.enabled_ca_policy_count} enabled Conditional Access policies are listed.`;
  }
  if (slug === "entra_guest_invites_admins_only") {
    const invite: Record<string, string> = {none:"Guest invitations are disabled.",adminsAndGuestInviters:"Only administrators and Guest Inviters may invite guests.",adminsGuestInvitersAndAllMembers:"Members, administrators and Guest Inviters may invite guests.",everyone:"Everyone may invite guests."};
    if (typeof e.allow_invites_from === "string") return invite[e.allow_invites_from];
  }
  if (slug === "entra_guest_access_restricted") {
    const roles: Record<string,string> = {"2af84b1e-32c8-42b7-82bc-daa82404023b":"Guests have restricted directory visibility.","10dae51f-b6af-4016-8d66-8c2a99b929b3":"Guests have the standard guest directory visibility.","a0b1b346-4d3e-4e8b-98f8-753987be4970":"Guests have member-equivalent directory visibility."};
    if (typeof e.guest_user_role_id === "string") return roles[e.guest_user_role_id];
  }
  if (slug === "entra_user_consent_disabled" && Array.isArray(e.assigned_self_consent_policies)) return `${e.assigned_self_consent_policies.length} user self-consent ${e.assigned_self_consent_policies.length === 1 ? "policy is" : "policies are"} assigned.`;
  if (slug === "entra_user_consent_not_legacy" && typeof e.legacy_policy_assigned === "boolean") return `The legacy user self-consent policy is ${e.legacy_policy_assigned ? "assigned" : "not assigned"}.`;
  if (slug === "entra_auth_methods_strong_registration" && typeof e.registration_campaign === "string" && Array.isArray(e.enabled_strong_methods) && e.enabled_strong_methods.every(v=>typeof v === "string")) return `The registration campaign is ${e.registration_campaign}; enabled strong methods: ${e.enabled_strong_methods.join(", ") || "none"}.`;
  if (slug === "entra_ca_mfa_admin_portals" || slug === "entra_ca_mfa_management_api") {
    if (Array.isArray(e.matching_policies)) return `${e.matching_policies.length} enabled policies declare All users, ${slug.endsWith("admin_portals") ? "admin portals" : "the Azure management API"} and MFA.`;
  }
  if (slug === "entra_global_admin_fewer_than_five" && finite(e.global_administrators)) return `${e.global_administrators} distinct ${e.global_administrators === 1 ? "principal has" : "principals have"} active tenant-wide Global Administrator assignments.`;
  if (slug === "entra_trusted_named_location_exists" && Array.isArray(e.trusted_locations)) return `${e.trusted_locations.length} trusted IP named ${e.trusted_locations.length === 1 ? "location with declared ranges is" : "locations with declared ranges are"} listed.`;
  if (slug === "entra_m365_group_creation_restricted") {
    if (e.group_unified_setting === false) return "No Group.Unified restriction is set; users may create Microsoft 365 groups.";
    if (typeof e.enable_group_creation === "string" && ["true","false"].includes(e.enable_group_creation.toLowerCase())) return `Microsoft 365 group creation is ${e.enable_group_creation.toLowerCase() === "true" ? "allowed" : "restricted"} for default users.`;
  }
  if (slug === "entra_ca_policy_requires_mfa" && Array.isArray(e.built_in_controls) && e.built_in_controls.every(v=>typeof v === "string") && ["AND","OR"].includes(String(e.grant_operator))) {
    const controls = [...e.built_in_controls];
    if (e.authentication_strength_requirement === "mfa") controls.push("an MFA authentication strength");
    return `The enabled policy combines ${controls.join(", ") || "no built-in controls"} with ${e.grant_operator}.`;
  }
  if (slug === "entra_named_location_trusted" && typeof e.is_trusted === "boolean") return `The IP named location is ${e.is_trusted ? "marked" : "not marked"} trusted.`;
  if (slug === "entra_app_credential_not_expiring" && finite(e.credentials) && Array.isArray(e.credential_issues)) return e.credentials === 1 ? (e.credential_issues.length ? "The credential has no end date or expires within 30 days of the snapshot." : "The credential expires more than 30 days after the snapshot.") : `${e.credential_issues.length} of ${e.credentials} credentials have no end date or expire within 30 days of the snapshot.`;
  if (slug === "entra_user_recent_sign_in" && finite(e.days_since_successful_sign_in)) return `The last recorded successful sign-in was ${e.days_since_successful_sign_in} days before the snapshot.`;
  if (["entra_privileged_user_mfa","entra_non_privileged_user_mfa","entra_vm_access_user_mfa"].includes(slug) && typeof e.is_mfa_capable === "boolean") return `The user is ${e.is_mfa_capable ? "reported" : "not reported"} as MFA capable; sign-in enforcement is assessed separately.`;
  if (["iam_no_user_access_administrator_assignment","iam_user_no_contributor_assignment"].includes(slug) && typeof e.role === "string") {
    const names: Record<string,string> = {"acdd72a7-3385-48ef-bd42-f606fba81ae7":"Reader","18d7d88d-d35e-4fb5-a5c3-7773c20a72d9":"User Access Administrator","b24988ac-6180-42a0-ab88-20f7382dd24c":"Contributor","8e3af657-a8ff-443c-a75c-2fe8c4bcb635":"Owner"};
    return `The assignment grants ${names[e.role] || `role ${e.role}`}.`;
  }
  if (slug === "iam_custom_role_no_wildcard_actions" && Array.isArray(e.wildcard) && e.wildcard.every(v=>v === "*" || v === "*:*") ) return e.wildcard.length ? `The custom role declares global wildcard actions: ${e.wildcard.join(", ")}.` : "No literal global wildcard action is declared in the custom role.";
  if (slug === "iam_no_custom_role" && finite(e.custom_roles)) return `${e.custom_roles} custom role ${e.custom_roles === 1 ? "definition is" : "definitions are"} listed.`;
  if (slug === "iam_custom_role_administers_locks" && Array.isArray(e.lock_administrator_roles)) return `${e.lock_administrator_roles.length} custom roles declare a resource-lock action.`;
  if (slug.startsWith("iam_subscription_owner_") && finite(e.subscription_owners)) return `${e.subscription_owners} distinct Owner ${e.subscription_owners === 1 ? "principal is" : "principals are"} visible at or above the subscription.`;
  if (["iam_external_user_no_owner","iam_external_user_no_reader","iam_external_user_no_write","iam_disabled_user_no_role_assignment","iam_disabled_user_no_owner"].includes(slug) && Array.isArray(e.principals)) {
    const target: Record<string,string> = {iam_external_user_no_owner:"guest users have direct Owner assignments",iam_external_user_no_reader:"guest users have direct Reader assignments",iam_external_user_no_write:"guest users have direct Owner or Contributor assignments",iam_disabled_user_no_role_assignment:"disabled users retain direct role assignments",iam_disabled_user_no_owner:"disabled users retain direct Owner assignments"};
    return `${e.principals.length} ${e.principals.length === 1 ? target[slug].replace("users have", "user has").replace("users retain", "user retains") : target[slug]}.`;
  }
  if (slug === "iam_subscription_tenant_transfer_restricted" && typeof e.block_into_tenant === "boolean" && typeof e.block_leaving_tenant === "boolean") return `Tenant transfer: incoming subscriptions ${e.block_into_tenant ? "blocked" : "not blocked"}; outgoing subscriptions ${e.block_leaving_tenant ? "blocked" : "not blocked"}.`;
  return undefined;
}

const identityAdjacentAzureIds = new Set(["azure.claude.eventgrid_domain_managed_identity", "azure.claude.eventgrid_topic_managed_identity", "azure.claude.eventgrid_domain_private_link", "azure.claude.eventgrid_topic_private_link", "azure.claude.eventgrid_domain_public_access_disabled", "azure.claude.eventhub_namespace_logging", "azure.claude.iot_hub_logging", "azure.claude.eventhub_namespace_private_link", "azure.claude.iot_hub_private_link", "azure.claude.eventhub_namespace_vnet_rule", "azure.claude.frontdoor_waf_policy_linked", "azure.claude.hdinsight_cmk", "azure.claude.hdinsight_encryption_at_host", "azure.claude.hdinsight_encryption_in_transit", "azure.claude.fhir_cmk", "azure.claude.fhir_private_link", "azure.claude.hpc_cache_cmk", "azure.claude.keyvault_private_endpoint_exists", "azure.claude.keyvault_private_endpoint_only_access", "azure.claude.keyvault_firewall_ip_rules", "azure.claude.keyvault_vnet_service_endpoint", "azure.claude.keyvault_audit_logging", "azure.claude.keyvault_audit_and_alllogs_groups", "azure.claude.managed_hsm_audit_logging", "azure.claude.keyvault_key_expiration_set", "azure.claude.keyvault_rbac_key_expiration_set", "azure.claude.keyvault_non_rbac_key_expiration_set", "azure.claude.keyvault_rbac_secret_expiration_set", "azure.claude.keyvault_non_rbac_secret_expiration_set", "azure.claude.keyvault_key_rotation_policy", "azure.claude.keyvault_key_automatic_rotation_after_create", "azure.claude.keyvault_certificate_validity_12_months", "azure.claude.aks_azure_policy_addon", "azure.claude.aks_http_application_routing_disabled", "azure.claude.aks_secret_store_rotation", "azure.claude.aks_container_insights_logging", "azure.claude.aks_authorized_ip_ranges", "azure.claude.aks_max_pods_at_least_50", "azure.claude.aks_node_public_ip_disabled", "azure.claude.aks_encryption_at_host", "azure.claude.aks_disk_encryption_set", "azure.claude.aks_network_policy_configured", "azure.claude.aks_paid_sku_tier", "azure.claude.aks_version_not_cve_2019_9946", "azure.claude.kusto_cmk", "azure.claude.kusto_sku_with_sla"]);

function identityAdjacentAzureEvidence(checkId: string, e: Record<string, unknown>): string | undefined {
  if (!identityAdjacentAzureIds.has(checkId)) return undefined;
  const slug = checkId.replace("azure.claude.", "");
  if (["eventgrid_domain_managed_identity","eventgrid_topic_managed_identity"].includes(slug) && typeof e.identity_type === "string") return `Managed identity type is ${e.identity_type}.`;
  if (["eventgrid_domain_private_link","eventgrid_topic_private_link","eventgrid_domain_public_access_disabled","keyvault_private_endpoint_only_access"].includes(slug) && typeof e.public_network_access === "string") {
    const states = Array.isArray(e.private_link_states) ? ` Private endpoint states: ${e.private_link_states.join(", ") || "none"}.` : "";
    return `Public network access is ${e.public_network_access}.${states}`;
  }
  if (["eventhub_namespace_logging","iot_hub_logging"].includes(slug)) return toggle("Resource-log diagnostics", e.diagnostic_logging_enabled);
  if (["eventhub_namespace_private_link","iot_hub_private_link","fhir_private_link","keyvault_private_endpoint_exists"].includes(slug) && Array.isArray(e.private_link_states) && e.private_link_states.every(v=>typeof v === "string")) return e.private_link_states.length ? `Private endpoint states: ${e.private_link_states.join(", ")}.` : "No private endpoint connections are listed.";
  if (slug === "eventhub_namespace_vnet_rule" && finite(e.virtual_network_rules)) return `${e.virtual_network_rules} virtual-network ${e.virtual_network_rules === 1 ? "rule is" : "rules are"} declared.`;
  if (slug === "frontdoor_waf_policy_linked" && finite(e.frontend_endpoints) && finite(e.waf_linked)) return e.frontend_endpoints === 1 ? `The frontend endpoint ${e.waf_linked === 1 ? "has a" : "has no"} WAF policy reference.` : `${e.waf_linked} of ${e.frontend_endpoints} frontend endpoints have a WAF policy reference.`;
  if (slug === "hdinsight_cmk" && (e.key_name === null || typeof e.key_name === "string")) return e.key_name ? "A customer-managed disk key name is declared." : "No customer-managed disk key name is declared.";
  if (slug === "hdinsight_encryption_at_host") return toggle("Encryption at host", e.encryption_at_host);
  if (slug === "hdinsight_encryption_in_transit") return toggle("Cluster encryption in transit", e.encryption_in_transit);
  if (slug === "fhir_cmk" && typeof e.key_vault_key_uri_configured === "boolean") return `A customer-key URI is ${e.key_vault_key_uri_configured ? "declared" : "not declared"}.`;
  if (slug === "hpc_cache_cmk" && typeof e.customer_managed_key === "boolean") return `Customer-managed key and vault references are ${e.customer_managed_key ? "declared" : "not fully declared"}.`;
  if (slug === "keyvault_firewall_ip_rules" && finite(e.ip_rules)) return `${e.ip_rules} firewall IP ${e.ip_rules === 1 ? "rule is" : "rules are"} declared.`;
  if (slug === "keyvault_vnet_service_endpoint" && typeof e.default_action === "string" && finite(e.virtual_network_rules)) return `The vault firewall defaults to ${e.default_action.toLowerCase()} with ${e.virtual_network_rules} virtual-network rules.`;
  if (slug === "keyvault_audit_logging") return toggle("Matching vault audit logging", e.audit_logging);
  if (slug === "keyvault_audit_and_alllogs_groups" && typeof e.audit_group === "boolean" && typeof e.all_logs_group === "boolean") return `Enabled log groups: audit ${e.audit_group ? "present" : "absent"}; allLogs ${e.all_logs_group ? "present" : "absent"}.`;
  if (slug === "managed_hsm_audit_logging" && typeof e.audit_archive === "boolean") return e.audit_archive ? `AuditEvent logging declares a storage archive${finite(e.retention_days) ? ` with ${e.retention_days === 0 ? "indefinite" : `${e.retention_days}-day`} retention` : " and a retention-days field"}.` : "No enabled AuditEvent storage-archive declaration with a retention-days field was found.";
  if (["keyvault_key_expiration_set","keyvault_rbac_key_expiration_set","keyvault_non_rbac_key_expiration_set","keyvault_rbac_secret_expiration_set","keyvault_non_rbac_secret_expiration_set"].includes(slug) && typeof e.expiration_configured === "boolean") return `The enabled object ${e.expiration_configured ? "declares" : "does not declare"} an expiration timestamp.`;
  if (slug === "keyvault_key_rotation_policy" && typeof e.rotate_action_present === "boolean") return `The key policy ${e.rotate_action_present ? "includes" : "does not include"} a Rotate action.`;
  if (slug === "keyvault_key_automatic_rotation_after_create" && typeof e.scheduled_rotation === "boolean") return `The key policy ${e.scheduled_rotation ? "includes" : "does not include"} a supported after-create Rotate schedule.`;
  if (slug === "keyvault_certificate_validity_12_months" && finite(e.validity_months)) return `The certificate policy declares ${e.validity_months} months of validity.`;
  if (slug === "aks_azure_policy_addon") return toggle("The Azure Policy add-on", e.azure_policy_addon);
  if (slug === "aks_http_application_routing_disabled") return toggle("The legacy HTTP application routing add-on", e.http_application_routing);
  if (slug === "aks_secret_store_rotation") {
    if (e.secrets_provider_enabled === false) return "The Secrets Store provider add-on is disabled.";
    if (e.enable_secret_rotation === null || ["true","false"].includes(String(e.enable_secret_rotation))) return `Secrets Store rotation is ${e.enable_secret_rotation === "true" ? "enabled" : "not enabled"}.`;
  }
  if (slug === "aks_container_insights_logging" && typeof e.omsagent_enabled === "boolean" && typeof e.configured === "boolean") return `Container Insights is ${e.omsagent_enabled ? "enabled" : "disabled"}; a valid workspace reference is ${e.configured ? "declared" : "not declared"}.`;
  if (slug === "aks_authorized_ip_ranges" && Array.isArray(e.authorized_ip_ranges) && e.authorized_ip_ranges.every(v=>typeof v === "string")) return e.authorized_ip_ranges.length ? `API-server authorized sources: ${e.authorized_ip_ranges.join(", ")}.` : "The public API server has no authorized-source range restriction declared.";
  const lists: Record<string,[string,string]> = {aks_max_pods_at_least_50:["pools_below_50","declare maxPods below 50"],aks_node_public_ip_disabled:["pools_with_public_ip","declare node public IPs"],aks_encryption_at_host:["pools_without_host_encryption","do not declare encryption at host"]};
  const list = lists[slug];if (list && Array.isArray(e[list[0]])) return `${(e[list[0]] as unknown[]).length} agent pools ${list[1]}.`;
  if (slug === "aks_disk_encryption_set" && (e.disk_encryption_set === null || typeof e.disk_encryption_set === "string")) return `A disk encryption set is ${e.disk_encryption_set ? "referenced" : "not referenced"}.`;
  if (slug === "aks_network_policy_configured" && (e.network_policy === null || typeof e.network_policy === "string")) return e.network_policy && e.network_policy !== "none" ? `The declared network-policy engine is ${e.network_policy}.` : "No network-policy engine is declared.";
  if (slug === "aks_paid_sku_tier" && typeof e.sku_tier === "string") return `The AKS tier is ${e.sku_tier}.`;
  if (slug === "aks_version_not_cve_2019_9946" && typeof e.kubernetes_version === "string") return `The declared Kubernetes version is ${e.kubernetes_version}.`;
  if (slug === "kusto_cmk") {
    if (e.customer_managed_key === false) return "No customer-managed key configuration is declared.";
    if ((e.key_name === null || typeof e.key_name === "string") && (e.key_vault_uri === null || typeof e.key_vault_uri === "string")) return `Customer-key name and vault URI are ${e.key_name && e.key_vault_uri ? "declared" : "not fully declared"}.`;
  }
  if (slug === "kusto_sku_with_sla" && typeof e.sku_name === "string") return `The cluster SKU is ${e.sku_name}.`;
  return undefined;
}

const hacktricksAzureIds = new Set(["azure.htbp.eventhub.local_auth_disabled", "azure.htbp.eventgrid.topic_local_auth_disabled", "azure.htbp.eventgrid.domain_local_auth_disabled", "azure.htbp.signalr.local_auth_disabled", "azure.htbp.webpubsub.local_auth_disabled", "azure.htbp.appconfig.local_auth_disabled", "azure.htbp.search.api_key_auth_disabled", "azure.htbp.iothub.local_auth_disabled", "azure.htbp.redis.access_key_auth_disabled", "azure.htbp.batch.shared_key_auth_disabled", "azure.htbp.acr.anonymous_pull_disabled", "azure.htbp.keyvault.template_deployment_disabled", "azure.htbp.sql.entra_only_authentication", "azure.htbp.postgresql.password_auth_disabled", "azure.htbp.storage.sftp_local_users_disabled", "azure.htbp.logicapp.request_trigger_caller_restricted", "azure.htbp.entra.app_no_tier0_graph_application_permissions", "azure.htbp.entra.temporary_access_pass_one_time", "azure.htbp.appservice.scm_basic_auth_disabled", "azure.htbp.appservice.ftp_basic_auth_disabled", "azure.htbp.appservice.scm_site_restricted_like_main", "azure.htbp.entra.service_principal_no_password_credentials", "azure.htbp.entra.app_fic_github_not_pull_request", "azure.htbp.managed_identity.fic_github_not_pull_request", "azure.htbp.automation.webhook_expiry_bounded", "azure.htbp.synapse.firewall_no_allow_all_internet"]);

function hacktricksAzureEvidence(checkId: string, e: Record<string, unknown>): string | undefined {
  if (!hacktricksAzureIds.has(checkId)) return undefined;
  const slug = checkId.replace("azure.htbp.", "");
  if (typeof e.disable_local_auth === "boolean") return `Local key/SAS authentication is ${e.disable_local_auth ? "disabled" : "enabled"}.`;
  if (slug === "redis.access_key_auth_disabled" && typeof e.disable_access_key_authentication === "boolean") return `Redis access-key authentication is ${e.disable_access_key_authentication ? "disabled" : "enabled"}.`;
  if (slug === "batch.shared_key_auth_disabled" && Array.isArray(e.allowed_authentication_modes) && e.allowed_authentication_modes.every(v=>typeof v === "string")) return `Allowed Batch authentication modes: ${e.allowed_authentication_modes.join(", ") || "none"}.`;
  if (slug === "acr.anonymous_pull_disabled") return toggle("Anonymous image pull", e.anonymous_pull_enabled);
  if (slug === "keyvault.template_deployment_disabled" && typeof e.enabled_for_template_deployment === "boolean") return `ARM template access to vault secrets is ${e.enabled_for_template_deployment ? "enabled" : "disabled"}.`;
  if (slug === "sql.entra_only_authentication" && Array.isArray(e.azure_ad_only_authentication) && e.azure_ad_only_authentication.every(v=>typeof v === "boolean")) return `Entra-only authentication is enabled in ${e.azure_ad_only_authentication.filter(Boolean).length} of ${e.azure_ad_only_authentication.length} Entra administrator declarations.`;
  if (slug === "postgresql.password_auth_disabled" && ["Enabled","Disabled"].includes(String(e.password_auth))) return `PostgreSQL password authentication is ${String(e.password_auth).toLowerCase()}.`;
  if (slug === "storage.sftp_local_users_disabled" && typeof e.is_sftp_enabled === "boolean" && typeof e.is_local_user_enabled === "boolean") return `Storage SFTP is ${e.is_sftp_enabled ? "enabled" : "disabled"}; local users are ${e.is_local_user_enabled ? "enabled" : "disabled"}.`;
  if (slug === "logicapp.request_trigger_caller_restricted" && Array.isArray(e.request_triggers) && Array.isArray(e.oauth_policies)) {
    if (e.allowed_caller_ip_ranges === null && e.oauth_policies.length === 0) return "The HTTP Request workflow declares no caller-IP or OAuth-policy restriction beyond its signed callback URL.";
    if (Array.isArray(e.allowed_caller_ip_ranges)) return `The HTTP Request workflow declares ${e.allowed_caller_ip_ranges.length} caller-IP entries and ${e.oauth_policies.length} OAuth policies.`;
    return `The HTTP Request workflow declares ${e.oauth_policies.length} OAuth policies.`;
  }
  if (slug === "entra.app_no_tier0_graph_application_permissions" && Array.isArray(e.tier0_application_permissions)) return `${e.tier0_application_permissions.length} high-impact Graph application ${e.tier0_application_permissions.length === 1 ? "permission is" : "permissions are"} requested in the manifest.`;
  if (slug === "entra.temporary_access_pass_one_time" && typeof e.is_usable_once === "boolean" && finite(e.maximum_lifetime_minutes)) return `Temporary Access Pass is ${e.is_usable_once ? "one-time" : "reusable"} with a ${e.maximum_lifetime_minutes}-minute maximum lifetime.`;
  if (slug === "appservice.scm_basic_auth_disabled" && typeof e.scm_basic_auth_allowed === "boolean") return `SCM basic publishing authentication is ${e.scm_basic_auth_allowed ? "allowed" : "disabled"}.`;
  if (slug === "appservice.ftp_basic_auth_disabled" && typeof e.ftp_basic_auth_allowed === "boolean") return `FTP basic publishing authentication is ${e.ftp_basic_auth_allowed ? "allowed" : "disabled"}.`;
  if (slug === "appservice.scm_site_restricted_like_main" && typeof e.main_restricted === "boolean" && typeof e.scm_restricted === "boolean") return `The main site is ${e.main_restricted ? "restricted" : "unrestricted"}; SCM is ${e.scm_restricted ? "restricted" : "unrestricted"} by its declared access rules.`;
  if (slug === "entra.service_principal_no_password_credentials") {
    if (finite(e.password_credentials)) return `${e.password_credentials} password credentials are present on the service principal.`;
    if (Array.isArray(e.active_password_credentials)) return `${e.active_password_credentials.length} password ${e.active_password_credentials.length === 1 ? "credential has" : "credentials have"} no end date or expire${e.active_password_credentials.length === 1 ? "s" : ""} after the snapshot.`;
  }
  if (["entra.app_fic_github_not_pull_request","managed_identity.fic_github_not_pull_request"].includes(slug) && typeof e.issuer === "string" && typeof e.subject === "string") return `The GitHub Actions federation subject is ${e.subject}.`;
  if (slug === "automation.webhook_expiry_bounded" && Array.isArray(e.long_lived_webhooks) && finite(e.webhooks)) return e.webhooks === 1 ? (e.long_lived_webhooks.length ? "The enabled webhook has no expiry or expires more than one year after the snapshot." : "The webhook is disabled or expires within one year of the snapshot.") : `${e.long_lived_webhooks.length} of ${e.webhooks} webhooks are enabled with no expiry or an expiry over one year after the snapshot.`;
  if (slug === "synapse.firewall_no_allow_all_internet" && Array.isArray(e.internet_wide_rules)) return `${e.internet_wide_rules.length} firewall rules span at least half the IPv4 address space.`;
  return undefined;
}

const standardAzureIds = new Set(["azure.storage.https_only", "azure.storage.no_blob_public_access", "azure.storage.minimum_tls", "azure.iam.review_owner_assignment", "azure.iam.no_full_custom_role", "azure.network.restrict_internet_ingress", "azure.sql.restrict_firewall", "azure.aks.network_policy", "azure.storage.blob_versioning", "azure.storage.blob_soft_delete_retention", "azure.storage.container_soft_delete", "azure.vm.linux_ssh_keys", "azure.vm.trusted_launch", "azure.vm.managed_disks", "azure.app.client_certificates", "azure.aks.auto_upgrade", "azure.sql.audit_retention", "azure.sql.threat_alerts_all", "azure.sql.tde_enabled", "azure.app.minimum_tls", "azure.app.scm_minimum_tls", "azure.app.ftps_only", "azure.app.cors_no_wildcards", "azure.vault.secret_expiration", "azure.vault.approved_private_endpoint", "azure.defender.standard_tier"]);

function standardAzureEvidence(checkId: string, e: Record<string, unknown>): string | undefined {
  if (!standardAzureIds.has(checkId)) return undefined;
  const bools: Record<string,[string,string]> = {"azure.storage.https_only":["supports_https_traffic_only","Secure transfer"],"azure.storage.no_blob_public_access":["allow_blob_public_access","Account-level anonymous blob access capability"],"azure.storage.blob_versioning":["versioning_enabled","Blob versioning"],"azure.storage.container_soft_delete":["container_soft_delete_enabled","Container soft delete"]};
  const boolean = bools[checkId];if (boolean) return toggle(boolean[1],e[boolean[0]]);
  if (checkId === "azure.storage.minimum_tls" && typeof e.minimum_tls_version === "string") return `The storage minimum TLS version is ${e.minimum_tls_version.replace("TLS1_","1.")}.`;
  if (checkId === "azure.iam.review_owner_assignment" && typeof e.role_definition_id === "string") return `The assignment declares ${e.role_definition_id.toLowerCase().endsWith("/8e3af657-a8ff-443c-a75c-2fe8c4bcb635") ? "Owner" : "a role other than built-in Owner"} access.`;
  if (checkId === "azure.iam.no_full_custom_role" && Array.isArray(e.unrestricted_permission_blocks)) return `${e.unrestricted_permission_blocks.length} custom-role permission blocks contain a global wildcard without exclusions.`;
  if (checkId === "azure.network.restrict_internet_ingress" && Array.isArray(e.broad_ingress_rules)) {
    if (!e.broad_ingress_rules.length) return "No global-source custom inbound Allow rules are declared.";
    const rules = e.broad_ingress_rules as Record<string,unknown>[];
    const ports = [...new Set(rules.flatMap(r=>Array.isArray(r.destination_ports) ? r.destination_ports : []).filter(v=>typeof v === "string"))];
    return `${rules.length} custom inbound ${rules.length === 1 ? "rule allows" : "rules allow"} internet sources${ports.length ? ` on ports ${ports.join(", ")}` : ""}.`;
  }
  if (checkId === "azure.sql.restrict_firewall" && typeof e.start_ip === "string" && typeof e.end_ip === "string") return `The SQL firewall allows source addresses ${e.start_ip}–${e.end_ip}.`;
  if (checkId === "azure.aks.network_policy") {
    if (e.network_dataplane === "cilium") return "The cluster declares the Cilium network dataplane.";
    if (typeof e.network_policy === "string") return e.network_policy && e.network_policy !== "none" ? `The cluster uses the ${e.network_policy} network-policy engine.` : "No network-policy engine is configured.";
  }
  if (checkId === "azure.storage.blob_soft_delete_retention" && typeof e.enabled === "boolean") return !e.enabled ? "Blob soft delete is disabled." : finite(e.retention_days) ? `Blob soft delete is enabled for ${e.retention_days} days.` : undefined;
  if (checkId === "azure.vm.linux_ssh_keys" && typeof e.password_authentication_disabled === "boolean") return `SSH password authentication is ${e.password_authentication_disabled ? "disabled" : "enabled"} in the VM declaration.`;
  if (checkId === "azure.vm.trusted_launch" && typeof e.security_type === "string") return e.security_type !== "TrustedLaunch" ? `The VM security type is ${e.security_type}.` : typeof e.secure_boot === "boolean" && typeof e.virtual_tpm === "boolean" ? `Trusted Launch: Secure Boot ${e.secure_boot ? "enabled" : "disabled"}; vTPM ${e.virtual_tpm ? "enabled" : "disabled"}.` : undefined;
  if (checkId === "azure.vm.managed_disks") {
    if (e.unmanaged_disk_observed === true) return "An unmanaged OS or data-disk declaration was found.";
    if (finite(e.disk_count)) return `${e.disk_count} OS and data disks declare managed storage.`;
  }
  if (checkId === "azure.app.client_certificates" && typeof e.client_certificates_enabled === "boolean") return !e.client_certificates_enabled ? "Client certificates are disabled." : typeof e.client_certificate_mode === "string" ? `Client certificates are enabled in ${e.client_certificate_mode} mode.` : undefined;
  if (checkId === "azure.aks.auto_upgrade" && typeof e.upgrade_channel === "string") return e.upgrade_channel && e.upgrade_channel !== "none" ? `The cluster uses the ${e.upgrade_channel} upgrade channel.` : "Automatic cluster upgrades are not configured.";
  if (checkId === "azure.sql.audit_retention" && finite(e.retention_days)) return e.retention_days === 0 ? "SQL auditing retention is declared indefinite." : `SQL auditing retention is ${e.retention_days} days.`;
  if (checkId === "azure.sql.threat_alerts_all" && Array.isArray(e.disabled_alerts) && e.disabled_alerts.every(v=>typeof v === "string")) return `Disabled threat-alert categories: ${e.disabled_alerts.filter(Boolean).join(", ") || "none"}.`;
  if (checkId === "azure.sql.tde_enabled" && typeof e.state === "string") return `Transparent data encryption is ${e.state.toLowerCase()}.`;
  if (checkId === "azure.app.minimum_tls" && typeof e.minimum_tls === "string") return `The application minimum TLS version is ${e.minimum_tls}.`;
  if (checkId === "azure.app.scm_minimum_tls" && typeof e.scm_minimum_tls === "string") return `The SCM minimum TLS version is ${e.scm_minimum_tls}.`;
  if (checkId === "azure.app.ftps_only" && typeof e.ftp_state === "string") return `The FTP publishing mode is ${e.ftp_state}.`;
  if (checkId === "azure.app.cors_no_wildcards" && Array.isArray(e.allowed_origins)) return e.allowed_origins.includes("*") ? "The browser-origin allowlist contains a wildcard." : `${e.allowed_origins.length} browser origins are declared without a wildcard.`;
  if (checkId === "azure.vault.secret_expiration" && typeof e.expiration_configured === "boolean") return `The enabled secret ${e.expiration_configured ? "declares" : "does not declare"} an expiration timestamp.`;
  if (checkId === "azure.vault.approved_private_endpoint") {
    if (typeof e.default_action === "string") return `The vault firewall default is ${e.default_action.toLowerCase()}.`;
    if (e.approved_connections === 0) return "No private endpoint connections are declared.";
    if (Array.isArray(e.approval_states)) return `Private endpoint states: ${e.approval_states.join(", ")}.`;
  }
  if (checkId === "azure.defender.standard_tier" && typeof e.plan === "string" && typeof e.pricing_tier === "string") return `The ${e.plan} Defender plan pricing tier is ${e.pricing_tier}.`;
  return undefined;
}

const successorAzureIds = new Set(["azure.claude2.nsg_flow_log_configured", "azure.claude2.nsg_flow_log_retention_90", "azure.claude2.vnet_flow_log_retention_90", "azure.claude2.vnet_with_app_gateway_ddos_protection", "azure.claude2.vm_nic_ip_forwarding_disabled", "azure.claude2.app_gateway_http2_enabled", "azure.claude2.app_gateway_min_tls_12", "azure.claude2.app_gateway_waf_enabled", "azure.claude2.app_gateway_waf_mode_specified", "azure.claude2.apim_consumption_client_certificate", "azure.claude2.aks_azure_monitor_metrics_enabled", "azure.claude2.aks_private_cluster_nodes_without_public_ip", "azure.claude2.vm_encryption_at_host", "azure.claude2.vmss_encryption_at_host", "azure.claude2.vm_linux_ssh_key_only_guest_config", "azure.claude2.vm_trusted_launch_secure_boot_vtpm", "azure.claude2.sql_server_threat_detection_all_alerts", "azure.claude2.batch_account_customer_managed_key", "azure.claude2.batch_account_managed_identity", "azure.claude2.batch_account_resource_logs", "azure.claude2.automation_variable_encrypted"]);

function successorAzureEvidence(checkId: string,e: Record<string,unknown>): string | undefined {
  if (!successorAzureIds.has(checkId)) return undefined;
  const slug = checkId.replace("azure.claude2.", "");
  if (slug === "nsg_flow_log_configured") {
    if (Array.isArray(e.nsg_flow_logs)) return `${e.nsg_flow_logs.length} NSG flow-log ${e.nsg_flow_logs.length === 1 ? "reference or matching log record is" : "references or matching log records are"} declared.`;
    if (Array.isArray(e.vnet_flow_logs)) return `${e.vnet_flow_logs.length} enabled successor flow logs cover an attached network target.`;
  }
  if (slug === "nsg_flow_log_retention_90") {
    const rows = e.flow_logs ?? e.vnet_flow_logs;
    if (Array.isArray(rows)) {
      if (rows.every(v=>typeof v === "string" || v === null)) return `${rows.length} matching flow logs meet the enabled-retention criterion.`;
      if (rows.every(v=>!!v && typeof v === "object")) return `${rows.length} matching flow ${rows.length === 1 ? "log is" : "logs are"} disabled or below the required retention.`;
    }
  }
  if (slug === "vnet_flow_log_retention_90" && typeof e.enabled === "boolean" && finite(e.retention_days)) return `Flow logging is ${e.enabled ? "enabled" : "disabled"}; retention is ${e.retention_days === 0 ? "indefinite" : `${e.retention_days} days`}.`;
  if (slug === "vnet_with_app_gateway_ddos_protection") return toggle("The gateway VNet DDoS protection flag",e.enable_ddos_protection);
  if (slug === "vm_nic_ip_forwarding_disabled" && Array.isArray(e.ip_forwarding_nics)) return `${e.ip_forwarding_nics.length} VM interfaces declare IP forwarding enabled.`;
  if (slug === "app_gateway_http2_enabled") return toggle("Gateway HTTP/2",e.enable_http2);
  if (slug === "app_gateway_min_tls_12") {
    if (e.ssl_policy === null) return "No explicit TLS policy is declared; the source accepts the service default.";
    if (typeof e.min_protocol_version === "string") return `The gateway minimum TLS declaration is ${e.min_protocol_version}.`;
    if (typeof e.policy_name === "string") return `The declared gateway TLS policy is ${e.policy_name}.`;
  }
  if (["app_gateway_waf_enabled","app_gateway_waf_mode_specified"].includes(slug)) {
    if (e.reason === "no WAF configuration or WAF policy") return "No WAF policy reference or inline WAF configuration is declared.";
    if (typeof e.firewall_policy === "string") return "A WAF policy is referenced; its enablement is assessed separately.";
    if (typeof e.waf_configuration_enabled === "boolean") return toggle("Inline gateway WAF",e.waf_configuration_enabled);
    if (["Prevention","Detection"].includes(String(e.mode))) return `The declared WAF mode is ${e.mode}.`;
  }
  if (slug === "apim_consumption_client_certificate") return toggle("Client-certificate requests",e.enable_client_certificate);
  if (slug === "aks_azure_monitor_metrics_enabled") {
    if (e.azure_monitor_profile === null || e.metrics === null) return "Managed Prometheus metrics are not configured in the Azure Monitor profile.";
    return toggle("Managed Prometheus metrics",e.metrics_enabled);
  }
  if (slug === "aks_private_cluster_nodes_without_public_ip" && (e.private_fqdn === null || typeof e.private_fqdn === "string") && Array.isArray(e.node_public_ip) && e.node_public_ip.every(v=>typeof v === "boolean")) return `A private API FQDN is ${e.private_fqdn ? "declared" : "not declared"}; ${e.node_public_ip.filter(Boolean).length} of ${e.node_public_ip.length} pools declare node public IPs.`;
  if (["vm_encryption_at_host","vmss_encryption_at_host"].includes(slug)) return toggle("Encryption at host",e.encryption_at_host);
  if (slug === "vm_linux_ssh_key_only_guest_config" && Array.isArray(e.statuses) && e.statuses.every(v=>typeof v === "string")) return `LinuxNoPasswordForSSH compliance reports: ${e.statuses.join(", ") || "none"}.`;
  if (slug === "vm_trusted_launch_secure_boot_vtpm" && typeof e.secure_boot_enabled === "boolean" && typeof e.vtpm_enabled === "boolean") return `Trusted Launch: Secure Boot ${e.secure_boot_enabled ? "enabled" : "disabled"}; vTPM ${e.vtpm_enabled ? "enabled" : "disabled"}.`;
  if (slug === "sql_server_threat_detection_all_alerts" && Array.isArray(e.policies)) return `${e.policies.length} SQL alert ${e.policies.length === 1 ? "policy is disabled or excludes" : "policies are disabled or exclude"} alert categories.`;
  if (slug === "batch_account_customer_managed_key" && ["Microsoft.KeyVault","Microsoft.Batch"].includes(String(e.key_source))) return `Batch encryption uses ${e.key_source === "Microsoft.KeyVault" ? "a customer-managed Key Vault key" : "a platform-managed key"}.`;
  if (slug === "batch_account_managed_identity" && typeof e.identity_type === "string") return `Batch managed identity type is ${e.identity_type}.`;
  if (slug === "batch_account_resource_logs" && typeof e.matching_enabled_logs === "boolean") return `${e.matching_enabled_logs ? "At least one" : "No"} enabled Batch diagnostic-log entry meets the declaration criterion.`;
  if (slug === "automation_variable_encrypted" && typeof e.is_encrypted === "boolean") return `The Automation variable is declared ${e.is_encrypted ? "encrypted" : "unencrypted"}.`;
  return undefined;
}

const parentAzureAlertLabels: Record<string,string> = {
  "azure.claude.activity_log_alert_subscription_nsg_delete": "delete network security group",
  "azure.claude.activity_log_alert_subscription_nsg_rule_delete": "delete network security group rule",
  "azure.claude.activity_log_alert_subscription_nsg_rule_write": "create or update network security group rule",
  "azure.claude.activity_log_alert_subscription_nsg_write": "create or update network security group",
  "azure.claude.activity_log_alert_subscription_public_ip_delete": "delete public ip address",
  "azure.claude.activity_log_alert_subscription_public_ip_write": "create or update public ip address",
  "azure.claude.activity_log_alert_subscription_security_solution_write": "create or update security solution",
  "azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete": "delete sql server firewall rule",
  "azure.claude.activity_log_alert_subscription_sql_firewall_rule_write": "create or update sql server firewall rule"
};
const declarationAzureIds = new Set(["azure.gap.nsg_declared_internet_rdp", "azure.gap.nsg_declared_internet_ssh", "azure.gap.nsg_declared_internet_http", "azure.gap.nsg_declared_internet_http_https", "azure.gap.nsg_declared_internet_remote_access", "azure.gap.nsg_declared_internet_udp_services", "azure.gap.nsg_declared_internet_udp_any", "azure.claude.activity_log_alert_subscription_nsg_delete", "azure.claude.activity_log_alert_subscription_nsg_rule_delete", "azure.claude.activity_log_alert_subscription_nsg_rule_write", "azure.claude.activity_log_alert_subscription_nsg_write", "azure.claude.activity_log_alert_subscription_public_ip_delete", "azure.claude.activity_log_alert_subscription_public_ip_write", "azure.claude.activity_log_alert_subscription_security_solution_write", "azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete", "azure.claude.activity_log_alert_subscription_sql_firewall_rule_write"]);
function declarationAzureEvidence(checkId: string,e: Record<string,unknown>): string | undefined {
  if (!declarationAzureIds.has(checkId)) return undefined;
  const label = parentAzureAlertLabels[checkId];
  if (label) {
    if (typeof e.alert === "string" && e.alert) return `An enabled Global subscription alert matches ${label} events.`;
    if (e.reason === "no matching enabled activity log alert") return `No enabled Global subscription alert matches ${label} events.`;
    return undefined;
  }
  if (!Array.isArray(e.declared_internet_allow_rules)) return undefined;
  if (!e.declared_internet_allow_rules.length) return "No matching internet-source custom Allow rule is declared.";
  const paths: string[] = [];
  for (const row of e.declared_internet_allow_rules) {
    if (!row || typeof row !== "object" || Array.isArray(row)) return undefined;
    const rule = row as Record<string,unknown>;
    if (typeof rule.protocol !== "string" || !Array.isArray(rule.ports) || !rule.ports.every(v=>typeof v === "string")) return undefined;
    paths.push(...rule.ports.map(v=>`${rule.protocol!.toString().toLowerCase()}/${v}`));
  }
  return `Internet-source custom rules allow ${[...new Set(paths)].join(", ")}.`;
}

const legacyAzureIds = new Set(["azure.cis.enforce_ssl_connection_mysql_server", "azure.cis.postgresql_single_ssl_enforcement", "azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server", "azure.cis.mysql_single_audit_log_enabled", "azure.cis.postgresql_single_connection_throttling", "azure.cis.postgresql_single_log_checkpoints", "azure.cis.postgresql_single_log_connections", "azure.cis.postgresql_single_log_disconnections", "azure.cis.mysql_single_audit_log_events_connection", "azure.cis.postgresql_single_no_azure_services_rule", "azure.cis.postgresql_single_log_retention_days", "azure.cis.public_network_access_should_mariadb_servers", "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled", "azure_firewall_policy_1_2_8_42_cacbd9e", "azure_firewall_policy_1_2_8_24_cc7cb8a"]);

function legacyAzureEvidence(checkId: string,e: Record<string,unknown>): string | undefined {
  if (!legacyAzureIds.has(checkId)) return undefined;
  const enums: Record<string,string> = {"azure.cis.enforce_ssl_connection_mysql_server":"Legacy MySQL SSL enforcement","azure.cis.postgresql_single_ssl_enforcement":"Legacy PostgreSQL SSL enforcement","azure.cis.legacy_infrastructure_double_encryption_postgresql_single_server":"Legacy PostgreSQL infrastructure encryption","azure.cis.public_network_access_should_mariadb_servers":"MariaDB public network access"};
  if (enums[checkId] && ["Enabled","Disabled"].includes(String(e.configured))) return `${enums[checkId]} is ${String(e.configured).toLowerCase()}.`;
  const parameters: Record<string,string> = {"azure.cis.mysql_single_audit_log_enabled":"audit_log_enabled","azure.cis.postgresql_single_connection_throttling":"connection_throttling","azure.cis.postgresql_single_log_checkpoints":"log_checkpoints","azure.cis.postgresql_single_log_connections":"log_connections","azure.cis.postgresql_single_log_disconnections":"log_disconnections","azure.cis.postgresql_single_log_retention_days":"log_retention_days"};
  if (parameters[checkId] && e.configuration === parameters[checkId]) {
    if (e.reason === "confirmed absent") return `The ${e.configuration} parameter is absent from the complete configuration inventory.`;
    if (typeof e.value === "string" || finite(e.value)) return `The ${e.configuration} parameter is ${e.value}${e.configuration === "log_retention_days" ? " days" : ""}.`;
  }
  if (checkId === "azure.cis.mysql_single_audit_log_events_connection") {
    if (e.missing_required_configuration === true) return "A required MySQL audit configuration is absent.";
    if (typeof e.audit_enabled === "string" && typeof e.connection_token_present === "boolean") return `MySQL audit logging is ${e.audit_enabled.toLowerCase()}; CONNECTION events are ${e.connection_token_present ? "included" : "not included"}.`;
  }
  if (checkId === "azure.cis.postgresql_single_no_azure_services_rule" && Array.isArray(e.azure_services_rule_ids)) return `${e.azure_services_rule_ids.length} firewall ${e.azure_services_rule_ids.length === 1 ? "rule allows" : "rules allow"} Azure services to connect.`;
  if (checkId === "azure.gap.monitor_log_cluster_infrastructure_encryption_enabled") return toggle("Log Analytics cluster infrastructure encryption",e.is_double_encryption_enabled);
  if (checkId === "azure_firewall_policy_1_2_8_42_cacbd9e" && finite(e.custom_rule_count) && finite(e.managed_rule_set_count)) return `The WAF policy declares ${e.custom_rule_count} custom ${e.custom_rule_count === 1 ? "rule" : "rules"} and ${e.managed_rule_set_count} managed rule ${e.managed_rule_set_count === 1 ? "set" : "sets"}.`;
  if (checkId === "azure_firewall_policy_1_2_8_24_cc7cb8a" && Array.isArray(e.empty_group_ids)) return `${e.empty_group_ids.length} Firewall Policy rule-collection groups contain no rules.`;
  return undefined;
}

const dataIdentityAzureIds = new Set(["azure.claude.defender_default_initiative_no_disabled_effects", "azure.claude.defender_iot_security_solution_enabled", "azure.claude.servicebus_namespace_network_restricted", "azure.claude.sql_database_va_findings_resolved", "azure.claude.sql_server_minimal_tls_12", "azure.claude.sql_server_vulnerability_assessment_enabled", "azure.claude.storage_vhd_accounts_cmk", "azure.claude.waf_policy_bot_protection", "azure.aks.api_server_restricted", "azure.claude2.entra_lockout_duration_min_60", "azure.claude2.entra_lockout_threshold_max_10", "azure.claude2.entra_custom_banned_password_enforced", "azure.claude2.entra_ca_mfa_all_users_or_roles", "azure.claude2.entra_device_join_requires_mfa", "azure.claude2.entra_user_mfa_registered", "azure.claude2.entra_global_admin_between_2_and_4"]);

function dataIdentityAzureEvidence(checkId: string,e: Record<string,unknown>): string | undefined {
  if (!dataIdentityAzureIds.has(checkId)) return undefined;
  if (checkId === "azure.claude.defender_default_initiative_no_disabled_effects" && Array.isArray(e.disabled_parameters)) return `${e.disabled_parameters.length} applicable Defender initiative ${e.disabled_parameters.length === 1 ? "parameter is" : "parameters are"} disabled.`;
  if (checkId === "azure.claude.defender_iot_security_solution_enabled" && Array.isArray(e.statuses) && e.statuses.every(v=>typeof v === "string")) return `IoT security solution statuses: ${e.statuses.join(", ")}.`;
  if (checkId === "azure.claude.servicebus_namespace_network_restricted") {
    if (e.public_network_access === "Disabled") return "Service Bus public network access is disabled.";
    if (e.default_action === "Allow") return "Service Bus public network filtering defaults to Allow.";
    if (e.default_action === "Deny" && finite(e.ip_rule_count) && finite(e.virtual_network_rule_count)) return `Service Bus defaults to Deny with ${e.ip_rule_count} IP rules and ${e.virtual_network_rule_count} virtual-network rules.`;
  }
  if (checkId === "azure.claude.sql_database_va_findings_resolved" && finite(e.failed_checks) && typeof e.latest_scan_end === "string") return `The latest scan (${e.latest_scan_end}) reports ${e.failed_checks} failed security checks.`;
  if (checkId === "azure.claude.sql_server_minimal_tls_12" && typeof e.configured_minimal_tls_version === "string") return e.configured_minimal_tls_version === "None" && e.effective_provider_minimum === "TLS 1.2" ? "No explicit SQL minimum TLS is set; the reviewed provider default requires TLS1.2+." : `The declared SQL minimum TLS version is ${e.configured_minimal_tls_version}.`;
  if (checkId === "azure.claude.sql_server_vulnerability_assessment_enabled") {
    if (e.configuration === "classic") return "A classic vulnerability-assessment storage path is declared.";
    if (e.configuration === "express" && typeof e.state === "string") return `Express vulnerability assessment is ${e.state.toLowerCase()}.`;
  }
  if (checkId === "azure.claude.storage_vhd_accounts_cmk" && Array.isArray(e.platform_key_vhd_accounts)) return `${e.platform_key_vhd_accounts.length} matched unmanaged OS-disk accounts use platform-managed storage keys.`;
  if (checkId === "azure.claude.waf_policy_bot_protection" && typeof e.bot_rule_set === "boolean" && Array.isArray(e.disabled_rules)) return !e.bot_rule_set ? "No Microsoft Bot Manager rule set is declared." : `The Bot Manager rule set declares ${e.disabled_rules.length} explicitly disabled rules.`;
  if (checkId === "azure.aks.api_server_restricted") {
    if (e.private_cluster === true) return "The cluster declares a private API server.";
    if (e.private_cluster === false && Array.isArray(e.authorized_ip_ranges) && e.authorized_ip_ranges.every(v=>typeof v === "string")) return e.authorized_ip_ranges.length ? `Public API authorized sources: ${e.authorized_ip_ranges.join(", ")}.` : "The public API server declares no authorized-source restriction.";
  }
  const settings:Record<string,[string,string]> = {"azure.claude2.entra_lockout_duration_min_60":["LockoutDurationInSeconds","Customized lockout durations"],"azure.claude2.entra_lockout_threshold_max_10":["LockoutThreshold","Customized lockout thresholds"],"azure.claude2.entra_custom_banned_password_enforced":["EnableBannedPasswordCheck","Customized banned-password checks"]};
  const setting = settings[checkId];
  if (setting && e.setting === setting[0] && Array.isArray(e.values) && e.values.every(v=>typeof v === "boolean" || finite(v))) return `${setting[1]}: ${e.values.map(v=>typeof v === "boolean" ? v ? "enabled" : "disabled" : String(v)).join(", ")}${e.setting === "LockoutDurationInSeconds" ? " seconds" : ""}.`;
  if (checkId === "azure.claude2.entra_ca_mfa_all_users_or_roles" && Array.isArray(e.matching_policies)) return `${e.matching_policies.length} enabled MFA-policy declarations match All users or an activated role without individual user exclusions.`;
  if (checkId === "azure.claude2.entra_device_join_requires_mfa" && ["required","notRequired"].includes(String(e.multi_factor_auth_configuration))) return `The device-registration MFA setting is ${e.multi_factor_auth_configuration === "required" ? "required" : "not required"}.`;
  if (checkId === "azure.claude2.entra_user_mfa_registered" && typeof e.is_mfa_registered === "boolean") return `The user is ${e.is_mfa_registered ? "registered" : "not registered"} for MFA; enforcement is assessed separately.`;
  if (checkId === "azure.claude2.entra_global_admin_between_2_and_4" && finite(e.global_administrators)) return `${e.global_administrators} distinct ${e.global_administrators === 1 ? "principal has" : "principals have"} active tenant-wide Global Administrator assignments.`;
  return undefined;
}

const strictAzureIds = new Set(["azure.cis.public_network_access_should_postgresql_servers", "azure.cis.public_network_access_should_mysql_servers", "azure.gap.postgres_db_server_log_duration_on", "azure_search_service_3_5_1_19_a3c75c0", "azure_vm_app_function_identity_is_configured_bdb10d4", "azure_pci_1_2_8_39", "azure.cis.mysql_flexible_cmk", "azure.cis.agentless_scanning_machines_component_status", "azure_log_analytics_workspace_10_5_1_4_8c74ccb", "azure.cis.file_integrity_monitoring_component_status", "azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7", "azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679", "azure.cis.resource_manager_delete_locks_applied_storage_accounts", "azure.cis.legacy_vhds_encrypted", "azure.gap.compute_vm_remote_access_restricted_all_ports", "azure.gap.compute_vm_tcp_udp_access_restricted_internet", "azure.gap.web_pub_sub_private_link_used", "azure_firewall_policy_1_2_8_23_59ad733", "azure_api_management_appinsights_ensure_is_configured_42aac6a", "azure.cis.app_service_entra_registration_enabled", "azure.cis.defender_external_attack_surface_monitoring_easm", "azure.other.entra_app_secret_age_90", "azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28", "azure.gap.monitor_log_profile_retention_365_days", "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5"]);

function strictAzureEvidence(checkId: string,e: Record<string,unknown>,status:string): string | undefined {
  if (!strictAzureIds.has(checkId)) return undefined;
  if (["azure.cis.public_network_access_should_postgresql_servers","azure.cis.public_network_access_should_mysql_servers"].includes(checkId) && ["Enabled","Disabled"].includes(String(e.public_network_access))) return `Database public network access is ${String(e.public_network_access).toLowerCase()}.`;
  if (checkId === "azure.gap.postgres_db_server_log_duration_on" && e.parameter === "log_duration" && ["on","off"].includes(String(e.configured))) return `PostgreSQL log_duration is ${e.configured}.`;
  if (checkId === "azure_search_service_3_5_1_19_a3c75c0" && typeof e.enforcement === "string" && typeof e.encryption_compliance_status === "string") return `Search customer-key enforcement is ${e.enforcement.toLowerCase()}; reported compliance is ${e.encryption_compliance_status}.`;
  if (checkId === "azure_vm_app_function_identity_is_configured_bdb10d4" && typeof e.identity_type === "string") return `The VM managed-identity type is ${e.identity_type}.`;
  if (checkId === "azure_pci_1_2_8_39" && Array.isArray(e.association_ids)) return `The NSG declares ${e.association_ids.length} subnet or NIC associations.`;
  if (checkId === "azure.cis.mysql_flexible_cmk") {
    if (e.encryption_type === "SystemManaged") return "MySQL encryption uses a platform-managed key.";
    if (e.encryption_type === "AzureKeyVault" && typeof e.key_uri_present === "boolean" && typeof e.user_identity_present === "boolean") return `MySQL customer-key URI ${e.key_uri_present ? "present" : "absent"}; user-assigned identity reference ${e.user_identity_present ? "present" : "absent"}.`;
  }
  if (checkId === "azure.cis.agentless_scanning_machines_component_status") {
    if (e.pricing_tier === "Free") return "The VirtualMachines Defender plan is Free.";
    if (e.extension_present === false) return "The Standard plan declares no AgentlessVmScanning extension.";
    if (["True","False"].includes(String(e.configured_is_enabled))) return `Agentless VM scanning is declared ${e.configured_is_enabled === "True" ? "enabled" : "disabled"}.`;
  }
  if (checkId === "azure_log_analytics_workspace_10_5_1_4_8c74ccb" && finite(e.observed_days) && finite(e.required_days)) return `Workspace default interactive retention is ${e.observed_days} days; the threshold is ${e.required_days} days.`;
  if (checkId === "azure.cis.file_integrity_monitoring_component_status") {
    if (e.pricing_tier === "Free") return "The VirtualMachines Defender plan is Free.";
    if (e.subplan === "P1") return "The Defender Servers plan declares P1 instead of the required P2.";
    if (e.extension_present === false) return "The P2 plan declares no FileIntegrityMonitoring extension.";
    if (["True","False"].includes(String(e.configured_is_enabled))) return `File Integrity Monitoring is declared ${e.configured_is_enabled === "True" ? "enabled" : "disabled"}${e.resources_coverage_status ? `; coverage is ${e.resources_coverage_status}` : ""}.`;
  }
  if (checkId === "azure_application_gateway_app_ensure_http_is_redirected_to_https_1099ad7" && finite(e.assessed_route_count)) {
    if (finite(e.non_https_route_count)) return `${e.non_https_route_count} assessed HTTP routes do not declare an HTTPS redirect.`;
    if (status === "PASS") return `${e.assessed_route_count} assessed HTTP routes declare HTTPS redirects.`;
  }
  if (checkId === "azure_vm_monitor_diagnostic_setting_with_appropriate_categories_4e20679" && finite(e.setting_count)) {
    if (e.metric_category === "AllMetrics") return "An enabled AllMetrics export with a supported destination is declared.";
    if (status === "FAIL") return `No enabled AllMetrics export with a supported destination was found in ${e.setting_count} VM diagnostic settings.`;
  }
  if (checkId === "azure.cis.resource_manager_delete_locks_applied_storage_accounts" && finite(e.accounts)) return status === "PASS" ? (e.accounts === 1 ? "The assessed storage account has an applicable deletion lock." : `All ${e.accounts} assessed storage accounts have an applicable deletion lock.`) : `At least one of ${e.accounts} assessed storage accounts has no applicable deletion lock.`;
  if (checkId === "azure.cis.legacy_vhds_encrypted" && finite(e.unmanaged_vhd_count) && Array.isArray(e.unencrypted_backing_account_ids)) return `${e.unencrypted_backing_account_ids.length} backing storage accounts declare Blob encryption disabled across ${e.unmanaged_vhd_count} unmanaged VHDs.`;
  if (checkId === "azure.gap.compute_vm_remote_access_restricted_all_ports") {
    if (Array.isArray(e.permissive_associated_nsgs)) return `${e.permissive_associated_nsgs.length} associated NSG paths retain a modeled Internet-source Allow rule after priority evaluation.`;
    if (finite(e.evaluated_ip_configurations)) return `No modeled Internet-source Allow remains across ${e.evaluated_ip_configurations} assessed IP configurations.`;
  }
  if (checkId === "azure.gap.compute_vm_tcp_udp_access_restricted_internet" && Array.isArray(e.internet_facing_ip_configurations) && Array.isArray(e.unprotected_ip_configurations)) return `${e.unprotected_ip_configurations.length} of ${e.internet_facing_ip_configurations.length} modeled Internet-facing IP configurations lack a NIC or subnet NSG.`;
  if (checkId === "azure.gap.web_pub_sub_private_link_used" && Array.isArray(e.approved_connection_ids)) return `${e.approved_connection_ids.length} approved private endpoint ${e.approved_connection_ids.length === 1 ? "connection with a valid reference is" : "connections with valid references are"} declared.`;
  if (checkId === "azure_firewall_policy_1_2_8_23_59ad733" && Array.isArray(e.qualifying_group_ids)) return `${e.qualifying_group_ids.length} direct or inherited Firewall Policy groups contain recognized rules.`;
  if (checkId === "azure_api_management_appinsights_ensure_is_configured_42aac6a" && Array.isArray(e.missing_tracing_api_ids)) return `${e.missing_tracing_api_ids.length} online APIs lack the required declared Application Insights tracing path.`;
  if (checkId === "azure.cis.app_service_entra_registration_enabled" && typeof e.observed_identity_type === "string") return `The authoritative App Service GET declares managed-identity type ${e.observed_identity_type}.`;
  if (checkId === "azure.cis.defender_external_attack_surface_monitoring_easm" && finite(e.workspace_count) && finite(e.succeeded_count)) return `${e.succeeded_count} of ${e.workspace_count} EASM workspaces report successful provisioning.`;
  if (checkId === "azure.other.entra_app_secret_age_90") {
    if (Array.isArray(e.aged_active_credentials)) return `${e.aged_active_credentials.length} active application ${e.aged_active_credentials.length === 1 ? "credential is" : "credentials are"} at least 90 days old.`;
    if (finite(e.active_credential_count)) return `${e.active_credential_count} active application ${e.active_credential_count === 1 ? "credential is" : "credentials are"} younger than 90 days.`;
  }
  if (checkId === "azure_directory_user_keyvault_rbac_secret_expiration_set_e2e0e28" && finite(e.maxCredentialAgeDays)) {
    if (Array.isArray(e.old_active_credentials)) return `${e.old_active_credentials.length} active service-principal ${e.old_active_credentials.length === 1 ? "credential is" : "credentials are"} older than ${e.maxCredentialAgeDays} days.`;
    if (finite(e.active_credential_count)) return `${e.active_credential_count} active service-principal ${e.active_credential_count === 1 ? "credential is" : "credentials are"} within ${e.maxCredentialAgeDays} days of creation.`;
  }
  if (checkId === "azure.gap.monitor_log_profile_retention_365_days") {
    if (Array.isArray(e.short_retention_profile_ids)) return `${e.short_retention_profile_ids.length} legacy log profiles declare enabled retention below 365 days.`;
    if (finite(e.profile_count)) return `${e.profile_count} legacy log profiles declare enabled retention of at least 365 days.`;
  }
  if (checkId === "azure_sql_database_sqlserver_tde_encryption_enabled_c4383b5") {
    if (Array.isArray(e.disabled_database_ids)) return `${e.disabled_database_ids.length} user databases declare transparent data encryption disabled.`;
    if (finite(e.encrypted_database_count)) return `${e.encrypted_database_count} user databases declare transparent data encryption enabled.`;
  }
  return undefined;
}
