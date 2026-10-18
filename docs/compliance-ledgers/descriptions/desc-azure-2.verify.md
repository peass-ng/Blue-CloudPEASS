## Azure description slice 2 independent verification

- Input IDs: 302; unique IDs: 302; output entries: 302.
- Decisions: 178 corrected; 124 verified without edits. Each input ID appears once below.
- Local fixtures: 296 PASS and 296 FAIL cases matched the registered evaluators. 6 checks have no pass/fail fixture pair and were read directly.
- Structural validation: required fields, evaluated-path uniqueness, input/output set equality, index membership, and title-copy screening passed.

| # | Check ID | Evaluator | Decision and change |
|---:|---|---|---|
| 1 | `azure.claude.storage_private_link_all_approved` | `peaso/checks/claude_azure_data.py:720` | Verified all five fields against the predicate; no edit. |
| 2 | `azure.claude.storage_queue_classic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected: Removed unused account kind and corrected Premium skip condition. |
| 3 | `azure.claude.storage_queue_diagnostic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected: Removed unused account kind and corrected Premium skip condition. Included allLogs category group and aggregation across settings. |
| 4 | `azure.claude.storage_smb_channel_encryption_aes_256_gcm` | `peaso/checks/claude_azure_data.py:818` | Corrected: Corrected normalized semicolon-separated set predicate; exact raw string is not required. |
| 5 | `azure.claude.storage_smb_version_3_1_1` | `peaso/checks/claude_azure_data.py:818` | Corrected: Corrected normalized semicolon-separated set predicate; exact raw string is not required. |
| 6 | `azure.claude.storage_sync_private_link` | `peaso/checks/claude_azure_data.py:911` | Verified all five fields against the predicate; no edit. |
| 7 | `azure.claude.storage_table_classic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected: Removed unused account kind and corrected Premium skip condition. |
| 8 | `azure.claude.storage_table_diagnostic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected: Removed unused account kind and corrected Premium skip condition. Included allLogs category group and aggregation across settings. |
| 9 | `azure.claude.storage_trusted_azure_services_bypass` | `peaso/checks/claude_azure_data.py:703` | Verified all five fields against the predicate; no edit. |
| 10 | `azure.claude.storage_vhd_accounts_cmk` | `peaso/checks/claude_azure_data.py:37` | Verified all five fields against the predicate; no edit. |
| 11 | `azure.claude.storage_vnet_service_endpoint_rules` | `peaso/checks/claude_azure_data.py:710` | Verified all five fields against the predicate; no edit. |
| 12 | `azure.claude.stream_analytics_job_logging_enabled` | `peaso/checks/claude_azure_data.py:64` | Corrected: Corrected any-enabled-log logic; disabled categories do not force FAIL. |
| 13 | `azure.claude.subnet_nsg_associated` | `peaso/checks/claude_azure_network.py:885` | Verified all five fields against the predicate; no edit. |
| 14 | `azure.claude.subscription_diagnostic_setting_any_categories` | `peaso/checks/claude_azure_network.py:397` | Verified all five fields against the predicate; no edit. |
| 15 | `azure.claude.subscription_diagnostic_setting_categories` | `peaso/checks/claude_azure_network.py:385` | Verified all five fields against the predicate; no edit. |
| 16 | `azure.claude.subscription_diagnostic_setting_exists` | `peaso/checks/claude_azure_network.py:371` | Verified all five fields against the predicate; no edit. |
| 17 | `azure.claude.synapse_workspace_cmk` | `peaso/checks/claude_azure_data.py:931` | Corrected: Replaced unrelated double-encryption field with CMK key name. |
| 18 | `azure.claude.synapse_workspace_exfiltration_protection` | `peaso/checks/claude_azure_data.py:922` | Corrected: Included absent managed VNet settings in FAIL condition. |
| 19 | `azure.claude.synapse_workspace_private_link` | `peaso/checks/claude_azure_data.py:940` | Verified all five fields against the predicate; no edit. |
| 20 | `azure.claude.synapse_workspace_vulnerability_assessment` | `peaso/checks/claude_azure_data.py:947` | Verified all five fields against the predicate; no edit. |
| 21 | `azure.claude.vm_antimalware_auto_upgrade` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed untested provisioning-state condition. |
| 22 | `azure.claude.vm_antimalware_extension` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused OS and auto-upgrade fields from evaluated paths. Removed untested provisioning-state and auto-upgrade conditions. |
| 23 | `azure.claude.vm_backup_daily_retention_7_days` | `peaso/checks/claude_azure_compute.py:548` | Verified all five fields against the predicate; no edit. |
| 24 | `azure.claude.vm_backup_protected` | `peaso/checks/claude_azure_compute.py:534` | Verified all five fields against the predicate; no edit. |
| 25 | `azure.claude.vm_dependency_agent_linux` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused extension auto-upgrade field. |
| 26 | `azure.claude.vm_dependency_agent_windows` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused extension auto-upgrade field. |
| 27 | `azure.claude.vm_guest_configuration_extension` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused OS and auto-upgrade fields from evaluated paths. Publisher and Succeeded state suffice; type is only structurally validated. |
| 28 | `azure.claude.vm_guest_configuration_extension_linux` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused extension auto-upgrade field. Included extension name suffix and type requirements. |
| 29 | `azure.claude.vm_guest_configuration_extension_windows` | `peaso/checks/claude_azure_compute.py:118` | Corrected: Removed unused extension auto-upgrade field. Included extension name suffix and type requirements. |
| 30 | `azure.claude.vm_guest_configuration_managed_identity` | `peaso/checks/claude_azure_compute.py:196` | Verified all five fields against the predicate; no edit. |
| 31 | `azure.claude.vm_guest_configuration_system_identity` | `peaso/checks/claude_azure_compute.py:196` | Verified all five fields against the predicate; no edit. |
| 32 | `azure.claude.vm_guest_configuration_user_and_system_identity` | `peaso/checks/claude_azure_compute.py:196` | Verified all five fields against the predicate; no edit. |
| 33 | `azure.claude.vm_jit_access` | `peaso/checks/claude_azure_compute.py:494` | Verified all five fields against the predicate; no edit. |
| 34 | `azure.claude.vm_linux_no_passwordless_accounts` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 35 | `azure.claude.vm_linux_remote_requires_password` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 36 | `azure.claude.vm_linux_security_baseline` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 37 | `azure.claude.vm_nic_nsg_internet_tcp_ingress` | `peaso/checks/claude_azure_compute.py:450` | Verified all five fields against the predicate; no edit. |
| 38 | `azure.claude.vm_no_public_ip` | `peaso/checks/claude_azure_compute.py:435` | Verified all five fields against the predicate; no edit. |
| 39 | `azure.claude.vm_nsg_internet_management_ports` | `peaso/checks/claude_azure_compute.py:474` | Verified all five fields against the predicate; no edit. |
| 40 | `azure.claude.vm_os_managed_disk` | `peaso/checks/claude_azure_compute.py:316` | Corrected: Distinguished explicit unmanaged disk from missing managedDisk ID UNKNOWN. |
| 41 | `azure.claude.vm_site_recovery_enabled` | `peaso/checks/claude_azure_compute.py:511` | Verified all five fields against the predicate; no edit. |
| 42 | `azure.claude.vm_windows_automatic_updates` | `peaso/checks/claude_azure_compute.py:336` | Corrected: Added Windows OS selection and corresponding evaluated path. Removed generic generated consequence; retained the concrete evaluated condition. |
| 43 | `azure.claude.vm_windows_exploit_guard` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 44 | `azure.claude.vm_windows_max_password_age` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 45 | `azure.claude.vm_windows_min_password_age` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 46 | `azure.claude.vm_windows_min_password_length` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 47 | `azure.claude.vm_windows_no_reversible_password_encryption` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 48 | `azure.claude.vm_windows_password_complexity` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 49 | `azure.claude.vm_windows_password_history` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 50 | `azure.claude.vm_windows_secure_boot` | `peaso/checks/claude_azure_compute.py:350` | Verified all five fields against the predicate; no edit. |
| 51 | `azure.claude.vm_windows_secure_protocol_tls13` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Clarified assignment-only TLS check and required parameter, including UNKNOWN cases. Removed duplicate combined parameter path. |
| 52 | `azure.claude.vm_windows_security_baseline` | `peaso/checks/claude_azure_compute.py:246` | Corrected: Excluded pending-only assignments from FAIL wording. |
| 53 | `azure.claude.vmss_automatic_upgrade_mode` | `peaso/checks/claude_azure_common.py:67` | Corrected: Replaced generic consequence with exact VMSS setting. |
| 54 | `azure.claude.vmss_boot_diagnostics` | `peaso/checks/claude_azure_common.py:67` | Corrected: Replaced generic consequence with exact VMSS setting. |
| 55 | `azure.claude.vmss_linux_ssh_keys` | `peaso/checks/claude_azure_compute.py:587` | Corrected: Added Linux OS selection and corresponding evaluated path. Removed generic generated consequence; retained the concrete evaluated condition. |
| 56 | `azure.claude.vmss_load_balancer_backend` | `peaso/checks/claude_azure_compute.py:620` | Verified all five fields against the predicate; no edit. |
| 57 | `azure.claude.vmss_managed_disks` | `peaso/checks/claude_azure_compute.py:601` | Corrected: Distinguished explicit unmanaged VHD containers from uncollected disk storage type. |
| 58 | `azure.claude.vmss_not_empty` | `peaso/checks/claude_azure_compute.py:636` | Verified all five fields against the predicate; no edit. |
| 59 | `azure.claude.vnet_gateway_entra_only` | `peaso/checks/claude_azure_network.py:913` | Verified all five fields against the predicate; no edit. |
| 60 | `azure.claude.vnet_gateway_no_basic_sku` | `peaso/checks/claude_azure_common.py:67` | Corrected: Replaced generic network exposure claim with actual SKU baseline. |
| 61 | `azure.claude.vnet_peering_connected` | `peaso/checks/claude_azure_network.py:855` | Verified all five fields against the predicate; no edit. |
| 62 | `azure.claude.waf_policy_bot_protection` | `peaso/checks/claude_azure_data.py:958` | Corrected: Corrected nested rule override path. |
| 63 | `azure.claude.waf_policy_request_body_inspection` | `peaso/checks/claude_azure_common.py:67` | Corrected: Specified request-body inspection effect. |
| 64 | `azure.claude2.activity_log_alert_service_health` | `peaso/checks/claude2_azure_common.py:48` | Verified all five fields against the predicate; no edit. |
| 65 | `azure.claude2.aks_azure_monitor_metrics_enabled` | `peaso/checks/claude2_azure_network.py:381` | Verified all five fields against the predicate; no edit. |
| 66 | `azure.claude2.aks_private_cluster_nodes_without_public_ip` | `peaso/checks/claude2_azure_network.py:399` | Corrected: Corrected any-pool condition and removed unused public FQDN field. |
| 67 | `azure.claude2.api_app_client_certificates` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 68 | `azure.claude2.api_app_cors_no_wildcard` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Included absent CORS setting and arbitrary non-wildcard origins. Specified actual App Service kind selection from app_rule closure. |
| 69 | `azure.claude2.api_app_ftps_required` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 70 | `azure.claude2.api_app_https_only` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified API-app scope and transport meaning. Specified actual App Service kind selection from app_rule closure. |
| 71 | `azure.claude2.api_app_managed_identity` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 72 | `azure.claude2.api_app_min_tls_12` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Replaced fixture values with numeric version threshold. Specified actual App Service kind selection from app_rule closure. |
| 73 | `azure.claude2.api_app_remote_debugging_disabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 74 | `azure.claude2.apim_consumption_client_certificate` | `peaso/checks/claude2_azure_network.py:362` | Verified all five fields against the predicate; no edit. |
| 75 | `azure.claude2.app_gateway_http2_enabled` | `peaso/checks/claude2_azure_network.py:277` | Corrected: Specified HTTP/2 configuration effect. |
| 76 | `azure.claude2.app_gateway_min_tls_12` | `peaso/checks/claude2_azure_network.py:290` | Verified all five fields against the predicate; no edit. |
| 77 | `azure.claude2.app_gateway_waf_enabled` | `peaso/checks/claude2_azure_network.py:314` | Verified all five fields against the predicate; no edit. |
| 78 | `azure.claude2.app_gateway_waf_mode_specified` | `peaso/checks/claude2_azure_network.py:334` | Corrected: Clarified Detection is accepted as PASS and unknown modes yield UNKNOWN. |
| 79 | `azure.claude2.app_service_environment_internal_encryption` | `peaso/checks/claude2_azure_app.py:480` | Verified all five fields against the predicate; no edit. |
| 80 | `azure.claude2.app_service_plan_minimum_sku` | `peaso/checks/claude2_azure_app.py:472` | Verified all five fields against the predicate; no edit. |
| 81 | `azure.claude2.app_workers_more_than_one` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Replaced fixture values with worker-count threshold. Specified actual App Service kind selection from app_rule closure. |
| 82 | `azure.claude2.application_insights_configured` | `peaso/checks/claude2_azure_common.py:48` | Corrected: Added no-App-Service subscription skip. |
| 83 | `azure.claude2.application_insights_public_access_blocked` | `peaso/checks/claude2_azure_app.py:511` | Corrected: Both ingestion and query public-access switches must be Disabled. |
| 84 | `azure.claude2.application_insights_workspace_based` | `peaso/checks/claude2_azure_app.py:526` | Corrected: Removed fixture-only workspace ID and included empty-string failure. Removed generic generated consequence; retained the concrete evaluated condition. |
| 85 | `azure.claude2.automation_variable_encrypted` | `peaso/checks/claude2_azure_defender.py:182` | Corrected: Specified encryption flag effect. |
| 86 | `azure.claude2.batch_account_customer_managed_key` | `peaso/checks/claude2_azure_defender.py:139` | Corrected: Distinguished platform key from CMK. |
| 87 | `azure.claude2.batch_account_managed_identity` | `peaso/checks/claude2_azure_defender.py:150` | Verified all five fields against the predicate; no edit. |
| 88 | `azure.claude2.batch_account_resource_logs` | `peaso/checks/claude2_azure_defender.py:164` | Corrected: Included malformed enabled retention-policy branch that cannot count as a hit. |
| 89 | `azure.claude2.defender_attack_path_setting_and_alert_contacts` | `peaso/checks/claude2_azure_common.py:48` | Corrected: Added no-setting NOT_APPLICABLE case. Included non-subscription anchor skip. |
| 90 | `azure.claude2.entra_ca_mfa_all_users_or_roles` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Clarified no excluded users and intersection with active role templates. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 91 | `azure.claude2.entra_custom_banned_password_enforced` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Replaced fixture literals with full threshold/boolean predicate and customization skip. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 92 | `azure.claude2.entra_device_join_requires_mfa` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Corrected indexed field and tenant-specific predicate. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 93 | `azure.claude2.entra_global_admin_between_2_and_4` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Clarified distinct principals and tenant-wide scope. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 94 | `azure.claude2.entra_lockout_duration_min_60` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Replaced fixture literals with full threshold/boolean predicate and customization skip. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 95 | `azure.claude2.entra_lockout_threshold_max_10` | `peaso/checks/claude2_azure_identity.py:20` | Corrected: Replaced fixture literals with full threshold/boolean predicate and customization skip. Included foreign-tenant wrapper skip and tenant scope inputs. |
| 96 | `azure.claude2.entra_user_mfa_registered` | `peaso/checks/claude2_azure_identity.py:148` | Corrected: Specified the user-level MFA registration predicate. |
| 97 | `azure.claude2.function_app_authentication_enabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 98 | `azure.claude2.function_app_client_certificates` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 99 | `azure.claude2.function_app_ftps_required` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 100 | `azure.claude2.function_app_linux_http2` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Specified Linux-function scope and HTTP/2 switch. |
| 101 | `azure.claude2.function_app_managed_identity` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 102 | `azure.claude2.function_app_restrict_public_access` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Added Allow action and absent-restrictions PASS branch. Specified actual App Service kind selection from app_rule closure. |
| 103 | `azure.claude2.iam_no_custom_owner_roles` | `peaso/checks/claude2_azure_common.py:48` | Corrected: Removed untested notActions qualification; literal wildcard actions drive FAIL. Added non-subscription scope skip. |
| 104 | `azure.claude2.nsg_flow_log_configured` | `peaso/checks/claude2_azure_network.py:96` | Verified all five fields against the predicate; no edit. |
| 105 | `azure.claude2.nsg_flow_log_retention_90` | `peaso/checks/claude2_azure_network.py:115` | Corrected: Removed unsupported attachment prerequisite from description. |
| 106 | `azure.claude2.nsg_flow_logs_to_log_analytics` | `peaso/checks/claude2_azure_common.py:48` | Corrected: Included VNet/NIC targets and no-network NOT_APPLICABLE branch. |
| 107 | `azure.claude2.prowler_app_authentication` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Specified Easy Auth platform switch. |
| 108 | `azure.claude2.prowler_app_client_certificates_required` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 109 | `azure.claude2.prowler_app_http_logs` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Included both HTTP category and allLogs category group. Specified actual App Service kind selection from app_rule closure. |
| 110 | `azure.claude2.prowler_app_identity` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 111 | `azure.claude2.prowler_function_ftp_ftps_disabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Corrected exact Disabled requirement, including AllAllowed failure. Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. |
| 112 | `azure.claude2.prowler_function_identity` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 113 | `azure.claude2.prowler_function_identity_not_admin` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added no-managed-identity NOT_APPLICABLE branch. |
| 114 | `azure.claude2.prowler_function_not_public` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Clarified unset public-network mode is UNKNOWN. |
| 115 | `azure.claude2.prowler_function_vnet_integration` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Included empty subnet ID in FAIL. |
| 116 | `azure.claude2.sql_server_threat_detection_all_alerts` | `peaso/checks/claude2_azure_defender.py:119` | Verified all five fields against the predicate; no edit. |
| 117 | `azure.claude2.vm_encryption_at_host` | `peaso/checks/claude2_azure_defender.py:58` | Verified all five fields against the predicate; no edit. |
| 118 | `azure.claude2.vm_linux_ssh_key_only_guest_config` | `peaso/checks/claude2_azure_defender.py:77` | Verified all five fields against the predicate; no edit. |
| 119 | `azure.claude2.vm_nic_ip_forwarding_disabled` | `peaso/checks/claude2_azure_network.py:251` | Verified all five fields against the predicate; no edit. |
| 120 | `azure.claude2.vm_trusted_launch_secure_boot_vtpm` | `peaso/checks/claude2_azure_defender.py:95` | Verified all five fields against the predicate; no edit. |
| 121 | `azure.claude2.vmss_encryption_at_host` | `peaso/checks/claude2_azure_defender.py:67` | Corrected: Specified scale-set host-encryption switch. |
| 122 | `azure.claude2.vnet_flow_log_retention_90` | `peaso/checks/claude2_azure_network.py:136` | Verified all five fields against the predicate; no edit. |
| 123 | `azure.claude2.vnet_flow_logs_to_log_analytics` | `peaso/checks/claude2_azure_common.py:48` | Corrected: Included NIC targets and no-VNet NOT_APPLICABLE branch. |
| 124 | `azure.claude2.vnet_with_app_gateway_ddos_protection` | `peaso/checks/claude2_azure_network.py:230` | Verified all five fields against the predicate; no edit. |
| 125 | `azure.claude2.web_app_always_on` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Specified web-app selection. |
| 126 | `azure.claude2.web_app_authentication_enabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 127 | `azure.claude2.web_app_client_certificates` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 128 | `azure.claude2.web_app_diagnostic_http_log_category` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 129 | `azure.claude2.web_app_diagnostic_logs_enabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 130 | `azure.claude2.web_app_failed_request_tracing` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. Specified App Service failed-request trace setting. |
| 131 | `azure.claude2.web_app_ftps_required` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 132 | `azure.claude2.web_app_health_check` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Included empty-string PASS and null-only FAIL. Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. |
| 133 | `azure.claude2.web_app_incoming_client_cert` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 134 | `azure.claude2.web_app_managed_identity` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 135 | `azure.claude2.web_app_register_with_entra` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Clarified that the check only evaluates managed identity, not an Entra app registration. Specified actual App Service kind selection from app_rule closure. |
| 136 | `azure.claude2.web_app_remote_debugging_disabled` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Specified actual App Service kind selection from app_rule closure. |
| 137 | `azure.claude2.web_app_slot_https_only` | `peaso/checks/claude2_azure_app.py:492` | Verified all five fields against the predicate; no edit. |
| 138 | `azure.claude2.web_app_vnet_connection` | `peaso/checks/claude2_azure_app.py:88` | Corrected: Included absent and empty VNet names in FAIL. Specified actual App Service kind selection from app_rule closure. Added kind selector to evaluated paths. |
| 139 | `azure.defender.standard_tier` | `peaso/checks/azure_extended.py:243` | Corrected: Added supported-plan applicability. Removed generic generated consequence; retained the concrete evaluated condition. |
| 140 | `azure.disk.entra_export_auth` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 141 | `azure.disk.private_export` | `peaso/checks/azure_extended.py:33` | Corrected: Corrected OR failure and all passing export-policy combinations. |
| 142 | `azure.gap.nsg_declared_internet_http` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 143 | `azure.gap.nsg_declared_internet_http_https` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 144 | `azure.gap.nsg_declared_internet_rdp` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 145 | `azure.gap.nsg_declared_internet_remote_access` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 146 | `azure.gap.nsg_declared_internet_ssh` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 147 | `azure.gap.nsg_declared_internet_udp_any` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 148 | `azure.gap.nsg_declared_internet_udp_services` | `peaso/checks/azure_gap_nsg.py:87` | Verified all five fields against the predicate; no edit. |
| 149 | `azure.htbp.acr.anonymous_pull_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 150 | `azure.htbp.appconfig.local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 151 | `azure.htbp.appservice.ftp_basic_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Added FTP/FTPS Disabled NOT_APPLICABLE branch and FTPS selector. |
| 152 | `azure.htbp.appservice.scm_basic_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 153 | `azure.htbp.appservice.scm_site_restricted_like_main` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 154 | `azure.htbp.automation.webhook_expiry_bounded` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 155 | `azure.htbp.batch.shared_key_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 156 | `azure.htbp.entra.app_fic_github_not_pull_request` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 157 | `azure.htbp.entra.app_no_tier0_graph_application_permissions` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 158 | `azure.htbp.entra.service_principal_no_password_credentials` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Distinguished active credentials from expired credentials and SAML exception. |
| 159 | `azure.htbp.entra.temporary_access_pass_one_time` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 160 | `azure.htbp.eventgrid.domain_local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 161 | `azure.htbp.eventgrid.topic_local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 162 | `azure.htbp.eventhub.local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 163 | `azure.htbp.iothub.local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 164 | `azure.htbp.keyvault.template_deployment_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 165 | `azure.htbp.logicapp.request_trigger_caller_restricted` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Included OAuth policy alternative and both NOT_APPLICABLE branches. |
| 166 | `azure.htbp.managed_identity.fic_github_not_pull_request` | `peaso/checks/hacktricks_bp_common.py:53` | Verified all five fields against the predicate; no edit. |
| 167 | `azure.htbp.postgresql.password_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 168 | `azure.htbp.redis.access_key_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 169 | `azure.htbp.search.api_key_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 170 | `azure.htbp.signalr.local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 171 | `azure.htbp.sql.entra_only_authentication` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Included Entra-administrator filter, all-admin comparison and skip. |
| 172 | `azure.htbp.storage.sftp_local_users_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed untested hierarchical namespace condition and included documented defaults for SFTP and local users. |
| 173 | `azure.htbp.synapse.firewall_no_allow_all_internet` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Corrected half-IPv4-space threshold and disabled-public-access skip. |
| 174 | `azure.htbp.webpubsub.local_auth_disabled` | `peaso/checks/hacktricks_bp_common.py:53` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 175 | `azure.iam.no_full_custom_role` | `peaso/checks/__init__.py:578` | Verified all five fields against the predicate; no edit. |
| 176 | `azure.iam.review_owner_assignment` | `peaso/checks/__init__.py:567` | Verified all five fields against the predicate; no edit. |
| 177 | `azure.network.ddos_configured` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 178 | `azure.network.load_balancer_standard` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 179 | `azure.network.nic_no_ip_forwarding` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 180 | `azure.network.public_ip_standard` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 181 | `azure.network.restrict_internet_ingress` | `peaso/checks/__init__.py:592` | Verified all five fields against the predicate; no edit. |
| 182 | `azure.port.ad_authorization_policy_guest_invite_restricted` | `peaso/checks/azure_ports_directory.py:54` | Corrected: Included both permissive guest-invite enum values. |
| 183 | `azure.port.ad_authorization_policy_guest_user_access_restricted` | `peaso/checks/azure_ports_directory.py:64` | Verified all five fields against the predicate; no edit. |
| 184 | `azure.port.ad_authorization_policy_user_consent_disallowed` | `peaso/checks/azure_ports_directory.py:82` | Verified all five fields against the predicate; no edit. |
| 185 | `azure.port.ad_authorization_policy_user_consent_verified_publishers_selected_permissions` | `peaso/checks/azure_ports_directory.py:91` | Verified all five fields against the predicate; no edit. |
| 186 | `azure.port.ad_security_defaults_policy_enabled` | `peaso/checks/azure_ports_directory.py:41` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 187 | `azure.port.apimanagement_service_with_virtual_network` | `peaso/checks/azure_ports_services.py:178` | Corrected: Included Internal as well as External VNet mode. |
| 188 | `azure.port.app_configuration_encryption_enabled` | `peaso/checks/azure_ports_services.py:143` | Corrected: Clarified nonempty CMK identifier requirement. |
| 189 | `azure.port.app_configuration_private_link_used` | `peaso/checks/azure_ports_services.py:126` | Corrected: Added Free SKU skip and SKU field. |
| 190 | `azure.port.app_configuration_sku_standard` | `peaso/checks/azure_ports_services.py:136` | Corrected: Corrected case-sensitive SKU enum. |
| 191 | `azure.port.cognitive_account_encrypted_with_cmk` | `peaso/checks/azure_ports_services.py:106` | Corrected: Included CMK capability gate and Microsoft.KeyVault key-source predicate. |
| 192 | `azure.port.cognitive_account_private_link_used` | `peaso/checks/azure_ports_services.py:116` | Corrected: Corrected capability plus approval test and no-connection MANUAL branch. |
| 193 | `azure.port.cognitive_account_public_network_access_disabled` | `peaso/checks/azure_ports_services.py:89` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 194 | `azure.port.cognitive_account_restrict_public_access` | `peaso/checks/azure_ports_services.py:96` | Corrected: Included VirtualNetworks capability gate. Removed generic generated consequence; retained the concrete evaluated condition. |
| 195 | `azure.port.cognitive_service_local_auth_disabled` | `peaso/checks/azure_ports_services.py:82` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 196 | `azure.port.cosmosdb_account_uses_private_link` | `peaso/checks/azure_ports_paas.py:30` | Verified all five fields against the predicate; no edit. |
| 197 | `azure.port.cosmosdb_account_virtual_network_filter_enabled` | `peaso/checks/azure_ports_paas.py:46` | Corrected: Included public-network Disabled bypass. |
| 198 | `azure.port.data_factory_encrypted_with_cmk` | `peaso/checks/azure_ports_services.py:157` | Corrected: Clarified nonempty vault URL requirement. |
| 199 | `azure.port.data_factory_public_network_access_disabled` | `peaso/checks/azure_ports_services.py:150` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 200 | `azure.port.data_factory_uses_git_repository` | `peaso/checks/azure_ports_services.py:164` | Corrected: Clarified nonempty repository name requirement. |
| 201 | `azure.port.data_factory_uses_private_link` | `peaso/checks/azure_ports_services.py:171` | Verified all five fields against the predicate; no edit. |
| 202 | `azure.port.databricks_workspace_deployed_in_custom_vnet` | `peaso/checks/azure_ports_paas.py:62` | Corrected: Corrected presence-only parameter test. |
| 203 | `azure.port.databricks_workspace_no_public_ip_enabled` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 204 | `azure.port.databricks_workspace_public_network_access_disabled` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 205 | `azure.port.databricks_workspace_uses_private_endpoint` | `peaso/checks/azure_ports_paas.py:30` | Verified all five fields against the predicate; no edit. |
| 206 | `azure.port.defender_alert_severity_contact` | `peaso/checks/azure_ports_defender.py:179` | Verified all five fields against the predicate; no edit. |
| 207 | `azure.port.defender_notify_owner_contact` | `peaso/checks/azure_ports_defender.py:164` | Corrected: Added Owner role requirement alongside state On. |
| 208 | `azure.port.defender_required_mcas` | `peaso/checks/azure_ports_defender.py:141` | Verified all five fields against the predicate; no edit. |
| 209 | `azure.port.defender_required_wdatp` | `peaso/checks/azure_ports_defender.py:141` | Verified all five fields against the predicate; no edit. |
| 210 | `azure.port.iam_user_not_allowed_to_create_security_group` | `peaso/checks/azure_ports_directory.py:41` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 211 | `azure.port.iam_user_not_allowed_to_register_application` | `peaso/checks/azure_ports_directory.py:41` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 212 | `azure.port.keyvault_key_automatic_rotation_enabled` | `peaso/checks/azure_ports_vault.py:69` | Verified all five fields against the predicate; no edit. |
| 213 | `azure.port.keyvault_key_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 214 | `azure.port.keyvault_logging_enabled` | `peaso/checks/azure_ports_vault.py:100` | Corrected: Replaced AuditEvent-or-allLogs with exact audit-and-allLogs category-group requirement. |
| 215 | `azure.port.keyvault_public_network_access_disabled` | `peaso/checks/azure_ports_vault.py:143` | Verified all five fields against the predicate; no edit. |
| 216 | `azure.port.keyvault_secret_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 217 | `azure.port.keyvault_vault_private_link_used` | `peaso/checks/azure_ports_vault.py:127` | Verified all five fields against the predicate; no edit. |
| 218 | `azure.port.keyvault_vault_recoverable` | `peaso/checks/azure_ports_common.py:10` | Corrected: Included both required recovery switches. |
| 219 | `azure.port.keyvault_with_non_rbac_key_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 220 | `azure.port.keyvault_with_non_rbac_secret_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 221 | `azure.port.keyvault_with_rbac_key_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 222 | `azure.port.keyvault_with_rbac_secret_expiration_set` | `peaso/checks/azure_ports_vault.py:51` | Verified all five fields against the predicate; no edit. |
| 223 | `azure.port.monitor_log_alert_create_policy_assignment` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 224 | `azure.port.monitor_log_alert_create_update_nsg` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 225 | `azure.port.monitor_log_alert_create_update_public_ip_address` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 226 | `azure.port.monitor_log_alert_create_update_security_solution` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 227 | `azure.port.monitor_log_alert_create_update_sql_servers_firewall_rule` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 228 | `azure.port.monitor_log_alert_delete_nsg` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 229 | `azure.port.monitor_log_alert_delete_policy_assignment` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 230 | `azure.port.monitor_log_alert_delete_public_ip_address` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 231 | `azure.port.monitor_log_alert_delete_security_solution` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 232 | `azure.port.monitor_log_alert_delete_sql_servers_firewall_rule` | `peaso/checks/azure_ports_monitor.py:58` | Verified all five fields against the predicate; no edit. |
| 233 | `azure.port.redis_cache_in_virtual_network` | `peaso/checks/azure_ports_services.py:68` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 234 | `azure.port.redis_cache_min_tls_1_2` | `peaso/checks/azure_ports_services.py:54` | Corrected: Included TLS 1.0 failure; evaluator accepts exactly 1.2. |
| 235 | `azure.port.redis_cache_no_basic_sku` | `peaso/checks/azure_ports_services.py:61` | Verified all five fields against the predicate; no edit. |
| 236 | `azure.port.redis_cache_ssl_enabled` | `peaso/checks/azure_ports_services.py:47` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 237 | `azure.port.redis_cache_uses_private_link` | `peaso/checks/azure_ports_services.py:75` | Verified all five fields against the predicate; no edit. |
| 238 | `azure.port.search_service_public_network_access_disabled` | `peaso/checks/azure_ports_services.py:185` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 239 | `azure.port.search_service_uses_managed_identity` | `peaso/checks/azure_ports_services.py:199` | Verified all five fields against the predicate; no edit. |
| 240 | `azure.port.search_service_uses_private_link` | `peaso/checks/azure_ports_services.py:192` | Verified all five fields against the predicate; no edit. |
| 241 | `azure.port.search_service_uses_sku_supporting_private_link` | `peaso/checks/azure_ports_services.py:206` | Verified all five fields against the predicate; no edit. |
| 242 | `azure.port.security_center_defender_for_api_enabled` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 243 | `azure.port.security_center_defender_for_cloudposture_enabled` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 244 | `azure.port.securitycenter_azure_defender_on_for_appservice` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 245 | `azure.port.securitycenter_azure_defender_on_for_containerregistry` | `peaso/checks/azure_ports_legacy_plans.py:19` | Verified all five fields against the predicate; no edit. |
| 246 | `azure.port.securitycenter_azure_defender_on_for_containers` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 247 | `azure.port.securitycenter_azure_defender_on_for_cosmosdb` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 248 | `azure.port.securitycenter_azure_defender_on_for_database` | `peaso/checks/azure_ports_defender.py:92` | Verified all five fields against the predicate; no edit. |
| 249 | `azure.port.securitycenter_azure_defender_on_for_dns` | `peaso/checks/azure_ports_legacy_plans.py:19` | Verified all five fields against the predicate; no edit. |
| 250 | `azure.port.securitycenter_azure_defender_on_for_k8s` | `peaso/checks/azure_ports_legacy_plans.py:19` | Verified all five fields against the predicate; no edit. |
| 251 | `azure.port.securitycenter_azure_defender_on_for_keyvault` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 252 | `azure.port.securitycenter_azure_defender_on_for_opensource_relational_db` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 253 | `azure.port.securitycenter_azure_defender_on_for_resource_manager` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 254 | `azure.port.securitycenter_azure_defender_on_for_server` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 255 | `azure.port.securitycenter_azure_defender_on_for_sqldb` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 256 | `azure.port.securitycenter_azure_defender_on_for_sqlservervm` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 257 | `azure.port.securitycenter_azure_defender_on_for_storage` | `peaso/checks/azure_ports_defender.py:71` | Verified all five fields against the predicate; no edit. |
| 258 | `azure.port.securitycenter_mcas_integration` | `peaso/checks/azure_ports_defender.py:115` | Verified all five fields against the predicate; no edit. |
| 259 | `azure.port.securitycenter_wdatp_integration` | `peaso/checks/azure_ports_defender.py:115` | Verified all five fields against the predicate; no edit. |
| 260 | `azure.port.storage_account_access_keys_periodically_regenerated` | `peaso/checks/azure_ports_storage.py:147` | Verified all five fields against the predicate; no edit. |
| 261 | `azure.port.storage_account_blob_and_container_soft_delete_enabled` | `peaso/checks/azure_ports_storage.py:103` | Verified all five fields against the predicate; no edit. |
| 262 | `azure.port.storage_account_blob_soft_delete_enabled` | `peaso/checks/azure_ports_storage.py:95` | Verified all five fields against the predicate; no edit. |
| 263 | `azure.port.storage_account_blob_versioning_enabled` | `peaso/checks/azure_ports_storage.py:112` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 264 | `azure.port.storage_account_container_soft_delete_enabled` | `peaso/checks/azure_ports_storage.py:95` | Verified all five fields against the predicate; no edit. |
| 265 | `azure.port.storage_account_encryption_at_rest_using_cmk` | `peaso/checks/azure_ports_storage.py:62` | Corrected: Distinguished customer-managed key from platform encryption. |
| 266 | `azure.port.storage_account_file_share_smb_channel_encryption_aes_256_gcm` | `peaso/checks/azure_ports_storage.py:124` | Corrected: Replaced one failure fixture with exact provider-string predicate. |
| 267 | `azure.port.storage_account_file_share_smb_protocol_version_3_1_1` | `peaso/checks/azure_ports_storage.py:124` | Corrected: Replaced one failure fixture with exact provider-string predicate. |
| 268 | `azure.port.storage_account_geo_redundant_enabled` | `peaso/checks/azure_ports_storage.py:69` | Verified all five fields against the predicate; no edit. |
| 269 | `azure.port.storage_account_key_rotation_reminder_enabled` | `peaso/checks/azure_ports_storage.py:76` | Corrected: Replaced fixture value with exact 90-day predicate and absent-policy failure. |
| 270 | `azure.port.storage_account_soft_delete_enabled` | `peaso/checks/azure_ports_storage.py:86` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 271 | `azure.port.storage_account_trusted_microsoft_services_enabled` | `peaso/checks/azure_ports_common.py:21` | Corrected: Replaced one bypass fixture with AzureServices presence predicate. |
| 272 | `azure.sql.audit_retention` | `peaso/checks/azure_extended.py:146` | Corrected: Corrected 0-or-at-least-90-day predicate. |
| 273 | `azure.sql.auditing` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 274 | `azure.sql.minimum_tls` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 275 | `azure.sql.no_public_network` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 276 | `azure.sql.restrict_firewall` | `peaso/checks/azure.py:30` | Corrected: Included broad-range exact match and 0.0.0.0 Azure-services MANUAL branch. |
| 277 | `azure.sql.tde_enabled` | `peaso/checks/azure_extended.py:164` | Corrected: Added master database exception. Removed generic generated consequence; retained the concrete evaluated condition. |
| 278 | `azure.sql.threat_alerts_all` | `peaso/checks/azure_extended.py:155` | Corrected: Corrected any nonempty disabled alert category. |
| 279 | `azure.sql.threat_detection` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 280 | `azure.storage.blob_soft_delete_retention` | `peaso/checks/azure_extended.py:58` | Corrected: Added enabled switch, full retention range and blob-service selection. |
| 281 | `azure.storage.blob_versioning` | `peaso/checks/azure_extended.py:50` | Corrected: Added blob-service applicability and concrete setting meaning. |
| 282 | `azure.storage.container_soft_delete` | `peaso/checks/azure_extended.py:70` | Corrected: Added blob-service applicability and concrete setting meaning. |
| 283 | `azure.storage.cross_tenant_replication` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 284 | `azure.storage.default_deny` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 285 | `azure.storage.default_oauth` | `peaso/checks/facts.py:46` | Corrected: Clarified this is default authentication preference, not disabling keys. |
| 286 | `azure.storage.https_only` | `peaso/checks/__init__.py:543` | Verified all five fields against the predicate; no edit. |
| 287 | `azure.storage.infrastructure_encryption` | `peaso/checks/facts.py:46` | Corrected: Specified the additional infrastructure-encryption layer. |
| 288 | `azure.storage.minimum_tls` | `peaso/checks/__init__.py:559` | Verified all five fields against the predicate; no edit. |
| 289 | `azure.storage.no_blob_public_access` | `peaso/checks/__init__.py:551` | Verified all five fields against the predicate; no edit. |
| 290 | `azure.storage.no_public_network` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 291 | `azure.storage.no_shared_key` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 292 | `azure.vault.approved_private_endpoint` | `peaso/checks/azure_extended.py:226` | Verified all five fields against the predicate; no edit. |
| 293 | `azure.vault.default_deny` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 294 | `azure.vault.no_public_network` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 295 | `azure.vault.purge_protection` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 296 | `azure.vault.rbac` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 297 | `azure.vault.secret_expiration` | `peaso/checks/azure_extended.py:212` | Verified all five fields against the predicate; no edit. |
| 298 | `azure.vault.soft_delete` | `peaso/checks/facts.py:46` | Corrected: Removed generic generated consequence; retained the concrete evaluated condition. |
| 299 | `azure.vm.encryption_at_host` | `peaso/checks/facts.py:46` | Corrected: Specified VM host encryption rather than transport encryption. |
| 300 | `azure.vm.linux_ssh_keys` | `peaso/checks/azure_extended.py:78` | Corrected: Added Windows NOT_APPLICABLE branch. Removed generic generated consequence; retained the concrete evaluated condition. |
| 301 | `azure.vm.managed_disks` | `peaso/checks/azure_extended.py:103` | Corrected: Clarified null managedDisk failure and missing metadata UNKNOWN. |
| 302 | `azure.vm.trusted_launch` | `peaso/checks/azure_extended.py:90` | Verified all five fields against the predicate; no edit. |

Checks lacking a fixture pair: `azure.iam.no_full_custom_role`, `azure.iam.review_owner_assignment`, `azure.network.restrict_internet_ingress`, `azure.storage.https_only`, `azure.storage.minimum_tls`, `azure.storage.no_blob_public_access`.
