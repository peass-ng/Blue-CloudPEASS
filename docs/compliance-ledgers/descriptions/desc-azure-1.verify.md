
## Independent verification — 2026-10-12

Input: `inputs/desc-azure-1.json` (302 IDs). Output: `descriptions/desc-azure-1.json` (302 keys). Every ID received one decision against its registered evaluator, including shared helper predicates. Source locations below are the executable predicate/helper locations; the index registration line was also checked for every ID.

Corrections: 77 entries, 180 fields. Fixture verdicts: 302 PASS and 302 FAIL checked. Problems: 0.

| ID | Evaluator | Decision |
| --- | --- | --- |
| `azure.aks.api_server_restricted` | `peaso/checks/exposure_endpoints.py:23` | Verified; no change |
| `azure.aks.auto_upgrade` | `peaso/checks/azure_extended.py:137` | Verified; no change |
| `azure.aks.azure_rbac` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.defender_monitoring` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.network_policy` | `peaso/checks/azure.py:43` | Verified; no change |
| `azure.aks.no_local_accounts` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.private_cluster` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.rbac` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.client_certificates` | `peaso/checks/azure_extended.py:125` | Corrected fail_when |
| `azure.app.cors_no_wildcards` | `peaso/checks/azure_extended.py:203` | Verified; no change |
| `azure.app.ftps_only` | `peaso/checks/azure_extended.py:194` | Verified; no change |
| `azure.app.http2` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.https_only` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.minimum_tls` | `peaso/checks/azure_extended.py:176` | Verified; no change |
| `azure.app.remote_debugging_off` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.request_logging` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.scm_minimum_tls` | `peaso/checks/azure_extended.py:185` | Verified; no change |
| `azure.claude.acr_admin_user_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_cmk` | `peaso/checks/claude_azure_common.py:67` | Corrected description |
| `azure.claude.acr_geo_replication` | `peaso/checks/claude_azure_compute.py:733` | Verified; no change |
| `azure.claude.acr_network_default_deny` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_private_endpoint_present` | `peaso/checks/claude_azure_compute.py:773` | Corrected description |
| `azure.claude.acr_private_link_approved` | `peaso/checks/claude_azure_compute.py:763` | Verified; no change |
| `azure.claude.acr_public_network_access_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_quarantine_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_retention_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_trust_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_vnet_service_endpoint` | `peaso/checks/claude_azure_compute.py:749` | Verified; no change |
| `azure.claude.activity_log_alert_nsg_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_nsg_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_policy_assignment_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_policy_assignment_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_public_ip_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_public_ip_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_security_solution_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_security_solution_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_service_health` | `peaso/checks/claude_azure_network.py:325` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.activity_log_alert_sql_firewall_rule_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_sql_firewall_rule_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_subscription_administrative_operations` | `peaso/checks/claude_azure_network.py:239` | Corrected description, fail_when, pass_when |
| `azure.claude.activity_log_alert_subscription_nsg_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_rule_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_rule_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_policy_assignment_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_policy_assignment_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_public_ip_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_public_ip_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_security_solution_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_security_solution_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_firewall_rule_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_server` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_storage_cmk` | `peaso/checks/claude_azure_network.py:459` | Verified; no change |
| `azure.claude.activity_log_storage_private` | `peaso/checks/claude_azure_network.py:466` | Verified; no change |
| `azure.claude.aks_authorized_ip_ranges` | `peaso/checks/claude_azure_identity.py:1057` | Verified; no change |
| `azure.claude.aks_azure_policy_addon` | `peaso/checks/claude_azure_identity.py:1012` | Verified; no change |
| `azure.claude.aks_container_insights_logging` | `peaso/checks/claude_azure_identity.py:1046` | Verified; no change |
| `azure.claude.aks_disk_encryption_set` | `peaso/checks/claude_azure_identity.py:1098` | Verified; no change |
| `azure.claude.aks_encryption_at_host` | `peaso/checks/claude_azure_identity.py:1089` | Verified; no change |
| `azure.claude.aks_http_application_routing_disabled` | `peaso/checks/claude_azure_identity.py:1021` | Corrected description |
| `azure.claude.aks_max_pods_at_least_50` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.aks_network_plugin_azure` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.aks_network_policy_configured` | `peaso/checks/claude_azure_identity.py:1111` | Corrected description, fail_when |
| `azure.claude.aks_node_public_ip_disabled` | `peaso/checks/claude_azure_identity.py:1080` | Verified; no change |
| `azure.claude.aks_paid_sku_tier` | `peaso/checks/claude_azure_identity.py:1123` | Corrected description, pass_when |
| `azure.claude.aks_secret_store_rotation` | `peaso/checks/claude_azure_identity.py:1030` | Verified; no change |
| `azure.claude.aks_version_not_cve_2019_9946` | `peaso/checks/claude_azure_identity.py:1131` | Verified; no change |
| `azure.claude.bastion_host_exists` | `peaso/checks/claude_azure_network.py:824` | Verified; no change |
| `azure.claude.container_group_cmk` | `peaso/checks/claude_azure_compute.py:649` | Verified; no change |
| `azure.claude.container_group_managed_identity` | `peaso/checks/claude_azure_compute.py:665` | Corrected description, fail_when, pass_when |
| `azure.claude.container_group_secure_environment_variables` | `peaso/checks/claude_azure_compute.py:693` | Verified; no change |
| `azure.claude.container_group_virtual_network` | `peaso/checks/claude_azure_compute.py:676` | Verified; no change |
| `azure.claude.cosmos_automatic_failover` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_cmk` | `peaso/checks/claude_azure_compute.py:820` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.cosmos_continuous_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_cors_no_wildcard` | `peaso/checks/claude_azure_compute.py:832` | Verified; no change |
| `azure.claude.cosmos_key_based_metadata_write_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_local_auth_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_minimum_tls12` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_network_restricted` | `peaso/checks/claude_azure_compute.py:846` | Verified; no change |
| `azure.claude.cosmos_private_endpoint_present` | `peaso/checks/claude_azure_compute.py:773` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.cosmos_public_network_access_disabled` | `peaso/checks/claude_azure_common.py:67` | Corrected description, fail_when |
| `azure.claude.cosmos_public_network_access_restricted` | `peaso/checks/claude_azure_common.py:67` | Corrected description, pass_when |
| `azure.claude.cosmos_virtual_network_filter` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_vnet_service_endpoint` | `peaso/checks/claude_azure_compute.py:863` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.databox_edge_double_encryption` | `peaso/checks/claude_azure_compute.py:882` | Verified; no change |
| `azure.claude.databricks_diagnostic_log_delivery` | `peaso/checks/claude_azure_compute.py:915` | Verified; no change |
| `azure.claude.databricks_managed_disk_cmk` | `peaso/checks/claude_azure_compute.py:893` | Verified; no change |
| `azure.claude.databricks_subnet_nsg` | `peaso/checks/claude_azure_compute.py:940` | Verified; no change |
| `azure.claude.databricks_vnet_injection_value` | `peaso/checks/claude_azure_compute.py:970` | Corrected description, fail_when, pass_when |
| `azure.claude.defender_alert_notifications_high` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.defender_alerts_to_owner` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_endpoint_protection` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_running_images_vulnerabilities` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_system_updates` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_vulnerability_solution` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_attack_path_notifications` | `peaso/checks/claude_azure_data.py:109` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.defender_contact_has_email` | `peaso/checks/claude_azure_data.py:99` | Corrected description, fail_when, pass_when |
| `azure.claude.defender_container_registry_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_container_registry_vulnerability_scanning` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_database_plans_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_default_initiative_no_disabled_effects` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.defender_default_policy_enforced` | `peaso/checks/claude_azure_network.py:1028` | Corrected description, not_applicable_when |
| `azure.claude.defender_dns_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_iot_security_solution_enabled` | `peaso/checks/claude_azure_data.py:37` | Corrected description, fail_when, not_applicable_when, pass_when |
| `azure.claude.defender_kubernetes_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_plan_standard_any` | `peaso/checks/claude_azure_data.py:230` | Corrected not_applicable_when |
| `azure.claude.defender_security_contact_email_configured` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.disk_access_private_link` | `peaso/checks/claude_azure_compute.py:104` | Verified; no change |
| `azure.claude.disk_attached_cmk` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_attached_customer_key` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_attached_double_encryption` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_unattached_cmk` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_unattached_customer_key` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.entra_app_credential_not_expiring` | `peaso/checks/claude_azure_identity.py:453` | Verified; no change |
| `azure.claude.entra_auth_methods_strong_registration` | `peaso/checks/claude_azure_identity.py:330` | Verified; no change |
| `azure.claude.entra_ca_mfa_admin_portals` | `peaso/checks/claude_azure_identity.py:353` | Verified; no change |
| `azure.claude.entra_ca_mfa_management_api` | `peaso/checks/claude_azure_identity.py:353` | Verified; no change |
| `azure.claude.entra_ca_policy_requires_mfa` | `peaso/checks/claude_azure_identity.py:432` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.entra_global_admin_fewer_than_five` | `peaso/checks/claude_azure_identity.py:377` | Verified; no change |
| `azure.claude.entra_guest_access_restricted` | `peaso/checks/claude_azure_identity.py:295` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_guest_invites_admins_only` | `peaso/checks/claude_azure_identity.py:286` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_m365_group_creation_restricted` | `peaso/checks/claude_azure_identity.py:409` | Verified; no change |
| `azure.claude.entra_named_location_trusted` | `peaso/checks/claude_azure_identity.py:441` | Verified; no change |
| `azure.claude.entra_non_privileged_user_mfa` | `peaso/checks/claude_azure_identity.py:494` | Verified; no change |
| `azure.claude.entra_privileged_user_mfa` | `peaso/checks/claude_azure_identity.py:494` | Verified; no change |
| `azure.claude.entra_security_defaults_enabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_trusted_named_location_exists` | `peaso/checks/claude_azure_identity.py:391` | Verified; no change |
| `azure.claude.entra_user_consent_disabled` | `peaso/checks/claude_azure_identity.py:310` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_user_consent_not_legacy` | `peaso/checks/claude_azure_identity.py:320` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_user_recent_sign_in` | `peaso/checks/claude_azure_identity.py:473` | Verified; no change |
| `azure.claude.entra_users_cannot_create_apps` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_users_cannot_create_security_groups` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_users_cannot_create_tenants` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_vm_access_user_mfa` | `peaso/checks/claude_azure_identity.py:518` | Verified; no change |
| `azure.claude.eventgrid_domain_managed_identity` | `peaso/checks/claude_azure_identity.py:667` | Corrected description, pass_when |
| `azure.claude.eventgrid_domain_private_link` | `peaso/checks/claude_azure_identity.py:683` | Verified; no change |
| `azure.claude.eventgrid_domain_public_access_disabled` | `peaso/checks/claude_azure_identity.py:700` | Verified; no change |
| `azure.claude.eventgrid_topic_managed_identity` | `peaso/checks/claude_azure_identity.py:667` | Corrected description, pass_when |
| `azure.claude.eventgrid_topic_private_link` | `peaso/checks/claude_azure_identity.py:683` | Verified; no change |
| `azure.claude.eventhub_namespace_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.eventhub_namespace_logging` | `peaso/checks/claude_azure_identity.py:715` | Verified; no change |
| `azure.claude.eventhub_namespace_private_link` | `peaso/checks/claude_azure_identity.py:728` | Verified; no change |
| `azure.claude.eventhub_namespace_vnet_rule` | `peaso/checks/claude_azure_identity.py:745` | Verified; no change |
| `azure.claude.fhir_cmk` | `peaso/checks/claude_azure_identity.py:818` | Verified; no change |
| `azure.claude.fhir_private_link` | `peaso/checks/claude_azure_identity.py:828` | Verified; no change |
| `azure.claude.flow_log_enabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.flow_log_traffic_analytics` | `peaso/checks/claude_azure_network.py:979` | Verified; no change |
| `azure.claude.frontdoor_waf_policy_linked` | `peaso/checks/claude_azure_identity.py:756` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.gateway_subnet_no_nsg` | `peaso/checks/claude_azure_network.py:900` | Verified; no change |
| `azure.claude.hdinsight_cmk` | `peaso/checks/claude_azure_identity.py:772` | Verified; no change |
| `azure.claude.hdinsight_encryption_at_host` | `peaso/checks/claude_azure_identity.py:772` | Verified; no change |
| `azure.claude.hdinsight_encryption_in_transit` | `peaso/checks/claude_azure_identity.py:772` | Verified; no change |
| `azure.claude.hpc_cache_cmk` | `peaso/checks/claude_azure_identity.py:835` | Verified; no change |
| `azure.claude.iam_custom_role_administers_locks` | `peaso/checks/claude_azure_identity.py:584` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_custom_role_no_wildcard_actions` | `peaso/checks/claude_azure_identity.py:552` | Corrected description, fail_when |
| `azure.claude.iam_disabled_user_no_owner` | `peaso/checks/claude_azure_identity.py:630` | Verified; no change |
| `azure.claude.iam_disabled_user_no_role_assignment` | `peaso/checks/claude_azure_identity.py:630` | Verified; no change |
| `azure.claude.iam_external_user_no_owner` | `peaso/checks/claude_azure_identity.py:630` | Verified; no change |
| `azure.claude.iam_external_user_no_reader` | `peaso/checks/claude_azure_identity.py:630` | Verified; no change |
| `azure.claude.iam_external_user_no_write` | `peaso/checks/claude_azure_identity.py:630` | Verified; no change |
| `azure.claude.iam_no_custom_role` | `peaso/checks/claude_azure_identity.py:574` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_no_user_access_administrator_assignment` | `peaso/checks/claude_azure_identity.py:533` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_root_custom_role_no_wildcard` | `peaso/checks/claude_azure_identity.py:563` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_subscription_owner_between_2_and_3` | `peaso/checks/claude_azure_identity.py:608` | Verified; no change |
| `azure.claude.iam_subscription_owner_max_3` | `peaso/checks/claude_azure_identity.py:608` | Verified; no change |
| `azure.claude.iam_subscription_owner_more_than_1` | `peaso/checks/claude_azure_identity.py:608` | Verified; no change |
| `azure.claude.iam_subscription_tenant_transfer_restricted` | `peaso/checks/claude_azure_identity.py:652` | Verified; no change |
| `azure.claude.iam_user_no_contributor_assignment` | `peaso/checks/claude_azure_identity.py:542` | Verified; no change |
| `azure.claude.insights_activity_logs_container_byok` | `peaso/checks/claude_azure_network.py:496` | Verified; no change |
| `azure.claude.insights_activity_logs_container_private` | `peaso/checks/claude_azure_network.py:513` | Verified; no change |
| `azure.claude.insights_operational_logs_container_byok` | `peaso/checks/claude_azure_network.py:496` | Verified; no change |
| `azure.claude.insights_operational_logs_container_private` | `peaso/checks/claude_azure_network.py:513` | Verified; no change |
| `azure.claude.iot_hub_logging` | `peaso/checks/claude_azure_identity.py:715` | Verified; no change |
| `azure.claude.iot_hub_private_link` | `peaso/checks/claude_azure_identity.py:728` | Verified; no change |
| `azure.claude.keyvault_audit_and_alllogs_groups` | `peaso/checks/claude_azure_identity.py:908` | Corrected description |
| `azure.claude.keyvault_audit_logging` | `peaso/checks/claude_azure_identity.py:893` | Corrected description, fail_when, pass_when |
| `azure.claude.keyvault_certificate_validity_12_months` | `peaso/checks/claude_azure_identity.py:1000` | Verified; no change |
| `azure.claude.keyvault_firewall_ip_rules` | `peaso/checks/claude_azure_identity.py:872` | Verified; no change |
| `azure.claude.keyvault_key_automatic_rotation_after_create` | `peaso/checks/claude_azure_identity.py:990` | Verified; no change |
| `azure.claude.keyvault_key_expiration_set` | `peaso/checks/claude_azure_identity.py:944` | Verified; no change |
| `azure.claude.keyvault_key_rotation_policy` | `peaso/checks/claude_azure_identity.py:981` | Corrected description |
| `azure.claude.keyvault_non_rbac_key_expiration_set` | `peaso/checks/claude_azure_identity.py:944` | Verified; no change |
| `azure.claude.keyvault_non_rbac_secret_expiration_set` | `peaso/checks/claude_azure_identity.py:944` | Verified; no change |
| `azure.claude.keyvault_private_endpoint_exists` | `peaso/checks/claude_azure_identity.py:852` | Verified; no change |
| `azure.claude.keyvault_private_endpoint_only_access` | `peaso/checks/claude_azure_identity.py:860` | Corrected description |
| `azure.claude.keyvault_rbac_key_expiration_set` | `peaso/checks/claude_azure_identity.py:944` | Verified; no change |
| `azure.claude.keyvault_rbac_secret_expiration_set` | `peaso/checks/claude_azure_identity.py:944` | Verified; no change |
| `azure.claude.keyvault_vnet_service_endpoint` | `peaso/checks/claude_azure_identity.py:881` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.kusto_cmk` | `peaso/checks/claude_azure_identity.py:1165` | Verified; no change |
| `azure.claude.kusto_disk_encryption` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.kusto_double_encryption` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.kusto_sku_with_sla` | `peaso/checks/claude_azure_identity.py:1182` | Verified; no change |
| `azure.claude.log_analytics_local_auth_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.log_analytics_public_ingestion_query_disabled` | `peaso/checks/claude_azure_network.py:537` | Verified; no change |
| `azure.claude.logic_app_workflow_diagnostic_logging` | `peaso/checks/claude_azure_network.py:570` | Verified; no change |
| `azure.claude.managed_hsm_audit_logging` | `peaso/checks/claude_azure_identity.py:918` | Verified; no change |
| `azure.claude.managed_hsm_purge_protection` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.ml_workspace_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.mssql_managed_instance_tde_cmk` | `peaso/checks/claude_azure_network.py:595` | Corrected description, fail_when, pass_when |
| `azure.claude.mssql_managed_instance_vulnerability_assessment` | `peaso/checks/claude_azure_network.py:615` | Corrected description, fail_when, pass_when |
| `azure.claude.mysql_flexible_audit_log_connection` | `peaso/checks/claude_azure_network.py:678` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.mysql_flexible_audit_log_enabled` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.mysql_flexible_geo_redundant_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.mysql_flexible_high_availability` | `peaso/checks/claude_azure_network.py:716` | Corrected description, pass_when |
| `azure.claude.mysql_flexible_min_tls_12` | `peaso/checks/claude_azure_network.py:692` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.mysql_flexible_secure_transport` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.network_watcher_flow_logs_retention_90` | `peaso/checks/claude_azure_network.py:1008` | Verified; no change |
| `azure.claude.network_watcher_flow_logs_traffic_analytics` | `peaso/checks/claude_azure_network.py:994` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.network_watcher_in_vnet_region` | `peaso/checks/claude_azure_network.py:941` | Verified; no change |
| `azure.claude.nic_no_public_ip` | `peaso/checks/claude_azure_network.py:838` | Verified; no change |
| `azure.claude.nsg_associated_with_subnet` | `peaso/checks/claude_azure_network.py:868` | Verified; no change |
| `azure.claude.nsg_diagnostic_logging` | `peaso/checks/claude_azure_network.py:581` | Verified; no change |
| `azure.claude.nsg_internet_all_ports_tcp_udp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_common_ports` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_http` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_http_https` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_icmp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_rdp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_remote_access` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_ssh` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_135` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_1433` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_20` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_21` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_23` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_25` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_3306` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_4333` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_445` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_53` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5432` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5500` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5900` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_137` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_138` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_1434` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_445` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_53` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_any` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_services` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_outbound_restricted` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.postgresql_flexible_connection_throttling` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_entra_authentication` | `peaso/checks/claude_azure_network.py:804` | Verified; no change |
| `azure.claude.postgresql_flexible_geo_redundant_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.postgresql_flexible_high_availability` | `peaso/checks/claude_azure_network.py:716` | Corrected description, pass_when |
| `azure.claude.postgresql_flexible_log_checkpoints` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_connections` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_disconnections` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_retention_over_3_days` | `peaso/checks/claude_azure_network.py:744` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.postgresql_flexible_no_azure_services_rule` | `peaso/checks/claude_azure_network.py:770` | Verified; no change |
| `azure.claude.postgresql_flexible_no_zero_address_rule` | `peaso/checks/claude_azure_network.py:781` | Verified; no change |
| `azure.claude.postgresql_flexible_secure_transport` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.recovery_vault_backup_retention_30_days` | `peaso/checks/claude_azure_network.py:1083` | Verified; no change |
| `azure.claude.recovery_vault_has_protected_items` | `peaso/checks/claude_azure_network.py:1113` | Verified; no change |
| `azure.claude.recovery_vault_managed_identity` | `peaso/checks/claude_azure_network.py:1057` | Verified; no change |
| `azure.claude.recovery_vault_private_endpoint_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.recovery_vault_private_endpoint_site_recovery` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.search_service_logging_enabled` | `peaso/checks/claude_azure_data.py:64` | Verified; no change |
| `azure.claude.search_service_replica_count_above_3` | `peaso/checks/claude_azure_data.py:78` | Verified; no change |
| `azure.claude.servicebus_namespace_local_auth_disabled` | `peaso/checks/claude_azure_data.py:396` | Corrected description, not_applicable_when |
| `azure.claude.servicebus_namespace_logging_enabled` | `peaso/checks/claude_azure_data.py:64` | Verified; no change |
| `azure.claude.servicebus_namespace_network_restricted` | `peaso/checks/claude_azure_data.py:406` | Corrected description, evaluated, fail_when, not_applicable_when, pass_when |
| `azure.claude.servicebus_namespace_private_link` | `peaso/checks/claude_azure_data.py:383` | Corrected not_applicable_when |
| `azure.claude.servicebus_premium_namespace_cmk` | `peaso/checks/claude_azure_data.py:419` | Verified; no change |
| `azure.claude.servicebus_premium_namespace_vnet_rules` | `peaso/checks/claude_azure_data.py:430` | Corrected description, fail_when, pass_when |
| `azure.claude.servicefabric_cluster_encrypt_and_sign` | `peaso/checks/claude_azure_data.py:454` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.servicefabric_cluster_entra_auth` | `peaso/checks/claude_azure_data.py:444` | Verified; no change |
| `azure.claude.signalr_service_no_free_tier` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.signalr_service_private_link` | `peaso/checks/claude_azure_data.py:467` | Corrected not_applicable_when |
| `azure.claude.spring_cloud_service_vnet_injection` | `peaso/checks/claude_azure_data.py:478` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_audit_retention_over_90` | `peaso/checks/claude_azure_data.py:587` | Verified; no change |
| `azure.claude.sql_audit_storage_retention_90` | `peaso/checks/claude_azure_data.py:575` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_database_long_term_retention` | `peaso/checks/claude_azure_data.py:516` | Verified; no change |
| `azure.claude.sql_database_va_findings_resolved` | `peaso/checks/claude_azure_data.py:530` | Corrected not_applicable_when |
| `azure.claude.sql_firewall_no_full_range` | `peaso/checks/claude_azure_data.py:509` | Verified; no change |
| `azure.claude.sql_firewall_no_internet_or_azure_services` | `peaso/checks/claude_azure_data.py:501` | Verified; no change |
| `azure.claude.sql_server_entra_admin` | `peaso/checks/claude_azure_data.py:546` | Corrected evaluated |
| `azure.claude.sql_server_minimal_tls_12` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.sql_server_private_link` | `peaso/checks/claude_azure_data.py:555` | Verified; no change |
| `azure.claude.sql_server_vnet_rules` | `peaso/checks/claude_azure_data.py:562` | Verified; no change |
| `azure.claude.sql_server_vulnerability_assessment_enabled` | `peaso/checks/claude_azure_data.py:605` | Corrected description, fail_when |
| `azure.claude.sql_tde_protector_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.sql_va_notify_admins` | `peaso/checks/claude_azure_data.py:621` | Corrected evaluated, not_applicable_when |
| `azure.claude.sql_va_recurring_scans` | `peaso/checks/claude_azure_data.py:621` | Corrected evaluated, not_applicable_when |
| `azure.claude.sql_va_report_emails` | `peaso/checks/claude_azure_data.py:621` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_va_reports_configured` | `peaso/checks/claude_azure_data.py:621` | Corrected description, evaluated, fail_when, not_applicable_when, pass_when |
| `azure.claude.storage_access_keys_rotated_90` | `peaso/checks/claude_azure_data.py:685` | Verified; no change |
| `azure.claude.storage_account_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.storage_account_geo_redundant` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.storage_blob_and_container_soft_delete_7_365` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_blob_classic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected description |
| `azure.claude.storage_blob_diagnostic_logging` | `peaso/checks/claude_azure_data.py:739` | Verified; no change |
| `azure.claude.storage_blob_soft_delete_enabled` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_container_no_public_access` | `peaso/checks/claude_azure_data.py:895` | Corrected description, fail_when |
| `azure.claude.storage_encryption_scope_cmk` | `peaso/checks/claude_azure_data.py:902` | Verified; no change |
| `azure.claude.storage_file_share_soft_delete_1_365` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_file_share_soft_delete_enabled` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_key_expiration_policy_90` | `peaso/checks/claude_azure_data.py:671` | Verified; no change |
| `azure.claude.storage_key_expiration_policy_max_90` | `peaso/checks/claude_azure_data.py:678` | Verified; no change |
| `azure.claude.storage_private_endpoint_present` | `peaso/checks/claude_azure_data.py:727` | Corrected description |

### Validation and remaining doubts

- Input IDs, output keys, and decisions are complete and unique. All registered predicates have a PASS and FAIL fixture with the expected result.
- UNKNOWN, MANUAL, DENIED, and malformed-fact returns follow the evaluator and shared fact guards; descriptions focus on PASS, FAIL, and explicit NOT_APPLICABLE branches.
- No cloud API or network call was made.
- Remaining doubts: none identified in this slice.

## Independent verification — 2026-10-12

Input: `inputs/desc-azure-1.json` (302 IDs). Output: `descriptions/desc-azure-1.json` (302 keys). Every ID received one decision against its registered evaluator, including shared helper predicates. Source locations below are the executable predicate/helper locations; the index registration line was also checked for every ID.

Corrections: 77 entries, 180 fields. Fixture verdicts: 302 PASS and 302 FAIL checked. Problems: 8.

| ID | Evaluator | Decision |
| --- | --- | --- |
| `azure.aks.api_server_restricted` | `peaso/checks/exposure_endpoints.py:23` | Verified; no change |
| `azure.aks.auto_upgrade` | `peaso/checks/azure_extended.py:137` | Verified; no change |
| `azure.aks.azure_rbac` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.defender_monitoring` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.network_policy` | `peaso/checks/azure.py:43` | Verified; no change |
| `azure.aks.no_local_accounts` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.private_cluster` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.aks.rbac` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.client_certificates` | `peaso/checks/azure_extended.py:125` | Corrected fail_when |
| `azure.app.cors_no_wildcards` | `peaso/checks/azure_extended.py:203` | Verified; no change |
| `azure.app.ftps_only` | `peaso/checks/azure_extended.py:194` | Verified; no change |
| `azure.app.http2` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.https_only` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.minimum_tls` | `peaso/checks/azure_extended.py:176` | Verified; no change |
| `azure.app.remote_debugging_off` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.request_logging` | `peaso/checks/facts.py:46` | Verified; no change |
| `azure.app.scm_minimum_tls` | `peaso/checks/azure_extended.py:185` | Verified; no change |
| `azure.claude.acr_admin_user_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_cmk` | `peaso/checks/claude_azure_common.py:67` | Corrected description |
| `azure.claude.acr_geo_replication` | `peaso/checks/claude_azure_compute.py:733` | Verified; no change |
| `azure.claude.acr_network_default_deny` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_private_endpoint_present` | `peaso/checks/claude_azure_compute.py:773` | Corrected description |
| `azure.claude.acr_private_link_approved` | `peaso/checks/claude_azure_compute.py:763` | Verified; no change |
| `azure.claude.acr_public_network_access_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_quarantine_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_retention_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_trust_policy` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.acr_vnet_service_endpoint` | `peaso/checks/claude_azure_compute.py:749` | Verified; no change |
| `azure.claude.activity_log_alert_nsg_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_nsg_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_policy_assignment_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_policy_assignment_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_public_ip_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_public_ip_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_security_solution_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_security_solution_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_service_health` | `peaso/checks/claude_azure_network.py:325` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.activity_log_alert_sql_firewall_rule_delete` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_sql_firewall_rule_write` | `peaso/checks/claude_azure_network.py:257` | Corrected description |
| `azure.claude.activity_log_alert_subscription_administrative_operations` | `peaso/checks/claude_azure_network.py:239` | Corrected description, fail_when, pass_when |
| `azure.claude.activity_log_alert_subscription_nsg_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_rule_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_rule_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_nsg_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_policy_assignment_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_policy_assignment_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_public_ip_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_public_ip_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_security_solution_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_security_solution_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_firewall_rule_delete` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_firewall_rule_write` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_alert_subscription_sql_server` | `peaso/checks/claude_azure_network.py:239` | Verified; no change |
| `azure.claude.activity_log_storage_cmk` | `peaso/checks/claude_azure_network.py:459` | Corrected description, evaluated, fail_when, not_applicable_when, pass_when |
| `azure.claude.activity_log_storage_private` | `peaso/checks/claude_azure_network.py:466` | Verified; no change |
| `azure.claude.aks_authorized_ip_ranges` | `peaso/checks/claude_azure_identity.py:1184` | Verified; no change |
| `azure.claude.aks_azure_policy_addon` | `peaso/checks/claude_azure_identity.py:1139` | Verified; no change |
| `azure.claude.aks_container_insights_logging` | `peaso/checks/claude_azure_identity.py:1173` | Verified; no change |
| `azure.claude.aks_disk_encryption_set` | `peaso/checks/claude_azure_identity.py:1225` | Verified; no change |
| `azure.claude.aks_encryption_at_host` | `peaso/checks/claude_azure_identity.py:1216` | Verified; no change |
| `azure.claude.aks_http_application_routing_disabled` | `peaso/checks/claude_azure_identity.py:1148` | Corrected description |
| `azure.claude.aks_max_pods_at_least_50` | `peaso/checks/claude_azure_identity.py:1198` | Verified; no change |
| `azure.claude.aks_network_plugin_azure` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.aks_network_policy_configured` | `peaso/checks/claude_azure_identity.py:1238` | Corrected description, fail_when |
| `azure.claude.aks_node_public_ip_disabled` | `peaso/checks/claude_azure_identity.py:1207` | Verified; no change |
| `azure.claude.aks_paid_sku_tier` | `peaso/checks/claude_azure_identity.py:1250` | Corrected description, pass_when |
| `azure.claude.aks_secret_store_rotation` | `peaso/checks/claude_azure_identity.py:1157` | Verified; no change |
| `azure.claude.aks_version_not_cve_2019_9946` | `peaso/checks/claude_azure_identity.py:1258` | Verified; no change |
| `azure.claude.bastion_host_exists` | `peaso/checks/claude_azure_network.py:824` | Verified; no change |
| `azure.claude.container_group_cmk` | `peaso/checks/claude_azure_compute.py:649` | Verified; no change |
| `azure.claude.container_group_managed_identity` | `peaso/checks/claude_azure_compute.py:665` | Corrected description, fail_when, pass_when |
| `azure.claude.container_group_secure_environment_variables` | `peaso/checks/claude_azure_compute.py:693` | Verified; no change |
| `azure.claude.container_group_virtual_network` | `peaso/checks/claude_azure_compute.py:676` | Verified; no change |
| `azure.claude.cosmos_automatic_failover` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_cmk` | `peaso/checks/claude_azure_compute.py:820` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.cosmos_continuous_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_cors_no_wildcard` | `peaso/checks/claude_azure_compute.py:832` | Verified; no change |
| `azure.claude.cosmos_key_based_metadata_write_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_local_auth_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_minimum_tls12` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_network_restricted` | `peaso/checks/claude_azure_compute.py:846` | Verified; no change |
| `azure.claude.cosmos_private_endpoint_present` | `peaso/checks/claude_azure_compute.py:773` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.cosmos_public_network_access_disabled` | `peaso/checks/claude_azure_common.py:67` | Corrected description, fail_when |
| `azure.claude.cosmos_public_network_access_restricted` | `peaso/checks/claude_azure_common.py:67` | Corrected description, pass_when |
| `azure.claude.cosmos_virtual_network_filter` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.cosmos_vnet_service_endpoint` | `peaso/checks/claude_azure_compute.py:863` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.databox_edge_double_encryption` | `peaso/checks/claude_azure_compute.py:882` | Verified; no change |
| `azure.claude.databricks_diagnostic_log_delivery` | `peaso/checks/claude_azure_compute.py:915` | Verified; no change |
| `azure.claude.databricks_managed_disk_cmk` | `peaso/checks/claude_azure_compute.py:893` | Verified; no change |
| `azure.claude.databricks_subnet_nsg` | `peaso/checks/claude_azure_compute.py:940` | Verified; no change |
| `azure.claude.databricks_vnet_injection_value` | `peaso/checks/claude_azure_compute.py:970` | Corrected description, fail_when, pass_when |
| `azure.claude.defender_alert_notifications_high` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.defender_alerts_to_owner` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_endpoint_protection` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_running_images_vulnerabilities` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_system_updates` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_assessment_vulnerability_solution` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_attack_path_notifications` | `peaso/checks/claude_azure_data.py:109` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.defender_contact_has_email` | `peaso/checks/claude_azure_data.py:99` | Corrected description, fail_when, pass_when |
| `azure.claude.defender_container_registry_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_container_registry_vulnerability_scanning` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_database_plans_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_default_initiative_no_disabled_effects` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.defender_default_policy_enforced` | `peaso/checks/claude_azure_network.py:1028` | Corrected description, not_applicable_when |
| `azure.claude.defender_dns_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_iot_security_solution_enabled` | `peaso/checks/claude_azure_data.py:37` | Corrected description, fail_when, not_applicable_when, pass_when |
| `azure.claude.defender_kubernetes_plan_standard` | `peaso/checks/claude_azure_data.py:37` | Verified; no change |
| `azure.claude.defender_plan_standard_any` | `peaso/checks/claude_azure_data.py:230` | Corrected not_applicable_when |
| `azure.claude.defender_security_contact_email_configured` | `peaso/checks/claude_azure_data.py:37` | Corrected description |
| `azure.claude.disk_access_private_link` | `peaso/checks/claude_azure_compute.py:104` | Verified; no change |
| `azure.claude.disk_attached_cmk` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_attached_customer_key` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_attached_double_encryption` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_unattached_cmk` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.disk_unattached_customer_key` | `peaso/checks/claude_azure_compute.py:75` | Verified; no change |
| `azure.claude.entra_app_credential_not_expiring` | `peaso/checks/claude_azure_identity.py:561` | Verified; no change |
| `azure.claude.entra_auth_methods_strong_registration` | `peaso/checks/claude_azure_identity.py:378` | Verified; no change |
| `azure.claude.entra_ca_mfa_admin_portals` | `peaso/checks/claude_azure_identity.py:401` | Verified; no change |
| `azure.claude.entra_ca_mfa_management_api` | `peaso/checks/claude_azure_identity.py:401` | Verified; no change |
| `azure.claude.entra_ca_policy_requires_mfa` | `peaso/checks/claude_azure_identity.py:480` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.entra_global_admin_fewer_than_five` | `peaso/checks/claude_azure_identity.py:425` | Verified; no change |
| `azure.claude.entra_guest_access_restricted` | `peaso/checks/claude_azure_identity.py:312` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_guest_invites_admins_only` | `peaso/checks/claude_azure_identity.py:303` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_m365_group_creation_restricted` | `peaso/checks/claude_azure_identity.py:457` | Verified; no change |
| `azure.claude.entra_named_location_trusted` | `peaso/checks/claude_azure_identity.py:549` | Verified; no change |
| `azure.claude.entra_non_privileged_user_mfa` | `peaso/checks/claude_azure_identity.py:612` | Verified; no change |
| `azure.claude.entra_privileged_user_mfa` | `peaso/checks/claude_azure_identity.py:612` | Verified; no change |
| `azure.claude.entra_security_defaults_enabled` | `peaso/checks/claude_azure_identity.py:281` | Verified; no change |
| `azure.claude.entra_trusted_named_location_exists` | `peaso/checks/claude_azure_identity.py:439` | Verified; no change |
| `azure.claude.entra_user_consent_disabled` | `peaso/checks/claude_azure_identity.py:346` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_user_consent_not_legacy` | `peaso/checks/claude_azure_identity.py:362` | Corrected description, fail_when, pass_when |
| `azure.claude.entra_user_recent_sign_in` | `peaso/checks/claude_azure_identity.py:581` | Verified; no change |
| `azure.claude.entra_users_cannot_create_apps` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_users_cannot_create_security_groups` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_users_cannot_create_tenants` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.entra_vm_access_user_mfa` | `peaso/checks/claude_azure_identity.py:636` | Verified; no change |
| `azure.claude.eventgrid_domain_managed_identity` | `peaso/checks/claude_azure_identity.py:794` | Corrected description, pass_when |
| `azure.claude.eventgrid_domain_private_link` | `peaso/checks/claude_azure_identity.py:810` | Verified; no change |
| `azure.claude.eventgrid_domain_public_access_disabled` | `peaso/checks/claude_azure_identity.py:827` | Verified; no change |
| `azure.claude.eventgrid_topic_managed_identity` | `peaso/checks/claude_azure_identity.py:794` | Corrected description, pass_when |
| `azure.claude.eventgrid_topic_private_link` | `peaso/checks/claude_azure_identity.py:810` | Verified; no change |
| `azure.claude.eventhub_namespace_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.eventhub_namespace_logging` | `peaso/checks/claude_azure_identity.py:842` | Verified; no change |
| `azure.claude.eventhub_namespace_private_link` | `peaso/checks/claude_azure_identity.py:855` | Verified; no change |
| `azure.claude.eventhub_namespace_vnet_rule` | `peaso/checks/claude_azure_identity.py:872` | Verified; no change |
| `azure.claude.fhir_cmk` | `peaso/checks/claude_azure_identity.py:945` | Verified; no change |
| `azure.claude.fhir_private_link` | `peaso/checks/claude_azure_identity.py:955` | Verified; no change |
| `azure.claude.flow_log_enabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.flow_log_traffic_analytics` | `peaso/checks/claude_azure_network.py:979` | Verified; no change |
| `azure.claude.frontdoor_waf_policy_linked` | `peaso/checks/claude_azure_identity.py:883` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.gateway_subnet_no_nsg` | `peaso/checks/claude_azure_network.py:900` | Verified; no change |
| `azure.claude.hdinsight_cmk` | `peaso/checks/claude_azure_identity.py:899` | Verified; no change |
| `azure.claude.hdinsight_encryption_at_host` | `peaso/checks/claude_azure_identity.py:899` | Verified; no change |
| `azure.claude.hdinsight_encryption_in_transit` | `peaso/checks/claude_azure_identity.py:899` | Verified; no change |
| `azure.claude.hpc_cache_cmk` | `peaso/checks/claude_azure_identity.py:962` | Verified; no change |
| `azure.claude.iam_custom_role_administers_locks` | `peaso/checks/claude_azure_identity.py:711` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_custom_role_no_wildcard_actions` | `peaso/checks/claude_azure_identity.py:670` | Corrected description, fail_when |
| `azure.claude.iam_disabled_user_no_owner` | `peaso/checks/claude_azure_identity.py:757` | Verified; no change |
| `azure.claude.iam_disabled_user_no_role_assignment` | `peaso/checks/claude_azure_identity.py:757` | Verified; no change |
| `azure.claude.iam_external_user_no_owner` | `peaso/checks/claude_azure_identity.py:757` | Verified; no change |
| `azure.claude.iam_external_user_no_reader` | `peaso/checks/claude_azure_identity.py:757` | Verified; no change |
| `azure.claude.iam_external_user_no_write` | `peaso/checks/claude_azure_identity.py:757` | Verified; no change |
| `azure.claude.iam_no_custom_role` | `peaso/checks/claude_azure_identity.py:701` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_no_user_access_administrator_assignment` | `peaso/checks/claude_azure_identity.py:651` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_root_custom_role_no_wildcard` | `peaso/checks/claude_azure_identity.py:681` | Corrected description, fail_when, pass_when |
| `azure.claude.iam_subscription_owner_between_2_and_3` | `peaso/checks/claude_azure_identity.py:735` | Verified; no change |
| `azure.claude.iam_subscription_owner_max_3` | `peaso/checks/claude_azure_identity.py:735` | Verified; no change |
| `azure.claude.iam_subscription_owner_more_than_1` | `peaso/checks/claude_azure_identity.py:735` | Verified; no change |
| `azure.claude.iam_subscription_tenant_transfer_restricted` | `peaso/checks/claude_azure_identity.py:779` | Verified; no change |
| `azure.claude.iam_user_no_contributor_assignment` | `peaso/checks/claude_azure_identity.py:660` | Verified; no change |
| `azure.claude.insights_activity_logs_container_byok` | `peaso/checks/claude_azure_network.py:496` | Verified; no change |
| `azure.claude.insights_activity_logs_container_private` | `peaso/checks/claude_azure_network.py:513` | Verified; no change |
| `azure.claude.insights_operational_logs_container_byok` | `peaso/checks/claude_azure_network.py:496` | Verified; no change |
| `azure.claude.insights_operational_logs_container_private` | `peaso/checks/claude_azure_network.py:513` | Verified; no change |
| `azure.claude.iot_hub_logging` | `peaso/checks/claude_azure_identity.py:842` | Verified; no change |
| `azure.claude.iot_hub_private_link` | `peaso/checks/claude_azure_identity.py:855` | Verified; no change |
| `azure.claude.keyvault_audit_and_alllogs_groups` | `peaso/checks/claude_azure_identity.py:1035` | Corrected description |
| `azure.claude.keyvault_audit_logging` | `peaso/checks/claude_azure_identity.py:1020` | Corrected description, fail_when, pass_when |
| `azure.claude.keyvault_certificate_validity_12_months` | `peaso/checks/claude_azure_identity.py:1127` | Verified; no change |
| `azure.claude.keyvault_firewall_ip_rules` | `peaso/checks/claude_azure_identity.py:999` | Verified; no change |
| `azure.claude.keyvault_key_automatic_rotation_after_create` | `peaso/checks/claude_azure_identity.py:1117` | Verified; no change |
| `azure.claude.keyvault_key_expiration_set` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.keyvault_key_rotation_policy` | `peaso/checks/claude_azure_identity.py:1108` | Corrected description |
| `azure.claude.keyvault_non_rbac_key_expiration_set` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.keyvault_non_rbac_secret_expiration_set` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.keyvault_private_endpoint_exists` | `peaso/checks/claude_azure_identity.py:979` | Verified; no change |
| `azure.claude.keyvault_private_endpoint_only_access` | `peaso/checks/claude_azure_identity.py:987` | Corrected description |
| `azure.claude.keyvault_rbac_key_expiration_set` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.keyvault_rbac_secret_expiration_set` | `peaso/checks/claude_azure_identity.py:1071` | Verified; no change |
| `azure.claude.keyvault_vnet_service_endpoint` | `peaso/checks/claude_azure_identity.py:1008` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.kusto_cmk` | `peaso/checks/claude_azure_identity.py:1292` | Verified; no change |
| `azure.claude.kusto_disk_encryption` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.kusto_double_encryption` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.kusto_sku_with_sla` | `peaso/checks/claude_azure_identity.py:1309` | Verified; no change |
| `azure.claude.log_analytics_local_auth_disabled` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.log_analytics_public_ingestion_query_disabled` | `peaso/checks/claude_azure_network.py:537` | Verified; no change |
| `azure.claude.logic_app_workflow_diagnostic_logging` | `peaso/checks/claude_azure_network.py:570` | Verified; no change |
| `azure.claude.managed_hsm_audit_logging` | `peaso/checks/claude_azure_identity.py:1045` | Verified; no change |
| `azure.claude.managed_hsm_purge_protection` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.ml_workspace_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.mssql_managed_instance_tde_cmk` | `peaso/checks/claude_azure_network.py:595` | Corrected description, fail_when, pass_when |
| `azure.claude.mssql_managed_instance_vulnerability_assessment` | `peaso/checks/claude_azure_network.py:615` | Corrected description, fail_when, pass_when |
| `azure.claude.mysql_flexible_audit_log_connection` | `peaso/checks/claude_azure_network.py:678` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.mysql_flexible_audit_log_enabled` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.mysql_flexible_geo_redundant_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.mysql_flexible_high_availability` | `peaso/checks/claude_azure_network.py:716` | Corrected description, pass_when |
| `azure.claude.mysql_flexible_min_tls_12` | `peaso/checks/claude_azure_network.py:692` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.mysql_flexible_secure_transport` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.network_watcher_flow_logs_retention_90` | `peaso/checks/claude_azure_network.py:1008` | Verified; no change |
| `azure.claude.network_watcher_flow_logs_traffic_analytics` | `peaso/checks/claude_azure_network.py:994` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.network_watcher_in_vnet_region` | `peaso/checks/claude_azure_network.py:941` | Verified; no change |
| `azure.claude.nic_no_public_ip` | `peaso/checks/claude_azure_network.py:838` | Verified; no change |
| `azure.claude.nsg_associated_with_subnet` | `peaso/checks/claude_azure_network.py:868` | Verified; no change |
| `azure.claude.nsg_diagnostic_logging` | `peaso/checks/claude_azure_network.py:581` | Verified; no change |
| `azure.claude.nsg_internet_all_ports_tcp_udp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_common_ports` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_http` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_http_https` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_icmp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_rdp` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_remote_access` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_ssh` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_135` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_1433` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_20` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_21` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_23` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_25` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_3306` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_4333` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_445` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_53` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5432` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5500` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_tcp_5900` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_137` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_138` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_1434` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_445` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_53` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_any` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_internet_udp_services` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.nsg_outbound_restricted` | `peaso/checks/claude_azure_network.py:132` | Verified; no change |
| `azure.claude.postgresql_flexible_connection_throttling` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_entra_authentication` | `peaso/checks/claude_azure_network.py:804` | Verified; no change |
| `azure.claude.postgresql_flexible_geo_redundant_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.postgresql_flexible_high_availability` | `peaso/checks/claude_azure_network.py:716` | Corrected description, pass_when |
| `azure.claude.postgresql_flexible_log_checkpoints` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_connections` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_disconnections` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.postgresql_flexible_log_retention_over_3_days` | `peaso/checks/claude_azure_network.py:744` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.postgresql_flexible_no_azure_services_rule` | `peaso/checks/claude_azure_network.py:770` | Verified; no change |
| `azure.claude.postgresql_flexible_no_zero_address_rule` | `peaso/checks/claude_azure_network.py:781` | Verified; no change |
| `azure.claude.postgresql_flexible_secure_transport` | `peaso/checks/claude_azure_network.py:651` | Verified; no change |
| `azure.claude.recovery_vault_backup_retention_30_days` | `peaso/checks/claude_azure_network.py:1083` | Verified; no change |
| `azure.claude.recovery_vault_has_protected_items` | `peaso/checks/claude_azure_network.py:1113` | Verified; no change |
| `azure.claude.recovery_vault_managed_identity` | `peaso/checks/claude_azure_network.py:1057` | Verified; no change |
| `azure.claude.recovery_vault_private_endpoint_backup` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.recovery_vault_private_endpoint_site_recovery` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.search_service_logging_enabled` | `peaso/checks/claude_azure_data.py:64` | Verified; no change |
| `azure.claude.search_service_replica_count_above_3` | `peaso/checks/claude_azure_data.py:78` | Verified; no change |
| `azure.claude.servicebus_namespace_local_auth_disabled` | `peaso/checks/claude_azure_data.py:396` | Corrected description, not_applicable_when |
| `azure.claude.servicebus_namespace_logging_enabled` | `peaso/checks/claude_azure_data.py:64` | Verified; no change |
| `azure.claude.servicebus_namespace_network_restricted` | `peaso/checks/claude_azure_data.py:406` | Corrected description, evaluated, fail_when, not_applicable_when, pass_when |
| `azure.claude.servicebus_namespace_private_link` | `peaso/checks/claude_azure_data.py:383` | Corrected not_applicable_when |
| `azure.claude.servicebus_premium_namespace_cmk` | `peaso/checks/claude_azure_data.py:419` | Verified; no change |
| `azure.claude.servicebus_premium_namespace_vnet_rules` | `peaso/checks/claude_azure_data.py:430` | Corrected description, fail_when, pass_when |
| `azure.claude.servicefabric_cluster_encrypt_and_sign` | `peaso/checks/claude_azure_data.py:454` | Corrected description, evaluated, fail_when, pass_when |
| `azure.claude.servicefabric_cluster_entra_auth` | `peaso/checks/claude_azure_data.py:444` | Verified; no change |
| `azure.claude.signalr_service_no_free_tier` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.signalr_service_private_link` | `peaso/checks/claude_azure_data.py:467` | Corrected not_applicable_when |
| `azure.claude.spring_cloud_service_vnet_injection` | `peaso/checks/claude_azure_data.py:478` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_audit_retention_over_90` | `peaso/checks/claude_azure_data.py:587` | Verified; no change |
| `azure.claude.sql_audit_storage_retention_90` | `peaso/checks/claude_azure_data.py:575` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_database_long_term_retention` | `peaso/checks/claude_azure_data.py:516` | Verified; no change |
| `azure.claude.sql_database_va_findings_resolved` | `peaso/checks/claude_azure_data.py:530` | Corrected not_applicable_when |
| `azure.claude.sql_firewall_no_full_range` | `peaso/checks/claude_azure_data.py:509` | Verified; no change |
| `azure.claude.sql_firewall_no_internet_or_azure_services` | `peaso/checks/claude_azure_data.py:501` | Verified; no change |
| `azure.claude.sql_server_entra_admin` | `peaso/checks/claude_azure_data.py:546` | Corrected evaluated |
| `azure.claude.sql_server_minimal_tls_12` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.sql_server_private_link` | `peaso/checks/claude_azure_data.py:555` | Verified; no change |
| `azure.claude.sql_server_vnet_rules` | `peaso/checks/claude_azure_data.py:562` | Verified; no change |
| `azure.claude.sql_server_vulnerability_assessment_enabled` | `peaso/checks/claude_azure_data.py:605` | Corrected description, fail_when |
| `azure.claude.sql_tde_protector_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.sql_va_notify_admins` | `peaso/checks/claude_azure_data.py:621` | Corrected evaluated, not_applicable_when |
| `azure.claude.sql_va_recurring_scans` | `peaso/checks/claude_azure_data.py:621` | Corrected evaluated, not_applicable_when |
| `azure.claude.sql_va_report_emails` | `peaso/checks/claude_azure_data.py:621` | Corrected description, evaluated, not_applicable_when |
| `azure.claude.sql_va_reports_configured` | `peaso/checks/claude_azure_data.py:621` | Corrected description, evaluated, fail_when, not_applicable_when, pass_when |
| `azure.claude.storage_access_keys_rotated_90` | `peaso/checks/claude_azure_data.py:685` | Verified; no change |
| `azure.claude.storage_account_cmk` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.storage_account_geo_redundant` | `peaso/checks/claude_azure_common.py:67` | Verified; no change |
| `azure.claude.storage_blob_and_container_soft_delete_7_365` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_blob_classic_logging` | `peaso/checks/claude_azure_data.py:739` | Corrected description |
| `azure.claude.storage_blob_diagnostic_logging` | `peaso/checks/claude_azure_data.py:739` | Verified; no change |
| `azure.claude.storage_blob_soft_delete_enabled` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_container_no_public_access` | `peaso/checks/claude_azure_data.py:895` | Corrected description, fail_when |
| `azure.claude.storage_encryption_scope_cmk` | `peaso/checks/claude_azure_data.py:902` | Verified; no change |
| `azure.claude.storage_file_share_soft_delete_1_365` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_file_share_soft_delete_enabled` | `peaso/checks/claude_azure_data.py:818` | Verified; no change |
| `azure.claude.storage_key_expiration_policy_90` | `peaso/checks/claude_azure_data.py:671` | Verified; no change |
| `azure.claude.storage_key_expiration_policy_max_90` | `peaso/checks/claude_azure_data.py:678` | Verified; no change |
| `azure.claude.storage_private_endpoint_present` | `peaso/checks/claude_azure_data.py:727` | Corrected description |

### Validation and remaining doubts

- Input IDs, output keys, and decisions are complete and unique. All registered predicates have a PASS and FAIL fixture with the expected result.
- UNKNOWN, MANUAL, DENIED, and malformed-fact returns follow the evaluator and shared fact guards; descriptions focus on PASS, FAIL, and explicit NOT_APPLICABLE branches.
- No cloud API or network call was made.
- Problem: azure.claude.activity_log_storage_cmk: change tracking mismatch
- Problem: azure.claude.entra_ca_policy_requires_mfa: direct NA branch undocumented
- Problem: azure.claude.entra_user_consent_disabled: bad pass_when
- Problem: azure.claude.entra_user_consent_disabled: bad fail_when
- Problem: azure.claude.entra_user_consent_not_legacy: bad pass_when
- Problem: azure.claude.entra_user_consent_not_legacy: bad fail_when
- Problem: azure.claude.iam_root_custom_role_no_wildcard: pass fixture returned NOT_APPLICABLE
- Problem: azure.claude.iam_root_custom_role_no_wildcard: fail fixture returned UNKNOWN
