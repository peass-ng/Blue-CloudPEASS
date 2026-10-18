## Independent evaluator verification — 2026-10-12

Input: `inputs/desc-gcp-1.json`; output: `descriptions/desc-gcp-1.json`.
Checks: 362. Each input ID has exactly one entry and one decision below.
Corrections: 106 entries, 271 fields. Field counts: `description` 92, `evaluated` 55, `pass_when` 55, `fail_when` 59, `not_applicable_when` 10.
Validation: 356 PASS, 351 FAIL and 88 NOT_APPLICABLE fixture verdicts matched their registered evaluators; completeness and uniqueness passed. Problems: 0.
The evaluator column gives the executable predicate or shared predicate factory. Each check-index registration location was cross-referenced with the registered check ID.

| ID | Evaluator | Decision |
| --- | --- | --- |
| `gcp.claude.backend_bucket.bucket_exists` | `peaso/checks/claude_gcp_k8s_compute.py:524` | Verified; no change |
| `gcp.claude.backend_service.external_iap` | `peaso/checks/claude_gcp_k8s_compute.py:509` | Corrected description, pass_when, fail_when, not_applicable_when |
| `gcp.claude.bigquery_dataset.no_gmail_access` | `peaso/checks/claude_gcp_k8s_iam.py:701` | Verified; no change |
| `gcp.claude.bigquery_dataset.no_googlegroups_access` | `peaso/checks/claude_gcp_k8s_iam.py:701` | Verified; no change |
| `gcp.claude.bucket.log_sink_not_public` | `peaso/checks/claude_gcp_k8s_iam.py:52` | Verified; no change |
| `gcp.claude.bucket.log_sink_retention_locked` | `peaso/checks/claude_gcp_k8s_iam.py:52` | Verified; no change |
| `gcp.claude.bucket.log_sink_retention_policy` | `peaso/checks/claude_gcp_k8s_iam.py:52` | Verified; no change |
| `gcp.claude.bucket.log_sink_versioning` | `peaso/checks/claude_gcp_k8s_iam.py:52` | Verified; no change |
| `gcp.claude.bucket.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.bucket.retention_90_days` | `peaso/checks/claude_gcp_k8s_iam.py:108` | Verified; no change |
| `gcp.claude.disk.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.dns_zone.dnssec_enabled` | `peaso/checks/claude_gcp_k8s_compute.py:633` | Verified; no change |
| `gcp.claude.dns_zone.ksk_not_rsasha1` | `peaso/checks/claude_gcp_k8s_compute.py:648` | Verified; no change |
| `gcp.claude.dns_zone.zsk_not_rsasha1` | `peaso/checks/claude_gcp_k8s_compute.py:648` | Verified; no change |
| `gcp.claude.firewall.default_rules_not_open` | `peaso/checks/claude_gcp_k8s_compute.py:121` | Verified; no change |
| `gcp.claude.firewall.logging_enabled` | `peaso/checks/claude_gcp_k8s_compute.py:108` | Verified; no change |
| `gcp.claude.firewall.public_ingress_all_protocols` | `peaso/checks/claude_gcp_k8s_compute.py:72` | Verified; no change |
| `gcp.claude.firewall.public_ingress_common_ports` | `peaso/checks/claude_gcp_k8s_compute.py:145` | Verified; no change |
| `gcp.claude.firewall.public_ingress_dns_port_53` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_ftp_port_21` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_http_port_80` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_microsoft_ds_port_445` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_mongo_db_port_27017` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_mysql_db_port_3306` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_netbios_snn_port_139` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_oracle_db_port_1521` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_pop3_port_110` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_postgresql_port_10250` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_postgresql_port_10255` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_postgresql_port_5432` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_smtp_port_25` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_137_to_139` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_27017_to_27019` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_61620_61621` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_636` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_6379` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_7000_7001` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_7199` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_8888` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_9042` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_9090` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_9160` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_port_9200_9300` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_udp` | `peaso/checks/claude_gcp_k8s_compute.py:163` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_udp_port_11211` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_udp_port_11214_to_11215` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_udp_port_2483_to_2484` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_tcp_udp_port_389` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_telnet_port_23` | `peaso/checks/claude_gcp_k8s_compute.py:48` | Verified; no change |
| `gcp.claude.firewall.public_ingress_without_target` | `peaso/checks/claude_gcp_k8s_compute.py:88` | Verified; no change |
| `gcp.claude.gke.binary_authorization` | `peaso/checks/claude_gcp_k8s_iam.py:727` | Verified; no change |
| `gcp.claude.gke.dashboard_disabled` | `peaso/checks/claude_gcp_k8s_iam.py:780` | Verified; no change |
| `gcp.claude.gke.http_load_balancing` | `peaso/checks/claude_gcp_k8s_iam.py:768` | Verified; no change |
| `gcp.claude.gke.logging_enabled` | `peaso/checks/claude_gcp_k8s_iam.py:793` | Verified; no change |
| `gcp.claude.gke.master_authorized_networks_restricted` | `peaso/checks/claude_gcp_k8s_iam.py:911` | Verified; no change |
| `gcp.claude.gke.monitoring_enabled` | `peaso/checks/claude_gcp_k8s_iam.py:793` | Verified; no change |
| `gcp.claude.gke.network_no_untargeted_public_ingress` | `peaso/checks/claude_gcp_k8s_iam.py:884` | Verified; no change |
| `gcp.claude.gke.no_client_certificate` | `peaso/checks/claude_gcp_k8s_iam.py:743` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.claude.gke.no_default_network` | `peaso/checks/claude_gcp_k8s_iam.py:807` | Corrected description, pass_when, fail_when |
| `gcp.claude.gke.no_kubernetes_alpha` | `peaso/checks/claude_gcp_k8s_iam.py:757` | Verified; no change |
| `gcp.claude.gke.nodes_no_default_service_account` | `peaso/checks/claude_gcp_k8s_iam.py:817` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.claude.gke.private_nodes` | `peaso/checks/claude_gcp_k8s_iam.py:928` | Verified; no change |
| `gcp.claude.gke.release_channel` | `peaso/checks/claude_gcp_k8s_iam.py:838` | Corrected description, pass_when, fail_when |
| `gcp.claude.gke.subnetwork_private_google_access` | `peaso/checks/claude_gcp_k8s_iam.py:864` | Verified; no change |
| `gcp.claude.gke.zone_redundant` | `peaso/checks/claude_gcp_k8s_iam.py:849` | Verified; no change |
| `gcp.claude.iam_policy.no_all_users` | `peaso/checks/claude_gcp_k8s_iam.py:206` | Verified; no change |
| `gcp.claude.iam_policy.no_project_sa_user_or_token_creator` | `peaso/checks/claude_gcp_k8s_iam.py:223` | Verified; no change |
| `gcp.claude.image.not_public` | `peaso/checks/claude_gcp_k8s_compute.py:423` | Verified; no change |
| `gcp.claude.image.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.instance.disks_csek` | `peaso/checks/claude_gcp_k8s_compute.py:366` | Corrected evaluated |
| `gcp.claude.instance.not_preemptible` | `peaso/checks/claude_gcp_k8s_compute.py:339` | Corrected description |
| `gcp.claude.instance.not_preemptible_or_spot` | `peaso/checks/claude_gcp_k8s_compute.py:351` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.claude.instance.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.instance.sa_no_basic_role` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Verified; no change |
| `gcp.claude.instance.sa_no_data_destruction_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Corrected description |
| `gcp.claude.instance.sa_no_database_write_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Verified; no change |
| `gcp.claude.instance.sa_no_deny_policy_write_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Corrected description |
| `gcp.claude.instance.sa_no_deployments_manager_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Corrected description |
| `gcp.claude.instance.sa_no_disrupt_logging_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Verified; no change |
| `gcp.claude.instance.sa_no_iam_write_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Verified; no change |
| `gcp.claude.instance.sa_no_service_account_impersonate_permission` | `peaso/checks/claude_gcp_k8s_compute.py:248` | Corrected description |
| `gcp.claude.instance.suspended_without_disks` | `peaso/checks/claude_gcp_k8s_compute.py:384` | Corrected not_applicable_when |
| `gcp.claude.instance_group_manager.autohealing` | `peaso/checks/claude_gcp_k8s_compute.py:450` | Verified; no change |
| `gcp.claude.instance_group_manager.load_balancer_attached` | `peaso/checks/claude_gcp_k8s_compute.py:478` | Verified; no change |
| `gcp.claude.instance_group_manager.multiple_zones` | `peaso/checks/claude_gcp_k8s_compute.py:463` | Corrected description, pass_when, fail_when |
| `gcp.claude.instance_template.no_ip_forwarding` | `peaso/checks/claude_gcp_k8s_compute.py:399` | Corrected description |
| `gcp.claude.kms_key.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.kms_key.rotation_100_days` | `peaso/checks/claude_gcp_k8s_iam.py:539` | Verified; no change |
| `gcp.claude.kms_key.users_limited_to_3` | `peaso/checks/claude_gcp_k8s_iam.py:524` | Verified; no change |
| `gcp.claude.kms_key_ring.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.logging.metric_alert_audit_configuration_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_bucket_iam_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_compute_configuration_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_custom_role_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_custom_role_changes_with_undelete` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_firewall_rule_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_network_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_network_changes_beta_methods` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_project_ownership_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_route_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.metric_alert_sql_instance_configuration_changes` | `peaso/checks/claude_gcp_k8s_iam.py:456` | Verified; no change |
| `gcp.claude.logging.project_sink_all_entries` | `peaso/checks/claude_gcp_k8s_iam.py:495` | Verified; no change |
| `gcp.claude.network.dns_logging` | `peaso/checks/claude_gcp_k8s_compute.py:600` | Verified; no change |
| `gcp.claude.node_group.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.node_template.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.organization.essential_contacts_any` | `peaso/checks/claude_gcp_k8s_iam.py:344` | Verified; no change |
| `gcp.claude.project.audit_logs_configured` | `peaso/checks/claude_gcp_k8s_iam.py:189` | Verified; no change |
| `gcp.claude.project.container_scanning_api_enabled` | `peaso/checks/claude_gcp_k8s_iam.py:374` | Verified; no change |
| `gcp.claude.project.gemini_api_disabled` | `peaso/checks/claude_gcp_k8s_iam.py:374` | Verified; no change |
| `gcp.claude.project.no_api_keys` | `peaso/checks/claude_gcp_k8s_compute.py:409` | Corrected description |
| `gcp.claude.project.oslogin_enabled` | `peaso/checks/claude_gcp_k8s_compute.py:311` | Verified; no change |
| `gcp.claude.project.storage_data_access_audit_logs` | `peaso/checks/claude_gcp_k8s_iam.py:160` | Verified; no change |
| `gcp.claude.project.storage_vpc_service_controls` | `peaso/checks/claude_gcp_k8s_iam.py:125` | Verified; no change |
| `gcp.claude.pubsub_snapshot.not_public` | `peaso/checks/claude_gcp_k8s_iam.py:623` | Verified; no change |
| `gcp.claude.pubsub_subscription.not_public` | `peaso/checks/claude_gcp_k8s_iam.py:623` | Verified; no change |
| `gcp.claude.pubsub_subscription.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.pubsub_topic.not_public` | `peaso/checks/claude_gcp_k8s_iam.py:623` | Verified; no change |
| `gcp.claude.pubsub_topic.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.resource_policy.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.secret.not_public` | `peaso/checks/claude_gcp_k8s_iam.py:623` | Verified; no change |
| `gcp.claude.secret.rotation_90_days` | `peaso/checks/claude_gcp_k8s_iam.py:641` | Verified; no change |
| `gcp.claude.service_account.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.service_account.recently_used` | `peaso/checks/claude_gcp_k8s_iam.py:280` | Verified; no change |
| `gcp.claude.service_account_key.age_100_days` | `peaso/checks/claude_gcp_k8s_iam.py:246` | Verified; no change |
| `gcp.claude.service_account_key.recently_used` | `peaso/checks/claude_gcp_k8s_iam.py:298` | Verified; no change |
| `gcp.claude.snapshot.not_outdated` | `peaso/checks/claude_gcp_k8s_compute.py:435` | Verified; no change |
| `gcp.claude.sql_instance.private_ip_only` | `peaso/checks/claude_gcp_k8s_iam.py:684` | Verified; no change |
| `gcp.claude.sql_instance.second_gen_no_public_ip` | `peaso/checks/claude_gcp_k8s_iam.py:668` | Verified; no change |
| `gcp.claude.subnetwork.policy_shared_access` | `peaso/checks/claude_gcp_k8s_iam.py:575` | Verified; no change |
| `gcp.claude.target_proxy.https_custom_ssl_policy` | `peaso/checks/claude_gcp_k8s_compute.py:564` | Verified; no change |
| `gcp.claude.target_proxy.https_min_tls_1_2` | `peaso/checks/claude_gcp_k8s_compute.py:577` | Verified; no change |
| `gcp.claude.workload_identity_provider.multi_tenant_condition` | `peaso/checks/claude_gcp_k8s_iam.py:320` | Verified; no change |
| `gcp.claude2.api_key.created_within_90_days` | `peaso/checks/claude2_gcp_services.py:180` | Verified; no change |
| `gcp.claude2.bigquery_dataset.default_cmek` | `peaso/checks/claude2_gcp_services.py:199` | Verified; no change |
| `gcp.claude2.cloudrun_service.invoker_not_public` | `peaso/checks/claude2_gcp_services.py:160` | Verified; no change |
| `gcp.claude2.function.ingress_not_allow_all` | `peaso/checks/claude2_gcp_services.py:31` | Verified; no change |
| `gcp.claude2.function.not_publicly_accessible` | `peaso/checks/claude2_gcp_services.py:81` | Verified; no change |
| `gcp.claude2.function.vpc_connector_configured` | `peaso/checks/claude2_gcp_services.py:122` | Verified; no change |
| `gcp.claude2.logging.metric_alert_audit_configuration_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_bucket_iam_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_custom_role_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_custom_role_changes_with_undelete` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_firewall_rule_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_network_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_project_ownership_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_route_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.metric_alert_sql_instance_configuration_changes` | `peaso/checks/claude2_gcp_logging.py:228` | Verified; no change |
| `gcp.claude2.logging.sink_all_log_entries` | `peaso/checks/claude2_gcp_logging.py:336` | Verified; no change |
| `gcp.claude2.sql_instance.only_private_ip_addresses` | `peaso/checks/claude2_gcp_services.py:221` | Verified; no change |
| `gcp.compute.integrity_monitoring` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.compute.no_external_ip` | `peaso/checks/__init__.py:529` | Verified; no change |
| `gcp.compute.restrict_internet_ingress` | `peaso/checks/__init__.py:475` | Corrected not_applicable_when |
| `gcp.compute.secure_boot` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.compute.shielded_vtpm` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only` | `peaso/checks/gcp_gap_cis.py:56` | Corrected description, evaluated, pass_when, fail_when, not_applicable_when |
| `gcp.gap.iam_user_managed_sa_no_admin_roles` | `peaso/checks/gcp_gap_cis.py:42` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.gap.sql_3625_trace_flag_off_cis_v1` | `peaso/checks/gcp_gap_cis.py:120` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.gke.authorized_networks` | `peaso/checks/gcp.py:205` | Verified; no change |
| `gcp.gke.control_plane_restricted` | `peaso/checks/exposure_endpoints.py:39` | Verified; no change |
| `gcp.gke.network_policy` | `peaso/checks/gcp.py:220` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.gke.no_legacy_abac` | `peaso/checks/gcp.py:151` | Verified; no change |
| `gcp.gke.node_pools_gke_metadata` | `peaso/checks/gcp.py:260` | Verified; no change |
| `gcp.gke.private_endpoint` | `peaso/checks/gcp.py:161` | Corrected evaluated |
| `gcp.gke.private_nodes` | `peaso/checks/gcp.py:191` | Corrected evaluated |
| `gcp.gke.secrets_encryption` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.gke.shielded_nodes` | `peaso/checks/gcp.py:181` | Verified; no change |
| `gcp.gke.workload_identity` | `peaso/checks/gcp.py:245` | Verified; no change |
| `gcp.htbp.appengine.no_default_service_account` | `peaso/checks/hacktricks_bp_gcp.py:127` | Verified; no change |
| `gcp.htbp.artifactregistry.virtual_repo_private_precedence` | `peaso/checks/hacktricks_bp_gcp.py:321` | Verified; no change |
| `gcp.htbp.cloudbuild.pr_trigger_gated` | `peaso/checks/hacktricks_bp_gcp.py:414` | Verified; no change |
| `gcp.htbp.cloudbuild.trigger_no_default_sa` | `peaso/checks/hacktricks_bp_gcp.py:440` | Verified; no change |
| `gcp.htbp.cloudrun.job_no_default_compute_sa` | `peaso/checks/hacktricks_bp_gcp.py:39` | Corrected description |
| `gcp.htbp.cloudrun.job_secret_env_from_secret_manager` | `peaso/checks/hacktricks_bp_gcp.py:74` | Corrected description |
| `gcp.htbp.cloudrun.service_no_default_compute_sa` | `peaso/checks/hacktricks_bp_gcp.py:39` | Corrected description |
| `gcp.htbp.cloudrun.service_secret_env_from_secret_manager` | `peaso/checks/hacktricks_bp_gcp.py:74` | Corrected description |
| `gcp.htbp.composer.no_default_compute_sa` | `peaso/checks/hacktricks_bp_gcp.py:515` | Corrected description |
| `gcp.htbp.function.runtime_no_default_sa` | `peaso/checks/hacktricks_bp_gcp.py:103` | Verified; no change |
| `gcp.htbp.function.secret_env_from_secret_manager` | `peaso/checks/hacktricks_bp_gcp.py:367` | Corrected description |
| `gcp.htbp.gke.kubelet_readonly_port_disabled` | `peaso/checks/hacktricks_bp_gcp.py:174` | Verified; no change |
| `gcp.htbp.iam.policy_no_pool_wide_workload_principal_set` | `peaso/checks/hacktricks_bp_gcp.py:833` | Verified; no change |
| `gcp.htbp.iam.sa_no_pool_wide_workload_principal_set` | `peaso/checks/hacktricks_bp_gcp.py:823` | Verified; no change |
| `gcp.htbp.instance_template.no_default_sa_full_scope` | `peaso/checks/hacktricks_bp_gcp.py:147` | Verified; no change |
| `gcp.htbp.kms.destroy_window_not_shortened` | `peaso/checks/hacktricks_bp_gcp.py:238` | Corrected description |
| `gcp.htbp.logging.default_sink_not_disabled` | `peaso/checks/hacktricks_bp_gcp.py:216` | Corrected evaluated |
| `gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled` | `peaso/checks/hacktricks_bp_gcp.py:692` | Verified; no change |
| `gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled` | `peaso/checks/hacktricks_bp_gcp.py:712` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.htbp.orgpolicy.domain_restricted_sharing` | `peaso/checks/hacktricks_bp_gcp.py:725` | Verified; no change |
| `gcp.htbp.orgpolicy.essential_contacts_domain_restricted` | `peaso/checks/hacktricks_bp_gcp.py:741` | Verified; no change |
| `gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked` | `peaso/checks/hacktricks_bp_gcp.py:675` | Corrected description |
| `gcp.htbp.pubsub.push_endpoint_not_tunnel` | `peaso/checks/hacktricks_bp_gcp.py:290` | Corrected evaluated |
| `gcp.htbp.scheduler.no_recurring_access_regrant` | `peaso/checks/hacktricks_bp_gcp.py:561` | Verified; no change |
| `gcp.htbp.storage.default_object_acl_not_public` | `peaso/checks/hacktricks_bp_gcp.py:262` | Verified; no change |
| `gcp.htbp.storage.hmac_key_not_stale_or_default_sa` | `peaso/checks/hacktricks_bp_gcp.py:483` | Corrected description, evaluated, pass_when, fail_when, not_applicable_when |
| `gcp.htbp.storage.notification_topic_in_bucket_project` | `peaso/checks/hacktricks_bp_gcp.py:859` | Verified; no change |
| `gcp.htbp.workbench.no_default_compute_sa` | `peaso/checks/hacktricks_bp_gcp.py:535` | Corrected description |
| `gcp.iam.avoid_basic_roles` | `peaso/checks/__init__.py:344` | Verified; no change |
| `gcp.iam.data_access_audit` | `peaso/checks/gcp.py:117` | Verified; no change |
| `gcp.iam.no_user_managed_sa_keys` | `peaso/checks/gcp.py:31` | Corrected description |
| `gcp.iam.restrict_public_members` | `peaso/checks/__init__.py:327` | Verified; no change |
| `gcp.network.custom_subnets` | `peaso/checks/facts.py:46` | Verified; no change |
| `gcp.ports.access_approval_explicit_enrollment` | `peaso/checks/gcp_ports_relationships.py:161` | Corrected evaluated |
| `gcp.ports.alloydb_cluster_encrypted_with_cmk` | `peaso/checks/gcp_ports_configuration.py:75` | Verified; no change |
| `gcp.ports.alloydb_instance_log_error_verbosity_database_flag_default_or_stricter` | `peaso/checks/gcp_ports_configuration.py:59` | Verified; no change |
| `gcp.ports.alloydb_instance_log_min_error_statement_database_flag_configured` | `peaso/checks/gcp_ports_configuration.py:59` | Verified; no change |
| `gcp.ports.alloydb_instance_log_min_messages_database_flag_error` | `peaso/checks/gcp_ports_configuration.py:59` | Verified; no change |
| `gcp.ports.api_key_elapsed_age_gt90` | `peaso/checks/gcp_ports_metadata.py:161` | Verified; no change |
| `gcp.ports.api_key_meaningful_restrictions` | `peaso/checks/gcp_ports_perimeter.py:123` | Verified; no change |
| `gcp.ports.apikeys_api_restricted_with_gemini_api` | `peaso/checks/gcp_ports_configuration.py:112` | Verified; no change |
| `gcp.ports.app_engine_application_iap_enabled` | `peaso/checks/gcp_ports_services.py:55` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.artifacts_container_analysis_enabled` | `peaso/checks/gcp_ports_configuration.py:94` | Verified; no change |
| `gcp.ports.audit_logging_configured_for_all_service` | `peaso/checks/gcp_ports_compute.py:183` | Verified; no change |
| `gcp.ports.bigquery_dataset_not_publicly_accessible` | `peaso/checks/gcp_ports_metadata.py:88` | Verified; no change |
| `gcp.ports.bigquery_table_encrypted_with_cmk` | `peaso/checks/gcp_ports_keys.py:132` | Verified; no change |
| `gcp.ports.bigtable_instance_policy_shared_access` | `peaso/checks/gcp_ports_perimeter.py:22` | Verified; no change |
| `gcp.ports.billing_account_policy_shared_access` | `peaso/checks/gcp_ports_perimeter.py:22` | Verified; no change |
| `gcp.ports.cloud_function_policy_shared_access` | `peaso/checks/gcp_ports_perimeter.py:22` | Verified; no change |
| `gcp.ports.cloud_run_job_policy_shared_access` | `peaso/checks/gcp_ports_perimeter.py:22` | Verified; no change |
| `gcp.ports.cloud_run_not_publicly_accessible` | `peaso/checks/gcp_ports_perimeter.py:82` | Corrected description, pass_when, fail_when |
| `gcp.ports.cloud_run_service_policy_prohibit_public_access` | `peaso/checks/gcp_ports_perimeter.py:65` | Verified; no change |
| `gcp.ports.cloud_run_service_policy_shared_access` | `peaso/checks/gcp_ports_perimeter.py:22` | Verified; no change |
| `gcp.ports.cloudfunction_function_no_ingress_settings_allow_all` | `peaso/checks/gcp_ports_metadata.py:100` | Verified; no change |
| `gcp.ports.cloudfunction_function_restrict_public_access` | `peaso/checks/gcp_ports_metadata.py:58` | Corrected description, pass_when, fail_when |
| `gcp.ports.cloudfunction_function_vpc_connector_enabled` | `peaso/checks/gcp_ports_metadata.py:100` | Verified; no change |
| `gcp.ports.cloudrun_service_restrict_public_access` | `peaso/checks/gcp_ports_metadata.py:58` | Verified; no change |
| `gcp.ports.compute_disk_encrypted_with_csk` | `peaso/checks/gcp_ports_relationships.py:42` | Corrected description |
| `gcp.ports.compute_firewall_rule_rdp_access_restricted` | `peaso/checks/gcp_ports_compute.py:129` | Verified; no change |
| `gcp.ports.compute_firewall_rule_ssh_access_restricted` | `peaso/checks/gcp_ports_compute.py:129` | Verified; no change |
| `gcp.ports.compute_instance_block_project_wide_ssh_enabled` | `peaso/checks/gcp_ports_compute.py:75` | Verified; no change |
| `gcp.ports.compute_instance_ip_forwarding_disabled` | `peaso/checks/gcp_ports_compute.py:65` | Verified; no change |
| `gcp.ports.compute_instance_shielded_vm_enabled` | `peaso/checks/gcp_ports_compute.py:86` | Corrected description |
| `gcp.ports.compute_instance_with_no_default_service_account` | `peaso/checks/gcp_ports_compute.py:39` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.compute_instance_with_no_default_service_account_with_full_access` | `peaso/checks/gcp_ports_compute.py:39` | Verified; no change |
| `gcp.ports.compute_instance_with_no_public_ip_addresses` | `peaso/checks/gcp_ports_compute.py:108` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.compute_network_contains_no_legacy_network` | `peaso/checks/gcp_ports_compute.py:97` | Corrected description |
| `gcp.ports.compute_network_dns_logging_scoped` | `peaso/checks/gcp_ports_logging.py:112` | Verified; no change |
| `gcp.ports.compute_oslogin_metadata_precedence` | `peaso/checks/gcp_ports_relationships.py:30` | Corrected description |
| `gcp.ports.compute_ssl_policy_strict_declaration` | `peaso/checks/gcp_ports_relationships.py:56` | Verified; no change |
| `gcp.ports.compute_url_map_backend_logging` | `peaso/checks/gcp_ports_relationships.py:104` | Corrected evaluated, pass_when, not_applicable_when |
| `gcp.ports.dataproc_cluster_encryption_with_cmek` | `peaso/checks/gcp_ports_keys.py:132` | Verified; no change |
| `gcp.ports.dns_managed_zone_dnssec_enabled` | `peaso/checks/gcp_ports_metadata.py:23` | Verified; no change |
| `gcp.ports.dns_managed_zone_key_signing_not_using_rsasha1` | `peaso/checks/gcp_ports_metadata.py:23` | Verified; no change |
| `gcp.ports.dns_managed_zone_zone_signing_not_using_rsasha1` | `peaso/checks/gcp_ports_metadata.py:23` | Verified; no change |
| `gcp.ports.firewall_http_lb_proxy_source_restriction` | `peaso/checks/gcp_ports_perimeter.py:164` | Verified; no change |
| `gcp.ports.firewall_iap_tcp_proxy_source_restriction` | `peaso/checks/gcp_ports_perimeter.py:164` | Verified; no change |
| `gcp.ports.function_active_public_binding` | `peaso/checks/gcp_ports_metadata.py:58` | Verified; no change |
| `gcp.ports.function_active_vpc_connector` | `peaso/checks/gcp_ports_metadata.py:100` | Verified; no change |
| `gcp.ports.function_basic_role_declarations` | `peaso/checks/gcp_ports_iam.py:194` | Verified; no change |
| `gcp.ports.function_internal_ingress_declaration` | `peaso/checks/gcp_ports_perimeter.py:151` | Verified; no change |
| `gcp.ports.function_legacy_deployment_role_declarations` | `peaso/checks/gcp_ports_iam.py:194` | Verified; no change |
| `gcp.ports.function_logging_mutation_declarations` | `peaso/checks/gcp_ports_iam.py:194` | Verified; no change |
| `gcp.ports.iam_api_key_age_90` | `peaso/checks/gcp_ports_keys.py:33` | Corrected evaluated, not_applicable_when |
| `gcp.ports.iam_api_key_restricts_apis` | `peaso/checks/gcp_ports_keys.py:86` | Verified; no change |
| `gcp.ports.iam_api_key_restricts_websites_hosts_apps` | `peaso/checks/gcp_ports_keys.py:101` | Corrected description, pass_when, fail_when |
| `gcp.ports.iam_corporate_domain_declaration` | `peaso/checks/gcp_ports_iam.py:81` | Verified; no change |
| `gcp.ports.iam_service_account_gcp_managed_key` | `peaso/checks/gcp_ports_keys.py:158` | Verified; no change |
| `gcp.ports.iam_service_account_key_age_90` | `peaso/checks/gcp_ports_keys.py:33` | Corrected evaluated |
| `gcp.ports.iam_user_not_assigned_service_account_user_role_project_level` | `peaso/checks/gcp_ports_iam.py:63` | Verified; no change |
| `gcp.ports.iam_user_separation_of_duty_scoped` | `peaso/checks/gcp_ports_iam.py:39` | Verified; no change |
| `gcp.ports.kms_key_rotated_within_90_day` | `peaso/checks/gcp_ports_keys.py:57` | Corrected evaluated, not_applicable_when |
| `gcp.ports.kms_key_separation_of_duties_enforced` | `peaso/checks/gcp_ports_iam.py:39` | Verified; no change |
| `gcp.ports.kubernetes_cluster_auto_repair_enabled` | `peaso/checks/gcp_ports_services.py:231` | Verified; no change |
| `gcp.ports.kubernetes_cluster_auto_upgrade_enabled` | `peaso/checks/gcp_ports_services.py:231` | Verified; no change |
| `gcp.ports.kubernetes_cluster_intra_node_visibility_enabled` | `peaso/checks/gcp_ports_services.py:149` | Corrected description, fail_when |
| `gcp.ports.kubernetes_cluster_legacy_endpoints_disabled` | `peaso/checks/gcp_ports_services.py:86` | Verified; no change |
| `gcp.ports.kubernetes_cluster_node_config_image_cos_containerd` | `peaso/checks/gcp_ports_services.py:86` | Corrected description, pass_when, fail_when |
| `gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled` | `peaso/checks/gcp_ports_services.py:86` | Verified; no change |
| `gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled` | `peaso/checks/gcp_ports_services.py:86` | Verified; no change |
| `gcp.ports.kubernetes_cluster_use_ip_aliases` | `peaso/checks/gcp_ports_services.py:127` | Corrected description, evaluated, fail_when |
| `gcp.ports.logging_bucket_retention_policy_enabled` | `peaso/checks/gcp_ports_logging.py:95` | Verified; no change |
| `gcp.ports.logging_metric_alert_audit_configuration_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_custom_role_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_custom_role_changes_with_iam_admin_undelete_role_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_firewall_rule_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_network_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_network_route_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_project_ownership_assignment_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_sql_instance_configuration_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_metric_alert_storage_iam_permission_changes_scoped` | `peaso/checks/gcp_ports_logging.py:29` | Verified; no change |
| `gcp.ports.logging_sink_all_entries_enabled` | `peaso/checks/gcp_ports_logging.py:74` | Verified; no change |
| `gcp.ports.organization_essential_contacts_complete` | `peaso/checks/gcp_ports_relationships.py:141` | Verified; no change |
| `gcp.ports.project_no_api_key` | `peaso/checks/gcp_ports_metadata.py:146` | Verified; no change |
| `gcp.ports.project_service_cloudasset_api_enabled` | `peaso/checks/gcp_ports_configuration.py:94` | Verified; no change |
| `gcp.ports.reference_sql_pg_min_duration` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sql_pg_min_error` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sql_pg_min_messages` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sql_ssl_connections` | `peaso/checks/gcp_ports_perimeter.py:108` | Corrected description, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_contained_database_authentication` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_cross_db_ownership_chaining` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_external_scripts_enabled` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_remote_access` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_trace3625` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_user_connections` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.reference_sqlserver_user_options` | `peaso/checks/gcp_ports_configuration.py:21` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.service_account_mutating_role_declarations` | `peaso/checks/gcp_ports_iam.py:160` | Verified; no change |
| `gcp.ports.sql_instance_mysql_binary_log_enabled` | `peaso/checks/gcp_ports_services.py:18` | Verified; no change |
| `gcp.ports.sql_instance_not_open_to_internet` | `peaso/checks/gcp_ports_perimeter.py:94` | Verified; no change |
| `gcp.ports.sql_instance_not_publicly_accessible` | `peaso/checks/gcp_ports_metadata.py:120` | Corrected description, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_checkpoints_database_flag_on` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_duration_database_flag_on` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_error_verbosity_database_flag_default_or_stricter` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_executor_stats_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_hostname_database_flag_configured` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_lock_waits_database_flag_on` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_min_duration_statement_database_flag_disabled` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_min_error_statement_database_flag_configured` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, fail_when |
| `gcp.ports.sql_instance_postgresql_log_min_messages_database_flag_error` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_parser_stats_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_planner_stats_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_statement_stats_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_postgresql_log_temp_files_database_flag_0` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_require_ssl_enabled` | `peaso/checks/gcp_ports_compute.py:170` | Verified; no change |
| `gcp.ports.sql_instance_sql_3625_trace_database_flag_on` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_sql_contained_database_authentication_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_sql_cross_db_ownership_chaining_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_sql_external_scripts_enabled_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_sql_remote_access_database_flag_off` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_instance_sql_user_connections_database_flag_configured` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, fail_when |
| `gcp.ports.sql_instance_sql_user_options_database_flag_not_configured` | `peaso/checks/gcp_ports_services.py:173` | Corrected description, evaluated, fail_when |
| `gcp.ports.sql_instance_with_no_public_ips` | `peaso/checks/gcp_ports_metadata.py:120` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.ports.sql_no_primary_address` | `peaso/checks/gcp_ports_metadata.py:120` | Verified; no change |
| `gcp.ports.sql_private_ip_assignments` | `peaso/checks/gcp_ports_metadata.py:120` | Verified; no change |
| `gcp.ports.storage_bucket_not_publicly_accessible` | `peaso/checks/gcp_ports_metadata.py:58` | Corrected description, pass_when, fail_when |
| `gcp.reviewed.bigquery.cmek` | `peaso/checks/gcp_extended.py:434` | Verified; no change |
| `gcp.reviewed.bigquery.no_public_acl` | `peaso/checks/gcp_extended.py:450` | Verified; no change |
| `gcp.reviewed.compute.automatic_restart` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.reviewed.compute.block_project_ssh_keys` | `peaso/checks/gcp_extended.py:196` | Corrected description |
| `gcp.reviewed.compute.confidential_computing` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.reviewed.compute.deletion_protection` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.reviewed.compute.disk_auto_delete` | `peaso/checks/gcp_extended.py:169` | Verified; no change |
| `gcp.reviewed.compute.ip_forwarding` | `peaso/checks/gcp_extended.py:115` | Corrected description |
| `gcp.reviewed.compute.maintenance_migrate` | `peaso/checks/facts.py:46` | Corrected description |
| `gcp.reviewed.compute.no_default_full_api` | `peaso/checks/gcp_extended.py:154` | Corrected description |
| `gcp.reviewed.compute.no_default_service_account` | `peaso/checks/gcp_extended.py:146` | Verified; no change |
| `gcp.reviewed.compute.no_serial_console` | `peaso/checks/gcp_extended.py:202` | Corrected description |
| `gcp.reviewed.compute.single_interface` | `peaso/checks/gcp_extended.py:124` | Verified; no change |
| `gcp.reviewed.kms.no_public_iam` | `peaso/checks/gcp_extended.py:412` | Verified; no change |
| `gcp.reviewed.kms.rotation_90_days` | `peaso/checks/gcp_extended.py:395` | Corrected not_applicable_when |
| `gcp.reviewed.kms.rotation_enabled` | `peaso/checks/gcp_extended.py:386` | Corrected not_applicable_when |
| `gcp.reviewed.loadbalancer.backend_logging` | `peaso/checks/facts.py:46` | Verified; no change |
| `gcp.reviewed.network.flow_logs` | `peaso/checks/gcp_extended.py:82` | Verified; no change |
| `gcp.reviewed.network.no_default_vpc` | `peaso/checks/gcp_extended.py:233` | Corrected description, pass_when, fail_when |
| `gcp.reviewed.project.os_login_2fa` | `peaso/checks/gcp_extended.py:208` | Verified; no change |
| `gcp.reviewed.sql.cmek` | `peaso/checks/gcp_extended.py:302` | Verified; no change |
| `gcp.reviewed.sql.high_availability` | `peaso/checks/gcp_extended.py:292` | Verified; no change |
| `gcp.reviewed.sql.mysql_local_infile` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.mysql_skip_show_database` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.postgres_log_connections` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.postgres_log_disconnections` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.postgres_log_error_verbosity` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.postgres_log_statement` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.sql.postgres_pgaudit` | `peaso/checks/gcp_extended.py:311` | Verified; no change |
| `gcp.reviewed.storage.access_logging` | `peaso/checks/gcp_extended.py:258` | Verified; no change |
| `gcp.reviewed.storage.lifecycle` | `peaso/checks/gcp_extended.py:267` | Verified; no change |
| `gcp.reviewed.storage.soft_delete` | `peaso/checks/gcp_extended.py:241` | Corrected description, pass_when, fail_when |
| `gcp.reviewed.storage.versioning` | `peaso/checks/gcp_extended.py:251` | Verified; no change |
| `gcp.sql.backups` | `peaso/checks/facts.py:46` | Verified; no change |
| `gcp.sql.no_public_ip` | `peaso/checks/facts.py:46` | Verified; no change |
| `gcp.sql.restrict_authorized_networks` | `peaso/checks/gcp.py:45` | Verified; no change |
| `gcp.storage.no_public_iam` | `peaso/checks/gcp.py:19` | Corrected description, evaluated, pass_when, fail_when |
| `gcp.storage.public_access_prevention` | `peaso/checks/__init__.py:458` | Verified; no change |
| `gcp.storage.uniform_access` | `peaso/checks/__init__.py:355` | Verified; no change |
| `gcp.subnetwork.private_google_access` | `peaso/checks/gcp.py:59` | Verified; no change |

