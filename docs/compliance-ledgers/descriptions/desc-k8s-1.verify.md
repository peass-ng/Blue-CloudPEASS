# desc-k8s-1 independent evaluator verification

Input IDs: 301; unique decisions: 301; corrected entries: 17; unresolved problems: 0.

Each row records a decision after reviewing the indexed check's actual evaluator and its shared helper, including the evaluated fields, PASS/FAIL predicates, UNKNOWN/MANUAL paths, and NOT_APPLICABLE handling.

| ID | Evaluator family | Decision | Change |
| --- | --- | --- | --- |
| `k8s.claude.clusterrole.no_bind` | claude | verified | No correction needed |
| `k8s.claude.clusterrole.no_pod_create` | claude | verified | No correction needed |
| `k8s.claude.clusterrole.no_secret_read` | claude | verified | No correction needed |
| `k8s.claude.clusterrole.no_wildcard_resources_or_verbs` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.cluster_admin_review` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.no_human_csr_approval` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.no_human_node_proxy` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.no_human_pv_create` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.no_human_serviceaccount_token_create` | claude | verified | No correction needed |
| `k8s.claude.clusterrolebinding.no_human_webhook_config_write` | claude | verified | No correction needed |
| `k8s.claude.configuration.kubelet_client_ca_file` | claude | verified | No correction needed |
| `k8s.claude.configuration.kubelet_streaming_timeout` | claude | verified | No correction needed |
| `k8s.claude.configuration.kubelet_strong_ciphers` | claude | verified | No correction needed |
| `k8s.claude.configuration.kubelet_tls_cert_and_key` | claude | verified | No correction needed |
| `k8s.claude.cronjob.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.cronjob.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.cronjob.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.daemonset.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.daemonset.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.daemonset.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.deployment.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.deployment.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.deployment.replicas_minimum_3` | claude | verified | No correction needed |
| `k8s.claude.deployment.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.endpointslice.api_secure_port` | claude | verified | No correction needed |
| `k8s.claude.file_metadata.kubelet_conf_permissions` | claude | verified | No correction needed |
| `k8s.claude.file_metadata.kubelet_config_yaml_permissions` | claude | verified | No correction needed |
| `k8s.claude.file_metadata.kubelet_service_file_permissions` | claude | verified | No correction needed |
| `k8s.claude.ingress.no_nginx_snippet_alias` | claude | verified | No correction needed |
| `k8s.claude.ingress.no_nginx_snippet_lua` | claude | verified | No correction needed |
| `k8s.claude.ingress.no_nginx_snippets` | claude | verified | No correction needed |
| `k8s.claude.job.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.job.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.job.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.pod.capabilities_dropped` | claude | verified | No correction needed |
| `k8s.claude.pod.controller_manager_gc_threshold` | claude | verified | No correction needed |
| `k8s.claude.pod.cpu_limits_set` | claude | verified | No correction needed |
| `k8s.claude.pod.cpu_requests_set` | claude | verified | No correction needed |
| `k8s.claude.pod.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.pod.etcd_unique_ca` | claude | verified | No correction needed |
| `k8s.claude.pod.liveness_probe_configured` | claude | verified | No correction needed |
| `k8s.claude.pod.memory_limits_set` | claude | verified | No correction needed |
| `k8s.claude.pod.memory_requests_set` | claude | verified | No correction needed |
| `k8s.claude.pod.no_added_capabilities` | claude | verified | No correction needed |
| `k8s.claude.pod.no_host_ipc` | claude | verified | No correction needed |
| `k8s.claude.pod.no_host_pid` | claude | verified | No correction needed |
| `k8s.claude.pod.no_host_ports` | claude | verified | No correction needed |
| `k8s.claude.pod.no_literal_secret_env` | claude | verified | No correction needed |
| `k8s.claude.pod.no_net_raw_capability` | claude | verified | No correction needed |
| `k8s.claude.pod.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.pod.no_root_user` | claude | verified | No correction needed |
| `k8s.claude.pod.no_secret_env` | claude | verified | No correction needed |
| `k8s.claude.pod.no_windows_host_process` | claude | verified | No correction needed |
| `k8s.claude.pod.readiness_probe_configured` | claude | verified | No correction needed |
| `k8s.claude.pod.run_as_user_10000` | claude | verified | No correction needed |
| `k8s.claude.pod.runtime_default_seccomp` | claude | verified | No correction needed |
| `k8s.claude.pod.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.podsecuritypolicy.allowed_host_path_restricted` | claude | verified | No correction needed |
| `k8s.claude.podsecuritypolicy.default_seccomp_profile` | claude | verified | No correction needed |
| `k8s.claude.podsecuritypolicy.security_services_hardening` | claude | verified | No correction needed |
| `k8s.claude.podtemplate.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.podtemplate.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.replicaset.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.replicaset.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.replicaset.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.replicationcontroller.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.replicationcontroller.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.replicationcontroller.secrets_as_files` | claude | verified | No correction needed |
| `k8s.claude.role.no_bind` | claude | verified | No correction needed |
| `k8s.claude.role.no_pod_create` | claude | verified | No correction needed |
| `k8s.claude.role.no_secret_read` | claude | verified | No correction needed |
| `k8s.claude.role.no_wildcard_resources_or_verbs` | claude | verified | No correction needed |
| `k8s.claude.service.no_tiller_labels` | claude | verified | No correction needed |
| `k8s.claude.service.no_tiller_selector` | claude | verified | No correction needed |
| `k8s.claude.statefulset.dashboard_not_deployed` | claude | verified | No correction needed |
| `k8s.claude.statefulset.no_privileged_port` | claude | verified | No correction needed |
| `k8s.claude.statefulset.secrets_as_files` | claude | verified | No correction needed |
| `k8s.cronjob.no_host_network` | direct | verified | No correction needed |
| `k8s.cronjob.no_host_ports` | direct | verified | No correction needed |
| `k8s.cronjob.no_privileged` | direct | verified | No correction needed |
| `k8s.cronjob.non_root` | direct | verified | No correction needed |
| `k8s.daemonset.no_host_network` | direct | verified | No correction needed |
| `k8s.daemonset.no_host_ports` | direct | verified | No correction needed |
| `k8s.daemonset.no_privileged` | direct | verified | No correction needed |
| `k8s.daemonset.non_root` | direct | verified | No correction needed |
| `k8s.deployment.no_host_network` | direct | verified | No correction needed |
| `k8s.deployment.no_host_ports` | direct | verified | No correction needed |
| `k8s.deployment.no_privileged` | direct | verified | No correction needed |
| `k8s.deployment.non_root` | direct | verified | No correction needed |
| `k8s.gap.apiserver.deny_service_external_ips` | direct | verified | No correction needed |
| `k8s.gap.apiserver.event_rate_limit` | direct | verified | No correction needed |
| `k8s.htbp.clusterrole.no_impersonation` | hacktricks | verified | No correction needed |
| `k8s.htbp.clusterrole.no_pod_interactive_access` | hacktricks | verified | No correction needed |
| `k8s.htbp.clusterrole.no_service_status_write` | hacktricks | verified | No correction needed |
| `k8s.htbp.clusterrole.no_workload_controller_write` | hacktricks | corrected | fail_when: include batch/core controllers and wildcards |
| `k8s.htbp.clusterrolebinding.no_anonymous_user` | hacktricks | verified | No correction needed |
| `k8s.htbp.role.no_impersonation` | hacktricks | verified | No correction needed |
| `k8s.htbp.role.no_pod_interactive_access` | hacktricks | verified | No correction needed |
| `k8s.htbp.role.no_service_status_write` | hacktricks | verified | No correction needed |
| `k8s.htbp.role.no_workload_controller_write` | hacktricks | corrected | fail_when: include batch/core controllers and wildcards |
| `k8s.htbp.rolebinding.no_anonymous_user` | hacktricks | verified | No correction needed |
| `k8s.htbp.secret.no_legacy_service_account_token` | hacktricks | verified | No correction needed |
| `k8s.htbp.service.no_external_ips` | hacktricks | verified | No correction needed |
| `k8s.job.no_host_network` | direct | verified | No correction needed |
| `k8s.job.no_host_ports` | direct | verified | No correction needed |
| `k8s.job.no_privileged` | direct | verified | No correction needed |
| `k8s.job.non_root` | direct | verified | No correction needed |
| `k8s.namespace.quota_limits_cpu` | direct | verified | No correction needed |
| `k8s.namespace.quota_limits_memory` | direct | verified | No correction needed |
| `k8s.namespace.quota_requests_cpu` | direct | verified | No correction needed |
| `k8s.namespace.quota_requests_memory` | direct | verified | No correction needed |
| `k8s.namespace.restricted_admission` | direct | verified | No correction needed |
| `k8s.network.namespace_policy_inventory` | direct | verified | No correction needed |
| `k8s.pod.default_proc_mount` | direct | verified | No correction needed |
| `k8s.pod.drop_capabilities` | direct | verified | No correction needed |
| `k8s.pod.no_default_serviceaccount` | direct | verified | No correction needed |
| `k8s.pod.no_host_namespaces` | direct | verified | No correction needed |
| `k8s.pod.no_host_ports` | direct | verified | No correction needed |
| `k8s.pod.no_hostpath` | direct | verified | No correction needed |
| `k8s.pod.no_privilege_escalation` | direct | verified | No correction needed |
| `k8s.pod.no_privileged_containers` | direct | verified | No correction needed |
| `k8s.pod.non_root` | direct | verified | No correction needed |
| `k8s.pod.read_only_root` | direct | verified | No correction needed |
| `k8s.pod.restrict_added_capabilities` | direct | verified | No correction needed |
| `k8s.pod.restrict_selinux_identity` | direct | verified | No correction needed |
| `k8s.pod.restrict_token_automount` | direct | verified | No correction needed |
| `k8s.pod.seccomp` | direct | verified | No correction needed |
| `k8s.ports.clusterrole.cluster_role_with_validating_or_mutating_admission_webhook_configurations` | ports-other | verified | No correction needed |
| `k8s.ports.clusterrole.role_with_rbac_approve_certificate_signing_requests` | ports-other | verified | No correction needed |
| `k8s.ports.clusterrole.role_with_rbac_escalate_permissions` | ports-other | verified | No correction needed |
| `k8s.ports.clusterrole.role_with_wildcards_used` | ports-other | verified | No correction needed |
| `k8s.ports.clusterrolebinding.cluster_role_binding_default_service_account_binding_not_active` | ports-other | verified | No correction needed |
| `k8s.ports.configmap_metadata.config_map_default_namespace_used` | ports-other | verified | No correction needed |
| `k8s.ports.configuration.kubelet_authorization_mode` | ports-other | verified | No correction needed |
| `k8s.ports.configuration.kubelet_disable_anonymous_auth` | ports-other | verified | No correction needed |
| `k8s.ports.configuration.kubelet_disable_read_only_port` | ports-other | verified | No correction needed |
| `k8s.ports.configuration.kubelet_manage_iptables` | ports-other | verified | No correction needed |
| `k8s.ports.configuration.kubelet_rotate_certificates` | ports-other | verified | No correction needed |
| `k8s.ports.cronjob.always_pull` | workload | corrected | fail_when: include empty image |
| `k8s.ports.cronjob.container_admission_control_plugin_always_pull_images` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_admission_control_plugin_no_always_admit` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_arg_peer_client_cert_auth_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_anonymous_auth_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_api_server_anonymous_auth_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_audit_log_maxage_greater_than_30` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_audit_log_maxbackup_greater_than_10` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_audit_log_maxsize_greater_than_100` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_audit_log_path_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_authorization_mode_no_always_allow` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_authorization_mode_node` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_authorization_mode_rbac` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_etcd_auto_tls_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_etcd_cafile_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_etcd_certfile_and_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_etcd_client_cert_auth_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_etcd_peer_certfile_and_peer_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_event_qps_less_than_5` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_insecure_port_0` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_apiserver_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_controller_manager_bind_address_127_0_0_1` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_controller_manager_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_controller_manager_root_ca_file_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_controller_manager_service_account_credentials_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_controller_manager_service_account_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_scheduler_bind_address_127_0_0_1` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kube_scheduler_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_authorization_mode_no_always_allow` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_client_ca_file_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_client_certificate_and_key_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_https_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_read_only_port_0` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_terminated_pod_gc_threshold_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_make_iptables_util_chains_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_namespace_lifecycle_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_node_restriction_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_pod_security_policy_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_protect_kernel_defaults_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_rotate_kubelet_server_certificate_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_secure_port_not_0` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_security_context_deny_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_service_account_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_service_account_key_file_appropriate` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_argument_service_account_lookup_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_encryption_providers_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_kubelet_certificate_authority_configured` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_no_argument_basic_auth_file` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.cronjob.container_no_argument_hostname_override_configured` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.cronjob.container_no_argument_insecure_bind_address` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.cronjob.container_rotate_certificate_enabled` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_runtime_default_seccomp` | workload | verified | No correction needed |
| `k8s.ports.cronjob.container_streaming_connection_idle_timeout_not_zero` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_strong_kube_apiserver_cryptographic_ciphers` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_strong_kubelet_cryptographic_ciphers` | component | verified | No correction needed |
| `k8s.ports.cronjob.container_token_auth_file_not_configured` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.cronjob.content_digest_or_always_pull` | workload | corrected | fail_when: include empty image |
| `k8s.ports.cronjob.context_present` | workload | verified | No correction needed |
| `k8s.ports.cronjob.cpu_limit` | workload | verified | No correction needed |
| `k8s.ports.cronjob.cpu_request` | workload | verified | No correction needed |
| `k8s.ports.cronjob.cronjob_default_namespace_used` | ports-other | verified | No correction needed |
| `k8s.ports.cronjob.declared_nonroot` | workload | verified | No correction needed |
| `k8s.ports.cronjob.drop_all` | workload | verified | No correction needed |
| `k8s.ports.cronjob.drop_net_raw` | workload | verified | No correction needed |
| `k8s.ports.cronjob.explicit_serviceaccount` | workload | verified | No correction needed |
| `k8s.ports.cronjob.host_namespaces` | workload | verified | No correction needed |
| `k8s.ports.cronjob.liveness_probe` | workload | verified | No correction needed |
| `k8s.ports.cronjob.memory_limit` | workload | verified | No correction needed |
| `k8s.ports.cronjob.memory_request` | workload | verified | No correction needed |
| `k8s.ports.cronjob.no_added_capabilities` | workload | verified | No correction needed |
| `k8s.ports.cronjob.no_host_ports` | workload | verified | No correction needed |
| `k8s.ports.cronjob.no_sys_admin` | workload | verified | No correction needed |
| `k8s.ports.cronjob.pinned_image` | workload | corrected | description and pass_when: any @ reference passes without digest validation |
| `k8s.ports.cronjob.privilege_escalation` | workload | verified | No correction needed |
| `k8s.ports.cronjob.readiness_probe` | workload | verified | No correction needed |
| `k8s.ports.cronjob.readonly_root` | workload | verified | No correction needed |
| `k8s.ports.daemonset.always_pull` | workload | corrected | fail_when: include empty image |
| `k8s.ports.daemonset.container_admission_control_plugin_always_pull_images` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_admission_control_plugin_no_always_admit` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_arg_peer_client_cert_auth_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_anonymous_auth_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_api_server_anonymous_auth_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_audit_log_maxage_greater_than_30` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_audit_log_maxbackup_greater_than_10` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_audit_log_maxsize_greater_than_100` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_audit_log_path_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_authorization_mode_no_always_allow` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_authorization_mode_node` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_authorization_mode_rbac` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_etcd_auto_tls_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_etcd_cafile_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_etcd_certfile_and_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_etcd_client_cert_auth_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_etcd_peer_certfile_and_peer_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_event_qps_less_than_5` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_insecure_port_0` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_apiserver_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_controller_manager_bind_address_127_0_0_1` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_controller_manager_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_controller_manager_root_ca_file_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_controller_manager_service_account_credentials_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_controller_manager_service_account_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_scheduler_bind_address_127_0_0_1` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kube_scheduler_profiling_disabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_authorization_mode_no_always_allow` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_client_ca_file_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_client_certificate_and_key_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_https_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_read_only_port_0` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_terminated_pod_gc_threshold_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_make_iptables_util_chains_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_namespace_lifecycle_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_node_restriction_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_pod_security_policy_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_protect_kernel_defaults_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_rotate_kubelet_server_certificate_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_secure_port_not_0` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_security_context_deny_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_service_account_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_service_account_key_file_appropriate` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_argument_service_account_lookup_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_encryption_providers_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_kubelet_certificate_authority_configured` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_no_argument_basic_auth_file` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.daemonset.container_no_argument_hostname_override_configured` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.daemonset.container_no_argument_insecure_bind_address` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.daemonset.container_rotate_certificate_enabled` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_runtime_default_seccomp` | workload | verified | No correction needed |
| `k8s.ports.daemonset.container_streaming_connection_idle_timeout_not_zero` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_strong_kube_apiserver_cryptographic_ciphers` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_strong_kubelet_cryptographic_ciphers` | component | verified | No correction needed |
| `k8s.ports.daemonset.container_token_auth_file_not_configured` | component | corrected | not_applicable_when: absent forbidden flag passes with complete flags |
| `k8s.ports.daemonset.content_digest_or_always_pull` | workload | corrected | fail_when: include empty image |
| `k8s.ports.daemonset.context_present` | workload | verified | No correction needed |
| `k8s.ports.daemonset.cpu_limit` | workload | verified | No correction needed |
| `k8s.ports.daemonset.cpu_request` | workload | verified | No correction needed |
| `k8s.ports.daemonset.daemonset_default_namespace_used` | ports-other | verified | No correction needed |
| `k8s.ports.daemonset.declared_nonroot` | workload | verified | No correction needed |
| `k8s.ports.daemonset.drop_all` | workload | verified | No correction needed |
| `k8s.ports.daemonset.drop_net_raw` | workload | verified | No correction needed |
| `k8s.ports.daemonset.explicit_serviceaccount` | workload | verified | No correction needed |
| `k8s.ports.daemonset.host_namespaces` | workload | verified | No correction needed |
| `k8s.ports.daemonset.liveness_probe` | workload | verified | No correction needed |
| `k8s.ports.daemonset.memory_limit` | workload | verified | No correction needed |
| `k8s.ports.daemonset.memory_request` | workload | verified | No correction needed |
| `k8s.ports.daemonset.no_added_capabilities` | workload | verified | No correction needed |
| `k8s.ports.daemonset.no_host_ports` | workload | verified | No correction needed |
| `k8s.ports.daemonset.no_sys_admin` | workload | verified | No correction needed |
| `k8s.ports.daemonset.pinned_image` | workload | corrected | description and pass_when: any @ reference passes without digest validation |
| `k8s.ports.daemonset.privilege_escalation` | workload | verified | No correction needed |
| `k8s.ports.daemonset.readiness_probe` | workload | verified | No correction needed |
| `k8s.ports.daemonset.readonly_root` | workload | verified | No correction needed |
| `k8s.ports.deployment.always_pull` | workload | corrected | fail_when: include empty image |
| `k8s.ports.deployment.container_admission_control_plugin_always_pull_images` | component | verified | No correction needed |
| `k8s.ports.deployment.container_admission_control_plugin_no_always_admit` | component | verified | No correction needed |
| `k8s.ports.deployment.container_arg_peer_client_cert_auth_enabled` | component | verified | No correction needed |
| `k8s.ports.deployment.container_argument_anonymous_auth_disabled` | component | verified | No correction needed |

## Validation

- Input IDs are unique; JSON keys exactly equal the 301 input IDs.
- Each entry has exactly the five required, nonempty fields.
- Every ID resolves to a registered Kubernetes check with the indexed resource kind.
- Component flag entries were cross-checked against the evaluator's component, field, operation, and missing-field semantics.
- Per-check fixtures matched evaluator outcomes: pass=296, fail=297, manual=6, unknown=4, not_applicable=26.
- Three direct checks have no fixture cases; their evaluator bodies were reviewed: `k8s.network.namespace_policy_inventory`, `k8s.pod.no_host_namespaces`, `k8s.pod.no_privileged_containers`.
- Every input ID has exactly one decision in the table.
