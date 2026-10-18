
## Independent evaluator verification: desc-k8s-3

Checked 299 unique input IDs against their check-index registration and underlying evaluator implementations. Corrected 299 entries. Missing/duplicate entries: 0.

Common evaluator sources: `peaso/checks/k8s_ports_components.py`, `k8s_ports_workloads.py`, `k8s_ports_cluster.py`, `k8s_extended.py`, and `peaso/checks/__init__.py`. Component missing flags and incomplete projections produce UNKNOWN even after another failed declaration; a failed observed declaration takes precedence over missing component-identification gaps. The Kubernetes registration wrapper converts nonpassing results on positively identified provider/control-plane-managed resources to NOT_APPLICABLE. Workload PodSpecs require at least one regular container and validate names and structure before evaluating the predicate.

| ID | Decision | Fields changed | Registration |
| --- | --- | --- | --- |
| `k8s.ports.podtemplate.container_argument_rotate_kubelet_server_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_argument_secure_port_not_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_argument_security_context_deny_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_argument_service_account_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_argument_service_account_key_file_appropriate` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_argument_service_account_lookup_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_encryption_providers_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_kubelet_certificate_authority_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_no_argument_basic_auth_file` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_no_argument_hostname_override_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_no_argument_insecure_bind_address` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_rotate_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_runtime_default_seccomp` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.container_streaming_connection_idle_timeout_not_zero` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_strong_kube_apiserver_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_strong_kubelet_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.container_token_auth_file_not_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.podtemplate.content_digest_or_always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.context_present` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.cpu_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.cpu_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.declared_nonroot` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.drop_all` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.drop_net_raw` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.explicit_serviceaccount` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.host_namespaces` | corrected | evaluated, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.host_network` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.liveness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.memory_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.memory_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.no_added_capabilities` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.no_host_ports` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.no_sys_admin` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.pinned_image` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.privilege_escalation` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.privileged` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.readiness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.podtemplate.readonly_root` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.container_admission_control_plugin_always_pull_images` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_admission_control_plugin_no_always_admit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_arg_peer_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_api_server_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_audit_log_maxage_greater_than_30` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_audit_log_maxbackup_greater_than_10` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_audit_log_maxsize_greater_than_100` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_audit_log_path_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_authorization_mode_node` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_authorization_mode_rbac` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_etcd_auto_tls_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_etcd_cafile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_etcd_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_etcd_peer_certfile_and_peer_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_event_qps_less_than_5` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_insecure_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_apiserver_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_controller_manager_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_controller_manager_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_controller_manager_root_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_controller_manager_service_account_credentials_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_controller_manager_service_account_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_scheduler_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kube_scheduler_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_client_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_client_certificate_and_key_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_https_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_read_only_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_terminated_pod_gc_threshold_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_make_iptables_util_chains_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_namespace_lifecycle_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_node_restriction_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_pod_security_policy_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_protect_kernel_defaults_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_rotate_kubelet_server_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_secure_port_not_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_security_context_deny_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_service_account_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_service_account_key_file_appropriate` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_argument_service_account_lookup_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_encryption_providers_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_kubelet_certificate_authority_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_no_argument_basic_auth_file` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_no_argument_hostname_override_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_no_argument_insecure_bind_address` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_rotate_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_runtime_default_seccomp` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.container_streaming_connection_idle_timeout_not_zero` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_strong_kube_apiserver_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_strong_kubelet_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.container_token_auth_file_not_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicaset.content_digest_or_always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.context_present` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.cpu_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.cpu_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.declared_nonroot` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.drop_all` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.drop_net_raw` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.explicit_serviceaccount` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.host_namespaces` | corrected | evaluated, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.liveness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.memory_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.memory_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.no_added_capabilities` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.no_host_ports` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.no_sys_admin` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.pinned_image` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.privilege_escalation` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.readiness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.readonly_root` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicaset.replicaset_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.replicationcontroller.always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.container_admission_control_plugin_always_pull_images` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_admission_control_plugin_no_always_admit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_arg_peer_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_api_server_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_audit_log_maxage_greater_than_30` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_audit_log_maxbackup_greater_than_10` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_audit_log_maxsize_greater_than_100` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_audit_log_path_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_authorization_mode_node` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_authorization_mode_rbac` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_etcd_auto_tls_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_etcd_cafile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_etcd_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_etcd_peer_certfile_and_peer_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_event_qps_less_than_5` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_insecure_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_apiserver_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_controller_manager_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_controller_manager_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_controller_manager_root_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_controller_manager_service_account_credentials_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_controller_manager_service_account_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_scheduler_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kube_scheduler_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_client_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_client_certificate_and_key_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_https_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_read_only_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_terminated_pod_gc_threshold_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_make_iptables_util_chains_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_namespace_lifecycle_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_node_restriction_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_pod_security_policy_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_protect_kernel_defaults_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_rotate_kubelet_server_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_secure_port_not_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_security_context_deny_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_service_account_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_service_account_key_file_appropriate` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_argument_service_account_lookup_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_encryption_providers_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_kubelet_certificate_authority_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_no_argument_basic_auth_file` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_no_argument_hostname_override_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_no_argument_insecure_bind_address` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_rotate_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_runtime_default_seccomp` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.container_streaming_connection_idle_timeout_not_zero` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_strong_kube_apiserver_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_strong_kubelet_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.container_token_auth_file_not_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.replicationcontroller.content_digest_or_always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.context_present` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.cpu_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.cpu_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.declared_nonroot` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.drop_all` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.drop_net_raw` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.explicit_serviceaccount` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.host_namespaces` | corrected | evaluated, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.host_network` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.liveness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.memory_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.memory_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.no_added_capabilities` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.no_host_ports` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.no_sys_admin` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.pinned_image` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.privilege_escalation` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.privileged` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.readiness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.readonly_root` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.replicationcontroller.replication_controller_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.role.role_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.role.role_with_rbac_escalate_permissions` | corrected | not_applicable_when | `peaso/checks/__init__.py:72` |
| `k8s.ports.rolebinding.role_binding_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.rolebinding.role_binding_default_service_account_binding_not_active` | corrected | not_applicable_when | `peaso/checks/__init__.py:38` |
| `k8s.ports.secret_metadata.secret_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.service.service_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.service.service_type_forbidden` | corrected | not_applicable_when | `peaso/checks/__init__.py:112` |
| `k8s.ports.serviceaccount.service_account_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.ports.statefulset.always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.container_admission_control_plugin_always_pull_images` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_admission_control_plugin_no_always_admit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_arg_peer_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_api_server_anonymous_auth_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_audit_log_maxage_greater_than_30` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_audit_log_maxbackup_greater_than_10` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_audit_log_maxsize_greater_than_100` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_audit_log_path_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_authorization_mode_node` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_authorization_mode_rbac` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_etcd_auto_tls_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_etcd_cafile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_etcd_client_cert_auth_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_etcd_peer_certfile_and_peer_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_event_qps_less_than_5` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_insecure_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_apiserver_etcd_certfile_and_keyfile_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_apiserver_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_apiserver_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_controller_manager_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_controller_manager_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_controller_manager_root_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_controller_manager_service_account_credentials_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_controller_manager_service_account_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_scheduler_bind_address_127_0_0_1` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kube_scheduler_profiling_disabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_authorization_mode_no_always_allow` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_client_ca_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_client_certificate_and_key_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_https_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_read_only_port_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_terminated_pod_gc_threshold_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_kubelet_tls_cert_file_and_tls_private_key_file_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_make_iptables_util_chains_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_namespace_lifecycle_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_node_restriction_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_pod_security_policy_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_protect_kernel_defaults_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_rotate_kubelet_server_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_secure_port_not_0` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_security_context_deny_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_service_account_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_service_account_key_file_appropriate` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_argument_service_account_lookup_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_encryption_providers_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_kubelet_certificate_authority_configured` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_no_argument_basic_auth_file` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_no_argument_hostname_override_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_no_argument_insecure_bind_address` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_rotate_certificate_enabled` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_runtime_default_seccomp` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.container_streaming_connection_idle_timeout_not_zero` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_strong_kube_apiserver_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_strong_kubelet_cryptographic_ciphers` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.container_token_auth_file_not_configured` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:201` |
| `k8s.ports.statefulset.content_digest_or_always_pull` | corrected | description, evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.context_present` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.cpu_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.cpu_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.declared_nonroot` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.drop_all` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.drop_net_raw` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.explicit_serviceaccount` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.host_namespaces` | corrected | evaluated, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.liveness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.memory_limit` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.memory_request` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.no_added_capabilities` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.no_host_ports` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.no_sys_admin` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.pinned_image` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.privilege_escalation` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.readiness_probe` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.readonly_root` | corrected | evaluated, pass_when, fail_when, not_applicable_when | `peaso/checks/__init__.py:231` |
| `k8s.ports.statefulset.statefulset_default_namespace_used` | corrected | not_applicable_when | `peaso/checks/__init__.py:26` |
| `k8s.rbac.no_wildcards` | corrected | not_applicable_when | `peaso/checks/__init__.py:603` |
| `k8s.rbac.review_broad_subjects` | corrected | not_applicable_when | `peaso/checks/__init__.py:615` |
| `k8s.rbac.review_namespaced_subjects` | corrected | not_applicable_when | `peaso/checks/__init__.py:615` |
| `k8s.rbac.role_no_wildcards` | corrected | not_applicable_when | `peaso/checks/__init__.py:603` |
| `k8s.replicaset.no_host_network` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.replicaset.no_host_ports` | corrected | description, not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.replicaset.no_privileged` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.replicaset.non_root` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.service.review_public_type` | corrected | not_applicable_when | `peaso/checks/__init__.py:649` |
| `k8s.serviceaccount.disable_automount` | corrected | not_applicable_when | `peaso/checks/__init__.py:161` |
| `k8s.statefulset.no_host_network` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.statefulset.no_host_ports` | corrected | description, not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.statefulset.no_privileged` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
| `k8s.statefulset.non_root` | corrected | not_applicable_when, pass_when, fail_when | `peaso/checks/__init__.py:104` |
