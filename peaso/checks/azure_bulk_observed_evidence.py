"""Brief Azure success observations from exact reviewed native evidence fields."""
_EMPTY={
 'azure.cis.auto_provision_vulnerability_assessment_machines':('gaps','No assessed machine has a recorded vulnerability-assessment provisioning gap.'),
 'azure.gap.arc_kubernetes_cluster_azure_defender_extension_installed':('no_successful_defender_extension','No assessed Arc cluster lacks a successfully provisioned Defender extension.'),
 'azure_aks_cluster_10_2_1_1_17_885658f':('missing_categories','The required AKS diagnostic categories are configured.'),
 'azure_aks_cluster_1_4_5_2_3ac7b3c':('affected','No assessed Pod or container group declares host-process namespace sharing.'),
 'azure_aks_cluster_7_2_1_6_93c4fab':('privileged_containers','No assessed Pod container declares privileged mode.'),
 'azure_aks_cluster_aks_cluster_rbac_enabled_c41a0cb':('writable_root_containers','No assessed container declares a writable root filesystem.'),
 'azure_api_management_10_3_1_3_8a50dc0':('rest_apis_without_usable_tracing_diagnostic','No assessed REST API lacks a usable tracing diagnostic declaration.'),
 'azure_application_gateway_11_5_1_1_1_f56bdc2':('missing_protections','No assessed public resource lacks the required declared network or WAF protection.'),
 'azure_application_gateway_app_http_logs_enabled_2de0361':('resources_without_export','No assessed gateway or load balancer lacks a required supported-log export declaration.'),
 'azure_cdn_profile_10_3_4_1_4e40487':('affected_origins','No assessed Front Door Blob origin lacks the required managed-identity authentication and reader-role evidence.'),
 'azure_cdn_profile_1_2_8_5_ed953a0':('affected_domains','No assessed CDN custom domain lacks an activated customer-provided certificate configuration.'),
 'azure_directory_user_10_6_3_21_d013932':('users_without_groups','No assessed directory user lacks a group membership.'),
 'azure_directory_user_7_2_1_19_28e2aa7':('direct_assignment_ids','No direct user role assignments were found in the assessed scope.'),
 'azure_disk_10_3_3_12_174f526':('unprotected_disk_ids','No assessed managed disk lacks the required backup protection.'),
 'azure_frontdoor_1_2_5_4_ccc7b8f':('violating_domain_ids','No assessed Front Door domain lacks an activated Key Vault-backed SNI certificate configuration.'),
 'azure_frontdoor_1_2_8_4_90159db':('uncovered_or_disabled_routes','No assessed routed Front Door domain path lacks an enabled WAF binding.'),
 'azure_frontdoor_app_ensure_http_is_redirected_to_https_517a3c9':('violating_route_ids','No assessed Front Door route allows HTTP without the required HTTPS redirect.'),
 'azure_frontdoor_app_minimum_tls_version_12_0512053':('violating_domain_ids','No assessed Front Door domain declares a TLS minimum below 1.2.'),
 'azure_frontdoor_network_http_internet_access_restricted_7004685':('violating_route_ids','No assessed Front Door route permits the prohibited plain-HTTP path.'),
 'azure_log_analytics_workspace_monitor_diagnostic_setting_with_appropriate_categories_48f6b2b':('resources_without_workspace_log_export','No assessed resource lacks the required Log Analytics export declaration.'),
 'azure_pci_10_2_1_1_8':('violations','No assessed alert-routing declaration violates the required routing conditions.'),
 'azure_sql_database_sqlserver_azuread_administrator_enabled_4a039a9':('missing_entra_administrator','No assessed database parent server or managed instance lacks an Entra administrator.'),
 'azure_sql_server_sqlserver_unrestricted_inbound_access_9b32c6a':('servers_admitting_public_clients','No assessed SQL firewall declaration admits the matched public-client ranges.'),
 'azure_storage_account_10_3_3_24_61d5e36':('uncovered_containers','No assessed blob container lacks the required backup-plan selection.'),
 'azure_storage_account_10_3_4_7_02943e9':('containers_without_effective_default_retention','No assessed container lacks the required default immutable-retention declaration.'),
 'azure_storage_account_defender_ensure_defender_for_keyvault_is_on_2cabbc3':('containers_with_measured_platform_managed_encryption','No assessed blob container was measured using platform-managed encryption.'),
 'azure_storage_file_share_10_3_3_15_f2d7075':('unprotected_file_shares','No assessed file share lacks the required backup protection.'),
 'azure_storage_file_share_10_3_3_18_d67ab34':('unprotected_resources','No assessed file-share resource lacks the required protection.'),
}
# Legacy success records sometimes retain only the assessed count. State that
# exact limitation rather than inventing the absent deciding configuration.
_COUNTS={
 'azure.cis.agentless_discovery_kubernetes_component_status':('cluster_count','Kubernetes clusters','Defender discovery settings'),
 'azure.cis.guest_users_reviewed_monthly_basis':('applicable_subject_count','guest subjects','monthly review settings'),
 'azure.cis.guest_users_reviewed_regular_basis':('applicable_subject_count','guest subjects','access-review settings'),
 'azure.cis.private_endpoint_should_mariadb_servers':('assessed_count','MariaDB servers','private-endpoint bindings'),
 'azure.gap.machine_learning_workspace_private_link_used':('workspaces','Machine Learning workspaces','private-endpoint bindings'),
 'azure.gap.sql_database_long_term_geo_redundant_backup_enabled':('evaluated','SQL databases','backup-redundancy settings'),
 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524':('linux_pods','Linux Pods','effective container UID declarations'),
 'azure_cosmos_account_10_2_1_1_13_5c115b0':('assessed_count','Cosmos DB accounts','audit-export settings'),
 'azure_devops_project_1_2_8_6_fb0e5a8':('assessed_count','Azure DevOps projects','repository clone-URL user information'),
 'azure_firewall_policy_sqlserver_unrestricted_inbound_access_c12f86d':('evaluated_count','SQL firewall policies','deciding rule settings'),
 'azure_recovery_vault_10_3_3_1_1f42f66':('evaluated','online databases','point-in-time backup retention settings'),
 'azure_vm_1_4_5_1_d40be43':('evaluated_count','VMs','network-interface public-IP references'),
}
_MFA={'azure.cis.multifactor_authentication_policy_exists_administrative_groups','azure.cis.multifactor_authentication_policy_exists_users','azure.cis.multifactor_authentication_risky_sign_ins'}
_CONTEXT_MFA={'azure.cis.multifactor_auth_status_privileged_users','azure_directory_user_entra_non_privileged_user_has_mfa_b242ca9','azure_directory_user_entra_privileged_user_has_mfa_6f6d584'}

def _text(v):return isinstance(v,str) and bool(v) and len(v)<=250 and not any(ord(c)<32 for c in v)
def _strings(v):return isinstance(v,list) and all(_text(x) for x in v)

def evidence_summary(finding):
 if not isinstance(finding,dict) or finding.get('provider')!='azure' or finding.get('status')!='PASS':return None
 cid=finding.get('check_id');e=finding.get('evidence')
 if not isinstance(cid,str) or not isinstance(e,dict):return None
 if cid in _EMPTY:
  field,sentence=_EMPTY[cid]
  return sentence if field in e and e[field]==[] else None
 if cid in _COUNTS:
  field,noun,missing=_COUNTS[cid];count=e.get(field)
  if type(count)is int and count>0:return f'{count} {noun} were assessed; the deciding {missing} were not stored.'
 if cid in _MFA:
  n=e.get('evaluated_principals')
  if e.get('uncovered_contexts')==[] and type(n)is int and n>0:return f'MFA policies cover the recorded required contexts for {n} assessed principals.'
 if cid in _CONTEXT_MFA and e.get('uncovered_contexts')==[] and e.get('broad_mfa_status')=='PASS':
  return 'No recorded required MFA context is uncovered'+('; legacy per-user MFA is enforced.' if e.get('legacy_per_user_mfa_state')=='enforced' else '.')
 if cid=='azure.cis.multifactor_auth_status_non_privileged_users':
  if e.get('per_user_mfa_state')in {'enabled','enforced'} and e.get('usable_mfa_registered')is True:return 'Per-user MFA is '+e['per_user_mfa_state']+' and a usable MFA method is registered.'
 if cid=='azure.cis.latest_os_patches_vms_applied':
  results=e.get('results')
  if isinstance(results,list) and results and all(isinstance(r,dict) and type(r.get('available_critical_security_patches'))is int and r['available_critical_security_patches']==0 for r in results):return 'The VM assessments report no available critical or security patches.'
 if cid=='azure.gap.automation_account_encrypted_with_cmk':
  if _text(e.get('key_name')) and _text(e.get('principal_id')):return 'The automation account declares a customer key and an identity with verified key access.'
 if cid=='azure.gap.monitor_log_cluster_encrypted_with_cmk':
  if _text(e.get('cluster_id')) and e.get('key_access')=='allowed':return 'The Log Analytics cluster has verified customer-key access.'
 if cid=='azure.gap.monitor_log_profile_enabled_for_all_categories':
  values=e.get('exported_categories')
  if _strings(values) and {'Action','Delete','Write'}<=set(values):return 'The log profile declares exports for Action, Delete and Write events.'
 if cid=='azure.gap.postgresql_server_infrastructure_encryption_enabled':
  states=e.get('states')
  if _strings(states) and states and all(s=='Enabled' for s in states):return 'Infrastructure encryption is enabled on every assessed legacy PostgreSQL server.'
 if cid=='azure.gap.stream_analytics_job_encrypted_with_cmk':
  if _text(e.get('storage_account_id')):return 'The job storage account was assessed for customer-key encryption; its key binding was not stored.'
 if cid=='azure.other.access_analysis_coverage':
  results=e.get('results')
  if isinstance(results,list) and results and all(isinstance(r,dict) and r.get('capabilities')==['enabled','enabled'] for r in results):return 'Both assessed Defender CloudPosture capabilities are enabled.'
 if cid=='azure.other.backup_immutability_30':
  if e.get('short_retention_policy_ids')==[] and e.get('immutability_state')=='Locked':return 'Backup immutability is locked; no assessed policy has retention below 30 days.'
 if cid=='azure_directory_user_sqlserver_azuread_administrator_enabled_1a9c5cf':
  n=e.get('administrators')
  if _text(e.get('server_id')) and type(n)is int and n>0:return f'The PostgreSQL server declares {n} Entra administrators.'
 if cid=='azure_frontdoor_monitor_storage_account_with_activity_logs_is_private_d42518a':
  if _strings(e.get('qualifying_setting_ids')) and e['qualifying_setting_ids']:return 'Front Door declares an activity-log export; destination privacy and delivery were not measured.'
 if cid=='azure_pci_10_2_1_1_16':
  names=e.get('verified_logging_containers')
  if _strings(names) and names:return f'{len(names)} observed containers have the required logging configuration.'
 if cid=='azure_pci_1_3_1_33' and e.get('approved_sql_private_endpoint')is True:return 'A verified approved SQL private endpoint is configured.'
 if cid=='azure_synapse_workspace_1_2_8_29_fcdc827' and e.get('publicNetworkAccess')=='Disabled':return 'Synapse public network access is disabled.'
 if cid=='azure_vault_3_7_1_2_532ecd2':
  results=e.get('outcomes')
  if isinstance(results,list) and results and all(isinstance(r,dict) and r.get('status')=='PASS' and type(r.get('measured_rsa_modulus_bits'))is int and r['measured_rsa_modulus_bits']>=2048 for r in results):return 'The assessed current certificates have RSA public keys of at least 2048 bits.'
 if cid=='azure_vm_8_2_1_1_712e1ad' and type(e.get('configured_bootstrap_ssh_public_key_count'))is int and e['configured_bootstrap_ssh_public_key_count']==0:return 'The VM declares no bootstrap SSH public keys; guest runtime authentication was not measured.'
 return None
