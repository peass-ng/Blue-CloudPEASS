"""Concise GCP observations backed by decisive recorded evidence.

A FAIL status is not itself evidence. Legacy payloads that omit the deciding
field retain their technical evidence and get no inferred observation here.
"""
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlsplit
from .gcp_remaining_clarity_reviewed import ROWS

BOOLEAN_FAILURES = {'gcp.claude.backend_service.external_iap': ('iap_enabled', False),
 'gcp.claude.bucket.log_sink_retention_locked': ('retention_locked', False),
 'gcp.claude.bucket.log_sink_versioning': ('versioning_enabled', False),
 'gcp.claude.firewall.logging_enabled': ('log_config_enable', False),
 'gcp.claude.gke.dashboard_disabled': ('dashboard_disabled', False),
 'gcp.claude.gke.http_load_balancing': ('http_load_balancing_disabled', True),
 'gcp.claude.gke.no_client_certificate': ('client_certificate_issued', True),
 'gcp.claude.gke.no_kubernetes_alpha': ('enable_kubernetes_alpha', True),
 'gcp.claude.gke.private_nodes': ('private_nodes', False),
 'gcp.claude.gke.subnetwork_private_google_access': ('private_ip_google_access', False),
 'gcp.claude.instance.not_preemptible': ('preemptible', True),
 'gcp.claude.instance_template.no_ip_forwarding': ('can_ip_forward', True),
 'gcp.claude.network.dns_logging': ('enable_logging', False),
 'gcp.gke.network_policy': ('network_policy_enabled', False),
 'gcp.gke.no_legacy_abac': ('legacy_abac_enabled', True),
 'gcp.gke.private_endpoint': ('enable_public_endpoint', True),
 'gcp.gke.shielded_nodes': ('shielded_nodes_enabled', False),
 'gcp.htbp.logging.default_sink_not_disabled': ('disabled', True),
 'gcp.htbp.orgpolicy.cross_project_sa_usage_not_disabled': ('enforced', False),
 'gcp.htbp.orgpolicy.default_sa_automatic_grants_disabled': ('enforced', False),
 'gcp.ports.app_engine_application_iap_enabled': ('configured', False),
 'gcp.ports.compute_disk_encrypted_with_csk': ('csek_digest_present', False),
 'gcp.ports.kubernetes_cluster_intra_node_visibility_enabled': ('configured', False),
 'gcp.ports.kubernetes_cluster_use_ip_aliases': ('configured', False),
 'gcp.ports.logging_bucket_retention_policy_enabled': ('retention_locked', False),
 'gcp.ports.sql_instance_mysql_binary_log_enabled': ('configured', False),
 'gcp.reviewed.compute.block_project_ssh_keys': ('block_project_ssh_keys', False),
 'gcp.reviewed.compute.ip_forwarding': ('canIpForward', True),
 'gcp.reviewed.compute.no_serial_console': ('serial_port_enable', True),
 'gcp.reviewed.project.os_login_2fa': ('enable_oslogin_2fa', False),
 'gcp.reviewed.storage.versioning': ('configured', False),
 'gcp.sql.deletion_protection': ('deletion_protection_enabled', False),
 'gcp.sql.iam_database_authentication': ('iam_user_found', False),
 'gcp.storage.uniform_access': ('uniform_bucket_level_access', False),
 'gcp.subnetwork.private_google_access': ('configured', False)}

FILTERED_STRING_OBSERVATIONS = {'gcp.apikeys.active_service_restrictions': 'disabled_target_services',
 'gcp.claude.gke.network_no_untargeted_public_ingress': 'untargeted_public_rules',
 'gcp.claude.gke.nodes_no_default_service_account': 'default_service_account_pools',
 'gcp.claude.iam_policy.no_all_users': 'public_roles',
 'gcp.claude.instance.disks_csek': 'disks_without_csek',
 'gcp.claude.project.no_api_keys': 'api_keys',
 'gcp.compute.no_external_ip': 'external_ips',
 'gcp.gap.firewall_tcp_ingress_iap_health_check_sources_only': 'ranges_outside_cis_list',
 'gcp.htbp.function.secret_env_from_secret_manager': 'literal_credential_variables',
 'gcp.htbp.gke.kubelet_readonly_port_disabled': 'enabled_on',
 'gcp.htbp.instance_template.no_default_sa_full_scope': 'default_accounts_with_full_scope',
 'gcp.htbp.storage.default_object_acl_not_public': 'public_entities',
 'gcp.identity.super_admin_separation': 'conflicting_roles',
 'gcp.ports.compute_instance_with_no_default_service_account': 'declared_default_accounts',
 'gcp.ports.compute_instance_with_no_default_service_account_with_full_access': 'declared_default_accounts',
 'gcp.ports.compute_instance_with_no_public_ip_addresses': 'declared_external_addresses',
 'gcp.ports.compute_url_map_backend_logging': 'backend_services_without_logging',
 'gcp.ports.iam_service_account_gcp_managed_key': 'user_managed_keys',
 'gcp.ports.kubernetes_cluster_auto_repair_enabled': 'node_pools_needing_review',
 'gcp.ports.kubernetes_cluster_auto_upgrade_enabled': 'node_pools_needing_review',
 'gcp.ports.project_no_api_key': 'key_metadata_names',
 'gcp.reviewed.compute.no_default_full_api': 'accounts',
 'gcp.reviewed.compute.no_default_service_account': 'accounts',
 'gcp_c5_sbom': 'missing_sbom_digests',
 'gcp_gke_cluster_endpoint_publicly_accessible_ea8dcc0ec97d': 'public_ip_endpoint_clusters',
 'gcp_gke_small_cluster_auto_upgrade': 'pools_without_auto_upgrade',
 'gcp_kms_key_kms_keys_scheduled_deletion_56316ac06650': 'scheduled_versions',
 'gcp_lb_server_header_rewrite': 'unrewritten_route_indexes',
 'gcp_pci_backend_service_2ce96d36d0bf': 'weak_https_proxies',
 'gcp_pci_bigquery_dataset_fb9fcc01d5b7': 'all_users_roles'}

ENUM_FAILURES = {'gcp.appengine.version_https_only': ('handler_levels', ['SECURE_DEFAULT', 'SECURE_OPTIONAL', 'SECURE_NEVER']),
 'gcp.claude.dns_zone.dnssec_enabled': ('dnssec_state', ['off']),
 'gcp.claude.gke.binary_authorization': ('evaluation_mode', ['DISABLED', 'EVALUATION_MODE_UNSPECIFIED']),
 'gcp.claude.gke.logging_enabled': ('loggingService', ['none']),
 'gcp.claude.gke.monitoring_enabled': ('monitoringService', ['none']),
 'gcp.claude.gke.no_default_network': ('network', ['default']),
 'gcp.claude.gke.release_channel': ('channel', ['UNSPECIFIED']),
 'gcp.claude.instance.not_preemptible_or_spot': ('provisioning_model', ['SPOT']),
 'gcp.claude.project.container_scanning_api_enabled': ('state', ['DISABLED']),
 'gcp.claude.project.gemini_api_disabled': ('state', ['ENABLED']),
 'gcp.claude.sql_instance.private_ip_only': ('ip_address_types', ['PRIMARY', 'MIGRATED_1ST_GEN']),
 'gcp.claude.sql_instance.second_gen_no_public_ip': ('ip_address_types', ['PRIMARY', 'MIGRATED_1ST_GEN']),
 'gcp.claude.target_proxy.https_min_tls_1_2': ('min_tls_version', ['TLS_1_0', 'TLS_1_1']),
 'gcp.claude2.function.ingress_not_allow_all': ('ingress_settings', ['ALLOW_ALL']),
 'gcp.claude2.sql_instance.only_private_ip_addresses': ('ip_address_types',
                                                        ['PRIMARY', 'MIGRATED_1ST_GEN', 'OUTGOING']),
 'gcp.iam.no_user_managed_sa_keys': ('key_type', ['USER_MANAGED']),
 'gcp.ports.alloydb_cluster_encrypted_with_cmk': ('encryption_type', ['GOOGLE_DEFAULT_ENCRYPTION']),
 'gcp.ports.artifacts_container_analysis_enabled': ('state', ['DISABLED']),
 'gcp.ports.cloud_run_not_publicly_accessible': ('ingress', ['INGRESS_TRAFFIC_ALL']),
 'gcp.ports.cloudfunction_function_no_ingress_settings_allow_all': ('configured',
                                                                    ['ALLOW_ALL', 'INGRESS_SETTINGS_UNSPECIFIED']),
 'gcp.ports.dns_managed_zone_dnssec_enabled': ('state', ['off']),
 'gcp.ports.function_internal_ingress_declaration': ('ingress', ['ALLOW_ALL']),
 'gcp.ports.project_service_cloudasset_api_enabled': ('state', ['DISABLED']),
 'gcp.ports.reference_sql_ssl_connections': ('ssl_mode', ['ALLOW_UNENCRYPTED_AND_ENCRYPTED']),
 'gcp.ports.sql_instance_not_publicly_accessible': ('address_types', ['PRIMARY', 'MIGRATED_1ST_GEN']),
 'gcp.ports.sql_instance_require_ssl_enabled': ('sslMode', ['ALLOW_UNENCRYPTED_AND_ENCRYPTED']),
 'gcp.ports.sql_instance_with_no_public_ips': ('address_types', ['PRIMARY', 'MIGRATED_1ST_GEN']),
 'gcp.ports.sql_no_primary_address': ('address_types', ['PRIMARY']),
 'gcp.reviewed.network.no_default_vpc': ('network_name', ['default']),
 'gcp.reviewed.sql.high_availability': ('availability_type', ['ZONAL']),
 'gcp_https_proxy_mtls_required': ('client_validation_mode', ['ALLOW_INVALID_OR_MISSING_CLIENT_CERT']),
 'gcp_pci_cloudbuild_trigger_3302edf7cb18': ('logging', ['NONE']),
 'gcp_sql_trace3625_off': ('trace_flag_3625', ['on'])}

MISSING_DECLARATIONS = {'gcp.claude.bucket.log_sink_retention_policy': 'retention_period',
 'gcp.claude.target_proxy.https_custom_ssl_policy': 'ssl_policy',
 'gcp.claude2.bigquery_dataset.default_cmek': 'kms_key_name',
 'gcp.claude2.function.vpc_connector_configured': 'vpc_connector',
 'gcp.gke.workload_identity': 'workload_pool',
 'gcp.ports.bigquery_table_encrypted_with_cmk': 'key_reference',
 'gcp.ports.cloudfunction_function_vpc_connector_enabled': 'configured',
 'gcp.ports.dataproc_cluster_encryption_with_cmek': 'key_reference',
 'gcp.ports.function_active_vpc_connector': 'configured',
 'gcp.reviewed.sql.cmek': 'kms_key_name',
 'gcp.reviewed.storage.access_logging': 'log_bucket',
 'gcp_bucket_logging_enabled_fb7cc594582a': 'log_bucket',
 'gcp_pubsub_topic_cmek': 'kms_key_name'}


def _strings(value, *, nonempty=False):
    return isinstance(value, list) and (bool(value) or not nonempty) and all(isinstance(v, str) and v for v in value)


def _number(value):
    return type(value) in (int, float) and value == value and abs(value) != float('inf')


def _world(value):
    return _strings(value) and any(v in ('0.0.0.0/0', '::/0') for v in value)


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
        return parsed if parsed.tzinfo is not None else None
    except ValueError:
        return None


def _sql_observation(row, evidence):
    binding = row['reviewed_binding']
    closure = binding.get('predicate_bindings') or binding.get('closure', {})
    flag = closure.get('flag')
    if not isinstance(flag, str) or evidence.get('flag', evidence.get('field')) != flag:
        return None
    key = 'configured' if 'configured' in evidence else 'declared'
    if key not in evidence:
        return None
    value = evidence[key]
    if value is not None and not isinstance(value, str):
        return None
    if isinstance(value, str) and len(value) > 80:
        return None
    if closure.get('engine'):
        version = evidence.get('database_version')
        if not isinstance(version, str) or not version.startswith(closure['engine']):
            return None
    if 'good' in closure:
        failed = value in (closure.get('values') or [closure['good'], closure.get('bad')]) and value != closure['good']
    elif closure.get('forbidden'):
        failed = value is not None
    elif closure.get('presence'):
        failed = value is None
    elif 'allowed' in closure:
        effective = closure.get('default') if value is None and 'default' in closure else value
        failed = effective not in (closure.get('allowed') or [])
    else:
        return None
    if not failed:
        return None
    if value is None:
        return f'The database flag {flag} is not explicitly configured.'
    return f'The declared database flag {flag} is {value!r}.'


def _binding_failure(cid, evidence):
    """Validate explicit filtered IAM/ACL failure records, never generic inventory."""
    if cid in {
        'gcp.claude.bucket.log_sink_not_public', 'gcp.claude.image.not_public',
        'gcp.claude.pubsub_snapshot.not_public', 'gcp.claude.pubsub_subscription.not_public',
        'gcp.claude.pubsub_topic.not_public', 'gcp.claude.secret.not_public',
        'gcp.iam.restrict_public_members', 'gcp.storage.no_public_iam',
        'gcp.reviewed.kms.no_public_iam',
    }:
        records = evidence.get('public_bindings')
        return isinstance(records, list) and any(
            isinstance(r, dict) and isinstance(r.get('role'), str) and
            (r.get('member') in ('allUsers', 'allAuthenticatedUsers') or
             (_strings(r.get('members')) and any(v in ('allUsers', 'allAuthenticatedUsers') for v in r['members'])))
            for r in records)
    if cid in {'gcp.claude2.cloudrun_service.invoker_not_public', 'gcp.claude2.function.not_publicly_accessible'}:
        records = evidence.get('public_invoker_bindings')
        return isinstance(records, list) and any(isinstance(r, dict) and r.get('role') == 'roles/run.invoker' and
            _strings(r.get('members')) and any(v in ('allUsers', 'allAuthenticatedUsers') for v in r['members']) for r in records)
    if cid == 'gcp.iam.avoid_basic_roles':
        records = evidence.get('broad_bindings')
        return isinstance(records, list) and any(isinstance(r, dict) and r.get('role') in ('roles/owner','roles/editor','roles/viewer') and _strings(r.get('members'), nonempty=True) for r in records)
    if cid == 'gcp.reviewed.bigquery.no_public_acl':
        records = evidence.get('public_access_entries')
        return isinstance(records, list) and any(isinstance(r, dict) and r.get('principal') in ('allUsers','allAuthenticatedUsers') and r.get('role') in ('READER','WRITER','OWNER') for r in records)
    if cid in {'gcp_pci_bigquery_dataset_6017267cdf32','gcp_pci_bigquery_dataset_a4e25dbf9640'}:
        records = evidence.get('public_read_write_entries' if cid.endswith('6017267cdf32') else 'all_users_reader_entries')
        return isinstance(records, list) and any(isinstance(r, dict) and
            ((r.get('principal') in ('allUsers','allAuthenticatedUsers') and r.get('role') in ('READER','WRITER','OWNER')) if cid.endswith('6017267cdf32') else
             (r.get('special_group') == 'allUsers' and r.get('role') == 'READER')) for r in records)
    return False


def evidence_summary(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'gcp' or finding.get('status') != 'FAIL':
        return None
    cid = finding.get('check_id')
    if not isinstance(cid,str):
        return None
    row = ROWS.get(cid)
    evidence = finding.get('evidence')
    if row is None or not isinstance(evidence, dict) or not evidence:
        return None
    sql = _sql_observation(row, evidence)
    if sql is not None:
        return sql
    observed = row['static_observed_sentence']
    if cid == 'gcp.identity.non_service_account_mfa':
        enrolled, enforced = evidence.get('isEnrolledIn2Sv'), evidence.get('isEnforcedIn2Sv')
        return observed if type(enrolled) is bool and type(enforced) is bool and not (enrolled and enforced) else None
    if cid == 'gcp.identity.super_admin_recovery_group':
        count = evidence.get('active_member_count')
        missing = evidence.get('reason') == 'missing or non-group recovery address' and isinstance(evidence.get('recovery_email'), str)
        return observed if missing or (type(count) is int and 0 <= count < 2) else None
    if cid == 'gcp_pci_bucket_157fb0c69361':
        from .gcp_public_read_native import READ_ROLES
        grants = evidence.get('grants', [])
        inherited = evidence.get('inherited_public_read_grants', [])
        local_read = isinstance(grants, list) and any(
            isinstance(grant, (list, tuple)) and len(grant) == 2 and
            ((grant[0] == 'iam' and isinstance(grant[1], str) and grant[1] in READ_ROLES) or
             (grant[0] in ('bucketAccessControls', 'objectAccessControls') and grant[1] in ('allUsers', 'allAuthenticatedUsers')))
            for grant in grants)
        ancestor_read = isinstance(inherited, list) and any(
            isinstance(grant, dict) and isinstance(grant.get('scope'), str) and
            re.fullmatch(r'(projects|folders|organizations)/[A-Za-z0-9._-]+', grant['scope']) and
            isinstance(grant.get('role'), str) and grant['role'] in READ_ROLES for grant in inherited)
        return observed if local_read or ancestor_read else None
    if cid in BOOLEAN_FAILURES:
        field, failed = BOOLEAN_FAILURES[cid]
        return observed if evidence.get(field) is failed else None
    if cid in FILTERED_STRING_OBSERVATIONS:
        return observed if _strings(evidence.get(FILTERED_STRING_OBSERVATIONS[cid]), nonempty=True) else None
    if cid in ('gcp.ports.sql_instance_require_ssl_enabled', 'gcp.ports.reference_sql_ssl_connections'):
        mode = evidence.get('sslMode', evidence.get('ssl_mode'))
        if (mode in (None, 'SSL_MODE_UNSPECIFIED')
                and evidence.get('deciding_field') == 'settings.ipConfiguration.requireSsl'
                and evidence.get('legacy_require_ssl') is False):
            return 'The legacy SQL setting does not require encrypted client connections.'
    if cid in ENUM_FAILURES:
        field, failed = ENUM_FAILURES[cid]
        value = evidence.get(field)
        list_field = field in ('handler_levels','ip_address_types','address_types')
        if list_field:
            return observed if _strings(value, nonempty=True) and any(v in failed for v in value) else None
        return observed if isinstance(value,str) and value in failed else None
    if cid in MISSING_DECLARATIONS:
        field = MISSING_DECLARATIONS[cid]
        return observed if field in evidence and evidence[field] in (None, '') else None
    if _binding_failure(cid, evidence):
        return observed
    if cid == 'gcp.compute.restrict_internet_ingress':
        if not _world(evidence.get('source_ranges')):
            return None
        allowed = evidence.get('allowed')
        if not isinstance(allowed, list):
            return None
        declarations = []
        for entry in allowed[:3]:
            if not isinstance(entry, dict):
                continue
            protocol, ports = entry.get('IPProtocol'), entry.get('ports')
            if protocol in ('tcp','udp','6','17') and _strings(ports, nonempty=True) and all(len(p)<20 and all(ch in '0123456789-' for ch in p) for p in ports):
                declarations.append({'6':'TCP','17':'UDP'}.get(protocol, protocol.upper())+'/'+', '.join(ports[:3]))
            elif protocol == 'all':
                declarations.append('all protocols')
        return 'The firewall rule declares Internet-wide ingress to '+'; '.join(declarations)+'.' if declarations else None
    if cid in ('gcp.claude2.api_key.created_within_90_days','gcp.claude.snapshot.not_outdated'):
        age = evidence.get('age_days')
        minimum = 90
        if type(age) is int and age > minimum:
            noun = 'snapshot' if 'snapshot' in cid else 'API key'
            return f'The {noun} was created {age} days before collection.'
        return None
    if cid in ('gcp.ports.kms_key_rotated_within_90_day','gcp.claude.kms_key.rotation_100_days'):
        seconds = evidence.get('rotation_seconds')
        limit = 86400 * (100 if '100_days' in cid else 90)
        return f'The declared key rotation interval is {seconds / 86400:g} days.' if type(seconds) is int and seconds > limit else None
    if cid == 'gcp_pci_asset_6ee2fef37d98':
        days, minimum = evidence.get('retention_days'), evidence.get('min_retention_days')
        return f'Log retention is {days} days; this profile requires at least {minimum} days.' if type(days) is int and type(minimum) is int and minimum == 90 and 0 <= days < minimum else None
    if cid in ('gcp.ports.api_key_elapsed_age_gt90','gcp.ports.iam_api_key_age_90','gcp.ports.iam_service_account_key_age_90','gcp.claude.service_account_key.age_100_days'):
        created = _date(evidence.get('created_at', evidence.get('valid_after')))
        clock = _date(evidence.get('captured_at', evidence.get('observed_at')))
        cutoff = _date(evidence.get('cutoff'))
        if created and cutoff and created < cutoff:
            return observed
        return observed if created and clock and (clock-created).days > 90 else None
    if cid == 'gcp.gke.authorized_networks':
        return observed if evidence.get('ip_endpoints_authorized_networks_enabled') is False and evidence.get('master_authorized_networks_enabled') is False else None
    if cid == 'gcp.gke.private_nodes':
        return observed if evidence.get('network_config_default_private_nodes') is False and evidence.get('private_cluster_config_private_nodes') is False else None
    if cid == 'gcp.ports.compute_instance_shielded_vm_enabled':
        values = [evidence.get(k) for k in ('enableVtpm','enableIntegrityMonitoring')]
        return observed if all(type(v) is bool for v in values) and not all(values) else None
    if cid == 'gcp.ports.compute_oslogin_metadata_precedence':
        declared_at=evidence.get('declared_at')
        field = {'instance':'instance_enable_oslogin','project':'project_enable_oslogin'}.get(declared_at) if isinstance(declared_at,str) else None
        return observed if field and evidence.get(field) is False else None
    if cid == 'gcp.reviewed.network.flow_logs':
        return observed if evidence.get('flow_logs_enabled') is False and evidence.get('network_management_configs') == 'not_collected' else None
    if cid in ('gcp.htbp.orgpolicy.domain_restricted_sharing','gcp.htbp.orgpolicy.essential_contacts_domain_restricted'):
        return observed if evidence.get('enforced') is False and evidence.get('allowed_values') == [] else None
    if cid == 'gcp.htbp.orgpolicy.sa_key_creation_and_upload_blocked':
        values = [evidence.get(k) for k in ('key_creation_blocked','key_upload_blocked')]
        return observed if all(type(v) is bool for v in values) and not all(values) else None
    if cid == 'gcp_pci_firewall_2080b14f1361':
        return observed if evidence.get('public_source') is True and _strings(evidence.get('allowed_protocols'), nonempty=True) else None
    # Empty derived inventories mean absence only for these exact reviewed
    # contracts. Presence of the key is required; omitted evidence is not empty.
    empty_field = {
        'gcp.claude.instance_group_manager.autohealing':'health_checks',
        'gcp.claude.project.storage_vpc_service_controls':'perimeters',
        'gcp.ports.iam_api_key_restricts_apis':'restricted_services',
        'gcp.ports.apikeys_api_restricted_with_gemini_api':'restricted_services',
        'gcp.ports.access_approval_explicit_enrollment':'enrolled_products',
        'gcp.ports.logging_sink_all_entries_enabled':'declared_sinks',
        'gcp.ports.organization_essential_contacts_complete':'configured_categories',
        'gcp_api_keys_active_services_only':'restricted_services',
        'gcp_cloudsql_backup_failure_alert':'enabled_alert_policies',
    }.get(cid)
    if empty_field:
        return observed if empty_field in evidence and evidence[empty_field] == [] else None
    if cid.startswith('gcp.claude.logging.metric_alert_'):
        return observed if evidence.get('alerting') == [] and _strings(evidence.get('matching_metrics')) else None
    if cid.startswith('gcp.claude2.logging.metric_alert_'):
        return observed if evidence.get('alert_chains') == [] and _strings(evidence.get('matching_metrics')) and isinstance(evidence.get('unnotified'),list) else None
    if cid.startswith('gcp.ports.logging_metric_alert_') and cid.endswith('_scoped'):
        return observed if evidence.get('declared_alerts') == [] else None
    if cid in ('gcp.claude.bigquery_dataset.no_gmail_access','gcp.claude.bigquery_dataset.no_googlegroups_access'):
        suffix = 'gmail.com' if cid.endswith('gmail_access') else 'googlegroups.com'
        records = evidence.get('matching_entries')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and isinstance(r.get('userByEmail'),str) and r['userByEmail'].endswith(suffix) for r in records) else None
    if cid in ('gcp.claude.dns_zone.ksk_not_rsasha1','gcp.claude.dns_zone.zsk_not_rsasha1'):
        key_type = 'keySigning' if 'ksk_' in cid else 'zoneSigning'
        count = evidence.get('rsasha1_specs')
        return observed if evidence.get('key_type') == key_type and type(count) is int and count > 0 else None
    if cid == 'gcp.claude.firewall.default_rules_not_open':
        return observed if evidence.get('name') in ('default-allow-icmp','default-allow-internal','default-allow-rdp','default-allow-ssh') and _world(evidence.get('source_ranges')) else None
    if cid == 'gcp.claude.firewall.public_ingress_all_protocols':
        return observed if _world(evidence.get('source_ranges')) and _strings(evidence.get('protocols')) and 'all' in evidence['protocols'] else None
    if cid == 'gcp.claude.firewall.public_ingress_tcp_udp':
        return observed if _world(evidence.get('source_ranges')) and _strings(evidence.get('protocols')) and any(v in ('tcp','udp','6','17') for v in evidence['protocols']) else None
    if cid == 'gcp.claude.firewall.public_ingress_without_target':
        return observed if _world(evidence.get('source_ranges')) and evidence.get('target_tags') == [] and evidence.get('target_service_accounts') == [] else None
    if cid == 'gcp.claude.gke.master_authorized_networks_restricted':
        return observed if _world(evidence.get('cidr_blocks')) else None
    if cid == 'gcp.gke.control_plane_restricted':
        return observed if evidence.get('private_endpoint') is False and (evidence.get('authorized_networks_enabled') is False or _world(evidence.get('authorized_networks'))) else None
    if cid in ('gcp.ports.compute_firewall_rule_ssh_access_restricted','gcp.ports.compute_firewall_rule_rdp_access_restricted'):
        port = 22 if '_ssh_' in cid else 3389
        return observed if type(evidence.get('port')) is int and evidence['port'] == port and _world(evidence.get('source_ranges')) else None
    if cid == 'gcp.ports.sql_instance_not_open_to_internet':
        return observed if _world(evidence.get('declared_authorized_ranges')) else None
    if cid == 'gcp.sql.restrict_authorized_networks':
        records = evidence.get('broad_authorized_networks')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and r.get('value') in ('0.0.0.0/0','::/0') for r in records) else None
    if cid in ('gcp.ports.firewall_http_lb_proxy_source_restriction','gcp.ports.firewall_iap_tcp_proxy_source_restriction'):
        ranges, approved = evidence.get('declared_source_ranges'), evidence.get('approved_proxy_ranges')
        if not _strings(ranges,nonempty=True) or not _strings(approved,nonempty=True):
            return None
        try:
            nets = [ipaddress.ip_network(v,strict=False) for v in approved]
            declared = [ipaddress.ip_network(v,strict=False) for v in ranges]
            return observed if any(not any(v.version == a.version and v.subnet_of(a) for a in nets) for v in declared) else None
        except ValueError:
            return None
    if cid == 'gcp.claude.instance.suspended_without_disks':
        return observed if evidence.get('status') == 'SUSPENDED' and _strings(evidence.get('attached_disks'),nonempty=True) else None
    if cid == 'gcp.claude.instance_group_manager.multiple_zones':
        zones = evidence.get('zones')
        return observed if _strings(zones,nonempty=True) and len(set(zones)) < 2 else None
    if cid == 'gcp.claude.gke.zone_redundant':
        count,zones = evidence.get('distinct_zone_count'),evidence.get('node_locations')
        return observed if type(count) is int and _strings(zones,nonempty=True) and len(set(zones)) == count and count < 3 else None
    if cid == 'gcp.claude.organization.essential_contacts_any':
        return observed if type(evidence.get('contacts')) is int and evidence['contacts'] == 0 else None
    if cid == 'gcp.claude.bucket.retention_90_days':
        days = evidence.get('retention_days')
        return observed if _number(days) and 0 <= days < 90 else None
    if cid in ('gcp.claude.service_account.recently_used','gcp.claude.service_account_key.recently_used'):
        days = evidence.get('idle_days')
        return observed if type(days) is int and days > 180 else None
    if cid in ('gcp_certificate_rotation_90_days','gcp_certificate_rotation_180_days'):
        days = evidence.get('age_days'); limit=180 if '180' in cid else 90
        return observed if type(days) is int and days > limit else None
    if cid == 'gcp_certificate_renewal_30_days':
        # Native PASS and FAIL carry identical threshold metadata: replacement
        # coverage is not present in this legacy evidence payload.
        return None
    if cid == 'gcp.reviewed.compute.single_interface':
        count=evidence.get('interface_count')
        return observed if type(count) is int and count > 1 else None
    if cid == 'gcp.reviewed.storage.lifecycle':
        count=evidence.get('valid_rule_count')
        return observed if type(count) is int and count == 0 else None
    if cid == 'gcp.reviewed.storage.soft_delete':
        duration=evidence.get('retention_seconds')
        return observed if type(duration) is int and duration == 0 else None
    if cid == 'gcp.reviewed.bigquery.cmek':
        return observed if evidence.get('default_encryption_configuration') == {} else None
    if cid == 'gcp.storage.public_access_prevention':
        return observed if evidence.get('configured') == 'inherited' and evidence.get('org_policy_enforced') is False else None
    if cid == 'gcp.claude.project.oslogin_enabled':
        return observed if 'enable_oslogin' in evidence and evidence['enable_oslogin'] in (None,False) and evidence.get('require_os_login_enforced') is False else None
    if cid == 'gcp.htbp.cloudbuild.pr_trigger_gated':
        return observed if evidence.get('approval_required') is False and evidence.get('comment_control') == 'COMMENTS_DISABLED' else None
    if cid == 'gcp.sql.mysql_admin_account_posture':
        return observed if evidence.get('host') == '%' and (evidence.get('user_name') == 'root' or evidence.get('user_type') == 'BUILT_IN') else None
    if cid == 'gcp_cloudcdn_cookie_ttl':
        duration=evidence.get('affinity_cookie_ttl_sec')
        return observed if type(duration) is int and duration > 1800 and evidence.get('session_affinity') in ('HTTP_COOKIE','GENERATED_COOKIE') else None
    if cid == 'gcp_pci_bucket_0742bd5dc32c':
        return observed if evidence.get('versioning_enabled') is True and type(evidence.get('lifecycle_rule_count')) is int and evidence['lifecycle_rule_count'] == 0 else None
    if cid == 'gcp_pci_bucket_3d76b0b0701e':
        duration=evidence.get('retention_seconds')
        return observed if evidence.get('versioning_enabled') is True and 'retention_seconds' in evidence and (duration is None or type(duration) is int and duration <= 0) else None
    if cid in ('gcp_pci_instance_template_2e26bed500fc','gcp_pci_url_map_9ed56c323a05'):
        field='external_interfaces' if 'instance_template' in cid else 'unredirected_routes'
        value=evidence.get(field)
        return observed if isinstance(value,list) and value and all(type(v) is int and v >= 0 for v in value) else None
    if cid == 'gcp_pci_kms_key_a3927a5f3b84':
        principals=evidence.get('effective_principals')
        return observed if _strings(principals,nonempty=True) and (len(set(principals)) > 3 or any(v in ('allUsers','allAuthenticatedUsers') for v in principals)) else None
    if cid == 'gcp.gap.sql_3625_trace_flag_off_cis_v1':
        return observed if evidence.get('flag') == '3625' and evidence.get('configured') == 'on' else None
    if cid == 'gcp_sql_instance_sql_instance_does_have_iam_4b5fe00566e6':
        return observed if evidence.get('flag') == 'cloudsql.iam_authentication' and 'value' in evidence and evidence['value'] in (None,'off') else None
    if cid == 'gcp.claude.kms_key.users_limited_to_3':
        records=evidence.get('broad_bindings')
        return observed if _strings(evidence.get('public_roles'),nonempty=True) or isinstance(records,list) and any(isinstance(r,dict) and type(r.get('members')) is int and r['members'] > 3 and isinstance(r.get('role'),str) for r in records) else None
    if cid == 'gcp.claude.secret.rotation_90_days':
        value=evidence.get('rotation_seconds')
        return observed if isinstance(value,str) and value.isascii() and value.isdigit() and int(value)>90*86400 else None
    if cid == 'gcp.claude.workload_identity_provider.multi_tenant_condition':
        from .claude_gcp_k8s_iam import MULTI_TENANT_ISSUERS
        return observed if evidence.get('attribute_condition') is False and isinstance(evidence.get('issuer_host'),str) and evidence['issuer_host'] in MULTI_TENANT_ISSUERS else None
    if cid == 'gcp.htbp.pubsub.push_endpoint_not_tunnel':
        from .hacktricks_bp_gcp import EXFIL_HOST
        host=evidence.get('push_host')
        if not isinstance(host,str) or not host or len(host)>253:
            return None
        try:
            literal=bool(ipaddress.ip_address(host))
        except ValueError:
            literal=False
        if literal or EXFIL_HOST.search(host):
            return f'The push endpoint host is {host}, an IP literal or listed tunnel or request-capture host.'
        return None
    if cid == 'gcp.htbp.artifactregistry.virtual_repo_private_precedence':
        standard,remote=evidence.get('standard_priorities'),evidence.get('remote_priorities')
        return observed if isinstance(standard,list) and standard and isinstance(remote,list) and remote and all(type(v) is int for v in standard+remote) and max(remote)>=max(standard) else None
    if cid in ('gcp.htbp.cloudrun.job_secret_env_from_secret_manager','gcp.htbp.cloudrun.service_secret_env_from_secret_manager'):
        records=evidence.get('literal_credential_variables')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and isinstance(r.get('container'),str) and isinstance(r.get('variable'),str) and r['variable'] for r in records) else None
    if cid in ('gcp.htbp.appengine.no_default_service_account','gcp.htbp.cloudbuild.trigger_no_default_sa','gcp.htbp.cloudrun.job_no_default_compute_sa','gcp.htbp.cloudrun.service_no_default_compute_sa','gcp.htbp.composer.no_default_compute_sa','gcp.htbp.function.runtime_no_default_sa'):
        if 'service_account' not in evidence:
            return None
        account=evidence['service_account']
        default = account is None or account == '' or isinstance(account,str) and bool(re.fullmatch(r'(?:[^@/]+@appspot\.gserviceaccount\.com|[0-9]+-compute@developer\.gserviceaccount\.com|[0-9]+@cloudbuild\.gserviceaccount\.com)',account))
        return observed if default else None
    if cid == 'gcp.htbp.workbench.no_default_compute_sa':
        accounts=evidence.get('service_accounts')
        return observed if _strings(accounts,nonempty=True) and any(re.fullmatch(r'[0-9]+-compute@developer\.gserviceaccount\.com',a) for a in accounts) else None
    if cid == 'gcp.htbp.kms.destroy_window_not_shortened':
        value=evidence.get('destroy_scheduled_duration')
        return observed if isinstance(value,str) and re.fullmatch(r'[0-9]+s',value) and int(value[:-1])<7*86400 else None
    if cid == 'gcp.htbp.storage.notification_topic_in_bucket_project':
        bucket,topic=evidence.get('bucket_project'),evidence.get('topic_project')
        return observed if isinstance(bucket,str) and bucket and isinstance(topic,str) and topic and bucket != topic else None
    if cid == 'gcp.htbp.storage.hmac_key_not_stale_or_default_sa':
        age=evidence.get('age_days')
        return observed if evidence.get('default_service_account') is True or type(age) is int and age>90 else None
    if cid == 'gcp.ports.compute_network_contains_no_legacy_network':
        value=evidence.get('legacy_ipv4_range')
        if not isinstance(value,str):
            return None
        try:
            return observed if ipaddress.ip_network(value,strict=False).version == 4 else None
        except ValueError:
            return None
    if cid.startswith('gcp.ports.kubernetes_cluster_') and cid in {
        'gcp.ports.kubernetes_cluster_legacy_endpoints_disabled',
        'gcp.ports.kubernetes_cluster_node_config_image_cos_containerd',
        'gcp.ports.kubernetes_cluster_shielded_instance_integrity_monitoring_enabled',
        'gcp.ports.kubernetes_cluster_shielded_node_secure_boot_enabled',
    }:
        pools=evidence.get('node_pools');failed=evidence.get('failing_node_pools')
        expected = 'false' if cid.endswith('legacy_endpoints_disabled') else 'UBUNTU_CONTAINERD' if cid.endswith('image_cos_containerd') else False
        return observed if isinstance(pools,dict) and _strings(failed,nonempty=True) and any(name in pools and type(pools[name]) is type(expected) and pools[name] == expected for name in failed) else None
    if cid == 'gcp.gke.node_pools_gke_metadata':
        pools=evidence.get('node_pools_exposing_compute_metadata')
        return observed if isinstance(pools,list) and any(isinstance(r,dict) and r.get('mode') in ('GCE_METADATA','UNSPECIFIED') and isinstance(r.get('node_pool'),str) for r in pools) else None
    if cid == 'gcp.reviewed.kms.rotation_enabled':
        seconds=evidence.get('rotation_seconds')
        return observed if isinstance(seconds,str) and seconds == '0' else None
    if cid == 'gcp.reviewed.kms.rotation_90_days':
        period,next_rotation=evidence.get('rotation_seconds'),evidence.get('next_rotation_seconds')
        if isinstance(period,str) and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',period) and float(period)>90*86400:
            return observed
        return observed if isinstance(next_rotation,str) and re.fullmatch(r'-?[0-9]+(?:\.[0-9]+)?',next_rotation) and (float(next_rotation)<0 or float(next_rotation)>90*86400) else None
    if cid == 'gcp_autoscaler_capacity_target':
        cpu,maximum,target=evidence.get('cpu_target'),evidence.get('max_replicas'),evidence.get('target_size')
        return observed if _number(cpu) and cpu>0.8 or type(maximum) is int and type(target) is int and maximum<=target else None
    if cid == 'gcp_c5_log_event_fields':
        return observed if isinstance(evidence.get('timestamp'),str) and _date(evidence['timestamp']) is None or 'principal' in evidence and evidence['principal'] in (None,'') else None
    if cid == 'gcp.reviewed.compute.disk_auto_delete':
        records=evidence.get('auto_delete_devices')
        return observed if isinstance(records,list) and records and all(v is None or isinstance(v,str) for v in records) else None
    if cid == 'gcp.claude.iam_policy.no_project_sa_user_or_token_creator':
        records=evidence.get('project_level_bindings')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and r.get('role') in ('roles/iam.serviceAccountUser','roles/iam.serviceAccountTokenCreator') and not r.get('condition') and _strings(r.get('members'),nonempty=True) for r in records) else None
    if cid == 'gcp.claude.instance.sa_no_basic_role':
        records,accounts=evidence.get('matching_bindings'),evidence.get('service_accounts')
        return observed if _strings(accounts,nonempty=True) and isinstance(records,list) and any(isinstance(r,dict) and r.get('role') in ('roles/owner','roles/editor') and _strings(r.get('members')) and any('serviceAccount:'+account in r['members'] for account in accounts) for r in records) else None
    if cid == 'gcp.gap.iam_user_managed_sa_no_admin_roles':
        records=evidence.get('admin_role_bindings')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and isinstance(r.get('role'),str) and (r['role'] in ('roles/owner','roles/editor') or r['role'].lower().endswith('admin')) for r in records) else None
    if cid in ('gcp.htbp.iam.policy_no_pool_wide_workload_principal_set','gcp.htbp.iam.sa_no_pool_wide_workload_principal_set'):
        records=evidence.get('pool_wide_bindings')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and isinstance(r.get('member'),str) and re.fullmatch(r'principalSet://iam\.googleapis\.com/projects/[0-9]+/locations/global/workloadIdentityPools/[^/]+/\*',r['member']) for r in records) else None
    if cid == 'gcp.htbp.scheduler.no_recurring_access_regrant':
        from .hacktricks_bp_gcp import IAM_REPLAY
        uri=evidence.get('uri')
        if not isinstance(uri,str):
            return None
        try:
            parsed=urlsplit(uri)
            return observed if (parsed.hostname or '').endswith('.googleapis.com') and evidence.get('http_method') in ('POST','PUT','PATCH') and IAM_REPLAY.search(parsed.path) else None
        except ValueError:
            return None
    if cid == 'gcp.ports.audit_logging_configured_for_all_service':
        types=evidence.get('configured_log_types');exemptions=evidence.get('exempted_members')
        return observed if _strings(types) and _strings(exemptions) and (not {'ADMIN_READ','DATA_READ','DATA_WRITE'} <= set(types) or exemptions) else None
    if cid == 'gcp.iam.data_access_audit':
        types=evidence.get('configured_types')
        return observed if _strings(types) and _strings(evidence.get('evaluated_scopes'),nonempty=True) and evidence.get('missing_scopes') == [] and not {'DATA_READ','DATA_WRITE'} <= set(types) else None
    if cid == 'gcp.ports.iam_api_key_restricts_websites_hosts_apps':
        return observed if evidence.get('restriction_mode') == 'serverKeyRestrictions' and _world(evidence.get('allowed')) else None
    if cid == 'gcp.ports.iam_user_not_assigned_service_account_user_role_project_level':
        records=evidence.get('broad_project_role_declarations')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and r.get('role') in ('roles/iam.serviceAccountUser','roles/iam.serviceAccountTokenCreator') and isinstance(r.get('principal'),str) and not r['principal'].endswith('.gserviceaccount.com') for r in records) else None
    if cid == 'gcp.ports.function_basic_role_declarations':
        records=evidence.get('role_assignment_declarations')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and r.get('role') in ('roles/owner','roles/editor') for r in records) else None
    if cid == 'gcp.ports.service_account_mutating_role_declarations':
        records=evidence.get('mutating_role_declarations')
        return observed if isinstance(records,list) and any(isinstance(r,dict) and type(r.get('mutating_permission_count')) is int and r['mutating_permission_count']>0 and isinstance(r.get('role'),str) for r in records) else None
    if cid in ('gcp.ports.iam_user_separation_of_duty_scoped','gcp.ports.kms_key_separation_of_duties_enforced'):
        records=evidence.get('overlapping_role_declarations')
        administrator='roles/iam.serviceAccountAdmin' if '.iam_' in cid else 'roles/cloudkms.admin'
        others={'roles/iam.serviceAccountUser'} if '.iam_' in cid else {'roles/cloudkms.cryptoKeyEncrypter','roles/cloudkms.cryptoKeyDecrypter','roles/cloudkms.cryptoKeyEncrypterDecrypter'}
        if not isinstance(records,list):
            return None
        for record in records:
            if not isinstance(record,dict) or not isinstance(record.get('principal'),str) or not record['principal'].startswith('user:') or not isinstance(record.get('declarations'),list):
                continue
            roles={r.get('role') for r in record['declarations'] if isinstance(r,dict) and isinstance(r.get('role'),str)}
            if administrator in roles and roles & others:
                return observed
        return None
    # No blanket status-to-fact fallback. Unbound legacy payloads retain raw
    # evidence and the recorded result without inventing their missing facts.
    return None
