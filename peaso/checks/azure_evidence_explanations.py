"""Check-specific Azure evidence copy, independent of evaluator semantics.

The exact-ID review map is shared with the UI. It describes why each reviewed
setting matters and what the available evidence cannot establish. No title,
category, or keyword heuristics select an explanation at runtime.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROWS = json.loads(Path(__file__).with_suffix('.json').read_text())
_PLAIN_RULES = json.loads(Path(__file__).with_name('azure_observed_evidence_rules.json').read_text())
_NOT_APPLICABLE = json.loads(Path(__file__).with_name('azure_not_applicable_evidence.json').read_text())
_NOT_APPLICABLE_VARIANTS = json.loads(Path(__file__).with_name('azure_not_applicable_variants.json').read_text())
_MANUAL = json.loads(Path(__file__).with_name('azure_manual_evidence.json').read_text())
_INCOMPLETE = json.loads(Path(__file__).with_name('azure_incomplete_evidence_reasons.json').read_text())
_ACTIVITY_ALERTS = json.loads(Path(__file__).with_name('azure_activity_alert_evidence.json').read_text())
_MISSING_FACT_LABELS = json.loads(Path(__file__).with_name('azure_missing_fact_labels.json').read_text())
_DEPENDENCY_LABELS = json.loads(Path(__file__).with_name('azure_dependency_labels.json').read_text())
_SERVICEBUS_NETWORK = json.loads(Path(__file__).with_name('azure_servicebus_network_evidence.json').read_text())
_UNKNOWN_GROUP_EFFECTS = json.loads(Path(__file__).with_name('azure_unknown_group_effects.json').read_text())
_UNKNOWN_SPECIFIC_EFFECTS = json.loads(Path(__file__).with_name('azure_unknown_specific_effects.json').read_text())
_NATIVE_IMPACTS = json.loads(Path(__file__).with_name('azure_native_observed_impacts.json').read_text())
_BULK_IMPACT_PATTERNS = json.loads(Path(__file__).with_name('azure_bulk_observed_impact_patterns.json').read_text())
_BULK_FAILURE_SHAPES = json.loads(Path(__file__).with_name('azure_bulk_evidence_shapes.json').read_text())


def _single_unknown_reason(evidence):
    """Read a sole nested UNKNOWN result without changing its meaning."""
    current = evidence
    for _ in range(3):
        if not isinstance(current, dict) or current.get('evaluated_count') != 1:
            return None
        outcomes = current.get('outcomes')
        if not isinstance(outcomes, list) or len(outcomes) != 1:
            return None
        current = outcomes[0]
        if not isinstance(current, dict) or current.get('status') != 'UNKNOWN':
            return None
        if isinstance(current.get('reason'), str):
            return current['reason']
    return None

# Labels describe the actual field rather than the desired outcome in the title.
_SCALAR_LABELS = {
    'azure.storage.no_shared_key': 'Storage Shared Key authorization',
    'azure.storage.default_oauth': 'Default Microsoft Entra authorization',
    'azure.storage.no_public_network': 'Storage public network access',
    'azure.vault.soft_delete': 'Key Vault soft delete',
    'azure.vault.purge_protection': 'Key Vault purge protection',
    'azure.vault.rbac': 'Key Vault Azure RBAC authorization',
    'azure.vault.no_public_network': 'Key Vault public network access',
    'azure.vault.default_deny': 'The Key Vault network default',
    'azure.aks.rbac': 'Kubernetes RBAC',
    'azure.aks.no_local_accounts': 'Local AKS accounts',
    'azure.aks.private_cluster': 'The private AKS API endpoint',
    'azure.aks.azure_rbac': 'Azure RBAC for Kubernetes authorization',
    'azure.sql.minimum_tls': 'The SQL minimum TLS version',
    'azure.sql.no_public_network': 'SQL public network access',
    'azure.sql.auditing': 'SQL auditing',
    'azure.sql.threat_detection': 'SQL threat detection',
    'azure.storage.default_deny': 'The storage network default',
    'azure.storage.cross_tenant_replication': 'Cross-tenant object replication',
    'azure.storage.infrastructure_encryption': 'Additional storage infrastructure encryption',
    'azure.vm.encryption_at_host': 'VM encryption at host',
    'azure.disk.entra_export_auth': 'The disk export authentication mode',
    'azure.network.load_balancer_standard': 'The load-balancer SKU',
    'azure.network.public_ip_standard': 'The public-IP SKU',
    'azure.network.nic_no_ip_forwarding': 'NIC IP forwarding',
    'azure.network.ddos_configured': 'Virtual-network DDoS protection',
    'azure.aks.defender_monitoring': 'AKS Defender monitoring',
    'azure.app.https_only': 'The App Service HTTPS requirement',
    'azure.app.http2': 'App Service HTTP/2',
    'azure.app.request_logging': 'App Service HTTP request logging',
    'azure.app.remote_debugging_off': 'App Service remote debugging',
    'azure.port.databricks_workspace_no_public_ip_enabled': 'Databricks no-public-IP mode',
    'azure.port.databricks_workspace_public_network_access_disabled': 'Databricks public network access',
}


def reviewed_explanation(check_id: str, observation: str, status: str = '') -> str | None:
    """Explain an already verified observation once, retaining its actual values."""
    row = ROWS.get(check_id)
    if row is None or not isinstance(observation, str) or not observation.strip():
        return None
    observation = observation.strip()
    if row['purpose'] in observation:
        return observation
    suffix = row['purpose'] + ' ' + row['limit']
    return observation + ('' if observation.endswith(('.', '!', '?')) else '.') + ' ' + suffix


def _plain_observation(finding):
    """Use short copy only when its exact recorded witness is present."""
    rule = _PLAIN_RULES.get(finding.get('check_id'))
    if finding.get('status') not in {'PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE', 'MANUAL'}:
        return None
    evidence = finding.get('evidence')
    if not isinstance(evidence, dict):
        return None
    if finding['status'] == 'MANUAL':
        manual = _MANUAL.get(finding.get('check_id'))
        if manual and all(key in evidence and type(evidence[key]) is type(value) and evidence[key] == value
                          for key, value in manual['required'].items()):
            return '\n'.join(manual['lines'])
        return None
    check_id = finding.get('check_id')
    if finding['status'] == 'UNKNOWN' and evidence.get('reason') == 'authenticated complete AKS native Pod/Namespace capture unavailable':
        if check_id == 'azure_aks_cluster_7_2_1_6_93c4fab':
            return ('A complete authenticated AKS Pod and Namespace record is unavailable.\n'
                    "The containers' privilege settings remain unknown.\n"
                    'The team cannot tell whether any container could run with broad access.')
        if check_id == 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524':
            return ('A complete authenticated AKS Pod and Namespace record is unavailable.\n'
                    "The containers' run-as-user settings remain unknown.\n"
                    'The team cannot tell whether an app could run as root.')
    if finding['status'] == 'UNKNOWN' and check_id == 'azure_aks_cluster_aks_cluster_rbac_enabled_db12524' and evidence.get('reason') == 'Windows OS, node OS or security context unresolved':
        return ('The Pod OS or container security context is unresolved.\n'
                "The container's run-as-user setting remains unknown.\n"
                'The team cannot tell whether this app could run as root.')
    if finding['status'] == 'UNKNOWN' and check_id == 'azure.logging.aks_supported_log_categories_destination_declared' and evidence.get('reason') == 'native AKS diagnostic declaration incomplete, malformed or unbound':
        return ('The AKS diagnostic declaration is incomplete or unbound.\n'
                'The destination for supported log categories remains unknown.\n'
                'The team cannot tell where the cluster activity may be recorded.')
    if (check_id == 'azure_nsg_world_ingress_approved_ports' and finding['status'] == 'FAIL'
            and isinstance(evidence.get('observed_nsg_paths'), list)
            and len(evidence['observed_nsg_paths']) == evidence.get('evaluated')):
        offending = [port for row in evidence['observed_nsg_paths'] if isinstance(row, dict)
                     and isinstance(row.get('nsg_id'), str)
                     and isinstance(row.get('world_source_allowed_ports'), list)
                     and isinstance(row.get('approved_ports'), list)
                     for port in row['world_source_allowed_ports']
                     if type(port) is int and port not in row['approved_ports']]
        if offending:
            return (f'An NSG allows world-source inbound traffic on unapproved port {offending[0]}.\n'
                    'Outside hosts may send traffic toward that port.\n'
                    'The service could face more unwanted connection attempts.')
    if (check_id == 'azure_recovery_vault_10_3_3_1_1f42f66' and finding['status'] == 'FAIL'
            and isinstance(evidence.get('backup_policy_facts'), list)
            and len(evidence['backup_policy_facts']) == evidence.get('evaluated') == 1):
        fact = evidence['backup_policy_facts'][0]
        if isinstance(fact, dict) and isinstance(fact.get('database_id'), str) and fact.get('retention_days') == 0:
            return ('The SQL database has a short-term backup retention setting of zero days.\n'
                    'Older restore points may not be kept under that policy.\n'
                    'People could have fewer ways to recover data after a mistake.')
    if (check_id == 'azure_recovery_vault_10_3_3_8_26e08d7' and finding['status'] == 'FAIL'
            and isinstance(evidence.get('backup_window_facts'), list)
            and len(evidence['backup_window_facts']) == evidence.get('evaluated') == 1):
        fact = evidence['backup_window_facts'][0]
        if (isinstance(fact, dict) and isinstance(fact.get('database_id'), str)
                and fact.get('retention_days') == 0 and fact.get('latest_restore_point') is None):
            return ('The SQL database has a backup retention setting of zero days.\n'
                    'That policy may leave no older restore point to use.\n'
                    'People could lose data after a mistake.')
    if (check_id == 'azure_sql_database_sqlserver_auditing_enabled_77d6841' and finding['status'] == 'FAIL'
            and isinstance(evidence.get('diagnostic_facts'), list)
            and len(evidence['diagnostic_facts']) == evidence.get('evaluated') == 1):
        fact = evidence['diagnostic_facts'][0]
        if (isinstance(fact, dict) and isinstance(fact.get('resource_id'), str)
                and isinstance(fact.get('missing_categories'), list)
                and 'audit' in fact['missing_categories']):
            return ('The SQL database is missing the required audit log export category.\n'
                    'Some database activity may not reach the approved workspace.\n'
                    'The team could have less detail when investigating data use.')
    if (check_id == 'azure_c5_ops_17_02ac' and finding['status'] == 'PASS'
            and isinstance(evidence.get('direct_control_measures'), list)
            and evidence['direct_control_measures']
            and len(evidence['direct_control_measures']) == evidence.get('direct_control_measure_count')
            and all(isinstance(row, dict) and isinstance(row.get('control'), str)
                    and isinstance(row.get('measure_id'), str)
                    and row.get('observation') == 'implemented' and row.get('documented') is True
                    for row in evidence['direct_control_measures'])):
        return (f"{len(evidence['direct_control_measures'])} required log and infrastructure safeguards are documented as implemented.\n"
                'They may protect access to logs and keep services available.\n'
                'The team could rely on these records during an investigation.')
    if (check_id == 'azure_recovery_vault_10_3_3_1_1f42f66' and finding['status'] == 'PASS'
            and isinstance(evidence.get('backup_policy_facts'), list)
            and len(evidence['backup_policy_facts']) == evidence.get('evaluated') == 1):
        fact = evidence['backup_policy_facts'][0]
        if isinstance(fact, dict) and isinstance(fact.get('database_id'), str) and type(fact.get('retention_days')) is int and fact['retention_days'] > 0:
            return (f"The SQL database has a {fact['retention_days']}-day short-term backup retention policy.\n"
                    'That policy may keep point-in-time recovery available for recent changes.\n'
                    'People could have a way to restore data after a mistake.')
    if (check_id == 'azure_recovery_vault_10_3_3_8_26e08d7' and finding['status'] == 'PASS'
            and isinstance(evidence.get('backup_window_facts'), list)
            and len(evidence['backup_window_facts']) == evidence.get('evaluated') == 1):
        fact = evidence['backup_window_facts'][0]
        if (isinstance(fact, dict) and isinstance(fact.get('database_id'), str)
                and type(fact.get('retention_days')) is int and fact['retention_days'] > 0
                and isinstance(fact.get('latest_restore_point'), str)
                and isinstance(fact.get('captured_at'), str)):
            from datetime import datetime
            try:
                latest = datetime.fromisoformat(fact['latest_restore_point'].replace('Z', '+00:00'))
                capture = datetime.fromisoformat(fact['captured_at'].replace('Z', '+00:00'))
            except ValueError:
                pass
            else:
                if latest.tzinfo is not None and capture.tzinfo is not None and latest <= capture:
                    return (f"The SQL database has a {fact['retention_days']}-day backup policy and a recorded restore point.\n"
                            'That restore point may cover a recent data loss.\n'
                            'People could have a way to recover their data.')
    if (check_id == 'azure.claude.storage_vhd_accounts_cmk' and finding['status'] == 'UNKNOWN'
            and evidence.get('reason') == 'VHD selected subscription identity malformed'):
        return ('The VHD record has no valid selected subscription identity.\n'
                'Its backing storage account cannot be matched to that subscription.\n'
                'The team cannot tell which key protects the disk file.')
    if (check_id == 'azure.sql.minimum_tls' and finding['status'] == 'UNKNOWN'
            and evidence.get('reason') == 'SQL minimum TLS declaration unavailable'):
        return ('The SQL server record has no usable minimum TLS declaration.\n'
                'The permitted connection version is unclear.\n'
                'People may not know whether older connections are allowed.')
    if (check_id == 'azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled'
            and finding['status'] == 'FAIL' and isinstance(evidence.get('outcomes'), list)
            and len(evidence['outcomes']) == 1 and isinstance(evidence['outcomes'][0], dict)):
        group = evidence['outcomes'][0]
        if group.get('status') == 'FAIL' and isinstance(group.get('outcomes'), list):
            path = next((row for row in group['outcomes'] if isinstance(row, dict)
                         and row.get('status') == 'FAIL'
                         and row.get('reason') == 'permitted sign-in path without MFA'
                         and isinstance(row.get('principal_id'), str)
                         and isinstance(row.get('context_id'), str)), None)
            if path:
                return (f"The {path['context_id']} sign-in path permits {path['principal_id']} without MFA.\n"
                        'A password alone may be enough on that path.\n'
                        'Someone with a stolen password could enter as that user.')
    if (check_id == 'azure_c5_ops_13_01b' and finding['status'] == 'PASS'
            and isinstance(evidence.get('verified_source_ids'), list)
            and evidence['verified_source_ids'] and len(evidence['verified_source_ids']) == evidence.get('verified_sources')
            and all(isinstance(value, str) and value for value in evidence['verified_source_ids'])
            and isinstance(evidence.get('approved_destination_id'), str)
            and all(evidence.get(key) is True for key in ('correlation_verified', 'incident_workflow_verified',
                                                          'safeguard_inventory_documented'))):
        return (f"{', '.join(evidence['verified_source_ids'])} logs have verified export and ingestion to the approved SIEM destination.\n"
                'The central log may keep those events together.\n'
                'The team could investigate changes to these services sooner.')
    if (check_id == 'azure_vm_vm_ensure_using_managed_disks_11f205b' and finding['status'] == 'PASS'
            and isinstance(evidence.get('observed_disk_mappings'), list)
            and evidence['observed_disk_mappings'] and len(evidence['observed_disk_mappings']) == evidence.get('checked_mappings')
            and all(isinstance(row, dict) and isinstance(row.get('disk_id'), str)
                    and isinstance(row.get('vm_id'), str) and row.get('attached') is True
                    and row.get('owner_matches') is True and type(row.get('delete_with_vm')) is bool
                    for row in evidence['observed_disk_mappings'])):
        count = len(evidence['observed_disk_mappings'])
        first = ('The mapped managed disk is attached to its expected VM, and its owner matches.' if count == 1
                 else f'All {count} mapped managed disks are attached to their expected VMs, and their owners match.')
        return (first + '\nEach disk may remain linked to its intended workload.\n'
                'VM users could face fewer unexpected disk changes.')
    if (check_id == 'azure_nsg_world_ingress_approved_ports' and finding['status'] == 'PASS'
            and isinstance(evidence.get('observed_nsg_paths'), list) and evidence['observed_nsg_paths']
            and len(evidence['observed_nsg_paths']) == evidence.get('evaluated')
            and all(isinstance(row, dict) and isinstance(row.get('nsg_id'), str)
                    and isinstance(row.get('world_source_allowed_ports'), list)
                    and isinstance(row.get('approved_ports'), list)
                    and set(row['world_source_allowed_ports']) <= set(row['approved_ports'])
                    for row in evidence['observed_nsg_paths'])):
        count = sum(len(row['world_source_allowed_ports']) for row in evidence['observed_nsg_paths'])
        if count:
            return ('The recorded NSGs allow world-source inbound traffic only on approved ports.\n'
                    'Other ports may stay closed to those sources.\n'
                    'Services could receive fewer unwanted connection attempts.')
        return ('The recorded NSGs have no effective world-source inbound Allow paths.\n'
                'Outside hosts may have fewer direct paths to these networks.\n'
                'Services could receive fewer unwanted connection attempts.')
    if (check_id == 'azure_sql_database_sqlserver_auditing_enabled_77d6841' and finding['status'] == 'PASS'
            and isinstance(evidence.get('diagnostic_facts'), list) and evidence['diagnostic_facts']
            and len(evidence['diagnostic_facts']) == evidence.get('evaluated')
            and all(isinstance(row, dict) and isinstance(row.get('resource_id'), str)
                    and isinstance(row.get('required_categories'), list) and row['required_categories']
                    and isinstance(row.get('covered_categories'), list)
                    and row.get('missing_categories') == []
                    and set(row['required_categories']) <= set(row['covered_categories'])
                    for row in evidence['diagnostic_facts'])):
        return ('The SQL databases route their required audit log categories to an approved Log Analytics workspace.\n'
                'Those database events may be available in one place.\n'
                'The team could investigate use of the data sooner.')
    if (check_id == 'azure.claude.managed_hsm_audit_logging' and finding['status'] == 'UNKNOWN'
            and evidence.get('audit_archive_declared') is True
            and evidence.get('diagnostic_retention_retired_on') == '2025-09-30'):
        return ('An AuditEvent storage destination is declared for this Managed HSM.\n'
                'The record has no current retention setting for those logs.\n'
                'The team cannot tell how long key activity would remain available.')
    if (check_id == 'azure.claude.storage_access_keys_rotated_90' and finding['status'] == 'FAIL'
            and evidence.get('threshold_seconds') == 90 * 86400
            and isinstance(evidence.get('captured_at'), str) and isinstance(evidence.get('key_age_days'), dict)):
        old = next(((key, age) for key, age in evidence['key_age_days'].items()
                    if key in ('key1', 'key2') and type(age) in (int, float) and age > 90), None)
        if old:
            return (f'Storage access key {old[0]} was created about {round(old[1])} days before this capture.\n'
                    'An old exposed key may stay useful if it is still valid.\n'
                    'Someone holding it could reach stored files.')
    if (check_id == 'azure.claude.synapse_workspace_vulnerability_assessment' and finding['status'] == 'FAIL'
            and evidence.get('recurring_scans') == [False]):
        return ('The Synapse workspace has a recurring vulnerability scan policy set to disabled.\n'
                'New weak settings may stay unseen between manual scans.\n'
                'The team could review risks to data later than needed.')
    if (check_id == 'azure.claude.vm_windows_secure_boot' and finding['status'] == 'NOT_APPLICABLE'
            and evidence.get('os_type') == 'Linux'):
        return ('This VM runs Linux.\n'
                'The Windows Secure Boot setting does not apply to it.\n'
                'Its users are outside the scope of that Windows setting.')
    if (check_id in ('azure.claude2.nsg_flow_logs_to_log_analytics',
                     'azure.claude2.vnet_flow_logs_to_log_analytics') and finding['status'] == 'UNKNOWN'
            and evidence.get('reason') == 'flow log target not uniquely resolved in selected network inventory'):
        return ('The flow log target has no unique match in the network records.\n'
                'Its Log Analytics route remains unclear.\n'
                'The team cannot tell whether those flow records are available for review.')
    if check_id == 'azure.claude.recovery_vault_backup_retention_30_days' and finding['status'] == 'FAIL':
        policies = evidence.get('short_policies')
        if isinstance(policies, list) and policies and isinstance(policies[0], dict):
            policy = policies[0]
            if (isinstance(policy.get('policy'), str) and isinstance(policy.get('count'), int)
                    and policy.get('duration_type') in ('Days', 'Weeks', 'Months', 'Years')):
                return (f"The {policy['policy']} daily backup policy keeps recovery points for "
                        f"{policy['count']} {policy['duration_type'].lower()}.\n"
                        'Older restore points may disappear sooner.\n'
                        'People could have fewer chances to recover lost data.')
    if check_id == 'azure.gap.monitor_log_profile_retention_365_days' and finding['status'] == 'PASS':
        profiles = evidence.get('observed_retention_profiles')
        if (isinstance(profiles, list) and profiles and evidence.get('profile_count') == len(profiles)
                and all(isinstance(profile, dict) and isinstance(profile.get('profile_id'), str)
                        and profile.get('enabled') is True and isinstance(profile.get('retention_days'), int)
                        and profile['retention_days'] >= 365 for profile in profiles)):
            days = min(profile['retention_days'] for profile in profiles)
            return (f'A legacy log profile is enabled with at least {days} days of retention.\n'
                    'Older activity records may stay available for review.\n'
                    'That could help the team trace problems affecting users.')
    if check_id == 'azure.claude2.app_gateway_min_tls_12' and evidence.get('ssl_policy', 'missing') is None:
        name = evidence.get('default_policy_name')
        if finding['status'] == 'PASS' and name in ('AppGwSslPolicy20170401S', 'AppGwSslPolicy20220101', 'AppGwSslPolicy20220101S'):
            return (f'This gateway has no custom TLS policy and names {name} as its default.\n'
                    'That policy requires TLS 1.2 or newer.\n'
                    'Users may avoid older, weaker connections.')
        if finding['status'] == 'FAIL' and name in ('AppGwSslPolicy20150501', 'AppGwSslPolicy20170401'):
            return (f'This gateway has no custom TLS policy and names {name} as its default.\n'
                    'That policy may allow a TLS version below 1.2.\n'
                    "Users' connections could have weaker protection.")
    if check_id == 'azure.claude2.sql_server_threat_detection_all_alerts' and finding['status'] == 'PASS':
        policies = evidence.get('observed_policies')
        if (isinstance(policies, list) and policies and all(isinstance(policy, dict)
                and isinstance(policy.get('policy'), str) and policy.get('state') == 'Enabled'
                and policy.get('disabled_alerts') in ([], ['']) for policy in policies)):
            return ('The SQL server has enabled threat policies with no alert types disabled.\n'
                    'Defender may warn about suspicious database actions.\n'
                    'The team could respond sooner to threats to stored data.')
    if (check_id in ('azure.claude.network_watcher_flow_logs_retention_90',
                     'azure.claude.network_watcher_flow_logs_traffic_analytics')
            and finding['status'] == 'PASS'):
        logs = evidence.get('observed_flow_logs')
        if isinstance(logs, list) and logs:
            if (check_id.endswith('retention_90') and all(isinstance(log, dict)
                    and isinstance(log.get('flow_log'), str) and log.get('enabled') is True
                    and isinstance(log.get('retention_days'), int)
                    and (log['retention_days'] == 0 or log['retention_days'] >= 90) for log in logs)):
                return ('Each recorded Network Watcher flow log is enabled with at least 90 days of retention or no end date.\n'
                        'Network traffic may leave a longer history.\n'
                        'The team could trace suspicious connections affecting users.')
            if (check_id.endswith('traffic_analytics') and all(isinstance(log, dict)
                    and isinstance(log.get('flow_log'), str) and log.get('enabled') is True
                    and log.get('traffic_analytics_enabled') is True for log in logs)):
                return ('Each recorded Network Watcher flow log is enabled with Traffic Analytics.\n'
                        'Traffic patterns may be summarized for the team.\n'
                        'They could spot unusual traffic sooner.')
    if check_id == 'azure.claude.network_watcher_in_vnet_region':
        region, regions = evidence.get('region'), evidence.get('network_watcher_regions')
        if isinstance(region, str) and isinstance(regions, list) and all(isinstance(value, str) for value in regions):
            if finding['status'] == 'PASS' and region in regions:
                return (f"A Network Watcher is recorded in the VNet's {region} region.\n"
                        'Network diagnostics may be available there.\n'
                        'The team could review traffic problems affecting users.')
            if finding['status'] == 'FAIL' and region not in regions:
                return (f'The VNet is in {region}, with no Network Watcher recorded there.\n'
                        'Network diagnostics may be limited in that region.\n'
                        'The team could have less detail to solve traffic problems.')
    if check_id == 'azure.claude.recovery_vault_backup_retention_30_days' and finding['status'] == 'PASS':
        policies = evidence.get('observed_daily_policies')
        if (isinstance(policies, list) and policies and evidence.get('evaluated_policies') == len(policies)
                and all(isinstance(policy, dict) and isinstance(policy.get('policy'), str)
                        and isinstance(policy.get('minimum_retention_days'), int)
                        and policy['minimum_retention_days'] >= 30 for policy in policies)):
            days = min(policy['minimum_retention_days'] for policy in policies)
            return (f"The vault's daily backup policies retain recovery points for at least {days} days.\n"
                    'The policies may keep older points available for that time.\n'
                    'People could have more options to restore lost data.')
    if (check_id == 'azure.claude.vmss_managed_disks' and finding['status'] == 'PASS'
            and evidence.get('managed_os_disk') is True
            and isinstance(evidence.get('data_disk_count'), int)
            and evidence.get('managed_data_disk_count') == evidence['data_disk_count']):
        if evidence['data_disk_count'] == 0:
            return ('The VM scale set declares a managed OS disk and no data disks.\n'
                    'Azure handles storage placement for that disk.\n'
                    'That may reduce storage errors affecting the service.')
        return ('The VM scale set declares managed OS and data disks.\n'
                'Azure handles storage placement for those disks.\n'
                'That may reduce storage errors affecting the service.')
    if (check_id == 'azure.vm.managed_disks' and finding['status'] == 'PASS'
            and isinstance(evidence.get('disk_count'), int) and evidence['disk_count'] > 0
            and evidence.get('managed_disk_count') == evidence['disk_count']):
        if evidence['disk_count'] == 1:
            return ('The VM declares a managed OS disk and no data disks.\n'
                    'Azure handles storage placement for that disk.\n'
                    "That may reduce storage errors affecting users' data.")
        return ('The VM declares managed OS and data disks.\n'
                'Azure handles storage placement for those disks.\n'
                "That may reduce storage errors affecting users' data.")
    if check_id == 'azure.claude2.nsg_flow_log_retention_90' and finding['status'] == 'PASS':
        logs = evidence.get('observed_flow_logs')
        vnet = 'vnet_flow_logs' in evidence
        if (isinstance(logs, list) and logs and all(isinstance(log, dict)
                and isinstance(log.get('flow_log'), str) and log.get('enabled') is True
                and isinstance(log.get('retention_days'), int)
                and (log['retention_days'] == 0 or log['retention_days'] >= 90 if vnet
                     else log['retention_days'] >= 90) for log in logs)):
            days = min(log['retention_days'] for log in logs)
            kind = 'A covering VNet flow log' if vnet else 'An NSG flow log'
            duration = 'indefinitely' if days == 0 else f'for at least {days} days'
            return (f'{kind} is enabled and retains records {duration}.\n'
                    'Network traffic may leave a longer history.\n'
                    'The team could trace suspicious connections affecting users.')
    if check_id in ('azure.claude.activity_log_storage_cmk', 'azure.claude.activity_log_storage_private'):
        accounts = evidence.get('storage_accounts')
        values = evidence.get('observed_storage_settings')
        if (isinstance(accounts, list) and accounts and isinstance(values, list) and values
                and all(isinstance(item, dict) and isinstance(item.get('storage_account_id'), str)
                        and item['storage_account_id'] in accounts for item in values)):
            settings = [item.get('setting') for item in values]
            if check_id.endswith('_cmk'):
                if finding['status'] == 'PASS' and all(value == 'Microsoft.Keyvault' for value in settings):
                    return ('The storage account for activity logs uses a Key Vault customer key.\n'
                            'That key may protect stored activity logs.\n'
                            'The owner may control access to the key for those logs.')
                if finding['status'] == 'FAIL' and 'Microsoft.Storage' in settings:
                    return ('An activity-log storage account uses a Microsoft-managed key.\n'
                            'The owner may have less control over the encryption key.\n'
                            'That could limit how they protect logs used to investigate incidents.')
            else:
                if finding['status'] == 'PASS' and all(value is False for value in settings):
                    return ('The activity-log storage account has public Blob access disabled.\n'
                            'A public Blob grant may be blocked.\n'
                            'That could help keep activity records private.')
                if finding['status'] == 'FAIL' and True in settings:
                    return ('An activity-log storage account allows public Blob access.\n'
                            'A container could be shared publicly if its own setting allows it.\n'
                            'That could expose activity records to unwanted readers.')
    if (check_id == 'azure.claude.sql_va_reports_configured'
            and isinstance(evidence.get('email_subscription_admins'), bool)
            and isinstance(evidence.get('email_count'), int) and evidence['email_count'] >= 0):
        if finding['status'] == 'PASS' and evidence['email_subscription_admins']:
            return ('SQL vulnerability reports email subscription administrators.\n'
                    'A report may reach someone who can review it.\n'
                    'The team could learn about database weaknesses.')
        if finding['status'] == 'PASS' and evidence['email_count'] > 0:
            return ('SQL vulnerability reports have a listed email recipient.\n'
                    'A report may reach that address.\n'
                    'The team could learn about database weaknesses.')
        if finding['status'] == 'FAIL' and evidence['email_subscription_admins'] is False and evidence['email_count'] == 0:
            return ('SQL vulnerability reports have no admin or listed email recipient.\n'
                    'A scan report may not reach a responder by email.\n'
                    'The team could miss database weaknesses.')
    if check_id == 'azure.cis.resource_manager_delete_locks_applied_storage_accounts' and evidence.get('accounts') == 1:
        facts = evidence.get('observed_pass_facts' if finding['status'] == 'PASS' else 'observed_fail_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            fact = facts[0]
            if isinstance(fact.get('account_id'), str) and isinstance(fact.get('effective_lock_ids'), list):
                if finding['status'] == 'PASS' and fact['effective_lock_ids']:
                    return ('A storage account has an effective delete lock.\n'
                            'An accidental or unwanted delete may be blocked.\n'
                            'That could help keep stored files available to their users.')
                if finding['status'] == 'FAIL' and not fact['effective_lock_ids']:
                    return ('A storage account has no effective delete lock.\n'
                            'An accidental or unwanted delete may remove it.\n'
                            'People could lose access to files kept there.')
    if (check_id == 'azure.gap.compute_vm_remote_access_restricted_all_ports' and finding['status'] == 'PASS'
            and evidence.get('evaluated_ip_configurations') == 1):
        paths = evidence.get('observed_restricted_paths')
        if (isinstance(paths, list) and paths and all(isinstance(path, dict)
                and isinstance(path.get('ip_configuration'), str) and isinstance(path.get('nsg_id'), str)
                and path.get('effective_public_allow') is False for path in paths)):
            return ("A VM's attached network rules have no effective public inbound allow path.\n"
                    'Unwanted internet traffic may be stopped at those rules.\n'
                    "That could reduce exposure of the VM's services.")
    if (check_id == 'azure.other.entra_app_secret_age_90' and finding['status'] == 'PASS'
            and evidence.get('active_credential_count') == 1):
        credentials = evidence.get('observed_active_credentials')
        if isinstance(credentials, list) and len(credentials) == 1 and isinstance(credentials[0], dict):
            credential = credentials[0]
            age = credential.get('age_days')
            if (isinstance(credential.get('application_id'), str) and isinstance(credential.get('key_id'), str)
                    and isinstance(age, int) and 0 <= age < 90):
                return (f'An active Entra app secret is {age} days old.\n'
                        'Someone has had less time to copy this secret.\n'
                        'That may reduce unwanted access to data the app can reach.')
    if (check_id == 'azure.other.message_namespace_cmk' and finding['status'] == 'PASS'
            and evidence.get('namespace_count') == 1):
        keys = evidence.get('observed_approved_keys')
        if isinstance(keys, list) and len(keys) == 1 and isinstance(keys[0], dict):
            key = keys[0]
            if (isinstance(key.get('namespace_id'), str) and isinstance(key.get('key_uri'), str)
                    and key.get('key_usable') is True and key.get('publish_without_cmk_rejected') is True):
                return ('A messaging namespace uses an approved Key Vault key, and a publish without that key was rejected.\n'
                        'The key may protect messages stored by the namespace.\n'
                        'That could give the owner more control over access to message data.')
    if (check_id == 'azure.other.entra_password_baseline' and finding['status'] == 'PASS'
            and evidence.get('newly_provisioned_identity_count') == 1):
        policies = evidence.get('observed_password_policies')
        if isinstance(policies, list) and len(policies) == 1 and isinstance(policies[0], dict):
            settings = policies[0].get('verified_settings')
            if (policies[0].get('authentication_type') == 'Managed' and isinstance(settings, dict)
                    and settings.get('minimumLength') == 14 and settings.get('complexity') is True
                    and settings.get('lockoutThreshold') == 10):
                return ("A new Entra identity has a 14-character minimum, complexity enabled, and a lockout threshold of 10.\n"
                        "A weak or guessed password may be harder to use.\n"
                        "That could reduce unwanted access to the person's account.")
    if (check_id == 'azure.cis.agentless_discovery_kubernetes_component_status'
            and finding['status'] == 'PASS' and evidence.get('cluster_count') == 1):
        plans = evidence.get('observed_enabled_plans')
        if (isinstance(plans, list) and len(plans) == 1 and isinstance(plans[0], dict)
                and isinstance(plans[0].get('enabled_plans'), list) and 'Containers' in plans[0]['enabled_plans']):
            return ('An AKS cluster has AgentlessDiscoveryForKubernetes enabled under the Containers plan.\n'
                    'Defender may discover cluster assets without a node agent.\n'
                    'The team could find exposed workloads sooner.')
    if (check_id == 'azure.gap.postgres_sql_server_encrypted_at_rest_using_cmk'
            and evidence.get('encryption_type') == 'AzureKeyVault' and evidence.get('key_approved') is True
            and isinstance(evidence.get('key_uri'), str) and isinstance(evidence.get('assigned_identity'), str)):
        if finding['status'] == 'FAIL' and evidence.get('identity_attached') is False:
            return ('A PostgreSQL server names an approved Key Vault key, but its assigned identity is not attached.\n'
                    'It may be unable to use that key.\n'
                    'Database data may lack the intended customer-key protection.')
        if finding['status'] == 'PASS' and evidence.get('identity_attached') is True:
            return ('A PostgreSQL server names an approved Key Vault key and has the assigned identity attached.\n'
                    'It may use that customer key for stored data.\n'
                    'The owner may control access to the key protecting database data.')
    if check_id == 'azure.gap.compute_vm_scale_set_endpoint_protection_solution_installed':
        groups = evidence.get('outcomes')
        if isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict):
            outcomes = groups[0].get('outcomes')
            if isinstance(outcomes, list) and len(outcomes) == 1 and isinstance(outcomes[0], dict):
                leaf = outcomes[0]
                if finding['status'] == 'FAIL' and leaf.get('status') == 'FAIL' and leaf.get('endpoint_agent_installed') is False:
                    return ('A VM scale set instance has no endpoint protection agent installed.\n'
                            'Threats on that instance may be harder to detect.\n'
                            "People's data or service may face more risk.")
                if finding['status'] == 'PASS' and leaf.get('status') == 'PASS' and leaf.get('endpoint_agent_installed') is True:
                    return ('A VM scale set instance has its endpoint protection agent installed.\n'
                            'The agent may detect harmful activity.\n'
                            "The team could protect users' data or service sooner.")
    if check_id == 'azure.gap.iam_user_with_read_permission_on_subscription_mfa_enabled' and finding['status'] == 'PASS':
        groups = evidence.get('outcomes')
        if isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict):
            outcomes = groups[0].get('outcomes')
            if (isinstance(outcomes, list) and len(outcomes) == 2 and all(isinstance(value, dict) and
                    value.get('mfa_required') is True and value.get('allowed_path_count') == 1 for value in outcomes)
                    and {value.get('context_id') for value in outcomes} == {'browser', 'cli'}):
                return ('A subscription reader must use MFA for browser and CLI sign-ins.\n'
                        'A stolen password alone may not let someone sign in.\n'
                        'That could protect data the reader can access.')
    if check_id == 'azure.other.ml_download_audit':
        recorded, missing = evidence.get('recorded_download_count'), evidence.get('unrecorded_download_count')
        if type(recorded) is int and type(missing) is int and recorded + missing > 0:
            if finding['status'] == 'FAIL' and missing > 0:
                return ('An ML download has no matching audit record after the allowed delay.\n'
                        'The team may miss who took a file.\n'
                        'They could struggle to trace unwanted data access.')
            if finding['status'] == 'PASS' and missing == 0 and recorded > 0:
                return ('An ML download has a matching audit record in the approved destination.\n'
                        'The team may trace who took a file.\n'
                        'That could help them review unusual data access.')
    if (check_id == 'azure.other.diagnostic_destination_alert' and finding['status'] == 'PASS'
            and type(evidence.get('control_test_count')) is int and evidence['control_test_count'] > 0
            and evidence.get('redirection_prevented_count') == evidence['control_test_count']
            and type(evidence.get('delivered_case_count')) is int and evidence['delivered_case_count'] > 0):
        return ('Recorded diagnostic redirection attempts did not take effect, and related alerts were delivered.\n'
                'Unwanted destination changes may be stopped and reported.\n'
                'The team may keep logs available for review.')
    if check_id == 'azure.other.retention_change_alert':
        if (finding['status'] == 'FAIL' and evidence.get('reason') ==
                'Complete definitions prove no enabled actionable alert for a required operation/scope/status'):
            return ('No enabled alert covers the required retention change event.\n'
                    'A similar change may lack a timely notice.\n'
                    'The team could miss an attempt to erase logs.')
        if (finding['status'] == 'PASS' and evidence.get('required_case_count') == 1
                and evidence.get('delivered_case_count') == 1 and evidence.get('missed_case_count') == 0):
            return ('One retention change event delivered an alert on time.\n'
                    'A similar change may warn the team.\n'
                    'They could respond sooner to a threat to stored logs.')
        if (finding['status'] == 'FAIL' and evidence.get('required_case_count') == 1
                and evidence.get('delivered_case_count') == 0 and evidence.get('missed_case_count') == 1):
            return ('One retention change event had no timely alert delivery.\n'
                    'A similar change may go unnoticed.\n'
                    'The team could respond later to a threat to stored logs.')
    if check_id == 'azure.gap.compute_vm_image_builder_uses_private_link':
        facts = evidence.get('observed_pass_facts' if finding['status'] == 'PASS' else 'observed_fail_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict) and isinstance(facts[0].get('configured_subnet'), str):
            fact = facts[0]
            if finding['status'] == 'FAIL' and fact.get('reason') == 'subnet outside approved set':
                return ('An image template uses a build subnet outside the approved list.\n'
                        'Build traffic may leave the intended network.\n'
                        'Code or secrets used in builds may have less network isolation.')
            if (finding['status'] == 'PASS' and fact.get('semantics') ==
                    'Approved isolated build subnet signal; dependency Private Link paths unverified'):
                return ('An image template uses an approved isolated build subnet.\n'
                        'Build traffic may stay within the intended network.\n'
                        'Code or secrets used in builds may have more network isolation.')
    if check_id == 'azure.gap.network_subnet_protected_by_firewall' and finding['status'] == 'PASS':
        routes = evidence.get('approved_firewall_routes')
        if (isinstance(routes, list) and routes and len(routes) == evidence.get('route_count')
                and all(isinstance(route, (list, tuple)) and len(route) == 3 and isinstance(route[2], str)
                        for route in routes)):
            return ("The subnet's recorded Internet routes point to approved Azure Firewalls.\n"
                    'Outbound traffic may pass through those firewalls.\n'
                    'Their rules could help protect apps and data on this subnet.')
    if check_id == 'azure.cis.private_endpoint_should_mariadb_servers':
        facts = evidence.get('observed_pass_facts' if finding['status'] == 'PASS' else 'observed_fail_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            fact = facts[0]
            if finding['status'] == 'FAIL' and fact.get('approved_private_endpoint_count') == 0:
                return ('No approved private endpoint is recorded for a MariaDB server.\n'
                        'Clients may lack the intended private path to it.\n'
                        'People may have trouble reaching their database data.')
            if (finding['status'] == 'PASS' and type(fact.get('approved_private_endpoint_count')) is int
                    and fact['approved_private_endpoint_count'] > 0 and fact.get('public_network_access') == 'Disabled'):
                return ('A MariaDB server has an approved private endpoint and public network access disabled.\n'
                        'Clients may use its private path.\n'
                        'Their database traffic may stay within the connected network.')
    facts = evidence.get('observed_pass_facts')
    if finding['status'] == 'PASS' and isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
        fact = facts[0]
        if (check_id == 'azure.other.monitor_dashboard_access' and type(fact.get('approved_viewer_count')) is int
                and fact.get('public_share_enabled') is False):
            return (f"A sensitive dashboard has {fact['approved_viewer_count']} approved viewer and public sharing disabled.\n"
                    'Other users may be unable to open it.\n'
                    'That could keep dashboard data from unwanted readers.')
        if check_id == 'azure.other.vault_key_approved_algorithm':
            versions = fact.get('approved_versions')
            if isinstance(versions, list) and len(versions) == 1 and isinstance(versions[0], dict):
                version = versions[0]
                if version.get('key_type') == 'EC' and version.get('curve') == 'P-256' and version.get('origin') == 'generated':
                    return ('An enabled Key Vault key version uses a generated EC P-256 key.\n'
                            'Data protected with it may use the approved curve.\n'
                            'That could make stored data harder to read without the key.')
        if (check_id == 'azure.other.vnet_peering_allowlist' and isinstance(fact.get('approved_peer_targets'), list)
                and len(fact['approved_peer_targets']) == 1 and evidence.get('enforced_deny_policy') is True):
            return ('A VNet peers with one approved VNet, and an enforced policy denies unapproved peers.\n'
                    'New peer requests outside the approved list may be blocked.\n'
                    "That could keep data paths within the team's approved networks.")
    facts = evidence.get('observed_pass_facts')
    if finding['status'] == 'PASS' and isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
        fact = facts[0]
        if (check_id == 'azure.cis.key_vaults_store_secrets' and fact.get('storage') == 'key_vault'
                and fact.get('resolution_status') == 'Resolved' and isinstance(fact.get('secret_id'), str)):
            return ('A workload secret reference points to Key Vault and resolves there.\n'
                    'The app may read the secret when needed.\n'
                    "Its value may stay out of the app's saved settings.")
        if (check_id == 'azure.other.function_invoke_rate_limit' and type(fact.get('calls')) is int
                and type(fact.get('renewal_period')) is int and fact.get('beyond_threshold_status') == 429
                and fact.get('policy_denial') is True):
            return (f"A function accepted {fact['calls']} calls in {fact['renewal_period']} seconds, then denied the next call with 429.\n"
                    'A busy caller may be slowed.\n'
                    'Other people may have more room to use the function.')
        if (check_id == 'azure.other.monitor_alert_ack_authorization'
                and fact.get('unapproved_principals') == [] and isinstance(fact.get('workflow_id'), str)):
            return ('No unapproved principal has effective alert acknowledgment access in this workflow.\n'
                    'Only approved responders may close its alerts.\n'
                    'The team may keep important alerts visible until an approved responder acts.')
        if (check_id == 'azure.other.storage_immutability' and fact.get('protection') == 'Locked'
                and type(fact.get('retention_days')) is int and type(fact.get('premature_changes_denied')) is int
                and fact['premature_changes_denied'] > 0):
            return (f"A locked container has {fact['retention_days']} days of retention and denied early changes.\n"
                    'Stored records may remain available during that period.\n'
                    'People may recover them after unwanted deletion attempts.')
        if check_id == 'azure.other.vault_old_secret_disabled' and fact.get('outcome') == 'denied' and isinstance(fact.get('version_id'), str):
            return ('A read of an old secret version was denied.\n'
                    'That version may be harder to reuse.\n'
                    "People's data may face less risk from an old leaked credential.")
    if finding['status'] == 'PASS' and check_id == 'azure.other.gateway_affinity_cookie_timeout':
        routes = evidence.get('measured_routes')
        if isinstance(routes, list) and len(routes) == 1 and isinstance(routes[0], dict):
            idle = routes[0].get('idle_seconds')
            if type(idle) is int and idle > 1800 and routes[0].get('same_session_accepted') is False:
                return (f'A gateway affinity route rejected the same session after {idle} idle seconds.\n'
                        'Old routing affinity may stop being reused.\n'
                        'People may reach an available backend sooner.')
    if finding['status'] == 'PASS' and check_id == 'azure.other.gateway_client_rate_limit':
        thresholds = evidence.get('qualifying_thresholds')
        seconds = evidence.get('measured_block_seconds')
        if (evidence.get('sliding_five_minute_limit_enforced') is True
                and isinstance(thresholds, list) and len(thresholds) == 1 and type(thresholds[0]) is int
                and type(seconds) is int and seconds >= 60):
            return (f'A gateway enforced a {thresholds[0]} request limit over five minutes.\n'
                    f'High-rate clients may be blocked for at least {seconds} seconds.\n'
                    'Other people may have more room to use the service.')
    if finding['status'] == 'PASS' and check_id == 'azure.other.gateway_server_header_rewrite':
        paths = evidence.get('sampled_paths')
        if isinstance(paths, list) and len(paths) == 1 and isinstance(paths[0], dict) and paths[0].get('server_header') == 'lb':
            return ('A gateway response sample shows the Server header set to lb.\n'
                    'Callers may see fewer backend details.\n'
                    'That could give outsiders less information about the service.')
    if finding['status'] == 'PASS' and check_id == 'azure.other.gateway_throttle_log_alert':
        delays = evidence.get('correlated_log_delays_seconds')
        if isinstance(delays, list) and len(delays) == 1 and type(delays[0]) in (int, float) and 0 <= delays[0] <= 300:
            return (f'A throttled gateway request appeared in logs after {delays[0]:g} seconds.\n'
                    'The team may find similar blocked requests in time.\n'
                    'They could respond sooner to unusual traffic.')
    if finding['status'] == 'PASS' and check_id == 'azure.other.lb_certificate_auto_renew':
        delays = evidence.get('new_version_served_delays_seconds')
        if (evidence.get('served_within_24_hours') is True and isinstance(delays, list) and len(delays) == 1
                and type(delays[0]) in (int, float) and 0 <= delays[0] <= 86400):
            return ('A new gateway certificate version was served within 24 hours of its renewal trigger.\n'
                    'The service may avoid using an expiring certificate.\n'
                    'People may have fewer connection failures.')
    if (finding['status'] == 'PASS' and check_id == 'azure.other.ml_public_access_exception'
            and evidence.get('public_ip_enabled') is True and evidence.get('classification') == 'non_sensitive'
            and evidence.get('current_approved_exception') is True and evidence.get('effective_ingress_paths_compliant') is True):
        return ('Non-sensitive ML compute has public IP access under a current approved exception.\n'
                'Outside requests may use its reviewed network paths.\n'
                'The team may keep that access within its approved limits.')
    if (finding['status'] == 'PASS' and check_id in ('azure.other.ml_sensitive_subnet_allowlist', 'azure.other.ml_subnet_baseline')
            and isinstance(evidence.get('subnet_id'), str) and isinstance(evidence.get('network_security_group_id'), str)
            and isinstance(evidence.get('required_control_names'), list) and evidence['required_control_names']
            and evidence.get('effective_controls_compliant') is True):
        if (check_id == 'azure.other.ml_sensitive_subnet_allowlist' and evidence.get('classification') == 'sensitive'
                and evidence.get('sensitive_subnet_approved') is True):
            return ('Sensitive ML compute uses an approved subnet with an attached network security group.\n'
                    'Its required network controls may shape incoming traffic.\n'
                    'That could help keep sensitive work within approved paths.')
        if check_id == 'azure.other.ml_subnet_baseline' and evidence.get('classification') == 'non_sensitive':
            return ('ML compute uses a subnet with an attached network security group and approved controls.\n'
                    "Its traffic may follow the team's network rules.\n"
                    'That could reduce unwanted paths to the workload.')
    if check_id == 'azure.gap.asset_inventory_required_metadata':
        facts = evidence.get('metadata_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            fact = facts[0]
            required, missing = fact.get('required_tag_keys'), fact.get('missing_tag_keys')
            if isinstance(required, list) and 'owner' in required and isinstance(missing, list):
                if finding['status'] == 'FAIL' and 'owner' in missing:
                    return ('A resource inventory entry has no owner tag.\n'
                            'The team may not know who owns it.\n'
                            'A problem with its data could take longer to resolve.')
                if finding['status'] == 'PASS' and not missing:
                    return ('A resource inventory entry has its required owner tag.\n'
                            'The team may find who is responsible for it.\n'
                            'They could resolve data or service problems sooner.')
    if check_id == 'azure.gap.audit_diagnostic_setting':
        facts = evidence.get('diagnostic_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            fact = facts[0]
            required, missing = fact.get('required_categories'), fact.get('missing_categories')
            if isinstance(required, list) and 'audit' in required and isinstance(missing, list):
                if finding['status'] == 'FAIL' and 'audit' in missing:
                    return ("A resource's Audit logs are not routed to an approved sink.\n"
                            "Important activity may be missing from the team's logs.\n"
                            'They could take longer to understand a problem.')
                if finding['status'] == 'PASS' and not missing:
                    return ("A resource's required Audit logs are routed to an approved sink.\n"
                            'The team may see changes to that resource.\n'
                            'They could understand a problem sooner.')
    if check_id == 'azure.gap.sql_database_long_term_geo_redundant_backup_enabled':
        facts = evidence.get('ltr_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            redundancies = facts[0].get('backup_redundancies')
            if isinstance(redundancies, list) and len(redundancies) == 1:
                redundancy = redundancies[0]
                if finding['status'] == 'FAIL' and redundancy in ('Local', 'Zone'):
                    return (f'A SQL long-term backup uses {redundancy} storage redundancy.\n'
                            'A wider outage may leave fewer usable copies.\n'
                            'People could wait longer to recover database data.')
                if finding['status'] == 'PASS' and redundancy in ('Geo', 'GeoZone'):
                    return (f'A SQL long-term backup uses {redundancy} storage redundancy.\n'
                            'A copy may remain available after a local outage.\n'
                            'People could recover database data sooner.')
    review_subject = {
        'azure.cis.access_review_up_external_users_in_entra_privileged_identity_694482': 'external privileged user',
        'azure.cis.guest_users_reviewed_monthly_basis': 'guest user',
        'azure.cis.guest_users_reviewed_regular_basis': 'guest user',
        'azure.cis.non_privileged_role_assignments_periodically_reviewed': 'nonprivileged role assignment',
        'azure.cis.privileged_role_assignments_periodically_reviewed': 'privileged role assignment',
        'azure.cis.tenant_creator_role_assignments_periodically_reviewed': 'Tenant Creator role assignment',
    }
    count = evidence.get('reviewed_subject_count')
    if (finding['status'] == 'PASS' and check_id in review_subject and type(count) is int
            and count > 0 and count == evidence.get('applicable_subject_count')):
        verb = 'was' if count == 1 else 'were'
        noun = review_subject[check_id] + ('' if count == 1 else 's')
        return (f'{count} {noun} {verb} covered by completed access reviews.\n'
                'The team may spot access that should change.\n'
                'This could reduce continued access that people no longer need.')
    if check_id == 'azure.gap.capacity_usage_alerts' and finding['status'] == 'PASS':
        forecasts = evidence.get('observed_forecasts')
        if isinstance(forecasts, list) and len(forecasts) == 1 and isinstance(forecasts[0], dict):
            forecast = forecasts[0]
            if forecast.get('baseline_matches') is True and forecast.get('forecast_breached') is False:
                return ('The approved capacity baseline matches measured use, and the forecast stays within limits.\n'
                        'The component may have room for expected demand.\n'
                        'People may face fewer capacity slowdowns.')
            if (forecast.get('baseline_matches') is True and forecast.get('forecast_breached') is True
                    and forecast.get('change_initiated') is True):
                return ('The capacity forecast exceeded a limit, and a related change was started.\n'
                        'The team may add capacity before demand rises.\n'
                        'People may face fewer capacity slowdowns.')
    if check_id == 'azure.other.gateway_backend_health_alert' and finding['status'] == 'PASS':
        gateways = evidence.get('observed_gateways')
        if isinstance(gateways, list) and len(gateways) == 1 and isinstance(gateways[0], dict):
            crossing = gateways[0].get('threshold_crossings')
            if type(crossing) is int and crossing > 0 and gateways[0].get('timely_deliveries') == crossing:
                noun = 'drop triggered a' if crossing == 1 else 'drops triggered'
                alert = 'alert' if crossing == 1 else 'alerts'
                return (f'{crossing} gateway health {noun} timely delivered {alert}.\n'
                        'A similar drop may warn the team.\n'
                        'They could respond before users face long service problems.')
    guest_prefix = 'azure.gap.compute_vm_'
    if check_id.startswith(guest_prefix):
        guest_kind = check_id[len(guest_prefix):]
        if (finding['status'] == 'FAIL' and evidence.get('reason') == 'complete current inventory proves required assignment absent'
                and guest_kind in ('administrators_group_with_extra_accounts_windows', 'password_file_permissions_0644_linux')):
            return ('The required guest configuration assignment is absent from this VM.\n'
                    'Its local baseline may go unchecked.\n'
                    'The team could miss unsafe changes to the VM.')
        facts = evidence.get('baseline_facts')
        if isinstance(facts, list) and len(facts) == 1 and isinstance(facts[0], dict):
            fact = facts[0]
            violations = fact.get('violating_members')
            if (fact.get('kind') == 'administrators' and isinstance(violations, list)
                    and isinstance(fact.get('observed_members'), list)
                    and isinstance(fact.get('policy_members'), list)):
                count = len(violations)
                if guest_kind == 'administrators_group_with_extra_accounts_windows':
                    if finding['status'] == 'FAIL' and count > 0:
                        noun = 'member is' if count == 1 else 'members are'
                        return (f'{count} local Administrators group {noun} outside the approved list.\n'
                                'Those accounts may control the VM.\n'
                                'Their users could change or read data on it.')
                    if finding['status'] == 'PASS' and count == 0 and fact.get('compliance_status') == 'Compliant':
                        return ('All listed local Administrators group members are approved.\n'
                                'Local admin access may stay with those users.\n'
                                'That could reduce unwanted changes to VM data.')
                if guest_kind == 'administrators_group_with_no_specified_members_windows':
                    if finding['status'] == 'FAIL' and count > 0:
                        noun = 'Administrator is' if count == 1 else 'Administrators are'
                        return (f'{count} required local {noun} absent from the group.\n'
                                'Those people may be unable to manage the VM.\n'
                                'Others may wait longer for needed support.')
                    if finding['status'] == 'PASS' and count == 0 and fact.get('compliance_status') == 'Compliant':
                        return ('All required local Administrators are present in the group.\n'
                                'They may manage the VM when needed.\n'
                                'People may get support sooner when problems arise.')
                if guest_kind == 'administrators_group_with_specified_members_windows':
                    if finding['status'] == 'FAIL' and count > 0:
                        noun = 'member is' if count == 1 else 'members are'
                        return (f'{count} prohibited {noun} present in the local Administrators group.\n'
                                'Those accounts may control the VM.\n'
                                'Their users could change or read data on it.')
                    if finding['status'] == 'PASS' and count == 0 and fact.get('compliance_status') == 'Compliant':
                        return ('No prohibited member is present in the local Administrators group.\n'
                                'Those accounts may lack local admin access through this group.\n'
                                'That could reduce unwanted changes to VM data.')
            if (guest_kind == 'with_no_specified_certificates_in_trusted_root_windows'
                    and fact.get('kind') == 'trusted_root' and isinstance(fact.get('missing_thumbprints'), list)):
                count = len(fact['missing_thumbprints'])
                if finding['status'] == 'FAIL' and count > 0:
                    noun = 'certificate is' if count == 1 else 'certificates are'
                    return (f'{count} required {noun} absent from the VM trusted-root store.\n'
                            'Software needing that trust root may reject connections.\n'
                            'People could lose access to a service that uses it.')
                if finding['status'] == 'PASS' and count == 0 and fact.get('compliance_status') == 'Compliant':
                    return ('The required certificates are present in the VM trusted-root store.\n'
                            'Software using those trust roots may validate connections.\n'
                            'People may be able to use services that rely on them.')
            if guest_kind == 'password_file_permissions_0644_linux' and fact.get('kind') == 'passwd_permissions':
                mode = fact.get('observed_mode')
                if isinstance(mode, str) and re.fullmatch(r'0[0-7]{3}', mode):
                    if finding['status'] == 'FAIL' and mode != '0644':
                        return (f'The /etc/passwd file mode is {mode}, while the required mode is 0644.\n'
                                'Local tools may read it differently than expected.\n'
                                'People may have trouble using tools that need account records.')
                    if finding['status'] == 'PASS' and mode == '0644':
                        return ('The /etc/passwd file mode is 0644.\n'
                                'Local tools may read account records as expected.\n'
                                'People may have fewer account lookup problems.')
    if check_id in ('azure.other.gateway_vmss_autoscale', 'azure.other.snapshot_sharing_scope') and finding['status'] == 'PASS':
        results = evidence.get('results')
        leaf = results[0] if isinstance(results, list) and len(results) == 1 and isinstance(results[0], dict) else evidence
        if check_id == 'azure.other.gateway_vmss_autoscale':
            observations = leaf.get('scale_out_observations')
            if isinstance(observations, list) and len(observations) == 1 and isinstance(observations[0], dict):
                event = observations[0]
                before, after, seconds = (event.get('serving_instances_before'),
                                          event.get('serving_instances_after'), event.get('scale_out_seconds'))
                if (all(type(value) is int for value in (before, after, seconds))
                        and after > before and 0 <= seconds <= 300):
                    return (f'A gateway grew from {before} to {after} serving instances within {seconds} seconds of high demand.\n'
                            'More requests may have space to run.\n'
                            'People may see fewer slowdowns during a similar demand rise.')
        else:
            approved = leaf.get('approved_recipient_ids')
            granted = leaf.get('granted_recipient_ids')
            if (isinstance(approved, list) and isinstance(granted, list)
                    and all(recipient in approved for recipient in granted)
                    and leaf.get('current_unauthorized_test_denied') is True
                    and leaf.get('public_network_access') == 'Disabled'):
                return ('Snapshot grants go only to approved recipients, and an outside sharing test was denied.\n'
                        'Others may have a harder time using the tested sharing path.\n'
                        'This could reduce unintended access to saved data.')
    if check_id == 'azure.other.monitor_stream_auth' and finding['status'] == 'PASS':
        groups = evidence.get('outcomes')
        if isinstance(groups, list) and len(groups) == 1 and isinstance(groups[0], dict):
            outcomes = groups[0].get('outcomes')
            if isinstance(outcomes, list) and len(outcomes) == 1 and isinstance(outcomes[0], dict):
                leaf = outcomes[0]
                if all(leaf.get(key) is True for key in ('authorized_publisher_accepted',
                        'anonymous_publisher_rejected', 'wrong_type_publisher_rejected')):
                    return ('The stream accepted an approved publisher and rejected anonymous and wrong-type tests.\n'
                            'Unapproved senders may be unable to add data through that path.\n'
                            'This could help keep monitoring data trustworthy.')
    if check_id == 'azure.other.nsg_port_protocol_assignment':
        pairs = evidence.get('observed_service_pairs')
        if isinstance(pairs, list) and len(pairs) == 1 and isinstance(pairs[0], dict):
            pair = pairs[0]
            protocol, port, service = pair.get('protocol'), pair.get('port'), pair.get('measured_service')
            if (protocol in ('Tcp', 'Udp') and type(port) is int and 1 <= port <= 65535
                    and isinstance(service, str) and re.fullmatch(r'[A-Za-z0-9_-]+', service)):
                if finding['status'] == 'FAIL' and pair.get('assignment_matches') is False:
                    return (f'An exposed {protocol} port {port} path carries measured {service} traffic.\n'
                            'That service differs from the assigned port use.\n'
                            'The team may miss an unexpected service on a known port.')
                if finding['status'] == 'PASS' and pair.get('assignment_matches') is True:
                    return (f'An exposed {protocol} port {port} path carries measured {service} traffic, matching its assigned use.\n'
                            'The service on that port may be easier to identify.\n'
                            'The team could spot a later unexpected service sooner.')
    if (check_id == 'azure.other.gateway_api_cidr_allowlist'
            and evidence.get('outside_approved_ranges_empty') is False
            and isinstance(evidence.get('effective_paths'), list) and len(evidence['effective_paths']) == 1
            and isinstance(evidence.get('approved_cidrs'), list)):
        path = evidence['effective_paths'][0]
        if isinstance(path, dict) and path.get('policy_state') == 'Enabled' and path.get('policy_mode') == 'Prevention':
            rules = path.get('remote_addr_rules')
            if isinstance(rules, list) and rules and isinstance(rules[0], dict):
                first = rules[0]
                matches = first.get('remote_addr_matches')
                if isinstance(matches, list) and len(matches) == 1 and isinstance(matches[0], dict):
                    match = matches[0]
                    if isinstance(match.get('cidrs'), list):
                        if (finding['status'] == 'PASS' and path.get('decision') == 'PASS'
                                and first.get('action') == 'Block' and match.get('negated') is True
                                and match['cidrs'] == evidence['approved_cidrs']):
                            return ('An enabled gateway rule blocks source IPs outside the approved ranges.\n'
                                    'Requests from other ranges may stop at the gateway.\n'
                                    'This could reduce unwanted API traffic.')
                        if (finding['status'] == 'FAIL' and path.get('decision') == 'FAIL'
                                and first.get('action') == 'Allow' and match.get('negated') is False
                                and match.get('cidrs') == ['0.0.0.0/0']):
                            return ('An enabled gateway rule allows source IPs from all IPv4 ranges.\n'
                                    'Outside callers may send requests toward the API.\n'
                                    'The team could face more unwanted API traffic.')
    if (check_id == 'azure.other.runtime_public_ip' and finding['status'] == 'FAIL'
            and evidence.get('reason') == 'Explicit node public IP allocation'
            and isinstance(evidence.get('compute_ids'), list) and evidence['compute_ids']
            and all(isinstance(value, str) for value in evidence['compute_ids'])):
        return ('Sensitive ML compute has an explicit node public IP allocation.\n'
                'Outside hosts may send traffic toward that node.\n'
                'The team could face more unwanted connection attempts.')
    if check_id == 'azure.other.monitor_stream_auth' and finding['status'] == 'FAIL':
        outcomes = evidence.get('outcomes')
        if isinstance(outcomes, list) and len(outcomes) == 1 and isinstance(outcomes[0], dict):
            nested = outcomes[0].get('outcomes')
            if (isinstance(nested, list) and len(nested) == 1 and isinstance(nested[0], dict)
                    and nested[0].get('accepted_credential_kind') == 'anonymous'):
                return ('A monitoring stream accepted an anonymous publisher.\n'
                        'Someone without a named credential may send data to it.\n'
                        "That could make the team's monitoring data less trustworthy.")
    if check_id == 'azure.other.nsg_port_protocol_assignment' and finding['status'] == 'PASS' and evidence.get('exposed_paths') == 0:
        return ('No exposed NSG paths were recorded.\n'
                'No service and port pair is exposed on those paths.\n'
                'The team may have fewer open services to manage.')
    if check_id == 'azure.other.region_allowlist':
        locations = evidence.get('observed_locations')
        approved = evidence.get('approved_regions')
        if isinstance(locations, list) and len(locations) == 1 and isinstance(locations[0], dict) and isinstance(approved, list):
            location = locations[0].get('location')
            if isinstance(location, str) and location.isalnum():
                if finding['status'] == 'FAIL' and location not in approved:
                    return (f'A resource is in {location}, outside the approved regions.\n'
                            'Its data or operations may use that region.\n'
                            'This could affect where the team expects them to stay.')
                if (finding['status'] == 'PASS' and location in approved and
                        all(evidence.get(key) is True for key in ('disallowed_deployment_denied',
                            'unauthorized_region_secret_denied', 'eu_operations_verified'))):
                    return (f'A resource is in approved region {location}, and regional controls passed.\n'
                            'New resources may stay within approved regions.\n'
                            'The team may have better control over where data and operations run.')
    if check_id in ('azure.other.backup_freshness_14_days', 'azure.other.backup_freshness_30_days'):
        items = evidence.get('observed_items')
        if isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict) and evidence.get('freshness_days') in (14, 30):
            item = items[0]
            point = item.get('last_recovery_point')
            if (isinstance(point, str) and len(point) >= 11 and point[4] == '-' and point[7] == '-' and point[10] == 'T'
                    and item.get('last_backup_status') == 'Completed' and item.get('protection_state') == 'Protected'):
                date = point[:10]
                if finding['status'] == 'FAIL' and item.get('outcome') == 'stale':
                    return (f"The last recovery point is dated {date}, older than {evidence['freshness_days']} days.\n"
                            'A restore may lose newer changes.\n'
                            'People may have to redo work or recover missing data.')
                if finding['status'] == 'PASS' and item.get('outcome') == 'fresh':
                    return (f'A completed backup has a recovery point dated {date}.\n'
                            'A restore may recover recent changes.\n'
                            'People may lose less work if this resource fails.')
    if check_id == 'azure.other.activity_alert' and all(type(evidence.get(key)) is int
            for key in ('required_case_count', 'delivered_case_count', 'missed_case_count')):
        if evidence['required_case_count'] == 1 and evidence['delivered_case_count'] + evidence['missed_case_count'] == 1:
            if finding['status'] == 'PASS' and evidence['delivered_case_count'] == 1:
                return ('One activity alert test delivered a notice on time.\n'
                        'A similar activity event may warn the team.\n'
                        'They could respond sooner to unwanted changes.')
            if finding['status'] == 'FAIL' and evidence['missed_case_count'] == 1:
                return ('One activity alert test had no timely delivery.\n'
                        'A similar activity event may go unnoticed.\n'
                        'The team could respond later to unwanted changes.')
    if check_id == 'azure.other.azure_activity_anomaly' and evidence.get('detector_count') == 2:
        delivered = evidence.get('delivered_detector_kinds')
        missed = evidence.get('missed_detector_kinds')
        expected = {'per_principal_log_query_volume', 'suspicious_api_requests'}
        if (isinstance(delivered, list) and isinstance(missed, list)
                and len(delivered) + len(missed) == 2 and set(delivered + missed) == expected):
            if finding['status'] == 'PASS' and not missed:
                return ('The suspicious API and per-user query detectors delivered alerts.\n'
                        'Similar activity may warn the team.\n'
                        'They could respond sooner to unwanted changes.')
            if finding['status'] == 'FAIL' and 'suspicious_api_requests' in missed:
                return ('The suspicious API request detector missed its alert.\n'
                        'Similar API activity may go unnoticed.\n'
                        'The team could respond later to unwanted changes.')
            if finding['status'] == 'FAIL' and 'per_principal_log_query_volume' in missed:
                return ('The per-user query detector missed its alert.\n'
                        'Similar query activity may go unnoticed.\n'
                        'The team could respond later to unwanted changes.')
    if check_id == 'azure.other.runtime_public_ip' and all(type(evidence.get(key)) is int
            for key in ('compute_count', 'public_path_count', 'private_path_count')):
        count = evidence['public_path_count']
        if evidence['compute_count'] > 0 and count + evidence['private_path_count'] == evidence['compute_count'] * 4:
            if finding['status'] == 'FAIL' and count > 0:
                noun = 'path has' if count == 1 else 'paths have'
                return (f'{count} ML network {noun} public IP access.\n'
                        'Outside hosts may send traffic toward those paths.\n'
                        'The team could face more unwanted connection attempts.')
            if finding['status'] == 'PASS' and count == 0:
                return (f"{evidence['private_path_count']} ML network paths have public IP access disabled.\n"
                        'Outside hosts may have fewer paths toward this compute.\n'
                        'That could reduce unwanted connection attempts.')
    if finding.get('check_id') == 'azure.claude.servicebus_namespace_network_restricted':
        for branch in _SERVICEBUS_NETWORK:
            if finding['status'] == branch['status'] and all(
                    key in evidence and type(evidence[key]) is type(value) and evidence[key] == value
                    for key, value in branch['required'].items()):
                return '\n'.join(branch['lines'])
    alert = _ACTIVITY_ALERTS.get(finding.get('check_id'))
    if alert and finding['status'] in {'PASS', 'FAIL'}:
        event, impact = alert['event'], alert['impact']
        if finding['status'] == 'FAIL' and evidence.get('reason') == 'no matching enabled activity log alert':
            return (f'No enabled activity log alert is recorded when {event}.\n'
                    'That event may go unnoticed.\n'
                    f'The team could review {impact} later than needed.')
        value = evidence.get('alert')
        if (finding['status'] == 'PASS' and isinstance(value, str)
                and '/providers/microsoft.insights/activitylogalerts/' in value.lower()):
            return (f'An enabled activity log alert is configured to run when {event}.\n'
                    'It may notify the team about that event.\n'
                    f'That could help them review {impact} sooner.')
    if finding['status'] == 'NOT_APPLICABLE':
        for variant in _NOT_APPLICABLE_VARIANTS.get(finding.get('check_id'), ()):
            if all(key in evidence and type(evidence[key]) is type(value) and evidence[key] == value
                   for key, value in variant['required'].items()):
                return '\n'.join(variant['lines'])
        applies_to, os_type = evidence.get('applies_to'), evidence.get('os_type')
        if applies_to in ('Windows', 'Linux') and os_type in ('Windows', 'Linux') and applies_to != os_type:
            return (f'This VM runs {os_type}.\n'
                    f'This setting applies to {applies_to} VMs.\n'
                    'Its users are outside the scope of that setting.')
        disk_state = evidence.get('disk_state')
        if applies_to in ('attached', 'unattached') and disk_state in ('Attached', 'Unattached') and applies_to != disk_state.lower():
            return (f'This disk is {disk_state.lower()}.\n'
                    f'This setting applies to {applies_to} disks.\n'
                    'Data on this disk is outside that setting’s scope.')
        lines = _NOT_APPLICABLE.get(evidence.get('reason'))
        return '\n'.join(lines) if lines else None
    if finding['status'] == 'UNKNOWN':
        if rule and rule.get('missing_reason') and evidence.get('reason') == rule['missing_reason']:
            return '\n'.join(rule['unknown'])
        for variant in rule.get('unknown_variants', ()) if rule else ():
            if all(key in evidence and type(evidence[key]) is type(value) and evidence[key] == value
                   for key, value in variant['required'].items()):
                return '\n'.join(variant['lines'])
        reason = evidence.get('reason') or _single_unknown_reason(evidence)
        effects = _UNKNOWN_SPECIFIC_EFFECTS.get(check_id) or _UNKNOWN_GROUP_EFFECTS.get(ROWS.get(check_id, {}).get('review_group'))
        if isinstance(reason, str) and reason.startswith('missing fact:'):
            path = reason.removeprefix('missing fact:').strip()
            first = _MISSING_FACT_LABELS.get(path, 'The record is missing a required value.')
            return '\n'.join([first, *effects]) if effects else (first + '\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.')
        if isinstance(reason, str):
            for prefix, ending in (('dependency incomplete or unavailable: ', 'is incomplete or unavailable.'),
                                   ('dependency not collected: ', 'was not collected.')):
                if reason.startswith(prefix):
                    label = _DEPENDENCY_LABELS.get(reason[len(prefix):])
                    if label:
                        first = f'The related {label} record {ending}'
                        return '\n'.join([first, *effects]) if effects else (first + '\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.')
            first = _INCOMPLETE['exact'].get(reason)
            if first is None:
                first = next((line for prefix, line in _INCOMPLETE['prefixes'].items()
                              if reason.startswith(prefix) and len(reason) > len(prefix)), None)
            if first:
                return '\n'.join([first, *effects]) if effects else (first + '\nThat leaves the resource condition unknown.\nThe team cannot tell whether this resource needs attention.')
        return None
    if not rule:
        return None
    status = finding['status'].lower()
    if status not in rule:
        return None
    for variant in rule.get(status + '_variants', ()):
        if all(key in evidence and type(evidence[key]) is type(value) and evidence[key] == value
               for key, value in variant['required'].items()) and all(
                   isinstance(evidence.get(key), list) and bool(evidence[key]) == (state == 'nonempty')
                   for key, state in variant.get('array_states', {}).items()):
            return '\n'.join(variant['lines'])
    array_state = rule.get(status + '_array_state')
    if array_state in ('empty', 'nonempty'):
        value = evidence.get(rule['field'])
        if not isinstance(value, list) or bool(value) != (array_state == 'nonempty'):
            return None
    else:
        if (status + '_value' not in rule or rule['field'] not in evidence
                or type(evidence.get(rule['field'])) is not type(rule[status + '_value'])
                or evidence[rule['field']] != rule[status + '_value']):
            return None
    if any(type(evidence.get(key)) is not type(value) or evidence[key] != value
           for key, value in rule.get('required', {}).items()):
        return None
    if rule['field'] == 'configured' and rule.get('configured_field'):
        from .facts import FIELD_SPECS
        spec = FIELD_SPECS.get(finding['check_id'])
        if (evidence.get('field') != rule.get('configured_field')
                or (spec is not None and rule['configured_field'] != spec['path'])):
            return None
    return '\n'.join(rule[status])


def _scalar_observation(check_id, evidence):
    from .facts import FIELD_SPECS
    spec = FIELD_SPECS.get(check_id)
    label = _SCALAR_LABELS.get(check_id)
    if not spec or not label or evidence.get('field') != spec['path']:
        return None
    value = evidence.get('configured')
    if type(value) is not spec['expected'] or value not in (spec['good'], spec['bad']):
        return None
    if isinstance(value, bool):
        enabled = not value if check_id == 'azure.aks.no_local_accounts' else value
        return f'{label} is {"enabled" if enabled else "disabled"}.'
    if check_id == 'azure.disk.entra_export_auth':
        return ('Disk exports require Microsoft Entra authentication.' if value == 'AzureActiveDirectory'
                else 'Disk exports do not require Microsoft Entra authentication.')
    return f'{label} is {value}.'


def _observation(finding):
    """Reuse exact native evidence interpreters before adding explanatory copy."""
    from .azure_review_observed_20261020 import observation as current_review
    selected = current_review(finding)
    if selected:
        return selected
    from .azure_ai_services_observed import observation as ai_services
    selected = ai_services(finding)
    if selected:
        return selected
    from .selected_content_observed import observation as selected_content
    selected = selected_content(finding)
    if selected:
        return selected
    from .azure_native_evidence_observations import evidence_summary as native
    observed = native(finding)
    if observed:
        return observed
    from .provider_scope_observed_evidence import provider_scope
    from .azure_bulk_observed_evidence import evidence_summary as bulk_pass
    from .azure_bulk_finding_summary import evidence_summary as bulk_fail
    from .azure_native_evidence_observations import _matches
    # The legacy bulk failure helper has an unguarded static-text fallback.
    # Its text is safe only after the exact reviewed native witness matches.
    bulk_failure = None
    if finding['status'] == 'FAIL' and any(_matches(finding['evidence'], shape)
            for shape in _BULK_FAILURE_SHAPES.get(finding['check_id'], ())):
        bulk_failure = bulk_fail(finding)
        if finding['check_id'] == 'azure_vault_3_7_1_2_532ecd2':
            outcomes = finding['evidence'].get('outcomes', [])
            if not any(isinstance(item, dict) and item.get('status') == 'FAIL'
                       and type(item.get('measured_rsa_modulus_bits')) is int
                       and 0 < item['measured_rsa_modulus_bits'] < 2048 for item in outcomes):
                bulk_failure = None
    observation = provider_scope(finding) or bulk_pass(finding) or bulk_failure
    if observation:
        return observation
    check_id = finding['check_id']
    evidence = finding['evidence']
    scalar = _scalar_observation(check_id, evidence)
    if scalar:
        return scalar
    if check_id == 'azure.storage.https_only' and type(evidence.get('supports_https_traffic_only')) is bool:
        return 'The storage account '+('requires' if evidence['supports_https_traffic_only'] else 'does not require')+' secure HTTPS transfer.'
    if check_id == 'azure.storage.no_blob_public_access' and type(evidence.get('allow_blob_public_access')) is bool:
        return 'The storage account '+('permits' if evidence['allow_blob_public_access'] else 'disables')+' anonymous Blob access as an account capability.'
    if check_id == 'azure.storage.minimum_tls' and evidence.get('minimum_tls_version') in {'TLS1_0', 'TLS1_1', 'TLS1_2', 'TLS1_3'}:
        return 'The storage minimum TLS version is '+evidence['minimum_tls_version'].replace('TLS', '').replace('_', '.')+'.'
    if check_id == 'azure.iam.review_owner_assignment':
        role = evidence.get('role_definition_id')
        if isinstance(role, str) and role:
            return ('The declared assignment grants the Owner role.' if role.rsplit('/',1)[-1].lower() == '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'
                    else 'The declared assignment grants a role other than Owner.')
    return None


def evidence_summary(finding):
    """Return concise observations only for evidence shapes understood here.

    The UI retains its separately typed per-check interpreters for other native
    evidence shapes and uses the same exact-ID purpose and limit records.
    """
    if not isinstance(finding, dict) or finding.get('provider') != 'azure':
        return None
    check_id = finding.get('check_id')
    if not isinstance(check_id, str) or check_id not in ROWS or not isinstance(finding.get('evidence'), dict):
        return None
    if finding.get('status') not in {'PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE'}:
        return None
    from .azure_long_semantic_evidence import evidence_summary as long_semantic
    specific = long_semantic(finding)
    if specific:
        return specific
    plain = _plain_observation(finding)
    if plain:
        return plain
    if finding['status'] in {'UNKNOWN', 'NOT_APPLICABLE'}:
        return None
    from .public_source_secret_observed_20261020 import observation as public_source
    grouped = public_source(finding)
    if grouped:
        return grouped
    observation = _observation(finding)
    native_impact = _NATIVE_IMPACTS.get(check_id, {}).get(finding['status'])
    if native_impact:
        first = native_impact.get('first') if isinstance(native_impact, dict) else None
        impact = native_impact['impact'] if isinstance(native_impact, dict) else native_impact
        from .azure_native_evidence_observations import evidence_summary as native
        if observation and observation == native(finding):
            return '\n'.join([first or observation, *impact])
        pattern = _BULK_IMPACT_PATTERNS.get(check_id, {}).get(finding['status'])
        if pattern and observation and re.fullmatch(pattern, observation):
            return '\n'.join([first or observation, *impact])
    return reviewed_explanation(check_id, observation, finding['status']) if observation else None
