"""Current key-age evidence retains exact captured-time decisions."""
from datetime import datetime
import math
import re


def _configuration_observation(finding):
    if not isinstance(finding, dict) or finding.get('provider') != 'azure' or finding.get('status') not in ('PASS', 'FAIL'):
        return None
    e = finding.get('evidence')
    if not isinstance(e, dict):
        return None
    cid, failed = finding.get('check_id'), finding['status'] == 'FAIL'
    edge_text = {'azure_application_gateway_11_5_1_1_1_f56bdc2': ('The assessed public resources declare their applicable DDoS and WAF protection.', 'Some public resources lack the required declared DDoS or WAF protection.'), 'azure_application_gateway_app_http_logs_enabled_2de0361': ('Application Gateways declare enabled HTTP access-log export to inventoried destinations.', 'Some Application Gateways have no enabled HTTP access-log export to an inventoried destination.'), 'azure.review.devops.visible_clone_urls_without_userinfo': ('Visible clone URLs returned for the selected Azure DevOps projects contain no user information.', 'A visible Azure DevOps clone URL contains user information; the value was redacted.')}
    if cid in edge_text:
        if (e.get('native_review_id') != cid or type(e.get('native_review_satisfied')) is not bool
                or e['native_review_satisfied'] == failed or e.get('runtime_protection') != 'not_tested'):
            return None
        return edge_text[cid][1 if failed else 0]
    native_text = {'azure.logging.aks_supported_log_categories_destination_declared': ('AKS declares destinations for all supported control-plane log categories.', 'Some supported AKS control-plane log categories have no enabled destination declaration.'), 'azure.logging.managed_hsm_audit_destination_declared': ('Managed HSM declares AuditEvent logging to Storage or Log Analytics.', 'Managed HSM has no enabled AuditEvent destination declaration to Storage or Log Analytics.'), 'azure.encryption.log_analytics_cluster_cmk_declared': ('The Log Analytics cluster declares a customer-managed key and managed identity.', 'The Log Analytics cluster lacks a customer-managed key reference or managed identity.'), 'azure.encryption.stream_analytics_job_storage_cmk_declared': ('The selected Stream Analytics storage account declares a customer-managed key and managed identity.', 'The selected Stream Analytics storage account lacks a customer-managed key reference or managed identity.')}
    if cid in native_text:
        if (e.get('native_declaration_id') != cid or type(e.get('native_declaration_satisfied')) is not bool
                or e['native_declaration_satisfied'] == failed or e.get('effective_access') != 'not_tested'):
            return None
        return native_text[cid][1 if failed else 0]
    if cid in ('azure.encryption.automation_cmk_declared', 'azure.logging.aci_log_analytics_declared'):
        if (e.get('criterion') != cid or type(e.get('configured')) is not bool
                or e['configured'] == failed or e.get('effective_access') != 'not_tested'):
            return None
        if cid == 'azure.encryption.automation_cmk_declared':
            if failed:
                return 'Automation lacks a complete customer-managed key reference or attached system identity.'
            if (e.get('key_source') != 'Microsoft.Keyvault'
                    or e.get('identity_type') not in ('SystemAssigned', 'SystemAssigned, UserAssigned')
                    or any(not isinstance(e.get(k), str) or not e[k] for k in ('vault_hostname', 'key_name', 'key_version'))):
                return None
            return 'Automation declares a customer-managed key reference and an attached system identity.'
        if failed:
            return 'The container group has no complete Log Analytics destination declaration.'
        if (not isinstance(e.get('workspace_customer_id'), str)
                or not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', e['workspace_customer_id'], re.I)
                or e['workspace_customer_id'].replace('-', '') == '0' * 32
                or e.get('log_type') not in ('ContainerInsights', 'ContainerInstanceLogs')):
            return None
        return 'The container group declares a Log Analytics workspace customer UUID and supported log type.'
    if cid == 'azure.review.managed_hsm.audit_storage_destination':
        configured = e.get('audit_storage_configured')
        destinations = e.get('storage_destination_references', [])
        if (e.get('criterion') != 'declared_audit_storage_destination' or type(configured) is not bool
                or configured == failed or not isinstance(destinations, list)
                or any(not isinstance(v, str) or not v for v in destinations)
                or bool(destinations) != configured):
            return None
        return ('AuditEvent logging is configured to an Azure Storage destination.' if configured
                else 'No enabled AuditEvent logging to Azure Storage is configured.')
    if cid != 'azure.network.acr_public_ip_ranges_restricted' or e.get('criterion') != 'declared_public_ipv4_union' or e.get('effective_access') != 'not_tested':
        return None
    pna, bypass = e.get('public_network_access'), e.get('trusted_service_bypass')
    if bypass not in ('None', 'AzureServices'):
        return None
    if pna == 'Disabled':
        return 'The registry declares public network access disabled.' if not failed and e.get('allows_all_ipv4') is not True else None
    if (pna != 'Enabled' or e.get('default_action') not in ('Allow', 'Deny')
            or type(e.get('allows_all_ipv4')) is not bool or e['allows_all_ipv4'] != failed
            or e['default_action'] == 'Allow' and not failed):
        return None
    if e['default_action'] == 'Deny':
        ranges = e.get('collapsed_ipv4_ranges')
        if not isinstance(ranges, list) or len(ranges) > 200 or any(not isinstance(v, str) for v in ranges):
            return None
        if ('0.0.0.0/0' in ranges) != failed:
            return None
    text = ("The registry's public endpoint allows every IPv4 address in its declared network rules." if failed
            else "Public IPv4 access is restricted by the registry's declared rules.")
    return text + (' Trusted Azure service bypass is enabled.' if bypass == 'AzureServices' else ' Trusted Azure service bypass is disabled.')


def observation(finding):
    configuration = _configuration_observation(finding)
    if configuration:
        return configuration
    if (not isinstance(finding, dict) or finding.get('provider') != 'azure'
            or finding.get('check_id') != 'azure.claude.storage_access_keys_rotated_90'
            or finding.get('status') not in ('PASS', 'FAIL')):
        return None
    e = finding.get('evidence')
    if not isinstance(e, dict) or e.get('time_source') != 'scan_capture' or e.get('threshold_seconds') != 7776000:
        return None
    seconds, timestamps = e.get('key_age_seconds'), e.get('key_creation_time')
    if not isinstance(seconds, dict) or not isinstance(timestamps, dict) or set(seconds) != {'key1', 'key2'} or set(timestamps) != set(seconds):
        return None
    try:
        now = datetime.fromisoformat(e['captured_at'].replace('Z', '+00:00'))
        if now.tzinfo is None:
            return None
        for key, value in seconds.items():
            then = datetime.fromisoformat(timestamps[key].replace('Z', '+00:00'))
            if (then.tzinfo is None or type(value) not in (int, float) or not math.isfinite(value)
                    or value < 0 or (now - then).total_seconds() != value):
                return None
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return None
    old = [key for key in ('key1', 'key2') if seconds[key] > 7776000]
    if bool(old) != (finding['status'] == 'FAIL'):
        return None
    if old:
        return 'Storage ' + ' and '.join(old) + (' is' if len(old) == 1 else ' are') + ' older than 90 days at collection.'
    return 'Both storage access keys were created within 90 days before collection.'
