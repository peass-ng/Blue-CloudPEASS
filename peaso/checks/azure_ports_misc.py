"""Small reviewed service declarations and precise reuse of current native predicates."""
from . import register, result
from .facts import field_check, get, optional, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {
    'keyvault_certificate_validity_period_less_equal_12_months': 'azure.claude.keyvault_certificate_validity_12_months',
    'web_application_firewall_policy_request_body_inspection_enabled': 'azure.claude.waf_policy_request_body_inspection',
    'web_application_firewall_policy_bot_protection_enabled': 'azure.claude.waf_policy_bot_protection',
}


def scalar(query, kind, path, good, bad, title):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    field_check(cid, 'azure', kind, path, good, bad, title, expected=type(good))


scalar('application_gateway_http2_enabled', 'application_gateway', 'properties.enableHttp2', True, False, 'Application Gateway declares HTTP/2 enabled')
scalar('batch_account_encrypted_with_cmk', 'batch_account', 'properties.encryption.keySource', 'Microsoft.KeyVault', 'Microsoft.Batch', 'Batch account selects Key Vault key source')
scalar('apimanagement_service_client_certificate_enabled', 'api_management', 'properties.enableClientCertificate', True, False, 'API Management declares the client-certificate enablement flag')


cid = 'azure.port.batch_account_identity_provider_enabled'
CHECK_IDS.append(cid); SOURCE_QUERIES['batch_account_identity_provider_enabled'] = cid
@register(cid, 'azure', 'hardening', 'batch_account', 'Batch account declares a non-None managed identity', 'medium', 'IA-5', 'Review the identity type and required workload permissions; no grants or key values are inspected.')
def batch_identity(item, index):
    kind = get(item, 'identity.type', str)
    if kind not in ('None', 'SystemAssigned', 'UserAssigned', 'SystemAssigned, UserAssigned'):
        raise Unavailable('Unrecognized Batch identity type')
    return result(kind == 'None', identity_type=kind)
CASES[cid] = {'pass': {'identity': {'type': 'SystemAssigned'}}, 'fail': {'identity': {'type': 'None'}}}


cid = 'azure.port.application_insights_linked_to_log_analytics_workspace'
CHECK_IDS.append(cid); SOURCE_QUERIES['application_insights_linked_to_log_analytics_workspace'] = cid
@register(cid, 'azure', 'hardening', 'application_insights', 'Application Insights declares a Log Analytics workspace reference', 'medium', 'AU-12', 'Review the workspace association, retention and access separately; no logs or telemetry are queried.')
def workspace(item, index):
    kind = get(item, 'type', str)
    if kind.casefold() != 'microsoft.insights/components':
        raise Unavailable('Unexpected Application Insights provider type')
    value = optional(get(item, 'properties', dict), 'WorkspaceResourceId', None)
    if value is not None and (not isinstance(value, str) or not value):
        raise Unavailable('Malformed workspace reference')
    return result(value is None, workspace_id=value, semantics='Declaration only; no referenced workspace permission or telemetry delivery claim')
CASES[cid] = {'pass': {'type': 'microsoft.insights/components', 'properties': {'WorkspaceResourceId': '/subscriptions/sub/resourceGroups/g/providers/Microsoft.OperationalInsights/workspaces/w'}}, 'fail': {'type': 'microsoft.insights/components', 'properties': {'WorkspaceResourceId': None}}}


cid = 'azure.port.application_gateway_min_tls_1_2'
CHECK_IDS.append(cid); SOURCE_QUERIES['application_gateway_min_tls_1_2'] = cid
@register(cid, 'azure', 'hardening', 'application_gateway', 'Application Gateway explicit minimum TLS is1.2 or1.3', 'medium', 'SC-8', 'Review the explicit TLS policy or capture the authoritative predefined/default policy; no TLS connection is probed.')
def gateway_tls(item, index):
    policy = get(item, 'properties.sslPolicy')
    if policy is None:
        raise Unavailable('Default TLS policy/version not captured; source null assumption cannot certify its minimum')
    minimum = get(policy, 'minProtocolVersion', str)
    if minimum not in ('TLSv1_0', 'TLSv1_1', 'TLSv1_2', 'TLSv1_3'):
        raise Unavailable('Unrecognized TLS policy minimum')
    return result(minimum not in ('TLSv1_2', 'TLSv1_3'), minimum_protocol=minimum, semantics='Explicit minimum declaration; default/predefined policy context is required separately')
CASES[cid] = {'pass': {'properties': {'sslPolicy': {'minProtocolVersion': 'TLSv1_3'}}}, 'fail': {'properties': {'sslPolicy': {'minProtocolVersion': 'TLSv1_1'}}}}
