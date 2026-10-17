"""App Service scopes retain exact source kind selectors and declaration semantics."""
from . import register, result
from .facts import get, optional, list_of_objects, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {}
APP = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.Web/sites/site'


def port(query, title, control='CM-6'):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', 'app_service', title, 'medium', control,
                    'Review the exact declared App Service metadata; flags and diagnostic declarations do not prove request enforcement or log delivery.', dependencies=['app_service'])


def _web(item):
    # Primary plugin adapter excludes EXACT functionapp, not comma-kind tokens.
    # Keep this source boundary; functionapp,linux is not silently merged out.
    return get(item, 'kind', str) != 'functionapp'


@port('appservice_web_app_incoming_client_cert_on', 'Source-selected App Service site enables client-certificate flag', 'IA-2')
def client_cert(item, index):
    if not _web(item): return 'NOT_APPLICABLE', {'reason': 'Pinned web table excludes exact functionapp kind'}
    enabled = get(item, 'properties.clientCertEnabled', bool)
    return result(not enabled, client_certificate_flag=enabled, semantics='Flag only; clientCertMode/exclusions and application authorization remain separate')
CASES[SOURCE_QUERIES['appservice_web_app_incoming_client_cert_on']] = {'pass': {'kind': 'app', 'properties': {'clientCertEnabled': True}}, 'fail': {'kind': 'app', 'properties': {'clientCertEnabled': False}}}


@port('appservice_ftp_deployment_disabled', 'App Service web/function union excludes unencrypted FTP deployment', 'SC-8')
def ftp(item, index):
    get(item, 'kind', str)
    state = get(item, 'configuration.properties.ftpsState', str)
    if state not in ('AllAllowed', 'FtpsOnly', 'Disabled'):
        raise Unavailable('Unrecognized App Service FTPS mode')
    return result(state == 'AllAllowed', ftps_state=state, semantics='Pinned source allows FTPS-only and Disabled; does not require all deployment endpoints disabled')
CASES[SOURCE_QUERIES['appservice_ftp_deployment_disabled']] = {'pass': {'kind': 'functionapp', 'configuration': {'properties': {'ftpsState': 'FtpsOnly'}}}, 'fail': {'kind': 'app', 'configuration': {'properties': {'ftpsState': 'AllAllowed'}}}}


@port('appservice_web_app_remote_debugging_disabled', 'Source-selected non-api site disables remote debugging')
def debugging(item, index):
    if not _web(item) or get(item, 'kind', str) == 'api':
        return 'NOT_APPLICABLE', {'reason': 'Pinned table/CASE excludes exact functionapp and api kinds'}
    enabled = get(item, 'configuration.properties.remoteDebuggingEnabled', bool)
    return result(enabled, remote_debugging_enabled=enabled)
CASES[SOURCE_QUERIES['appservice_web_app_remote_debugging_disabled']] = {'pass': {'kind': 'app', 'configuration': {'properties': {'remoteDebuggingEnabled': False}}}, 'fail': {'kind': 'app', 'configuration': {'properties': {'remoteDebuggingEnabled': True}}}}


@port('appservice_web_app_diagnostic_log_category_http_log_enabled', 'Source-selected site explicitly enables AppServiceHTTPLogs diagnostic category', 'AU-12')
def http_diagnostics(item, index):
    if not _web(item): return 'NOT_APPLICABLE', {'reason': 'Pinned web table excludes exact functionapp'}
    rid = get(item, 'id', str)
    settings = list_of_objects(get(item, 'diagnosticSettings', list))
    matches = []
    for setting in settings:
        identity = get(setting, 'id', str)
        if not identity.casefold().startswith((rid + '/providers/Microsoft.Insights/diagnosticSettings/').casefold()):
            raise Unavailable('Foreign App Service diagnostic setting')
        for log in list_of_objects(get(setting, 'properties.logs', list)):
            enabled = get(log, 'enabled', bool)
            category = optional(log, 'category', None)
            if category is not None and not isinstance(category, str):
                raise Unavailable('Malformed diagnostic category')
            if enabled and category == 'AppServiceHTTPLogs': matches.append(identity)
    return result(not matches, matching_setting_ids=sorted(set(matches)), semantics='Exact category declaration; allLogs/audit categoryGroup alone differs and delivery is not tested')
CASES[SOURCE_QUERIES['appservice_web_app_diagnostic_log_category_http_log_enabled']] = {'pass': {'id': APP, 'kind': 'app', 'diagnosticSettings': [{'id': APP + '/providers/Microsoft.Insights/diagnosticSettings/log', 'properties': {'logs': [{'category': 'AppServiceHTTPLogs', 'enabled': True}]}}]}, 'fail': {'id': APP, 'kind': 'app', 'diagnosticSettings': []}}


@port('prowler_app_auth_platform_enabled', 'App-prefixed site has authentication platform enabled', 'IA-2')
def auth_platform(item, index):
    if not get(item, 'kind', str).startswith('app'):
        return 'NOT_APPLICABLE', {'reason': 'Pinned Prowler service selects app-prefixed site kind only'}
    enabled = get(item, 'authSettingsV2.properties.platform.enabled', bool)
    return result(not enabled, authentication_platform_enabled=enabled, semantics='Exact platform module flag; requireAuthentication, provider configuration and actual request authorization are separate')
CASES[SOURCE_QUERIES['prowler_app_auth_platform_enabled']] = {'pass': {'kind': 'app,linux', 'authSettingsV2': {'properties': {'platform': {'enabled': True}}}}, 'fail': {'kind': 'app', 'authSettingsV2': {'properties': {'platform': {'enabled': False}}}}}
