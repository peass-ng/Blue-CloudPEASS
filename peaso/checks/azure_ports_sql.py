"""SQL parent-target predicates use authoritative child identities and field coverage."""
import ipaddress
import re
from . import register, result
from .facts import get, list_of_objects, Unavailable
from .fixtures import CASES

CHECK_IDS = []
SOURCE_QUERIES = {'sql_db_public_network_access_disabled': 'azure.sql.no_public_network'}
SERVER = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.Sql/servers/server'


def port(query, title, control='CM-6'):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', 'sql_server', title, 'medium', control,
                    'Review the declared SQL metadata and intended security baseline; collection does not query databases or test runtime access.', dependencies=['sql_server'])


def _server(item):
    rid = get(item, 'id', str)
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Sql/servers/[^/]+', rid, re.I):
        raise Unavailable('Malformed SQL server ARM identity')
    return rid


def _children(item, field, component):
    rid = _server(item)
    rows = list_of_objects(get(item, field, list))
    ids = []
    for row in rows:
        identity = get(row, 'id', str)
        prefix = (rid + '/' + component).casefold()
        documented_default = component == 'securityAlertPolicies' and identity.casefold() == prefix and get(row, 'name', str).casefold() == 'default'
        if not identity.casefold().startswith(prefix + '/') and not documented_default:
            raise Unavailable('Foreign SQL child identity')
        ids.append(identity.casefold())
    if len(ids) != len(set(ids)):
        raise Unavailable('Ambiguous duplicate SQL child metadata')
    return rows


@port('sql_db_active_directory_admin_configured', 'SQL server has the documented Microsoft Entra administrator', 'IA-2')
def administrator(item, index):
    rows = _children(item, 'serverAdministrators', 'administrators')
    for row in rows:
        if get(row, 'properties.administratorType', str) != 'ActiveDirectory':
            raise Unavailable('Unrecognized SQL administrator type')
    return result(not rows, administrator_count=len(rows), semantics='Administrator existence only; Entra-only login and database role grants are separate')
CASES[SOURCE_QUERIES['sql_db_active_directory_admin_configured']] = {'pass': {'id': SERVER, 'serverAdministrators': [{'id': SERVER + '/administrators/ActiveDirectory', 'properties': {'administratorType': 'ActiveDirectory'}}]}, 'fail': {'id': SERVER, 'serverAdministrators': []}}


@port('sql_server_tde_protector_cmk_encrypted', 'SQL server current protector declares a customer-managed key', 'SC-28')
def protector(item, index):
    rid = _server(item)
    row = get(item, 'encryptionProtector', dict)
    if get(row, 'id', str).casefold() != (rid + '/encryptionProtector/current').casefold():
        raise Unavailable('Foreign or noncurrent SQL encryption protector')
    kind = get(row, 'kind', str)
    key_type = get(row, 'properties.serverKeyType', str)
    if (kind, key_type) not in (('servicemanaged', 'ServiceManaged'), ('azurekeyvault', 'AzureKeyVault')):
        raise Unavailable('Unrecognized or inconsistent encryption protector kind/key type')
    return result(kind == 'servicemanaged', kind=kind, key_type=key_type, semantics='Current protector declaration only; key access and per-database TDE state are separate')
CASES[SOURCE_QUERIES['sql_server_tde_protector_cmk_encrypted']] = {'pass': {'id': SERVER, 'encryptionProtector': {'id': SERVER + '/encryptionProtector/current', 'kind': 'azurekeyvault', 'properties': {'serverKeyType': 'AzureKeyVault'}}}, 'fail': {'id': SERVER, 'encryptionProtector': {'id': SERVER + '/encryptionProtector/current', 'kind': 'servicemanaged', 'properties': {'serverKeyType': 'ServiceManaged'}}}}


@port('sql_database_allow_internet_access', 'SQL server firewall excludes both all-address and Allow Azure services sentinel rules', 'SC-7')
def firewall(item, index):
    rows = _children(item, 'firewallRules', 'firewallRules')
    bad = []
    for row in rows:
        start, end = get(row, 'properties.startIpAddress', str), get(row, 'properties.endIpAddress', str)
        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
        if first.version != 4 or last.version != 4 or int(first) > int(last):
            raise Unavailable('Malformed SQL firewall address interval')
        if (start, end) in (('0.0.0.0', '0.0.0.0'), ('0.0.0.0', '255.255.255.255')):
            bad.append(row['id'])
    return result(bool(bad), matching_firewall_ids=bad, semantics='Two exact pinned sentinel declarations; Azure services sentinel is distinct from internet-wide reachability')
CASES[SOURCE_QUERIES['sql_database_allow_internet_access']] = {'pass': {'id': SERVER, 'firewallRules': [{'id': SERVER + '/firewallRules/rule', 'properties': {'startIpAddress': '10.0.0.1', 'endIpAddress': '10.0.0.1'}}]}, 'fail': {'id': SERVER, 'firewallRules': [{'id': SERVER + '/firewallRules/rule', 'properties': {'startIpAddress': '0.0.0.0', 'endIpAddress': '0.0.0.0'}}]}}


@port('sql_server_atp_enabled', 'SQL server observed security-alert policies are enabled', 'SI-4')
def alerts(item, index):
    rows = _children(item, 'securityAlertPolicies', 'securityAlertPolicies')
    if not rows:
        raise Unavailable('No security-alert policy returned; required enabled configuration cannot be certified')
    states = []
    for row in rows:
        state = get(row, 'properties.state', str)
        if state not in ('Enabled', 'Disabled'):
            raise Unavailable('Unrecognized security-alert policy state')
        states.append(state)
    return result('Disabled' in states, states=states, semantics='Security-alert policy flag only; not vulnerability-assessment or effective Defender sensor coverage')
CASES[SOURCE_QUERIES['sql_server_atp_enabled']] = {'pass': {'id': SERVER, 'securityAlertPolicies': [{'id': SERVER + '/securityAlertPolicies/Default', 'properties': {'state': 'Enabled'}}]}, 'fail': {'id': SERVER, 'securityAlertPolicies': [{'id': SERVER + '/securityAlertPolicies/Default', 'properties': {'state': 'Disabled'}}]}}
