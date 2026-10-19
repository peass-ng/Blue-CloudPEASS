"""Key Vault metadata predicates; values, key material and runtime access are absent."""
import re
from . import register, result, unknown
from .facts import get, optional, complete_items, list_of_objects, Unavailable
from .fixtures import CASES
from .azure_ports_services import _enum

CHECK_IDS = []
SOURCE_QUERIES = {'keyvault_rbac_enabled': 'azure.vault.rbac', 'keyvault_purge_protection_enabled': 'azure.vault.purge_protection', 'keyvault_vault_public_network_access_disabled': 'azure.vault.default_deny'}
VAULT_ID = '/subscriptions/sub/resourceGroups/group/providers/Microsoft.KeyVault/vaults/vault'


def port(query, kind, title, dependencies=None):
    cid = 'azure.port.' + query
    CHECK_IDS.append(cid); SOURCE_QUERIES[query] = cid
    return register(cid, 'azure', 'hardening', kind, title, 'medium', 'IA-5' if kind in ('key_metadata', 'secret_metadata') else 'CM-6',
                    'Review the exact declared Key Vault metadata and intended policy; no key material, secret value or runtime protection is examined.',
                    dependencies=dependencies or [kind])


def _parent(item, index, component):
    identity = get(item, 'id', str)
    match = re.fullmatch(r'(/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.KeyVault/vaults/[^/]+)/' + component + r'/[^/]+', identity, re.I)
    if match is None:
        raise Unavailable('Malformed vault child ARM identity')
    rows = [row for row in complete_items(index, 'vault') if get(row, 'id', str).lower() == match[1].lower()]
    if len(rows) != 1:
        raise Unavailable('Parent vault identity missing or ambiguous')
    return rows[0]


def _index(kind, rows, scope=VAULT_ID, status='collected'):
    return {kind: [{'data': row} for row in rows], 'collections': {kind: [{'status': status, 'scope': scope}]}}


def _expires(item):
    attrs = get(item, 'properties.attributes', dict)
    enabled = get(attrs, 'enabled', bool)
    if not enabled:
        return result(False, enabled=False, source_semantics='Pinned source passes explicitly disabled metadata; no expiration applicability inferred')
    expiry = optional(attrs, 'exp', None)
    if expiry is not None and (type(expiry) is not int or expiry <= 0):
        raise Unavailable('Malformed expiration metadata')
    return result(expiry is None, expiration_configured=expiry is not None, semantics='Expiration presence only, not freshness or successful rotation')


for _component, _kind in [('key', 'key_metadata'), ('secret', 'secret_metadata')]:
    def _register_expiration(component, kind, rbac):
        query = 'keyvault_' + ('with_' + ('rbac' if rbac else 'non_rbac') + '_' if rbac is not None else '') + component + '_expiration_set'
        dependencies = [kind, 'vault'] if rbac is not None else [kind]
        @port(query, kind, 'Enabled vault ' + component + ' metadata has expiration' + (' for ' + ('RBAC' if rbac else 'access-policy') + ' vaults' if rbac is not None else ''), dependencies)
        def evaluate(item, index):
            if rbac is not None:
                parent = _parent(item, index, component + 's')
                enabled = get(parent, 'properties.enableRbacAuthorization', bool)
                if enabled != rbac:
                    return 'NOT_APPLICABLE', {'reason': 'Vault authorization mode excluded by pinned source', 'rbac': enabled}
            return _expires(item)
        passed = {'id': VAULT_ID + '/' + component + 's/object', 'properties': {'attributes': {'enabled': True, 'exp': 2000000000}}}
        failed = {'id': VAULT_ID + '/' + component + 's/object', 'properties': {'attributes': {'enabled': True, 'exp': None}}}
        CASES[SOURCE_QUERIES[query]] = {'pass': passed, 'fail': failed}
        if rbac is not None:
            idx = _index('vault', [{'id': VAULT_ID, 'properties': {'enableRbacAuthorization': rbac}}], '/subscriptions/sub')
            CASES[SOURCE_QUERIES[query]].update(pass_index=idx, fail_index=idx)
    for _rbac in (None, True, False):
        _register_expiration(_component, _kind, _rbac)


@port('keyvault_key_automatic_rotation_enabled', 'key_metadata', 'Vault key rotation policy declares Rotate after creation', ['key_metadata', 'key_rotation_policy'])
def rotate(item, index):
    rid = get(item, 'id', str)
    policies = [row for row in complete_items(index, 'key_rotation_policy') if get(row, 'parent_id', str).lower() == rid.lower()]
    if len(policies) != 1:
        raise Unavailable('Key rotation policy missing or ambiguous')
    if get(policies[0], 'id', str).lower() != (rid + '/rotationpolicy').lower():
        raise Unavailable('Key rotation policy ARM identity mismatch')
    props = get(policies[0], 'properties', dict)
    actions = list_of_objects(optional(props, 'lifetimeActions', [], list))
    matches = []
    for action in actions:
        action_type = get(action, 'action.type', str)
        if action_type not in ('Rotate', 'Notify'):
            raise Unavailable('Unrecognized key rotation action')
        trigger = get(action, 'trigger', dict)
        if action_type == 'Rotate':
            # Source JSON -> tests key existence including explicit JSON null;
            # malformed explicit null cannot establish a valid schedule.
            value = optional(trigger, 'timeAfterCreate', None)
            if 'timeAfterCreate' in trigger and (not isinstance(value, str) or not re.fullmatch(r'P(?:\d+Y)?(?:\d+M)?(?:\d+D)?(?:T(?:\d+H)?(?:\d+M)?(?:\d+S)?)?', value) or value in ('P', 'PT')):
                raise Unavailable('Malformed rotation interval')
            if value is not None:
                from .azure_policy_periods import rotation_interval_supported
                if not rotation_interval_supported(value):
                    raise Unavailable('Rotation interval is below the supported seven-day minimum')
                matches.append(value)
    return result(not matches, rotate_after_create=matches, semantics='Pinned Rotate/timeAfterCreate declaration; timeBeforeExpiry-only schedules differ')
_key = VAULT_ID + '/keys/object'
CASES[SOURCE_QUERIES['keyvault_key_automatic_rotation_enabled']] = {'pass': {'id': _key}, 'fail': {'id': _key},
    'pass_index': _index('key_rotation_policy', [{'id': _key + '/rotationpolicy', 'parent_id': _key, 'properties': {'lifetimeActions': [{'action': {'type': 'Rotate'}, 'trigger': {'timeAfterCreate': 'P90D'}}]}}]),
    'fail_index': _index('key_rotation_policy', [{'id': _key + '/rotationpolicy', 'parent_id': _key, 'properties': {'lifetimeActions': [{'action': {'type': 'Rotate'}, 'trigger': {'timeBeforeExpiry': 'P30D'}}]}}])}


@port('keyvault_logging_enabled', 'vault', 'Vault declares enabled audit and allLogs category groups', ['vault', 'diagnostic_setting'])
def logging(item, index):
    rid = get(item, 'id', str)
    envelopes = [env for env in index.get('collections', {}).get('diagnostic_setting', []) if isinstance(env, dict) and str(env.get('scope', '')).lower() == rid.lower()]
    if len(envelopes) != 1 or envelopes[0].get('status') not in ('collected', 'empty'):
        raise Unavailable('Vault diagnostic settings incomplete or uncollected')
    groups = set()
    for resource in list_of_objects(index.get('diagnostic_setting', [])):
        row = get(resource, 'data', dict)
        identity = get(row, 'id', str)
        if not identity.lower().startswith(rid.lower() + '/providers/microsoft.insights/diagnosticsettings/'):
            continue
        logs = list_of_objects(get(row, 'properties.logs', list))
        for log in logs:
            enabled = get(log, 'enabled', bool)
            group = optional(log, 'categoryGroup', None)
            if group is not None and not isinstance(group, str):
                raise Unavailable('Malformed diagnostic category group')
            if enabled and group in ('audit', 'allLogs'):
                groups.add(group)
    return result(not {'audit', 'allLogs'}.issubset(groups), enabled_category_groups=sorted(groups), semantics='Exact source requires both groups; AuditEvent-only and allLogs-only differ. Destination health/retention not measured')
_diag = VAULT_ID + '/providers/Microsoft.Insights/diagnosticSettings/logs'
CASES[SOURCE_QUERIES['keyvault_logging_enabled']] = {'pass': {'id': VAULT_ID}, 'fail': {'id': VAULT_ID},
    'pass_index': _index('diagnostic_setting', [{'id': _diag, 'properties': {'logs': [{'enabled': True, 'categoryGroup': 'audit'}, {'enabled': True, 'categoryGroup': 'allLogs'}]}}]),
    'fail_index': _index('diagnostic_setting', [{'id': _diag, 'properties': {'logs': [{'enabled': True, 'categoryGroup': 'allLogs'}]}}])}


@port('keyvault_vault_private_link_used', 'vault', 'Vault ACL denies default access and declares approved private link')
def private_link(item, index):
    props = get(item, 'properties', dict)
    action = _enum(item, 'properties.networkAcls.defaultAction', ('Deny', 'Allow'))
    if action == 'Allow':
        return result(True, default_action=action)
    connections = optional(props, 'privateEndpointConnections', None)
    if connections is None:
        return 'MANUAL', {'reason': 'Known omitted/null connection metadata maps to pinned INFO; no approved link observed'}
    statuses = [get(row, 'properties.privateLinkServiceConnectionState.status', str) for row in list_of_objects(connections)]
    if any(status not in ('Approved', 'Pending', 'Rejected', 'Disconnected') for status in statuses):
        raise Unavailable('Unrecognized private endpoint approval')
    return result('Approved' not in statuses, approval_states=statuses, semantics='ACL and connection declaration; publicNetworkAccess remains separate')
CASES[SOURCE_QUERIES['keyvault_vault_private_link_used']] = {'pass': {'properties': {'networkAcls': {'defaultAction': 'Deny'}, 'privateEndpointConnections': [{'properties': {'privateLinkServiceConnectionState': {'status': 'Approved'}}}]}}, 'fail': {'properties': {'networkAcls': {'defaultAction': 'Deny'}, 'privateEndpointConnections': []}}}


@port('keyvault_public_network_access_disabled', 'vault', 'Vault with declared private connections defaults network ACLs to Deny')
def private_acl(item, index):
    connections = list_of_objects(get(item, 'properties.privateEndpointConnections', list))
    if not connections:
        return 'NOT_APPLICABLE', {'reason': 'Pinned source skips complete empty private-connection list'}
    action = _enum(item, 'properties.networkAcls.defaultAction', ('Deny', 'Allow'))
    return result(action != 'Deny', default_action=action, connection_count=len(connections), semantics='Pinned source ACL predicate; does not claim publicNetworkAccess Disabled or effective isolation')
CASES[SOURCE_QUERIES['keyvault_public_network_access_disabled']] = {'pass': {'properties': {'privateEndpointConnections': [{}], 'networkAcls': {'defaultAction': 'Deny'}}}, 'fail': {'properties': {'privateEndpointConnections': [{}], 'networkAcls': {'defaultAction': 'Allow'}}}}
