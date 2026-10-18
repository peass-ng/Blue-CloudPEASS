"""Read-only ARM inventory joins; no secret values or behavioral attestations."""
import copy
import re
from datetime import datetime, timezone

ARM = 'https://management.azure.com'
NATIVE_TYPES = {'application_gateway_and_frontdoor', 'automation_node', 'storage_file_share_and_backup_item'}


def required_types(wanted):
    result = set()
    if 'application_gateway_and_frontdoor' in wanted:
        result.update(('application_gateway', 'frontdoor'))
    if 'automation_node' in wanted:
        result.add('automation_account')
    if 'storage_file_share_and_backup_item' in wanted:
        result.update(('storage_file_share', 'storage_account', 'recovery_vault', 'backup_protected_item'))
    return result


def _collection(reader, kind, scope):
    from .azure import AzureReadError
    rows = [c for c in reader.collections if c['type'] == kind and c['scope'].casefold() == scope.casefold()]
    if len(rows) != 1 or rows[0]['status'] not in ('collected', 'empty'):
        raise AzureReadError('arm_join_parent_incomplete')
    return rows[0]


def _native_id(value, parent, suffix):
    if not isinstance(value, str) or '%' in value or '\\' in value or any(ord(c) <= 32 or ord(c) == 127 for c in value) or any(part in ('.', '..') for part in value.split('/')) or not re.fullmatch(re.escape(parent) + '/' + suffix, value, re.I):
        raise ValueError('foreign or malformed ARM metadata identity')
    return value


def collect(reader, request, scopes, wanted):
    jobs = []
    for scope in scopes:
        if 'application_gateway_and_frontdoor' in wanted:
            def gateways(scope=scope):
                seen = set()
                for kind, typ in (('application_gateway', 'Microsoft.Network/applicationGateways'),
                                  ('frontdoor', 'Microsoft.Network/frontDoors')):
                    for item in _collection(reader, kind, scope)['items']:
                        rid = _native_id(item.get('id'), scope, r'resourceGroups/[^/?#\s]+/providers/' + re.escape(typ) + r'/[^/?#\s]+')
                        if rid.casefold() in seen: raise ValueError('duplicate gateway')
                        seen.add(rid.casefold())
                        version = '2023-09-01' if kind == 'application_gateway' else '2021-06-01'
                        item = reader.call(request, ARM + rid + '?api-version=' + version)
                        if not isinstance(item, dict) or item.get('id', '').casefold() != rid.casefold():
                            raise ValueError('foreign gateway GET identity')
                        props = item.get('properties')
                        if not isinstance(props, dict): raise ValueError('gateway properties missing')
                        fields = ('httpListeners', 'sslProfiles', 'sslPolicy') if kind == 'application_gateway' else ('frontendEndpoints', 'routingRules')
                        projected = {key: copy.deepcopy(props[key]) for key in fields if key in props}
                        if kind == 'application_gateway':
                            for key, allowed in (('httpListeners', {'protocol', 'sslProfile', 'sslProfileId'}), ('sslProfiles', {'sslPolicy'})):
                                if isinstance(projected.get(key), list):
                                    projected[key] = [{'id': child.get('id'), 'properties': {name: value for name, value in child.get('properties', {}).items() if name in allowed}} for child in projected[key]]
                        else:
                            for key, allowed in (('frontendEndpoints', {'customHttpsProvisioningState'}), ('routingRules', {'acceptedProtocols', 'frontendEndpoints'})):
                                if isinstance(projected.get(key), list):
                                    projected[key] = [{'id': child.get('id'), 'properties': {name: value for name, value in child.get('properties', {}).items() if name in allowed}} for child in projected[key]]
                        for container in [projected, *[child.get('properties', {}) for child in projected.get('sslProfiles', [])]]:
                            if isinstance(container.get('sslPolicy'), dict):
                                container['sslPolicy'] = {key: value for key, value in container['sslPolicy'].items() if key in ('policyType', 'policyName', 'predefinedPolicyName')}
                        # Optional sslProfile absence in a full native GET means no
                        # listener-specific profile; retain explicit null in projection.
                        for listener in projected.get('httpListeners', []):
                            listener.get('properties', {}).setdefault('sslProfile', None)
                        yield [{'id': rid, 'type': typ, 'properties': projected,
                                '_provenance': {'source_operation': 'get', 'representation': 'full', 'api_version': version, 'read_only': True}}]
            jobs.append(('application_gateway_and_frontdoor', scope, 'Microsoft.Network', gateways))
        if 'automation_node' in wanted:
            def nodes(scope=scope):
                seen = set()
                for account in _collection(reader, 'automation_account', scope)['items']:
                    aid = _native_id(account.get('id'), scope, r'resourceGroups/[^/?#\s]+/providers/Microsoft.Automation/automationAccounts/[^/?#\s]+')
                    for page in reader.pages(request, ARM + aid + '/nodes?api-version=2024-10-23'):
                        projected = []
                        for raw in page:
                            rid = _native_id(raw.get('id'), aid, r'nodes/[^/?#\s]+')
                            if rid.casefold() in seen: raise ValueError('duplicate automation node')
                            seen.add(rid.casefold())
                            props = raw.get('properties')
                            if not isinstance(props, dict): raise ValueError('node properties missing')
                            selected = {key: copy.deepcopy(props[key]) for key in ('nodeId', 'lastSeen', 'status', 'nodeConfiguration') if key in props}
                            if isinstance(selected.get('nodeConfiguration'), dict):
                                selected['nodeConfiguration'] = {key: value for key, value in selected['nodeConfiguration'].items() if key == 'name'}
                            projected.append({'id': rid, 'properties': selected, 'parent_id': aid})
                        yield projected
            jobs.append(('automation_node', scope, 'Microsoft.Automation', nodes))
        if 'storage_file_share_and_backup_item' in wanted:
            def shares(scope=scope):
                for row in _collection(reader, 'storage_file_share', scope)['items']:
                    _native_id(row.get('id'), scope, r'resourceGroups/[^/?#\s]+/providers/Microsoft.Storage/storageAccounts/[^/?#\s]+/fileServices/default/shares/[^/?#\s]+')
                    yield [copy.deepcopy(row)]
            jobs.append(('storage_file_share_and_backup_item', scope, 'Microsoft.Storage', shares))
    reader.run(jobs)
    for scope in scopes:
        for collection in reader.collections:
            if collection['type'] == 'application_gateway_and_frontdoor' and collection['scope'] == scope and collection['status'] in ('collected', 'empty'):
                collection['scopeCoverage'] = {'scope': scope, '_provenance': {'source_operation': 'gateway_frontdoor_inventory_read', 'read_only': True},
                    'resolution': {key: 'complete' for key in ('applicationGateways', 'classicFrontDoors', 'pagination')},
                    'source_evidence_ids': [scope + '/providers/Microsoft.Network/applicationGateways', scope + '/providers/Microsoft.Network/frontDoors']}


def owner_metadata(reader, options, scopes):
    """Only normative approved policy enters; collection proofs are computed here."""
    output = {}
    policy = options.get('compliance_parameters', {}).get('azure_arm_metadata')
    if isinstance(policy, dict) and set(policy) <= {'scope', 'status', 'dscNodes', 'approvedPredefinedSslPolicyName'} and len(scopes) == 1 and isinstance(policy.get('scope'), str) and policy['scope'].casefold() == scopes[0].casefold() and policy.get('status') == 'collected':
        normalized = {}
        if isinstance(policy.get('dscNodes'), dict) and set(policy['dscNodes']) == {'requiredNodeIds', 'maxHeartbeatAgeHours'}:
            nodes = policy['dscNodes']
            ids, age = nodes.get('requiredNodeIds'), nodes.get('maxHeartbeatAgeHours')
            if isinstance(ids, list) and len(ids) <= 1000 and all(isinstance(value, str) and 0 < len(value) <= 256 and not re.search(r'[\x00-\x20/?#]', value) for value in ids) and len(ids) == len(set(ids)) and type(age) is int and 0 < age <= 8760:
                normalized['sw27'] = {'status': 'collected', 'dscNodes': copy.deepcopy(nodes)}
        if isinstance(policy.get('approvedPredefinedSslPolicyName'), str) and re.fullmatch(r'AppGwSslPolicy[0-9]{8}S?', policy['approvedPredefinedSslPolicyName']):
            normalized.update(status='collected', scope=scopes[0], observed_at=datetime.now(timezone.utc).isoformat(), max_age_seconds=3600,
                              parameters={'approvedPredefinedSslPolicyName': policy['approvedPredefinedSslPolicyName']})
        output['compliance_policy'] = normalized
    if len(scopes) == 1:
        try:
            vaults = _collection(reader, 'recovery_vault', scopes[0])
            backups = _collection(reader, 'backup_protected_item', scopes[0])
            vault_ids = {vault['id'].casefold(): vault['id'] for vault in vaults['items']}
            for backup in backups['items']:
                props = backup.get('properties', {})
                if props.get('protectedItemType') != 'AzureFileShareProtectedItem':
                    continue
                parent = backup.get('parent_id')
                if not isinstance(parent, str) or parent.casefold() not in vault_ids:
                    raise ValueError('backup vault identity unresolved')
                _native_id(backup.get('id'), parent, r'backupFabrics/[^/?#\s]+/protectionContainers/[^/?#\s]+/protectedItems/[^/?#\s]+')
                policy_id = props.get('policyId')
                if policy_id not in (None, ''):
                    _native_id(policy_id, parent, r'backupPolicies/[^/?#\s]+')
            if all(v.get('_coverage', {}).get('backupProtectedItems', {}).get('status') in ('collected', 'empty') for v in vaults['items']):
                output['sw21Evidence'] = {'backupVaultInventory': {'scope': scopes[0], 'status': 'collected', 'allScopedVaultsAccessible': True}}
        except Exception:
            pass
    return output
