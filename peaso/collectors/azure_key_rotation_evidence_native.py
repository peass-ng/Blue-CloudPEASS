"""Join current native key rotation policies without inventing enforcement.

This projection makes no requests. Effective Policy conditions/exemptions and
rotation-identity permissions are deliberately unavailable: a configured Rotate
action alone cannot establish the full PCI control.
"""
from copy import deepcopy
import re
from urllib.parse import urlsplit

NATIVE_TYPES = {'key_rotation_evidence'}
MAX_KEYS = 50000


def required_types(wanted):
    return {'vault', 'key_metadata', 'key_rotation_policy'} if NATIVE_TYPES.intersection(wanted) else set()


def _collection(reader, kind, scope):
    matches = [c for c in reader.collections if c.get('type') == kind
               and isinstance(c.get('scope'), str) and c['scope'].casefold() == scope.casefold()]
    if len(matches) != 1:
        raise ValueError('rotation native inventory missing or ambiguous: ' + kind)
    source = matches[0]
    rows, status = source.get('items'), source.get('status')
    if status == 'denied':
        from .azure import AzureReadError
        raise AzureReadError('rotation_native_parent_denied', 403)
    if status == 'timeout':
        raise TimeoutError('rotation_native_parent_timeout')
    if (status not in ('collected', 'empty') or not isinstance(rows, list)
            or (status == 'empty') != (not rows) or len(rows) > MAX_KEYS
            or any(not isinstance(row, dict) for row in rows)):
        raise ValueError('rotation native inventory incomplete: ' + kind)
    return rows


def _proof(row, endpoint):
    proof = row.get('_provenance')
    if (row.get('collection_status') not in (None, 'collected')
            or not isinstance(proof, dict) or proof.get('collection_status') not in (None, 'collected')
            or proof.get('read_only') is not True
            or proof.get('endpoint') != endpoint or proof.get('audience') != 'https://vault.azure.net'):
        raise ValueError('rotation native provenance unavailable')


def _actions(value):
    if not isinstance(value, list) or len(value) > 64:
        raise ValueError('rotation policy lifetime actions unavailable or oversized')
    projected = []
    for entry in value:
        if not isinstance(entry, dict) or set(entry) != {'action', 'trigger'}:
            raise ValueError('rotation lifetime action malformed')
        action, trigger = entry['action'], entry['trigger']
        if (not isinstance(action, dict) or set(action) != {'type'}
                or not isinstance(action['type'], str) or action['type'].casefold() not in ('rotate', 'notify') or not isinstance(trigger, dict)
                or len(trigger) != 1 or not set(trigger) <= {'timeAfterCreate', 'timeBeforeExpiry'}
                or any(not isinstance(v, str) or len(v) > 64 for v in trigger.values())):
            raise ValueError('rotation lifetime action or trigger unsupported')
        # The native REST contract explicitly defines this enum as insensitive
        # to case. Canonicalize only known values before the signed evaluator.
        kind = {'rotate': 'Rotate', 'notify': 'Notify'}[action['type'].casefold()]
        projected.append({'action': {'type': kind}, 'trigger': deepcopy(trigger)})
    return projected


def _vaults(reader, scope):
    if not isinstance(scope, str) or not re.fullmatch(
            r'/subscriptions/[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', scope):
        raise ValueError('rotation subscription scope malformed')
    vaults, seen = [], set()
    # Validate the entire authoritative parent roster before emitting facts.
    for vault in _collection(reader, 'vault', scope):
        vid = vault.get('id')
        if (not isinstance(vid, str) or not re.fullmatch(re.escape(scope) +
                r'/resourceGroups/[^/?#%\\\s]+/providers/Microsoft.KeyVault/vaults/[A-Za-z0-9-]{3,24}', vid, re.I)
                or any(p in ('.', '..') for p in vid.split('/')) or vid.casefold() in seen
                or str(vault.get('type', '')).casefold() != 'microsoft.keyvault/vaults'):
            raise ValueError('rotation vault identity malformed or duplicate')
        seen.add(vid.casefold())
        props = vault.get('properties')
        origin = props.get('vaultUri') if isinstance(props, dict) else None
        if not isinstance(origin, str) or not re.fullmatch(r'https://[A-Za-z0-9-]{3,24}\.vault\.azure\.net/?', origin):
            raise ValueError('rotation vault endpoint malformed')
        origin = origin.rstrip('/')
        if urlsplit(origin).hostname.casefold() != vid.rsplit('/', 1)[1].casefold() + '.vault.azure.net':
            raise ValueError('rotation vault endpoint differs from ARM identity')
        vaults.append((vid, origin))
    return vaults


def _keys(reader, vid, origin):
    keys, ids, native_ids = [], set(), set()
    for key in _collection(reader, 'key_metadata', vid):
        kid, name = key.get('id'), key.get('name')
        if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9-]{1,127}', name)
                or not isinstance(kid, str) or kid.casefold() != (vid + '/keys/' + name).casefold()
                or not isinstance(key.get('parent_id'), str) or key['parent_id'].casefold() != vid.casefold()
                or key.get('data_plane_id') != origin + '/keys/' + name
                or kid.casefold() in ids or key['data_plane_id'].casefold() in native_ids):
            raise ValueError('rotation key identity malformed, foreign or duplicate')
        _proof(key, 'keys/list')
        ids.add(kid.casefold()); native_ids.add(key['data_plane_id'].casefold())
        keys.append((key, kid))
    return keys


def _project(scope, vid, origin, key, kid, policy):
    if (not isinstance(policy.get('id'), str) or policy['id'].casefold() != (kid + '/rotationpolicy').casefold()
            or not isinstance(policy.get('parent_id'), str) or policy['parent_id'].casefold() != kid.casefold()
            or str(policy.get('type', '')).casefold() != 'microsoft.keyvault/vaults/keys/rotationpolicy'):
        raise ValueError('rotation policy native identity differs from key')
    _proof(policy, 'keys/rotationpolicy/get')
    settings = policy.get('properties')
    if not isinstance(settings, dict):
        raise ValueError('rotation policy lifetime actions unavailable')
    coverage = settings.get('_coverage', {})
    if (not isinstance(coverage, dict) or ('lifetimeActions' in coverage and
            (not isinstance(coverage['lifetimeActions'], dict) or
             coverage['lifetimeActions'].get('status') not in ('collected', 'empty')))):
        raise ValueError('rotation policy lifetime actions incomplete')
    actions = _actions(settings.get('lifetimeActions'))
    if coverage.get('lifetimeActions', {}).get('status') == 'empty' and actions:
        raise ValueError('rotation lifetime action coverage contradictory')
    proof = {'read_only': True, 'representation': 'full',
             'source_operation': 'keys/list+keys/rotationpolicy/get', 'adapter_version': 'key_rotation_native_v1',
             'projection': 'current_rotation_policy_only', 'request_uri': key['data_plane_id'] + '/rotationpolicy',
             'vault_inventory_complete': True, 'parent_inventory_complete': True}
    return {'id': kid + '/rotation-evidence', 'scope_id': scope, 'keyId': key['data_plane_id'],
        'vaultId': vid, 'armKeyId': kid, 'vaultUri': origin,
        'rotationPolicy': {'keyId': key['data_plane_id'], 'lifetimeActions': actions, '_provenance': deepcopy(proof)},
        'enforcementAssignments': [], 'rotationIdentities': [],
        '_coverage': {field: {'status': 'not_collected'} for field in ('enforcementAssignments', 'rotationIdentities')},
        '_provenance': proof}


def _facts(reader, scope):
    from .azure import AzureReadError
    vaults = _vaults(reader, scope)
    failures, count = [], 0
    for vid, origin in vaults:
        try:
            keys = _keys(reader, vid, origin)
            count += len(keys)
            if count > MAX_KEYS:
                raise ValueError('rotation key inventory oversized')
        except (ValueError, AzureReadError, TimeoutError) as exc:
            failures.append(exc)
            continue
        for key, kid in keys:
            try:
                policies = _collection(reader, 'key_rotation_policy', kid)
                if len(policies) != 1:
                    raise ValueError('rotation current policy missing or ambiguous')
                yield _project(scope, vid, origin, key, kid, policies[0])
            except (ValueError, AzureReadError, TimeoutError) as exc:
                failures.append(exc)
    if failures:
        # The reader retains all emitted independent facts as PARTIAL. Never
        # advertise a complete or empty inventory after an inaccessible child.
        raise failures[0]


def collect(reader, scopes, wanted):
    if not NATIVE_TYPES.intersection(wanted):
        return
    for scope in scopes:
        def fetch(scope=scope):
            for fact in _facts(reader, scope):
                yield [fact]
        reader.run([('key_rotation_evidence', scope, 'Microsoft.KeyVault', fetch)])
