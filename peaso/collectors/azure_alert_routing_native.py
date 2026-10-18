"""Interpret configured Azure Monitor routes from existing native ARM LIST rows.

No requests, receiver reads, query execution, or delivery assertions. The frozen
control's Activated label normalizes Azure's Fired notification condition.
"""
import hashlib
import json
import re

CONTRACTS = {
    'activity_log_alert': ('Microsoft.Insights/activityLogAlerts', '2020-10-01'),
    'metric_alert': ('Microsoft.Insights/metricAlerts', '2018-03-01'),
    'scheduled_query_rule': ('Microsoft.Insights/scheduledQueryRules', '2021-08-01'),
}
VERSION = 'azure-alert-routing-v1'
FIELDS = ('_applicableActionStates', '_actionStateBindings')


def _arm(value, scope, native_type=None):
    if not isinstance(value, str) or any(ord(c) < 32 or ord(c) == 127 for c in value) or any(c in value for c in '?%#\\') or any(p in ('.', '..') for p in value.split('/')):
        raise ValueError('routing ARM identity malformed')
    pattern = re.escape(scope) + r'/resourceGroups/[^/\s]+/providers/[^/\s]+/(?:[^/\s]+/[^/\s]+)(?:/[^/\s]+/[^/\s]+)*'
    if native_type:
        pattern = re.escape(scope) + r'/resourceGroups/[^/\s]+/providers/' + re.escape(native_type) + r'/[^/\s]+'
    if not re.fullmatch(pattern, value, re.I):
        raise ValueError('routing ARM identity outside selected type/scope')
    return value.casefold()


def _strings(values):
    if (not isinstance(values, list) or len(values) > 10000
            or any(not isinstance(v, str) or not v or v != v.strip() for v in values)
            or len({v.casefold() for v in values}) != len(values)):
        raise ValueError('routing string inventory malformed or duplicated')
    return values


def _derive(kind, scope, row, api_version):
    if kind not in CONTRACTS or api_version != CONTRACTS[kind][1]:
        raise ValueError('unsupported routing API contract')
    if not isinstance(scope, str) or not re.fullmatch(r'/subscriptions/[^/?#%\\\s]+', scope, re.I):
        raise ValueError('routing subscription malformed')
    native_type = CONTRACTS[kind][0]
    if not isinstance(row, dict) or str(row.get('type', '')).casefold() != native_type.casefold():
        raise ValueError('routing native type unavailable')
    rid = _arm(row.get('id'), scope, native_type)
    if row.get('collection_status') not in (None, 'collected'):
        raise ValueError('routing native declaration incomplete')
    proof = row.get('_provenance', {})
    if (not isinstance(proof, dict) or proof.get('read_only', True) is not True
            or proof.get('native_response_complete', True) is not True
            or proof.get('collection_status') not in (None, 'collected')):
        raise ValueError('routing declaration is not read-only')
    props = row.get('properties')
    if not isinstance(props, dict) or type(props.get('enabled')) is not bool:
        raise ValueError('routing enabled declaration unavailable')
    for value, fields in ((row, ('properties',)), (props, ('enabled', 'scopes', 'actions', 'autoMitigate'))):
        coverage = value.get('_coverage', {})
        if not isinstance(coverage, dict):
            raise ValueError('routing field coverage malformed')
        for field in fields:
            if field in coverage and (not isinstance(coverage[field], dict) or
                    coverage[field].get('status') not in ('collected', 'empty')):
                raise ValueError('routing native field unavailable')
    scopes = _strings(props.get('scopes'))
    if not scopes:
        raise ValueError('routing effective scope unavailable')
    normalized_scopes = [s.casefold() if s.casefold() == scope.casefold() else _arm(s, scope) for s in scopes]
    if kind == 'scheduled_query_rule' and row.get('kind', 'LogAlert') != 'LogAlert':
        raise ValueError('scheduled query is not an alert rule')
    # Both pinned APIs explicitly document true as the omitted-field default:
    # metricAlerts 2018-03-01 MetricAlertProperties.autoMitigate, and
    # scheduledQueryRules 2021-08-01. Explicit null/invalid values stay unknown.
    stateful = False if kind == 'activity_log_alert' else props.get('autoMitigate', True)
    if type(stateful) is not bool:
        raise ValueError('routing state semantics unavailable')
    actions = props.get('actions')
    if kind == 'metric_alert':
        if not isinstance(actions, list) or any(not isinstance(a, dict) for a in actions):
            raise ValueError('metric action declarations unavailable')
        ids = _strings([a.get('actionGroupId') for a in actions])
    else:
        if not isinstance(actions, dict):
            raise ValueError('alert actions unavailable')
        groups = actions.get('actionGroups')
        if kind == 'activity_log_alert':
            if not isinstance(groups, list) or any(not isinstance(a, dict) for a in groups):
                raise ValueError('activity-log action declarations unavailable')
            ids = _strings([a.get('actionGroupId') for a in groups])
        else:
            ids = _strings(groups)
    ids = [_arm(g, scope, 'Microsoft.Insights/actionGroups') for g in ids]
    states = ['Activated', 'Resolved'] if stateful else ['Activated']
    safe = {'id': rid, 'type': native_type.casefold(), 'kind': row.get('kind', 'LogAlert') if kind == 'scheduled_query_rule' else kind,
        'enabled': props['enabled'], 'scopes': normalized_scopes, 'stateful': stateful, 'actionGroupIds': ids}
    digest = hashlib.sha256(json.dumps(safe, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    provenance = {'adapter_version': VERSION, 'read_only': True, 'method': 'GET', 'api_version': api_version,
        'request_uri': scope + '/providers/' + native_type + '?api-version=' + api_version,
        'declarationSha256': digest, 'semantics': 'configured_routing_only'}
    return states, ids, provenance


def project(kind, scope, row, api_version):
    states, groups, proof = _derive(kind, scope, row, api_version)
    props = row['properties']
    if any(field in props for field in FIELDS) or '_routing_provenance' in row:
        raise ValueError('native routing row contains precomputed interpretation')
    return {**row, 'properties': {**props, '_applicableActionStates': states,
        '_actionStateBindings': [{'state': state, 'actionGroupIds': list(groups)} for state in states]},
        '_routing_provenance': proof}


def verify_projection(kind, scope, row):
    """Check that every interpreted state/route still binds its native fields."""
    if not isinstance(row, dict) or not isinstance(row.get('properties'), dict):
        raise ValueError('native routing projection unavailable')
    states, groups, proof = _derive(kind, scope, row, CONTRACTS.get(kind, (None, None))[1])
    expected = [{'state': state, 'actionGroupIds': list(groups)} for state in states]
    if (row.get('_routing_provenance') != proof or row['properties'].get(FIELDS[0]) != states
            or row['properties'].get(FIELDS[1]) != expected):
        raise ValueError('native routing projection does not bind current declaration')
