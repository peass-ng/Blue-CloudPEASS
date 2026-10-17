"""Native configuration counterexamples; logger credential usability unmeasured."""
from datetime import datetime, timezone
import hashlib
import json
import math
import re

from .azure_apim_protocol_policy import _inventory, _children, _unique, SERVICE
from .azure_wave_platform_native import apim_rest_api_has_no_configured_ai_trace

KIND = 'apim_diagnostic_evidence'
NATIVE_TYPES = frozenset({KIND})
CID = 'azure_api_management_10_3_1_3_8a50dc0'
CONTRACT = 'native-apim-missing-trace-diagnostic-v1'
SOURCE = 'apim_native'
VERSION = '2024-05-01'
TYPES = {'http', 'odata', 'soap', 'websocket', 'graphql', 'grpc'}


def required_types(selected):
    return {'api_management', SOURCE} if KIND in selected else set()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()


def _selected(row, key, expected=None):
    """Read a selected field without reviving retained, unavailable metadata."""
    from ..checks.facts import get
    value = get(row, key, expected)
    coverage = row.get('_coverage', {})
    marker = coverage.get(key)
    if isinstance(marker, dict) and marker.get('status') == 'empty' and value not in (None, '', [], {}):
        raise ValueError('native APIM empty coverage contradicts selected value')
    if 'collection_status' in row or 'collection_status' in coverage:
        status = get(row, 'collection_status', str)
        status_coverage = coverage.get('collection_status')
        if (status not in {'collected', 'empty'}
                or isinstance(status_coverage, dict) and status_coverage.get('status') == 'empty'):
            raise ValueError('native APIM parent status unavailable')
        if status == 'empty' and value not in (None, '', [], {}):
            raise ValueError('native APIM empty parent contradicts selected value')
    return value


def _proof(row, operations):
    proof = _selected(row, '_provenance', dict)
    if (not isinstance(proof, dict) or _selected(proof, 'read_only', bool) is not True
            or _selected(proof, 'api_version', str) != VERSION or _selected(proof, 'source_operation', str) not in operations):
        raise ValueError('native APIM source proof unavailable')


def _child(row, parent, segment):
    rid = _selected(row, 'id', str)
    if not isinstance(rid, str) or re.fullmatch(re.escape(parent) + '/' + segment + r'/[^/?#%\\\s]+', rid, re.I) is None:
        raise ValueError('foreign native APIM child')
    return rid.casefold()


def _complete_children(row, field):
    items = _selected(row, field, list)
    # Coverage is a metadata map, not a native resource: its collection_status
    # key may itself contain an availability entry rather than a status string.
    coverage = row.get('_coverage')
    state = coverage.get(field) if isinstance(coverage, dict) else None
    status = _selected(state, 'status', str)
    if (status not in {'collected', 'empty'} or (status == 'empty') != (not items)):
        raise ValueError('native APIM child pages unavailable')
    return _unique(items)


def _counterexamples(fact, parent):
    """Validate every relevant source before using a known configuration absence."""
    if (not isinstance(fact, dict) or _selected(fact, 'id', str).casefold() != parent
            or _selected(fact, 'parent_id', str).casefold() != parent):
        raise ValueError('native APIM parent binding unavailable')
    _proof(fact, {'APIM_native_metadata'})
    # The shared identity join also consumes these inventories and coverage.
    _selected(fact, 'apis', list)
    _selected(fact, 'online_api_ids', list)
    coverage = fact.get('_coverage')
    if not isinstance(coverage, dict):
        raise ValueError('native APIM coverage metadata unavailable')
    for field in ('apis', 'revisions'):
        _selected(coverage.get(field), 'status', str)
    apis = _children(fact)
    for api in apis.values():
        _selected(api, 'id', str)
    loggers = _complete_children(fact, 'loggers')
    for logger in loggers.values():
        _child(logger, fact['id'], 'loggers')
        _proof(logger, {'Logger_ListByService'})
        if _selected(_selected(logger, 'properties', dict), 'loggerType', str) not in {'applicationInsights', 'azureMonitor', 'azureEventHub'}:
            raise ValueError('native APIM logger metadata unresolved')
    def validate_diagnostics(rows, owner):
        for diagnostic in rows.values():
            _child(diagnostic, owner, 'diagnostics')
            _proof(diagnostic, {'Diagnostic_List'})
            properties = _selected(diagnostic, 'properties', dict)
            if not isinstance(properties, dict):
                raise ValueError('native APIM diagnostic metadata unavailable')
            reference = _selected(properties, 'loggerId', str)
            if (not isinstance(reference, str) or re.fullmatch(re.escape(fact['id']) + r'/loggers/[^/?#%\\\s]+', reference, re.I) is None):
                raise ValueError('native diagnostic logger reference foreign')
            sampling = _selected(properties, 'sampling', dict)
            percentage = _selected(sampling, 'percentage')
            if (not isinstance(sampling, dict) or _selected(sampling, 'samplingType', str) != 'fixed'
                    or type(percentage) not in (int, float) or not math.isfinite(percentage)
                    or not 0 <= percentage <= 100
                    or _selected(properties, 'alwaysLog') not in (None, 'allErrors')):
                raise ValueError('native diagnostic sampling unresolved')

    # All-APIs diagnostics can trace an API even when its own child list is
    # empty. Treat them as possible routes when an API override exists too:
    # optional multiplexing is not measured by this native inventory.
    service_diagnostics = _complete_children(fact, 'diagnostics')
    validate_diagnostics(service_diagnostics, fact['id'])
    bad, rest = [], 0
    for api in apis.values():
        _proof(api, {'Apis_ListByService', 'Apis_Get'})
        kind = _selected(api, 'apiType', str)
        if kind not in TYPES or _selected(_selected(api, '_provenance', dict), 'api_type_source', str) != 'properties.type':
            raise ValueError('native REST API type unavailable')
        diagnostics = _complete_children(api, 'diagnostics')
        validate_diagnostics(diagnostics, api['id'])
        if kind not in {'http', 'odata'}:
            continue
        rest += 1
        if apim_rest_api_has_no_configured_ai_trace(
                list(diagnostics.values()), list(service_diagnostics.values()), loggers):
            bad.append(api['id'])
    return sorted(bad), rest, len(apis)


def project(reader, scopes, wanted, options, instant=None):
    if KIND not in wanted: return instant
    instant = instant or datetime.now(timezone.utc).isoformat()
    for scope in scopes:
        envelope = {'type': KIND, 'scope': scope, 'service': 'Microsoft.ApiManagement', 'status': 'collected', 'items': []}
        try:
            parents, facts = _inventory(reader.collections, scope, 'api_management'), _inventory(reader.collections, scope, SOURCE)
            if parents.keys() != facts.keys(): raise ValueError('APIM parent inventories differ')
            for parent, source in facts.items():
                if SERVICE.fullmatch(source['id']) is None or not parent.startswith(scope.casefold() + '/'):
                    raise ValueError('native APIM parent foreign')
                # This is a binding to visible source facts, not a claim that
                # credentials, child data or runtime telemetry were measured.
                envelope['items'].append({'id': source['id'] + '/complianceEvidence/nativeTracing', 'parent_id': source['id'],
                    '_metadata_projection': CONTRACT, 'payload': {'source_configuration_sha256': digest(source)},
                    '_coverage': {'loggerCredentialUsability': {'status': 'not_collected'}},
                    '_provenance': {'schema_version': 1, 'read_only': True, 'source_inventory': SOURCE,
                        'captured_at': instant, 'source_operation': 'APIs_LIST+revisions_LIST+diagnostics_LIST+loggers_LIST'}})
        except (ValueError, TypeError, KeyError):
            source_states = [c.get('status') for c in reader.collections if c.get('type') in {'api_management', SOURCE}
                and str(c.get('scope', '')).casefold() == scope.casefold()]
            state = 'denied' if 'denied' in source_states else 'partial' if 'partial' in source_states else 'unknown'
            envelope.update(status=state, items=[], error={'code': 'native_apim_source_unavailable'})
        if envelope['status'] == 'collected' and not envelope['items']: envelope['status'] = 'empty'
        with reader.lock:
            capacity = len(envelope['items']) if reader.budget.max_items is None else max(0, reader.budget.max_items - reader.total)
            if len(envelope['items']) > capacity:
                envelope['items'] = envelope['items'][:capacity]
                envelope.update(status='partial', error={'code': 'resource_limit'})
            reader.total += len(envelope['items'])
            reader.collections.append(envelope)
        reader.progress(scope=scope, settled=envelope)
    return instant


def has_native(item, index):
    parent = str(item.get('id', '')).casefold()
    for wrapper in index.get(KIND, []):
        row = wrapper.get('data') if isinstance(wrapper, dict) else None
        if isinstance(row, dict) and str(row.get('parent_id', '')).casefold() == parent and '_metadata_projection' in row:
            return True
    return False


def assess(parent, context, evidence, facts, parents):
    unknown = ('UNKNOWN', {'reason': 'native APIM configuration or logger credential usability unavailable'})
    try:
        for row in evidence.values():
            pid = _selected(row, 'parent_id', str)
            if (not isinstance(pid, str) or pid.casefold() not in parents
                    or _selected(row, 'id', str).casefold() != pid.casefold() + '/complianceevidence/nativetracing'):
                return unknown
        rows = [row for row in evidence.values() if row['parent_id'].casefold() == parent]
        if len(rows) != 1 or parent not in facts: return unknown
        row, fact = rows[0], facts[parent]
        proof, payload = _selected(row, '_provenance', dict), _selected(row, 'payload', dict)
        if (_selected(row, '_metadata_projection', str) != CONTRACT or not isinstance(proof, dict)
                or _selected(proof, 'schema_version', int) != 1 or _selected(proof, 'read_only', bool) is not True
                or _selected(proof, 'source_inventory', str) != SOURCE or _selected(proof, 'captured_at', str) != context.get('created_at')
                or _selected(proof, 'source_operation', str) != 'APIs_LIST+revisions_LIST+diagnostics_LIST+loggers_LIST'
                or not isinstance(payload, dict) or _selected(payload, 'source_configuration_sha256', str) != digest(fact)):
            return unknown
        bad, rest, total = _counterexamples(fact, parent)
    except (ValueError, TypeError, KeyError):
        return unknown
    if not total: return 'NOT_APPLICABLE', {'reason': 'complete native API inventory is empty'}
    if not rest: return 'NOT_APPLICABLE', {'reason': 'complete native scope contains no REST APIs'}
    if bad:
        return 'FAIL', {'rest_apis_with_no_diagnostic_or_only_missing_logger_refs': bad,
            'semantics': 'Native configuration absence only; logger credential usability unassessed'}
    return unknown
