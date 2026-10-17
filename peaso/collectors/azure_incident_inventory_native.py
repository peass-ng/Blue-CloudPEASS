"""Export already collected Sentinel metadata; no HTTP and no triage history."""
from datetime import datetime
import re

NATIVE_TYPES = frozenset({'defender_incident'})
KIND = 'defender_incident'
SOURCE = 'sentinel_workspace'
TYPE = 'Microsoft.SecurityInsights/incidents'
VERSION = '2025-09-01'
_SEG = r'[^/?#%\\\s]+'
_GOOD = {'collected', 'empty'}
_STATES = _GOOD | {'partial', 'denied', 'timeout', 'unknown', 'not_collected', 'malformed'}


def required_types(selected):
    return {SOURCE} if KIND in selected else set()


def _workspace(value, scope):
    pattern = re.escape(scope) + r'/resourceGroups/' + _SEG + r'/providers/Microsoft\.OperationalInsights/workspaces/' + _SEG
    if (not isinstance(value, str) or re.fullmatch(pattern, value, re.I) is None
            or any(part in ('.', '..') for part in value.split('/'))):
        raise ValueError('incident workspace scope invalid')
    return value


def _project(item, parent, scope):
    _workspace(parent, scope)
    if not isinstance(item, dict): raise ValueError('incident metadata invalid')
    rid = item.get('id')
    native_type = item.get('type')
    pattern = re.escape(parent) + '/providers/Microsoft.SecurityInsights/incidents/' + _SEG
    if (not isinstance(rid, str) or re.fullmatch(pattern, rid, re.I) is None
            or rid.rsplit('/', 1)[-1] in ('.', '..')
            or not isinstance(native_type, str) or native_type.casefold() != TYPE.casefold()):
        raise ValueError('incident identity or type invalid')
    proof, properties = item.get('_provenance'), item.get('properties')
    if (not isinstance(proof, dict) or proof.get('read_only') is not True
            or proof.get('source_operation') != 'securityinsights.incidents.list'
            or proof.get('api_version') != VERSION
            or not isinstance(proof.get('workspace_id'), str) or proof['workspace_id'].casefold() != parent.casefold()
            or proof.get('type_source') not in {'native_field', 'validated_incidents_list_uri'}
            or not isinstance(properties, dict)):
        raise ValueError('incident native source proof unavailable')
    if (properties.get('status') not in {'New', 'Active', 'Closed'}
            or properties.get('severity') not in {'High', 'Medium', 'Low', 'Informational'}):
        raise ValueError('incident native state malformed')
    created = properties.get('createdTimeUtc')
    if not isinstance(created, str): raise ValueError('incident creation time unavailable')
    try: stamp = datetime.fromisoformat(created.replace('Z', '+00:00'))
    except ValueError: raise ValueError('incident creation time malformed') from None
    if stamp.tzinfo is None or stamp.utcoffset() is None: raise ValueError('incident creation time timezone unavailable')
    return {'id': rid, 'type': TYPE, 'parent_id': parent,
        'properties': {key: properties[key] for key in ('createdTimeUtc', 'status', 'severity')},
        '_coverage': {'triageHistory': {'status': 'not_collected', 'reason': 'native_metadata_has_no_complete_triage_history'},
                      'responseProcess': {'status': 'not_collected', 'reason': 'response_procedure_evidence_unavailable'}},
        '_provenance': {'read_only': True, 'source_operation': 'securityinsights.incidents.list',
            'api_version': VERSION, 'workspace_id': parent, 'source_inventory': SOURCE,
            'type_source': proof['type_source'], 'process_evidence': 'not_collected',
            'semantics': 'Current incident metadata only; triage timing, history completeness and response procedure unassessed'}}


def collect(reader, scopes, wanted):
    if KIND not in wanted: return
    for scope in scopes:
        state = {'status': 'collected'}
        def fetch(scope=scope):
            sources = [c for c in reader.collections if c.get('type') == SOURCE and isinstance(c.get('scope'), str)
                       and c['scope'].casefold() == scope.casefold()]
            if len(sources) != 1: raise ValueError('incident source inventory missing or ambiguous')
            source = sources[0]
            source_state, workspaces = source.get('status'), source.get('items')
            if source_state not in _STATES or not isinstance(workspaces, list): raise ValueError('incident source inventory malformed')
            state['status'] = source_state
            if source_state not in _GOOD | {'partial'}: return
            if source_state in _GOOD and (source_state == 'empty') != (not workspaces): raise ValueError('incident source inventory contradicts count')
            parents, incidents = set(), set()
            for workspace in workspaces:
                if not isinstance(workspace, dict): raise ValueError('incident workspace metadata malformed')
                parent = _workspace(workspace.get('id'), scope)
                if parent.casefold() in parents: raise ValueError('duplicate incident workspace')
                parents.add(parent.casefold())
                coverages = workspace.get('_coverage')
                coverage = coverages.get('incidents') if isinstance(coverages, dict) else None
                rows = workspace.get('incidents')
                if not isinstance(coverage, dict) or not isinstance(rows, list) or coverage.get('status') not in _STATES:
                    raise ValueError('incident source coverage missing')
                child_state = coverage['status']
                if child_state not in _GOOD:
                    if state['status'] in _GOOD or child_state == 'partial': state['status'] = child_state
                    if child_state != 'partial': continue
                if child_state in _GOOD and (child_state == 'empty') != (not rows): raise ValueError('incident child coverage contradicts count')
                for raw in rows:
                    row = _project(raw, parent, scope)
                    if row['id'].casefold() in incidents: raise ValueError('duplicate incident identity')
                    incidents.add(row['id'].casefold())
                    yield [row]
        before = len(reader.collections)
        reader.run([(KIND, scope, 'Microsoft.SecurityInsights', fetch)])
        result = reader.collections[before]
        if result['status'] in _GOOD:
            inherited = state['status']
            if inherited not in _GOOD:
                result.update(status=inherited, error={'code': 'sentinel_incident_source_' + inherited})
            elif not result['items']:
                result.update(status='not_collected', error={'code': 'sentinel_incident_binding_unavailable'})
