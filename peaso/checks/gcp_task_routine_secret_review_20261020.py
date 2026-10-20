"""Pure selected task/routine secret consumers; explicit installation only."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.gcp_selected_task_routine_secret_indicators import (
    SPECS, TASK_KIND, ROUTINE_KIND, MARKER, SCHEMA, MAX_CONTENT, MAX_WIRE)

DECLARATIONS = [{
    'id': spec['check'], 'provider': 'gcp', 'category': 'hardening', 'kind': kind,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': ['project', kind],
    'title': 'Selected ' + ('Cloud Tasks payloads' if kind == TASK_KIND else 'BigQuery routine definitions') + ' have no detected secrets',
    'remediation': 'Remove credential literals from the selected content and rotate confirmed exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in the ' + spec['label'] + '.',
                           'The value is hidden; offline detection did not validate the credential.'],
} for kind, spec in SPECS.items()]


def _envelope(index, kind, scope):
    rows = [e for e in index['collections'][kind] if isinstance(e, dict) and e.get('scope') == scope]
    if (len(rows) != 1 or rows[0].get('status') != 'collected'
            or rows[0].get('coverage_status') != 'collected' or not isinstance(rows[0].get('items'), list)):
        raise ValueError('collection')
    return rows[0]


def evaluate(item, index, *, kind):
    label = SPECS[kind]['label']
    try:
        ctx = index['context']
        scope, metadata = ctx['scope'], ctx['metadata']
        if (ctx['provider'] != 'gcp' or not isinstance(scope, str)
                or not re.fullmatch(r'projects/[a-z][a-z0-9-]{4,28}[a-z0-9]', scope)
                or metadata[kind + '_authorized'] is not True):
            raise ValueError('authorization')
        own, project = _envelope(index, kind, scope), _envelope(index, 'project', scope)
        selected = metadata[kind + '_selection']
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 8
                or any(not isinstance(n, str) or not re.fullmatch(kind + ':[0-9a-f]{64}', n) for n in selected)
                or len(set(selected)) != len(selected) or len(own['items']) != len(selected)
                or {i.get('name') for i in own['items']} != set(selected)
                or sum(i == item for i in own['items']) != 1):
            raise ValueError('selection')
        ident, m = item['name'], item[MARKER]
        if (set(m) != {'schema', 'kind', 'complete', 'scope', 'identity', 'parts', 'leaks',
                       'native_requests', 'read_receipts', 'source_requests', 'reason', 'verification'}
                or m['schema'] != SCHEMA or m['kind'] != kind or m['scope'] != scope or m['identity'] != ident
                or m['complete'] is not True or m['reason'] != 'complete'
                or m['verification'] != 'not_attempted'):
            raise ValueError('incomplete')
        if len(project['items']) != 1:
            raise ValueError('project count')
        p = project['items'][0]
        if (p.get('projectId') != scope.split('/')[1] or not isinstance(p.get('name'), str)
                or not re.fullmatch(r'projects/[1-9][0-9]{0,19}', p['name'])
                or 'projectNumber' in p and p['projectNumber'] != p['name'].split('/')[1]
                or set(p.get('_coverage', {})) & {'name', 'projectId', 'projectNumber', '*'}):
            raise ValueError('project binding')
        refs, native, receipts = m['source_requests'], m['native_requests'], m['read_receipts']
        if (not isinstance(refs, list) or len(refs) != 2 or len(set(refs)) != 2
                or any(not isinstance(r, str) or not re.fullmatch(r'request-[1-9][0-9]*', r) for r in refs)
                or not set(refs) <= set(own.get('source_requests', []))
                or not isinstance(native, list) or len(native) != 1
                or native[0] not in p.get('_provenance', {}).get('source_requests', [])
                or native[0] not in project.get('source_requests', [])
                or p.get('_provenance', {}).get('scope') != scope
                or set(item.get('_provenance', {}).get('source_requests', [])) != set(refs)
                or item.get('_provenance', {}).get('scope') != scope
                or item.get('_coverage', {}).get(MARKER) != {'status': 'collected', 'source_requests': refs}
                or not isinstance(receipts, list) or len(receipts) != 1):
            raise ValueError('provenance')
        receipt = receipts[0]
        spec = SPECS[kind]
        if (set(receipt) != {'id', 'scope', 'method', 'operation', 'resource_id', 'status', 'http_status', 'bytes', 'route', 'final_route_verified'}
                or receipt['scope'] != scope or receipt['method'] != 'GET' or receipt['operation'] != spec['operation']
                or receipt['route'] != spec['route'] or receipt['final_route_verified'] is not True
                or receipt['resource_id'] != ident or receipt['status'] != 'collected'
                or type(receipt['http_status']) is not int or receipt['http_status'] != 200
                or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= MAX_WIRE
                or receipt['id'] in native or set(refs) != set(native + [receipt['id']])):
            raise ValueError('read receipt')
        ledger = metadata['source_requests']
        if not isinstance(ledger, list):
            raise ValueError('ledger')
        for ref in refs:
            if sum(e.get('id') == ref for e in ledger) != 1:
                raise ValueError('ledger identity')
        if next(e for e in ledger if e['id'] == receipt['id']) != receipt:
            raise ValueError('ledger receipt')
        parent = next(e for e in ledger if e['id'] == native[0])
        if (parent.get('scope') != scope or parent.get('method') != 'GET' or parent.get('status') != 'collected'
                or parent.get('url') != 'https://cloudresourcemanager.googleapis.com/v3/' + scope
                or parent.get('query', {}).get('fields')):
            raise ValueError('parent receipt')
        parts, versions = m['parts'], {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        expected = ['body', 'headers'] if kind == TASK_KIND else ['definition']
        if not isinstance(parts, list) or len(parts) != len(expected):
            raise ValueError('parts')
        for part, name in zip(parts, expected):
            if (set(part) != {'part', 'bytes', 'complete', 'engines'} or part['part'] != name
                    or type(part['bytes']) is not int or not 0 <= part['bytes'] <= MAX_CONTENT
                    or kind == ROUTINE_KIND and part['bytes'] == 0 or part['complete'] is not True):
                raise ValueError('part completeness')
            engines = part['engines']
            if (not isinstance(engines, list) or len(engines) != 2
                    or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                           or e.get('engine') not in versions or e.get('version') != versions.get(e.get('engine'))
                           or e.get('status') != 'complete' for e in engines)
                    or {e['engine'] for e in engines} != set(versions)):
                raise ValueError('detectors')
        if sum(p['bytes'] for p in parts) > MAX_CONTENT or not isinstance(m['leaks'], list) or len(m['leaks']) > 256:
            raise ValueError('budget')
        leaks = merge_leaks(m['leaks'])
        if (leaks != m['leaks'] or sum(len(l['locations']) for l in leaks) > 512
                or any(set(loc) - {'path', 'line'} or loc.get('path') not in {ident + '.' + p for p in expected}
                       for leak in leaks for loc in leak['locations'])):
            raise ValueError('leaks')
        evidence = {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
                    'complete': True, 'coverage': 'selected_observed_content_only',
                    'parts': deepcopy(parts), 'source_requests': list(refs)}
        observed = ('A likely secret was detected in the ' + label + '. The value is hidden; offline detection did not validate the credential.' if leaks else
                    'Both offline detectors completed without detecting a supported secret in the ' + label + '. Coverage is limited to the selected content observed during this read.')
        return ('FAIL' if leaks else 'PASS'), {**evidence, 'observed': observed}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Inspection of the ' + label + ' is disabled, unsupported, incomplete or unbound; secret absence could not be assessed.'}


def task_payload(item, index):
    return evaluate(item, index, kind=TASK_KIND)


def routine_definition(item, index):
    return evaluate(item, index, kind=ROUTINE_KIND)


def install():
    """Explicit idempotent registration; fixture bytes have native test origins."""
    import gzip
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    fixtures = json.loads(gzip.decompress(Path(__file__).with_name(
        'gcp_task_routine_secret_review_20261020_fixtures.json.gz').read_bytes()))
    for declaration in DECLARATIONS:
        cid, kind = declaration['id'], declaration['kind']
        if any(c.id == cid for c in CHECKS):
            continue
        predicate = task_payload if kind == TASK_KIND else routine_definition
        register(cid, 'gcp', 'hardening', kind, declaration['title'], 'high',
                 'security_configuration', declaration['remediation'],
                 dependencies=declaration['dependencies'])(predicate)
        CASES[cid] = deepcopy(fixtures.get(cid, {}))
