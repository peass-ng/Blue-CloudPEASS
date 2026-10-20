"""Pure unregistered consumers for point-in-time referenced Workbench text."""
from copy import deepcopy
from datetime import datetime
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import gcp_workbench_referenced_source_20261020 as source

DECLARATIONS = [dict(id=p['check'], provider='gcp', category='exposure', kind=p['kind'],
    title=p['title'], severity='high', finding_type='secrets', ui_group='Secrets', requirements=[],
    dependencies=[p['kind']], allow_incomplete_failure=True,
    remediation='Remove credential literals from the referenced source and rotate confirmed exposed credentials. Use supported secret references.',
    coverage='Selected captured referenced plain source only; original executed bytes are not established.')
    for p in source.PROFILES.values()]


def _evaluate(item, index, profile):
    try:
        kind = source.PROFILES[profile]['kind']
        ctx = index['context']; scope = ctx['scope']; meta = ctx['metadata']
        if (ctx['provider'] != 'gcp' or not isinstance(scope, str) or not source.SCOPE.fullmatch(scope)
                or meta[kind + '_authorized'] is not True):
            raise ValueError('scope')
        capture = meta['workbench_source_capture']; selected = meta[kind + '_selection'][scope]
        if (not isinstance(capture, str) or not re.fullmatch('[0-9a-f]{32}', capture)
                or not isinstance(selected, list) or not 1 <= len(selected) <= source.MAX_TARGETS
                or len(set(selected)) != len(selected)
                or any(not isinstance(i, str) or not re.fullmatch(kind + ':[0-9a-f]{64}', i) for i in selected)):
            raise ValueError('selection')
        own, = [c for c in index['collections'][kind] if c.get('scope') == scope]
        ids = [r['name'] for r in own['items']]
        if (own.get('type') != kind or own['status'] not in ('collected', 'partial') or len(ids) != len(set(ids))
                or not set(ids) <= set(selected) or sum(o == item for o in own['items']) != 1):
            raise ValueError('collection')
        ident = item['name']; m = item[source.MARKER]
        if (set(m) != {'schema', 'identity', 'scope', 'profile', 'capture', 'complete', 'native_complete',
                       'association', 'generation', 'parts', 'leaks', 'source_requests', 'verification',
                       'reason', 'captured_at', 'executed_bytes_proven'}
                or m['schema'] != source.SCHEMA or m['identity'] != ident or ident not in selected
                or m['scope'] != scope or m['capture'] != capture or m['profile'] != profile
                or type(m['complete']) is not bool or m['native_complete'] is not True
                or m['executed_bytes_proven'] is not False or m['verification'] != 'not_attempted'
                or not isinstance(m['association'], str) or not re.fullmatch('[0-9a-f]{64}', m['association'])
                or not isinstance(m['generation'], str) or not source.objects._DECIMAL.fullmatch(m['generation'])
                or int(m['generation']) > 9223372036854775807
                or not isinstance(m['captured_at'], str) or datetime.fromisoformat(m['captured_at']).utcoffset() is None):
            raise ValueError('marker')
        refs = m['source_requests']; ledger = meta['workbench_source_receipts']
        if (not isinstance(refs, list) or len(refs) != len(source.OPERATIONS) or len(set(refs)) != len(refs)
                or not isinstance(ledger, list) or not len(refs) <= len(ledger) <= source.MAX_CALLS
                or len({r['id'] for r in ledger}) != len(ledger)
                or item['_provenance'].get('scope') != scope
                or item['_provenance'].get('capture') != capture
                or set(item['_provenance'].get('source_requests', [])) != set(refs)
                or item.get('_coverage', {}).get(source.MARKER) != {'status': 'collected', 'source_requests': refs}
                or not set(refs) <= set(own.get('source_requests', []))):
            raise ValueError('provenance')
        principals = set(); bindings = {}
        for ref, op in zip(refs, source.OPERATIONS):
            r, = [r for r in ledger if r.get('id') == ref]
            origin = ('cloudresourcemanager.googleapis.com' if op.startswith('project_') else
                      'notebooks.googleapis.com' if op.startswith('reference_') else 'storage.googleapis.com')
            if (set(r) != {'id', 'identity', 'scope', 'capture', 'operation', 'method', 'origin', 'request',
                           'principal', 'bound', 'status', 'bytes'}
                    or not re.fullmatch(('workbench' if op.startswith('reference_') else 'dataproc') + '-source-read:[0-9a-f]{32}', ref)
                    or r['identity'] != ident or r['scope'] != scope or r['capture'] != capture
                    or r['operation'] != op or r['method'] != 'GET' or r['origin'] != origin
                    or r['bound'] is not True or r['status'] != 'collected'
                    or any(not isinstance(r[k], str) or not re.fullmatch('[0-9a-f]{64}', r[k]) for k in ('request', 'principal'))
                    or type(r['bytes']) is not int or not 1 <= r['bytes'] <= (source.MAX_CONTENT if op == 'content' else source.MAX_METADATA)):
                raise ValueError('receipt')
            principals.add(r['principal']); bindings[op] = r['request']
        if len(principals) != 1 or any(bindings[k + '_before'] != bindings[k + '_after'] for k in ('project', 'reference', 'bucket', 'latest')):
            raise ValueError('closing receipt')
        part, = m['parts']; versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (set(part) != {'bytes', 'complete', 'engines'} or type(part['bytes']) is not int
                or not 1 <= part['bytes'] <= source.MAX_CONTENT or type(part['complete']) is not bool
                or part['bytes'] != next(r['bytes'] for r in ledger if r['id'] == refs[4])):
            raise ValueError('part')
        engines = part['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or {e['engine'] for e in engines} != set(versions)
                or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                       or e['status'] not in ('complete', 'unavailable') for e in engines)
                or part['complete'] != all(e['status'] == 'complete' for e in engines)
                or m['complete'] != part['complete']
                or m['reason'] != ('complete' if part['complete'] else 'detector_unavailable')):
            raise ValueError('engines')
        trusted = {e['engine'] for e in engines if e['status'] == 'complete'}
        leaks = m['leaks']
        if (not isinstance(leaks, list) or len(leaks) > source.MAX_LEAKS or merge_leaks(leaks) != leaks
                or sum(len(l['locations']) for l in leaks) > source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}', l['fingerprint']) or not l['detectors'] or not l['locations']
                    or any(d['engine'] not in trusted for d in l['detectors'])
                    or any(set(loc) - {'path', 'line'} or loc.get('path') != ident + '.source' for loc in l['locations']) for l in leaks)):
            raise ValueError('leaks')
        complete = bool(m['complete'] and own['status'] == 'collected' and set(ids) == set(selected)
                        and all(r.get(source.MARKER, {}).get('complete') is True for r in own['items']))
        if not leaks and not complete:
            raise ValueError('incomplete negative')
        observed = ('A likely secret was detected in the captured Workbench referenced source. Its value is hidden and was not validated.' if leaks else
                    'Both offline detectors completed without detecting a supported secret in the captured Workbench referenced source.')
        observed += ' This capture inspects the current selected GCS source; it does not establish bytes cached on the instance or originally executed.'
        return ('FAIL' if leaks else 'PASS'), dict(observed=observed, secret_leaks=deepcopy(leaks), complete=complete,
            coverage='selected_captured_referenced_source_only', executed_bytes_proven=False,
            credential_validation='not_attempted', parts=deepcopy(m['parts']))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
        return 'UNKNOWN', {'complete': False, 'observed': 'Selected referenced source was unavailable, unbound or incompletely inspected. A clean source result cannot be established.'}


def referenced_source(item, index):
    return _evaluate(item, index, 'instance')
