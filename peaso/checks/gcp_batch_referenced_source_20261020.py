"""Pure consumer of the unregistered Batch/GCS capture proposal."""
from copy import deepcopy
from datetime import datetime
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import gcp_batch_referenced_source_20261020 as source

DECLARATION = dict(id=source.CHECK, provider='gcp', category='exposure', kind=source.KIND,
    title='Captured selected Batch mounted script source has no detected secrets', severity='high',
    finding_type='secrets', ui_group='Secrets', requirements=[], dependencies=[source.KIND],
    allow_incomplete_failure=True,
    remediation='Remove exposed credentials from the selected script and rotate confirmed exposed credentials. Use supported secret references.',
    coverage='Selected captured plain GCS object bound to a native Batch script path and volume; executed bytes are not established.')


def _hex(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _evaluate(item, evidence, scope):
    """No IO, credentials or registry changes; untrusted/negative partial -> UNKNOWN."""
    try:
        if (not isinstance(scope, str) or not source.SCOPE.fullmatch(scope) or evidence['authorized'] is not True
                or not isinstance(evidence['capture'], str) or not re.fullmatch('[0-9a-f]{32}', evidence['capture'])
                or not isinstance(evidence['selected'], dict) or not 1 <= len(evidence['selected']) <= 8
                or any(not isinstance(s, str) or not source.SCOPE.fullmatch(s) for s in evidence['selected'])):
            raise ValueError('context')
        selected = [i for ids in evidence['selected'].values() for i in ids]
        if (not 1 <= len(selected) <= source.MAX_TARGETS or len(set(selected)) != len(selected)
                or any(not isinstance(ids, list) for ids in evidence['selected'].values())
                or any(not isinstance(i, str) or not re.fullmatch(source.KIND + ':[0-9a-f]{64}', i) for i in selected)):
            raise ValueError('selection')
        items = evidence['items']; ids = [r['name'] for r in items]
        if (not 1 <= len(items) <= source.MAX_TARGETS or len(set(ids)) != len(ids)
                or set(ids) != set(selected) or sum(r == item for r in items) != 1):
            raise ValueError('items')
        ident = item['name']; m = item[source.MARKER]
        if (set(m) != {'schema', 'identity', 'scope', 'capture', 'complete', 'native_complete', 'association',
                       'generation', 'parts', 'leaks', 'source_requests', 'verification', 'reason', 'captured_at', 'executed_bytes_proven'}
                or m['schema'] != source.SCHEMA or m['identity'] != ident or ident not in evidence['selected'][scope]
                or m['scope'] != scope or m['capture'] != evidence['capture'] or m['native_complete'] is not True
                or type(m['complete']) is not bool or m['executed_bytes_proven'] is not False
                or m['verification'] != 'not_attempted' or not _hex(m['association'])
                or not isinstance(m['generation'], str) or not source.objects._DECIMAL.fullmatch(m['generation'])
                or int(m['generation']) > 9223372036854775807 or not isinstance(m['captured_at'], str)
                or datetime.fromisoformat(m['captured_at']).utcoffset() is None):
            raise ValueError('marker')
        ledger = evidence['receipts']; refs = m['source_requests']
        if (not isinstance(ledger, list) or not 9 <= len(ledger) <= source.MAX_CALLS
                or len({r['id'] for r in ledger}) != len(ledger) or not isinstance(refs, list)
                or len(refs) != len(source.OPERATIONS) or len(set(refs)) != len(refs)):
            raise ValueError('ledger')
        principals = set(); bindings = {}; content_bytes = None
        for ref, op in zip(refs, source.OPERATIONS):
            r, = [r for r in ledger if r['id'] == ref]
            origin = ('cloudresourcemanager.googleapis.com' if op.startswith('project_') else
                      'batch.googleapis.com' if op.startswith('reference_') else 'storage.googleapis.com')
            prefix = 'batch-source-read:' if op.startswith('reference_') else 'dataproc-source-read:'
            if (set(r) != {'id', 'identity', 'scope', 'capture', 'operation', 'method', 'origin', 'request', 'principal', 'bound', 'status', 'bytes'}
                    or not isinstance(ref, str) or not re.fullmatch(prefix + '[0-9a-f]{32}', ref)
                    or r['identity'] != ident or r['scope'] != scope or r['capture'] != evidence['capture']
                    or r['operation'] != op or r['method'] != 'GET' or r['origin'] != origin
                    or r['bound'] is not True or r['status'] != 'collected'
                    or not _hex(r['request']) or not _hex(r['principal'])
                    or type(r['bytes']) is not int or not 1 <= r['bytes'] <= (source.MAX_CONTENT if op == 'content' else source.MAX_METADATA)):
                raise ValueError('receipt')
            principals.add(r['principal']); bindings[op] = r['request']
            if op == 'content': content_bytes = r['bytes']
        if len(principals) != 1 or any(bindings[k + '_before'] != bindings[k + '_after'] for k in ('project', 'reference', 'bucket', 'latest')):
            raise ValueError('closing receipt')
        part, = m['parts']; versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (set(part) != {'bytes', 'complete', 'engines'} or type(part['bytes']) is not int
                or part['bytes'] != content_bytes or type(part['complete']) is not bool):
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
                or any(set(l) != {'fingerprint', 'detectors', 'locations'} or not _hex(l['fingerprint'])
                    or not l['detectors'] or not l['locations']
                    or any(set(d) != {'engine', 'rule'} or d['engine'] not in trusted or not isinstance(d['rule'], str)
                           or not re.fullmatch(r'[A-Za-z0-9_.:/ -]{1,160}', d['rule']) for d in l['detectors'])
                    or any(set(loc) - {'path', 'line'} or loc.get('path') != ident + '.source'
                           or 'line' in loc and (type(loc['line']) is not int or not 1 <= loc['line'] <= 10000000) for loc in l['locations']) for l in leaks)):
            raise ValueError('leaks')
        complete = m['complete'] and all(r.get(source.MARKER, {}).get('complete') is True for r in items)
        if not leaks and not complete: raise ValueError('partial negative')
        observed = ('A likely secret was detected in the captured selected Batch mounted script source. Its value is hidden and was not validated.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the captured selected Batch mounted script source.')
        return ('FAIL' if leaks else 'PASS'), dict(observed=observed + ' This capture does not establish the bytes executed by the job.',
            secret_leaks=deepcopy(leaks), complete=bool(complete), coverage='selected_captured_mounted_script_source_only',
            executed_bytes_proven=False, credential_validation='not_attempted', parts=deepcopy(m['parts']))
    except (KeyError, TypeError, ValueError, AttributeError, IndexError, OverflowError):
        return 'UNKNOWN', dict(complete=False, observed='Selected Batch mounted script source was unavailable, unbound or incompletely inspected.')


def evaluate(item, evidence, scope):
    status, details = _evaluate(item, evidence, scope)
    if details['complete']:
        # Every selected item must independently bind before any clean batch
        # result. A trusted own hit survives another target's invalid capture.
        for other in evidence['items']:
            other_status, _ = _evaluate(other, evidence, other.get(source.MARKER, {}).get('scope'))
            if other_status == 'UNKNOWN':
                if status == 'PASS':
                    return 'UNKNOWN', dict(complete=False, observed='Another selected Batch mounted script source was incompletely inspected.')
                details['complete'] = False
                break
    return status, details
