"""Pure, unregistered consumer of Dataflow package reader proposal captures.

This validates a capture contract, not an authenticated snapshot signature.
Runtime authorization, scheduling, snapshot admission and UI are out of scope.
"""
from copy import deepcopy
from datetime import datetime
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import gcp_dataflow_referenced_source_20261020 as source

DECLARATION = dict(id=source.CHECK, provider='gcp', category='exposure', kind='dataflow_selected_package_source',
                   title='Captured selected Dataflow package source has no detected secrets', severity='high',
                   finding_type='secrets', allow_incomplete_failure=True,
                   coverage='Explicit selected current referenced package bytes only; original execution is not proven.')


def _hex(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def _evaluate(item, capture, global_complete):
    """Return (verdict, redacted evidence); incomplete clean observations are UNKNOWN."""
    try:
        if (set(capture) != {'schema', 'capture', 'authorized', 'selected', 'items', 'receipts'}
                or capture['schema'] != source.SCHEMA or capture['authorized'] is not True
                or not isinstance(capture['capture'], str) or not re.fullmatch('[0-9a-f]{32}', capture['capture'])):
            raise ValueError('capture')
        selected, rows, receipts = (capture[k] for k in ('selected', 'items', 'receipts'))
        if (not isinstance(selected, list) or not 1 <= len(selected) <= source.MAX_TARGETS
                or any(not isinstance(i, str) or not re.fullmatch('dataflow-source:[0-9a-f]{64}', i) for i in selected)
                or len(selected) != len(set(selected)) or not isinstance(rows, list) or len(rows) > len(selected)
                or sum(r == item for r in rows) != 1 or not isinstance(receipts, list) or len(receipts) > source.MAX_CALLS):
            raise ValueError('selection')
        ids = [r['identity'] for r in rows]
        if len(ids) != len(set(ids)) or not set(ids) <= set(selected):
            raise ValueError('rows')
        if (set(item) != {'identity', 'scope', 'capture', 'native_complete', 'complete', 'association', 'generation',
                          'format', 'source_bytes', 'parts', 'leaks', 'requests', 'reason', 'captured_at',
                          'executed_bytes_proven', 'credential_validation'}
                or item['identity'] not in selected or item['capture'] != capture['capture']
                or not isinstance(item['scope'], str) or not source.SCOPE.fullmatch(item['scope'])
                or item['native_complete'] is not True or type(item['complete']) is not bool
                or item['executed_bytes_proven'] is not False or item['credential_validation'] != 'not_attempted'
                or not _hex(item['association']) or not isinstance(item['generation'], str)
                or not source.objects._DECIMAL.fullmatch(item['generation']) or int(item['generation']) > 9223372036854775807
                or item['format'] not in {'text', 'zip', 'tar', 'tar.gz'}
                or type(item['source_bytes']) is not int or not 1 <= item['source_bytes'] <= source.MAX_CONTENT
                or not isinstance(item['captured_at'], str) or datetime.fromisoformat(item['captured_at']).utcoffset() is None
                or item['reason'] not in {'complete', 'capture_incomplete', 'detector_or_content_incomplete'}):
            raise ValueError('item')
        ledger = {}
        for receipt in receipts:
            if (set(receipt) != {'id', 'identity', 'scope', 'capture', 'operation', 'method', 'origin', 'request',
                                 'principal', 'bound', 'status', 'bytes'}
                    or not isinstance(receipt['id'], str) or not re.fullmatch('dataflow-source-read:[0-9a-f]{32}', receipt['id'])
                    or receipt['id'] in ledger or receipt['identity'] not in selected
                    or receipt['capture'] != capture['capture'] or not _hex(receipt['request'])
                    or type(receipt['bytes']) is not int or not 0 <= receipt['bytes'] <= source.MAX_CONTENT):
                raise ValueError('receipt')
            ledger[receipt['id']] = receipt
        refs = item['requests']
        if not isinstance(refs, list) or len(refs) != 9 or len(set(refs)) != 9:
            raise ValueError('requests')
        own = [ledger[r] for r in refs]
        if ([r['id'] for r in receipts if r['identity'] == item['identity']] != refs
                or [r['operation'] for r in own] != list(source.OPERATIONS)
                or [r['origin'] for r in own] != ['cloudresourcemanager.googleapis.com', 'dataflow.googleapis.com',
                    'storage.googleapis.com', 'storage.googleapis.com', 'storage.googleapis.com', 'storage.googleapis.com',
                    'dataflow.googleapis.com', 'storage.googleapis.com', 'cloudresourcemanager.googleapis.com']
                or any(r['method'] != 'GET' or r['scope'] != item['scope'] or r['identity'] != item['identity']
                       or r['bound'] is not True or r['status'] != 'collected' or not _hex(r['principal']) or r['bytes'] == 0
                       or r['operation'] != 'content' and r['bytes'] > source.MAX_METADATA for r in own)
                or len({r['principal'] for r in receipts if r['principal'] is not None}) != 1
                or own[4]['bytes'] != item['source_bytes'] or sum(r['bytes'] for r in receipts) > source.MAX_TOTAL):
            raise ValueError('native binding')
        parts = item['parts']
        if not isinstance(parts, list) or not 1 <= len(parts) <= source.archives.MAX_MEMBERS:
            raise ValueError('parts')
        trusted = {}
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        for i, part in enumerate(parts, 1):
            if (set(part) != {'path', 'bytes', 'engines', 'complete'}
                    or part['path'] != item['identity'] + '.part-' + str(i)
                    or type(part['bytes']) is not int or not 0 <= part['bytes'] <= source.archives.MAX_MEMBER_BYTES
                    or type(part['complete']) is not bool or not isinstance(part['engines'], list) or len(part['engines']) != 2
                    or {e['engine'] for e in part['engines']} != set(versions)
                    or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                           or e['status'] not in {'complete', 'unavailable'} for e in part['engines'])
                    or part['complete'] != all(e['status'] == 'complete' for e in part['engines'])):
                raise ValueError('engines')
            trusted[part['path']] = {e['engine'] for e in part['engines'] if e['status'] == 'complete'}
        if (sum(p['bytes'] for p in parts) > source.archives.MAX_EXPANDED_BYTES
                or item['format'] == 'text' and (len(parts) != 1 or parts[0]['bytes'] != item['source_bytes'])
                or item['complete'] and (not all(p['complete'] for p in parts) or item['reason'] != 'complete')
                or not item['complete'] and item['reason'] == 'complete'):
            raise ValueError('completeness')
        leaks = item['leaks']
        if (not isinstance(leaks, list) or len(leaks) > source.MAX_LEAKS or merge_leaks(leaks) != leaks
                or sum(len(l['locations']) for l in leaks) > source.MAX_LOCATIONS
                or any(any(set(loc) - {'path', 'line'} or loc['path'] not in trusted
                           or not ({d['engine'] for d in leak['detectors']} & trusted[loc['path']])
                           for loc in leak['locations'])
                       or any(not any(d['engine'] in trusted[loc['path']] for loc in leak['locations']) for d in leak['detectors'])
                       for leak in leaks)):
            raise ValueError('leaks')
        complete = item['complete']
        if global_complete:
            complete = complete and set(ids) == set(selected) and all(_evaluate(r, capture, False)[1]['complete'] for r in rows)
        if not leaks and not complete:
            raise ValueError('incomplete negative')
        return ('FAIL' if leaks else 'PASS'), dict(complete=complete, secret_leaks=deepcopy(leaks), parts=deepcopy(parts),
            executed_bytes_proven=False, credential_validation='not_attempted', coverage='selected_current_referenced_package_only',
            observed=('A likely secret was detected in captured Dataflow package bytes; its value is hidden.' if leaks else
                      'Both offline detectors completed without a supported secret detection in the selected captured Dataflow package bytes.')
                     + ' This does not establish the original executed or deployed code.')
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, OverflowError):
        return 'UNKNOWN', dict(complete=False, observed='The selected current referenced package was unavailable, unbound or incompletely inspected.')


def evaluate(item, capture):
    return _evaluate(item, capture, True)
