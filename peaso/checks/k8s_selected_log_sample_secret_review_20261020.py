"""Unregistered pure consumer proposal for bounded current-container samples."""
from copy import deepcopy
import re
from uuid import UUID

from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.k8s_selected_log_sample_secret_indicators import (
    KIND, CHECK, SCHEMA, MARKER, MAX_LOG, MAX_POD, MAX_LEAKS, MAX_LOCATIONS,
    TAIL_LINES, WINDOW_SECONDS, MAX_SECONDS, timestamp_ns)

DECLARATIONS = [{
    'id': CHECK, 'provider': 'k8s', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'ui_group': 'Secrets', 'severity': 'high',
    'control': 'security_configuration', 'requirements': [], 'dependencies': [KIND],
    'allow_incomplete_failure': True,
    'title': 'Selected current container log samples have no detected secrets',
    'description': 'Inspect at most 100 current-container log lines from the preceding fixed hour for each explicitly selected target. Both pinned offline detectors must complete for a clean sample; results do not establish secret absence in other logs or validate credentials.',
    'remediation': 'Remove credential values from application logging and rotate confirmed exposed credentials. Restrict access to the affected Pod logs and use an appropriate secret reference for application configuration.',
}]


def _digest(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{64}', value) is not None


def evaluate(item, index):
    try:
        ctx = index['context']
        scope, metadata = ctx['scope'], ctx['metadata']
        if ctx['provider'] != 'k8s' or metadata[KIND + '_authorized'] is not True:
            raise ValueError('authorization')
        own, = [r for r in index['collections'][KIND] if r.get('scope') == scope]
        if own['status'] not in ('collected', 'partial') or not isinstance(own['items'], list):
            raise ValueError('collection')
        all_selected = metadata[KIND + '_selection']
        selected = all_selected[scope]
        if (not isinstance(all_selected, dict) or any(not isinstance(v, list) for v in all_selected.values())
                or not 1 <= sum(len(v) for v in all_selected.values()) <= 4
                or len(set(v for ids in all_selected.values() for v in ids)) != sum(len(v) for v in all_selected.values())
                or not isinstance(selected, list) or not 1 <= len(selected) <= 4
                or any(not isinstance(v, str) or re.fullmatch(KIND + ':[0-9a-f]{64}', v) is None for v in selected)
                or {r['id'] for r in own['items']} != set(selected) or len(own['items']) != len(selected)
                or sum(r == item for r in own['items']) != 1):
            raise ValueError('selection')
        capture = metadata[KIND + '_capture']
        if (not isinstance(capture, str) or not re.fullmatch(r'k8s-log-capture:[0-9a-f-]{36}', capture)
                or str(UUID(capture[16:])) != capture[16:] or UUID(capture[16:]).version != 4):
            raise ValueError('capture')
        window = metadata[KIND + '_window']
        if not isinstance(window, list) or len(window) != 2:
            raise ValueError('window')
        start, end = map(timestamp_ns, window)
        if end - start != WINDOW_SECONDS * 1_000_000_000:
            raise ValueError('window')
        # The immutable capture remains valid offline; freshness is relative to
        # snapshot creation, never the evaluator's unbound current wall clock.
        created = ctx['created_at']
        if not end <= timestamp_ns(created) <= end + (MAX_SECONDS + 15) * 1_000_000_000:
            raise ValueError('capture time')
        marker, ident = item[MARKER], item['id']
        if (set(marker) != {'schema', 'identity', 'capture', 'scope', 'cluster_binding', 'complete', 'native_bound',
                'reason', 'verification', 'source_requests', 'parts', 'leaks', 'lines', 'sample_bytes',
                'first_ns', 'last_ns', 'uid_binding', 'version_binding', 'container_binding', 'context_binding'}
                or marker['schema'] != SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or marker['capture'] != capture or marker['native_bound'] is not True
                or type(marker['complete']) is not bool
                or not marker['complete'] and own['status'] != 'partial'
                or marker['reason'] != ('complete' if marker['complete'] else 'detectors_incomplete')
                or marker['verification'] != 'not_attempted'
                or marker['cluster_binding'] != metadata[KIND + '_cluster_binding']
                or any(not _digest(marker[k]) for k in ('cluster_binding', 'uid_binding', 'version_binding', 'container_binding', 'context_binding'))
                or type(marker['lines']) is not int or not 1 <= marker['lines'] <= TAIL_LINES
                or type(marker['sample_bytes']) is not int or not 1 <= marker['sample_bytes'] < MAX_LOG
                or type(marker['first_ns']) is not int or type(marker['last_ns']) is not int
                or not start <= marker['first_ns'] <= marker['last_ns'] <= end):
            raise ValueError('marker')
        refs, ledger = marker['source_requests'], metadata[KIND + '_receipts']
        if (not isinstance(refs, list) or len(refs) != 3 or len(set(refs)) != 3
                or not isinstance(ledger, list) or not 3 <= len(ledger) <= 12
                or len({r['id'] for r in ledger}) != len(ledger)):
            raise ValueError('receipts')
        bindings = []
        for ref, ordinal in zip(refs, (1, 2, 3)):
            receipt, = [r for r in ledger if r.get('id') == ref]
            if (not isinstance(ref, str) or re.fullmatch(r'k8s-log-read-[1-9][0-9]*', ref) is None
                    or set(receipt) != {'id', 'identity', 'scope', 'capture', 'method', 'route', 'status', 'bytes',
                        'ordinal', 'context_binding', 'request_binding'}
                    or receipt['identity'] != ident or receipt['scope'] != scope or receipt['capture'] != capture
                    or receipt['method'] != 'GET' or type(receipt['status']) is not int or receipt['status'] != 200
                    or type(receipt['ordinal']) is not int or receipt['ordinal'] != ordinal
                    or receipt['context_binding'] != marker['context_binding'] or not _digest(receipt['request_binding'])
                    or receipt['route'] != ('exact_selected_current_log' if ordinal == 2 else 'exact_selected_pod')
                    or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= (MAX_LOG if ordinal == 2 else MAX_POD)
                    or ordinal == 2 and receipt['bytes'] != marker['sample_bytes']):
                raise ValueError('receipt')
            bindings.append(receipt['request_binding'])
        if bindings[0] != bindings[2] or bindings[0] == bindings[1]:
            raise ValueError('request coherence')
        part, = marker['parts']
        if (set(part) != {'part', 'bytes', 'engines', 'complete'} or part['part'] != 'log_sample'
                or type(part['complete']) is not bool or part['complete'] != marker['complete']
                or type(part['bytes']) is not int or not 1 <= part['bytes'] <= MAX_LOG + 4096):
            raise ValueError('part')
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = part['engines']
        if (not isinstance(engines, list) or len(engines) != 2
                or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                    or e['engine'] not in versions or e['version'] != versions[e['engine']]
                    or e['status'] not in ('complete', 'unavailable') for e in engines)
                or {e['engine'] for e in engines} != set(versions)):
            raise ValueError('engines')
        completed = {e['engine'] for e in engines if e['status'] == 'complete'}
        if not completed or marker['complete'] != (completed == set(versions)):
            raise ValueError('completion')
        leaks = marker['leaks']
        if (not isinstance(leaks, list) or len(leaks) > MAX_LEAKS or merge_leaks(leaks) != leaks
                or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(d['engine'] not in completed for l in leaks for d in l['detectors'])
                or any(set(loc) - {'path', 'line'} or loc['path'] != ident + '.log_sample'
                    or 'line' in loc and not 1 <= loc['line'] <= marker['lines'] + 2
                    for l in leaks for loc in l['locations'])):
            raise ValueError('leaks')
        complete = marker['complete'] and own['status'] == 'collected'
        if not leaks and not complete:
            raise ValueError('incomplete absence')
        observed = ('A likely secret was detected in a selected current-container log sample or its bound identity text; the value is hidden and was not validated.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected current-container sample and bound identity text. Coverage is limited to the returned sample of at most 100 lines within the fixed preceding hour.')
        if not complete:
            observed += ' Coverage is incomplete; a completed detector still reported this secret.'
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'secret_leaks': deepcopy(leaks),
            'complete': complete, 'credential_validation': 'not_attempted', 'coverage': 'selected_current_container_sample_only',
            'parts': deepcopy(marker['parts']), 'source_requests': list(refs), 'sample_lines': marker['lines']}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'The selected current-container log sample was disabled, unavailable, incomplete or unbound. Secret absence could not be assessed.'}
