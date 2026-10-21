"""Pure conservative consumer of exact native Kubernetes literal inspections."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.k8s_literal_secret_indicators import (
    KIND, CHECK, MARKER, SCHEMA, MAX_CONTENT, MAX_WIRE, MAX_LITERALS, MAX_LEAKS, MAX_LOCATIONS, NATIVE_KINDS)

DECLARATIONS = [{
    'id': CHECK, 'provider': 'k8s', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [], 'dependencies': [KIND],
    'title': 'Selected Pod and ConfigMap literals have no detected secrets',
    'remediation': 'Remove exposed credential literals from the selected Pod specifications or ConfigMaps and rotate confirmed exposed credentials. Use an appropriate secret reference instead of embedding credential values.',
    'evidence_sentences': ['A likely secret was detected in selected Kubernetes literals.',
        'The value is hidden; offline detection did not validate the credential.'],
}]


def evaluate(item, index):
    try:
        ctx = index['context']
        scope, metadata = ctx['scope'], ctx['metadata']
        if ctx['provider'] != 'k8s' or metadata[KIND + '_authorized'] is not True:
            raise ValueError('authorization')
        own, = [r for r in index['collections'][KIND] if r.get('scope') == scope]
        if own['status'] not in ('collected', 'partial') or not isinstance(own['items'], list):
            raise ValueError('collection')
        selected = metadata[KIND + '_selection'][scope]
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 8 or len(set(selected)) != len(selected)
                or any(not isinstance(s, str) or not re.fullmatch(KIND + ':[0-9a-f]{64}', s) for s in selected)
                or len(own['items']) != len(selected) or {r.get('id') for r in own['items']} != set(selected)
                or sum(r == item for r in own['items']) != 1):
            raise ValueError('selection')
        marker, ident = item[MARKER], item['id']
        if (set(marker) != {'schema', 'identity', 'scope', 'kind', 'complete', 'reason', 'verification',
                'parts', 'leaks', 'source_requests', 'literal_count', 'reference_count',
                'cluster_binding', 'uid_binding', 'version_binding'}
                or marker['schema'] != SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or not isinstance(marker['kind'], str) or marker['kind'] not in NATIVE_KINDS or type(marker['complete']) is not bool
                or marker['reason'] != ('complete' if marker['complete'] else 'detectors_incomplete')
                or (not marker['complete'] and own['status'] != 'partial')
                or marker['verification'] != 'not_attempted'
                or marker['cluster_binding'] != metadata[KIND + '_cluster_binding']
                or any(not isinstance(marker[k], str) or not re.fullmatch(r'[0-9a-f]{64}', marker[k])
                    for k in ('uid_binding', 'version_binding'))
                or type(marker['literal_count']) is not int or not 1 <= marker['literal_count'] <= MAX_LITERALS
                or type(marker['reference_count']) is not int or not 0 <= marker['reference_count'] <= 4096):
            raise ValueError('marker')
        refs, ledger = marker['source_requests'], metadata[KIND + '_receipts']
        if (not isinstance(refs, list) or len(refs) != 2 or len(set(refs)) != 2
                or not isinstance(ledger, list) or not 2 <= len(ledger) <= 16
                or any(not isinstance(ref, str) or not re.fullmatch(r'k8s-literal-read-[1-9][0-9]*', ref) for ref in refs)):
            raise ValueError('receipts')
        for ref, ordinal in zip(refs, (1, 2)):
            receipt, = [r for r in ledger if r.get('id') == ref]
            if (set(receipt) != {'id', 'identity', 'scope', 'method', 'route', 'status', 'bytes', 'ordinal', 'identity_bound'}
                    or receipt['identity'] != ident or receipt['scope'] != scope or receipt['method'] != 'GET'
                    or receipt['route'] != 'exact_selected_native_object' or type(receipt['status']) is not int
                    or receipt['status'] != 200 or receipt['identity_bound'] is not True
                    or type(receipt['ordinal']) is not int or receipt['ordinal'] != ordinal
                    or type(receipt['bytes']) is not int or not 1 <= receipt['bytes'] <= MAX_WIRE):
                raise ValueError('receipt')
        parts = marker['parts']
        if not isinstance(parts, list) or len(parts) != 1:
            raise ValueError('parts')
        part = parts[0]
        if (set(part) != {'part', 'bytes', 'complete', 'engines'} or part['part'] != 'literals'
                or type(part['complete']) is not bool or part['complete'] != marker['complete'] or type(part['bytes']) is not int
                or not 1 <= part['bytes'] <= MAX_CONTENT):
            raise ValueError('part')
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = part['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or any(not isinstance(e, dict)
                or set(e) != {'engine', 'version', 'status'} or e.get('engine') not in versions
                or e.get('version') != versions.get(e.get('engine')) or e.get('status') not in ('complete', 'unavailable') for e in engines)
                or {e['engine'] for e in engines} != set(versions)):
            raise ValueError('engines')
        completed = {e['engine'] for e in engines if e['status'] == 'complete'}
        if not completed or (completed == set(versions)) != marker['complete']:
            raise ValueError('completion')
        leaks = marker['leaks']
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > MAX_LEAKS
                or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(loc['path'] != ident + '.literals' for l in leaks for loc in l['locations'])
                or any(d['engine'] not in completed for l in leaks for d in l['detectors'])):
            raise ValueError('leaks')
        complete = marker['complete'] and own['status'] == 'collected'
        if not leaks and not complete:
            raise ValueError('incomplete absence')
        observed = ('A likely secret was detected in selected Kubernetes literals. The value is hidden; offline detection did not validate the credential.' if leaks else
            'Both offline detectors completed without detecting a supported secret in selected Kubernetes literals. Coverage is limited to the observed workload and ConfigMap literals; references were not dereferenced.')
        if not complete:
            observed += ' Coverage is incomplete; a completed detector still reported this secret.'
        return ('FAIL' if leaks else 'PASS'), {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'complete': complete, 'coverage': 'selected_observed_literals_only', 'parts': deepcopy(parts),
            'literal_count': marker['literal_count'], 'reference_count': marker['reference_count'],
            'source_requests': list(refs), 'observed': observed}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Selected Kubernetes literals were disabled, unsupported, incomplete or unbound. Secret absence could not be assessed.'}


def evaluate_associated(item, index):
    from .k8s_literal_configmap_association_evaluator import evaluate as extended
    return extended(item, index)


def install():
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK for c in CHECKS):
        return
    declaration = DECLARATIONS[0]
    register(CHECK, 'k8s', 'hardening', KIND, declaration['title'], 'high',
        'security_configuration', declaration['remediation'], dependencies=[KIND])(evaluate_associated)
    CASES[CHECK] = json.loads(Path(__file__).with_name(
        'k8s_literal_secret_review_20261020_fixtures.json').read_text()).get(CHECK, {})
