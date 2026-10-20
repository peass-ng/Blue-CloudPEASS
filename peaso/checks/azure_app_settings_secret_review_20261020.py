"""Pure consumer of bounded selected App Service/Function literal settings."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.azure_app_settings_secret_indicators import (
    KIND, CHECK, MARKER, SCHEMA, MAX_CONTENT, MAX_WIRE, MAX_SETTINGS, MAX_LEAKS,
    MAX_LOCATIONS, HOST, API_VERSION, _SCOPE)

DECLARATIONS = [{
    'id': CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [], 'dependencies': [KIND],
    'title': 'Selected App Service and Function literal app settings have no detected secrets',
    'remediation': 'Remove exposed credential literals from the selected app settings and rotate confirmed exposed credentials. Use managed identity or Key Vault references where appropriate.',
    'evidence_sentences': ['A likely secret was detected in selected literal app settings.',
        'The value is hidden; offline detection did not validate the credential.'],
}]


def evaluate(item, index):
    try:
        ctx = index['context']
        scope, metadata = ctx['scope'], ctx['metadata']
        if (ctx['provider'] != 'azure' or not isinstance(scope, str) or not _SCOPE.fullmatch(scope)
                or metadata[KIND + '_authorized'] is not True or metadata['context_binding'] != 'scan_local'):
            raise ValueError('authorization')
        rows = [r for r in index['collections'][KIND] if r.get('scope') == scope]
        if len(rows) != 1 or rows[0].get('status') != 'collected' or not isinstance(rows[0].get('items'), list):
            raise ValueError('collection')
        own = rows[0]
        selected = metadata[KIND + '_selection'][scope]
        if (not isinstance(selected, list) or not 1 <= len(selected) <= 8
                or any(not isinstance(s, str) or not re.fullmatch(KIND + ':[0-9a-f]{64}', s) for s in selected)
                or len(set(selected)) != len(selected) or len(own['items']) != len(selected)
                or {r.get('id') for r in own['items']} != set(selected)
                or sum(r == item for r in own['items']) != 1):
            raise ValueError('selection')
        for row in (own, item):
            proof = row['_provenance']
            if any(not isinstance(metadata[key], str) or not metadata[key] or proof[key] != metadata[key]
                   for key in ('credential_context_id', 'customer_context_id')):
                raise ValueError('capture binding')
        ident, marker = item['id'], item[MARKER]
        if (set(marker) != {'schema', 'kind', 'identity', 'scope', 'complete', 'reason', 'verification',
                'parts', 'leaks', 'source_requests', 'literal_count', 'reference_count', 'slot'}
                or marker['schema'] != SCHEMA or marker['kind'] != KIND or marker['identity'] != ident
                or marker['scope'] != scope or marker['complete'] is not True or marker['reason'] != 'complete'
                or marker['verification'] != 'not_attempted' or type(marker['slot']) is not bool
                or type(marker['literal_count']) is not int or not 1 <= marker['literal_count'] <= MAX_SETTINGS
                or type(marker['reference_count']) is not int or not 0 <= marker['reference_count'] < MAX_SETTINGS
                or marker['literal_count'] + marker['reference_count'] > MAX_SETTINGS
                or item['_provenance']['scope'] != scope):
            raise ValueError('marker')
        refs, ledger = marker['source_requests'], metadata[KIND + '_receipts']
        if (not isinstance(refs, list) or len(refs) != 2 or len(set(refs)) != 2
                or any(not isinstance(r, str) or not re.fullmatch(r'app-settings-read-[1-9][0-9]*', r) for r in refs)
                or item['_provenance']['source_requests'] != refs or not isinstance(ledger, list)
                or not 2 <= len(ledger) <= 16):
            raise ValueError('receipts')
        for ref, operation, method in zip(refs, ('identity', 'settings'), ('GET', 'POST')):
            receipts = [r for r in ledger if r.get('id') == ref]
            if len(receipts) != 1:
                raise ValueError('receipt identity')
            receipt = receipts[0]
            if (set(receipt) != {'id', 'identity', 'scope', 'method', 'operation', 'route', 'host',
                    'api_version', 'status', 'http_status', 'bytes', 'final_route_verified', 'identity_bound'}
                    or receipt['identity'] != ident or receipt['scope'] != scope or receipt['method'] != method
                    or receipt['operation'] != operation or receipt['route'] != 'exact_selected_' + operation
                    or receipt['host'] != HOST or receipt['api_version'] != API_VERSION
                    or receipt['status'] != 'collected' or type(receipt['http_status']) is not int
                    or receipt['http_status'] != 200 or receipt['final_route_verified'] is not True
                    or receipt['identity_bound'] is not True or type(receipt['bytes']) is not int
                    or not 1 <= receipt['bytes'] <= MAX_WIRE):
                raise ValueError('receipt')
        parts = marker['parts']
        if not isinstance(parts, list) or len(parts) != 1:
            raise ValueError('parts')
        part = parts[0]
        if (set(part) != {'part', 'bytes', 'complete', 'engines'} or part['part'] != 'literals'
                or type(part['bytes']) is not int or not 1 <= part['bytes'] <= MAX_CONTENT
                or part['complete'] is not True):
            raise ValueError('part')
        engines = part['engines']
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if (not isinstance(engines, list) or len(engines) != 2
                or any(not isinstance(e, dict) or set(e) != {'engine', 'version', 'status'}
                       or e.get('engine') not in versions or e.get('version') != versions.get(e.get('engine'))
                       or e.get('status') != 'complete' for e in engines)
                or {e['engine'] for e in engines} != set(versions)):
            raise ValueError('engines')
        leaks = marker['leaks']
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > MAX_LEAKS
                or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(loc['path'] != ident + '.literals' for l in leaks for loc in l['locations'])):
            raise ValueError('leaks')
        observed = ('A likely secret was detected in selected literal app settings. The value is hidden; offline detection did not validate the credential.' if leaks else
            'Both offline detectors completed without detecting a supported secret in selected literal app settings. Coverage is limited to these observed literals; Key Vault references were not dereferenced.')
        return ('FAIL' if leaks else 'PASS'), {'secret_leaks': deepcopy(leaks), 'credential_validation': 'not_attempted',
            'complete': True, 'coverage': 'selected_observed_literals_only', 'parts': deepcopy(parts),
            'source_requests': list(refs), 'literal_count': marker['literal_count'],
            'reference_count': marker['reference_count'], 'observed': observed}
    except (KeyError, TypeError, ValueError, AttributeError, OverflowError):
        return 'UNKNOWN', {'observed': 'Selected literal app settings were disabled, unsupported, incomplete or unbound. Secret absence could not be assessed.'}


def install():
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(c.id == CHECK for c in CHECKS):
        return
    declaration = DECLARATIONS[0]
    register(CHECK, 'azure', 'hardening', KIND, declaration['title'], 'high',
        'security_configuration', declaration['remediation'], dependencies=[KIND])(evaluate)
    CASES[CHECK] = json.loads(Path(__file__).with_name(
        'azure_app_settings_secret_review_20261020_fixtures.json').read_text()).get(CHECK, {})
