"""Unregistered pure optional ARM literal/code secret-indicator proposal."""
from copy import deepcopy
import re

from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors.azure_selected_configuration_secret_indicators import (
    KIND, CHECK, MARKER, SCHEMA, HOST, SCOPE, GUID, SURFACES, MAX_TARGETS,
    MAX_CONTENT, MAX_WIRE, MAX_CALLS, MAX_LEAKS, MAX_LOCATIONS, MAX_VALUES)

DECLARATIONS = [{
    'id': CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': KIND,
    'finding_type': 'secrets', 'severity': 'high', 'requirements': [], 'dependencies': [KIND],
    'allow_incomplete_failure': True, 'ui_group': 'Secrets',
    'title': 'Selected Azure ARM configuration and code literals have no detected secrets',
    'remediation': 'Remove exposed literals from the selected configuration or code and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
    'scope': 'Explicit selected current ARM literals only; VMSS model only, published runbook source only. No execution, live environment, credential validation or referenced-content coverage.',
}]


def evaluate(item, index):
    try:
        ctx = index['context']; scope = ctx['scope']; metadata = ctx['metadata']
        if (ctx['provider'] != 'azure' or not SCOPE.fullmatch(scope)
                or metadata[KIND + '_authorized'] is not True or metadata['context_binding'] != 'scan_local'):
            raise ValueError()
        capture = metadata[KIND + '_capture']
        if not isinstance(capture, str) or not re.fullmatch(r'arm-config-capture:[0-9a-f]{32}', capture):
            raise ValueError()
        selected = metadata[KIND + '_selection'][scope]
        if (not isinstance(selected, list) or not 1 <= len(selected) <= MAX_TARGETS
                or len(set(selected)) != len(selected) or any(not isinstance(s, str) or
                    not re.fullmatch(KIND + ':[0-9a-f]{64}', s) for s in selected)):
            raise ValueError()
        own, = [r for r in index['collections'][KIND] if r.get('scope') == scope]
        if own['status'] not in ('collected', 'partial') or own.get('service') != 'Microsoft.Resources':
            raise ValueError()
        ids = [i['id'] for i in own['items']]
        if len(set(ids)) != len(ids) or any(i not in selected for i in ids) or sum(i == item for i in own['items']) != 1:
            raise ValueError()
        for obj in (item, own):
            proof = obj['_provenance']
            if any(not isinstance(metadata.get(key), str) or not metadata[key] or proof.get(key) != metadata[key]
                   for key in ('credential_context_id', 'customer_context_id')):
                raise ValueError()
        ident = item['id']; marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'scope', 'surface', 'capture', 'complete', 'reason',
                'verification', 'parts', 'leaks', 'source_requests', 'literal_count', 'reference_count'}
                or marker['schema'] != SCHEMA or marker['identity'] != ident or marker['scope'] != scope
                or marker['capture'] != capture or marker['surface'] not in SURFACES
                or type(marker['complete']) is not bool or marker['reason'] not in ('complete', 'incomplete', 'coverage_incomplete')
                or marker['verification'] != 'not_attempted' or item['_provenance']['scope'] != scope
                or item['_provenance']['capture'] != capture
                or type(marker['literal_count']) is not int or not 1 <= marker['literal_count'] <= MAX_VALUES
                or type(marker['reference_count']) is not int or not 0 <= marker['reference_count'] <= MAX_VALUES):
            raise ValueError()
        refs = marker['source_requests']; ledger = metadata[KIND + '_receipts']
        expected = ('selected_resource', 'published_content') if marker['surface'] == 'automation_runbook' else ('selected_resource',)
        if (not isinstance(refs, list) or len(refs) != len(expected) or len(set(refs)) != len(refs)
                or item['_provenance']['source_requests'] != refs or not isinstance(ledger, list)
                or not 1 <= len(ledger) <= MAX_CALLS or len({r['id'] for r in ledger}) != len(ledger)):
            raise ValueError()
        for ref, operation in zip(refs, expected):
            receipt, = [r for r in ledger if r.get('id') == ref]
            if (set(receipt) != {'id', 'identity', 'scope', 'surface', 'method', 'host', 'api_version', 'operation',
                    'request_digest', 'capture', 'status', 'http_status', 'bytes', 'identity_bound', 'tenant_id', 'tenant_bound'}
                    or not re.fullmatch(r'arm-config-read-[1-9][0-9]*', ref)
                    or receipt['identity'] != ident or receipt['scope'] != scope or receipt['surface'] != marker['surface']
                    or receipt['method'] != 'GET' or receipt['host'] != HOST or receipt['operation'] != operation
                    or receipt['api_version'] != SURFACES[marker['surface']][2] or receipt['capture'] != capture
                    or not re.fullmatch('[0-9a-f]{64}', receipt['request_digest'])
                    or receipt['status'] != 'collected' or type(receipt['http_status']) is not int or receipt['http_status'] != 200
                    or receipt['identity_bound'] is not True or receipt['tenant_bound'] is not True
                    or not isinstance(receipt['tenant_id'], str) or not re.fullmatch(GUID, receipt['tenant_id'], re.I)
                    or str(metadata.get('tenant_id', '')).casefold() != receipt['tenant_id'].casefold()
                    or metadata.get('tenant_verified') is not True or type(receipt['bytes']) is not int
                    or not 1 <= receipt['bytes'] <= MAX_WIRE):
                raise ValueError()
        part, = marker['parts']
        if (set(part) != {'bytes', 'engines', 'complete'} or type(part['bytes']) is not int
                or not 1 <= part['bytes'] <= MAX_CONTENT or type(part['complete']) is not bool):
            raise ValueError()
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        engines = part['engines']
        if (not isinstance(engines, list) or len(engines) != 2 or {e['engine'] for e in engines} != set(versions)
                or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                    or e['status'] not in ('complete', 'unavailable') for e in engines)
                or part['complete'] != all(e['status'] == 'complete' for e in engines)):
            raise ValueError()
        leaks = marker['leaks']; trusted = {e['engine'] for e in engines if e['status'] == 'complete'}
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > MAX_LEAKS
                or sum(len(l['locations']) for l in leaks) > MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}', l['fingerprint']) or not l['detectors'] or not l['locations']
                    or any(d['engine'] not in trusted for d in l['detectors'])
                    or any(loc['path'] != ident + '.selected_literals' for loc in l['locations']) for l in leaks)):
            raise ValueError()
        complete = (marker['complete'] and marker['reason'] == 'complete' and part['complete']
                    and not marker['reference_count'] and own['status'] == 'collected' and set(ids) == set(selected))
        if not leaks and not complete:
            raise ValueError()
        observed = ('A likely secret was detected in selected Azure configuration or code literals. The value is hidden; offline detection did not validate it.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected Azure literals. Coverage is limited to the selected current declarations and source content.')
        if not complete:
            observed += ' Coverage is incomplete.'
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'secret_leaks': deepcopy(leaks),
            'complete': bool(complete), 'coverage': 'selected_arm_literals_only' if complete else 'incomplete_selected_arm_literals',
            'credential_validation': 'not_attempted', 'surface': marker['surface'], 'parts': deepcopy(marker['parts']),
            'source_requests': list(refs), 'literal_count': marker['literal_count'], 'reference_count': marker['reference_count']}
    except (KeyError, TypeError, ValueError, AttributeError, IndexError):
        return 'UNKNOWN', {'complete': False, 'coverage': 'incomplete_selected_arm_literals',
            'observed': 'Selected Azure literal content was unavailable, unbound, unsupported or incompletely inspected. A clean result cannot be established.'}
