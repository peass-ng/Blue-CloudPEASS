"""Pure unregistered consumer for exact selected DevOps literals only."""
from copy import deepcopy
import re
from peaso.collectors.azure_devops_selected_content_secret_indicators import (
    KIND, CHECK, MARKER, SCHEMA, HOST, MAX_CALLS, MAX_TARGETS, MAX_CONTENT, MAX_PARTS, MAX_WIRE)
from peaso.azure_devops_git_policy import UUID
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

DECLARATIONS = [{'id': CHECK, 'provider': 'azure', 'category': 'hardening', 'kind': KIND,
    'ui_group': 'Secrets', 'finding_type': 'secrets', 'severity': 'high', 'requirements': [],
    'dependencies': [KIND], 'allow_incomplete_failure': True,
    'title': 'Selected Azure DevOps source and pipeline literals have no detected secrets',
    'remediation': 'Remove exposed literals from the selected source or nonsecret pipeline variables and rotate confirmed exposed credentials. Use supported secret references or workload identities.',
    'scope': 'Explicit selected files at immutable commits and selected pipeline definition revisions only; no template expansion, protected values, credential validation or whole-project coverage.'}]


def evaluate(item, index):
    try:
        context = index['context']; metadata = context['metadata']; scope = context['scope']
        if (context['provider'] != 'azure' or not re.fullmatch('/subscriptions/' + UUID, scope)
                or metadata.get('context_binding') != 'scan_local' or metadata.get('tenant_verified') is not True
                or not isinstance(metadata.get('tenant_id'), str) or not re.fullmatch(UUID, metadata['tenant_id'])
                or metadata.get(KIND + '_tenant') != metadata['tenant_id']
                or metadata.get(KIND + '_authorized') is not True):
            raise ValueError()
        capture = metadata[KIND + '_capture']; selected = metadata[KIND + '_selection'][scope]
        if (not isinstance(capture, str) or not re.fullmatch('devops-content:[0-9a-f]{32}', capture)
                or not isinstance(selected, list) or not 1 <= len(selected) <= MAX_TARGETS
                or len(set(selected)) != len(selected) or any(not isinstance(i, str)
                    or not re.fullmatch(KIND + ':[0-9a-f]{64}', i) for i in selected)):
            raise ValueError()
        own, = [c for c in index['collections'][KIND] if c.get('scope') == scope]
        if own.get('service') != 'AzureDevOps' or own.get('status') not in ('collected', 'partial'):
            raise ValueError()
        ids = [i['id'] for i in own['items']]
        if len(set(ids)) != len(ids) or not set(ids) <= set(selected) or sum(i == item for i in own['items']) != 1:
            raise ValueError()
        for obj in (own, item):
            proof = obj['_provenance']
            if any(not isinstance(metadata.get(k), str) or not metadata[k] or proof.get(k) != metadata[k]
                   for k in ('credential_context_id', 'customer_context_id')):
                raise ValueError()
        ident = item['id']; marker = item[MARKER]
        if (set(marker) != {'schema', 'identity', 'surface', 'scope', 'capture', 'complete', 'parts',
                'leaks', 'source_requests', 'verification', 'source_bound'}
                or marker['schema'] != SCHEMA or ident not in selected or marker['identity'] != ident
                or marker['surface'] not in ('git_file', 'pipeline') or marker['scope'] != scope
                or marker['capture'] != capture or type(marker['complete']) is not bool
                or marker['source_bound'] is not True or marker['verification'] != 'not_attempted'
                or item['_provenance'].get('scope') != scope or item['_provenance'].get('capture') != capture):
            raise ValueError()
        ledger = metadata[KIND + '_receipts']; refs = marker['source_requests']
        if (not isinstance(ledger, list) or not 1 <= len(ledger) <= MAX_CALLS
                or len({r['id'] for r in ledger}) != len(ledger) or not isinstance(refs, list)
                or not 1 <= len(refs) <= 3 or len(set(refs)) != len(refs)):
            raise ValueError()
        receipts = []
        for ref in refs:
            row, = [r for r in ledger if r['id'] == ref]
            if (set(row) != {'id', 'identity', 'scope', 'capture', 'operation', 'host', 'method',
                    'version', 'request_digest', 'bytes', 'http_status', 'bound'}
                    or not re.fullmatch('devops-read-[1-9][0-9]*', ref) or row['identity'] != ident
                    or row['scope'] != scope or row['capture'] != capture or row['host'] != HOST
                    or row['method'] != 'GET' or row['version'] != '7.1'
                    or not re.fullmatch('[0-9a-f]{64}', row['request_digest'])
                    or type(row['bound']) is not bool or type(row['bytes']) is not int
                    or not 0 <= row['bytes'] <= MAX_WIRE + 1
                    or row['http_status'] is not None and type(row['http_status']) is not int
                    or row['bound'] and (row['http_status'] != 200 or not 1 <= row['bytes'] <= MAX_WIRE)):
                raise ValueError()
            receipts.append(row)
        expected = ['repository', 'item'] if marker['surface'] == 'git_file' else ['definition', 'repository', 'item']
        if [r['operation'] for r in receipts] != expected[:len(receipts)] or not receipts[0]['bound']:
            raise ValueError()
        bound = {r['operation'] for r in receipts if r['bound']}
        parts = marker['parts']; versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if not isinstance(parts, list) or not 1 <= len(parts) <= MAX_PARTS or len({p['location'] for p in parts}) != len(parts):
            raise ValueError()
        complete_parts = True; trusted_locations = {}
        for part in parts:
            location = part['location']; engines = part['engines']
            if (set(part) != {'location', 'bytes', 'engines', 'complete'} or type(part['bytes']) is not int
                    or not 1 <= part['bytes'] <= MAX_CONTENT or type(part['complete']) is not bool
                    or not isinstance(location, str) or not re.fullmatch(r'selected-file|variable-[1-9][0-9]?', location)
                    or location == 'selected-file' and not {'repository', 'item'} <= bound
                    or location.startswith('variable-') and (marker['surface'] != 'pipeline' or 'definition' not in bound)
                    or not isinstance(engines, list) or len(engines) != 2 or {e['engine'] for e in engines} != set(versions)
                    or any(set(e) != {'engine', 'version', 'status'} or e['version'] != versions[e['engine']]
                        or e['status'] not in ('complete', 'unavailable') for e in engines)
                    or part['complete'] != all(e['status'] == 'complete' for e in engines)):
                raise ValueError()
            trusted_locations[ident + '.' + location] = {e['engine'] for e in engines if e['status'] == 'complete'}
            complete_parts = complete_parts and part['complete']
        if sum(p['bytes'] for p in parts) > MAX_CONTENT:
            raise ValueError()
        leaks = marker['leaks']
        if (not isinstance(leaks, list) or merge_leaks(leaks) != leaks or len(leaks) > 256
                or sum(len(l['locations']) for l in leaks) > 512
                or any(not re.fullmatch('[0-9a-f]{64}', l['fingerprint']) or not l['detectors'] or not l['locations']
                    or any(loc['path'] not in trusted_locations for loc in l['locations'])
                    or any(not any(d['engine'] in trusted_locations[loc['path']] for loc in l['locations']) for d in l['detectors'])
                    or any(not any(d['engine'] in trusted_locations[loc['path']] for d in l['detectors']) for loc in l['locations'])
                    for l in leaks)):
            # Union merging loses the detector/location relation. Every detector
            # needs a complete engine at a location, and each location a complete detector.
            raise ValueError()
        complete = (marker['complete'] and complete_parts and own['status'] == 'collected'
            and set(ids) == set(selected) and len(receipts) == len(expected) and all(r['bound'] for r in receipts)
            and 'selected-file' in {p['location'] for p in parts})
        if not complete and not leaks:
            raise ValueError()
        observed = ('A likely secret was detected in selected Azure DevOps literals. The value is hidden and was not validated.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected Azure DevOps literals. Coverage is limited to the selected file commit and pipeline definition revision.')
        if not complete:
            observed += ' Coverage is incomplete.'
        return ('FAIL' if leaks else 'PASS'), {'observed': observed, 'complete': bool(complete),
            'coverage': 'selected_devops_literals_only' if complete else 'incomplete',
            'credential_validation': 'not_attempted', 'secret_leaks': deepcopy(leaks),
            'parts': deepcopy(parts), 'source_requests': list(refs), 'surface': marker['surface']}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'complete': False, 'coverage': 'incomplete',
            'observed': 'Selected Azure DevOps literal content was unavailable, unbound or incompletely inspected. A clean result cannot be established.'}
