"""Standalone pure portable contract; no registry, collector, key or scanner import.

The SHA256 snapshot digest detects content inconsistency, not cloud authenticity.
The caller supplies an independently retained expected index context. An offline
party able to replace both snapshot and that context can fabricate assertions,
as with ordinary CSPM JSON snapshots. No online authentication is inferred here.
"""
from copy import deepcopy
from datetime import datetime
import hashlib
import json
import re

KIND = 'azure_function_package_portable_20261020'
NATIVE_KIND = 'azure_function_package_source_20261020'
NATIVE_SCHEMA = 'azure-function-package-source-v1'
SCHEMA = 'azure-function-package-portable-v1'
TRUST = 'collector_assertions_content_digest_not_cloud_authentication'
OPERATIONS = ('subscription', 'account', 'site_before', 'settings_before',
              'properties_before', 'content', 'properties_after', 'settings_after', 'site_after')
VERSIONS = {'kingfisher': '1.4.0', 'trufflehog': '3.92.5'}
MAX_TARGETS, MAX_CALLS, MAX_ARM = 2, 18, 524288
MAX_OBJECT, MAX_TOTAL = 4 * 1024 * 1024, 12 * 1024 * 1024
MAX_MEMBER, MAX_EXPANDED, MAX_TOTAL_EXPANDED = 1024 * 1024, 8 * 1024 * 1024, 16 * 1024 * 1024
MAX_MEMBERS, MAX_TOTAL_MEMBERS, MAX_LEAKS, MAX_LOCATIONS = 128, 256, 128, 512
MAX_JSON_BYTES = 2 * 1024 * 1024
GUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
SCOPE = r'/subscriptions/' + GUID
REASONS = {'complete', 'native_unavailable', 'unsupported_hosting', 'settings_unbound',
           'unsupported_package_reference', 'package_selection_mismatch', 'package_reference_changed',
           'source_version_changed', 'archive_or_detector_incomplete', 'redaction_incomplete'}
MARKER_KEYS = {'identity', 'scope', 'capture', 'association_complete', 'complete', 'reason',
               'verification', 'coverage', 'runtime_bytes', 'continuous_immutability', 'tenant',
               'principal', 'hosting', 'reference_locator', 'object_identity', 'selection_mode',
               'version_locator', 'etag_locator', 'object_bytes', 'expanded_bytes', 'members',
               'parts', 'leaks', 'source_requests'}
CONTEXT_KEYS = {'provider', 'scopes', 'capture', 'customer_context_id', 'credential_context_id',
                'tenant_id', 'principal', 'selection', 'target_order', 'targets'}
RECEIPT_KEYS = {'id', 'identity', 'scope', 'capture', 'operation', 'method', 'origin', 'request',
                'version', 'status', 'bytes', 'bound', 'tenant', 'principal', 'native_request'}


class Invalid(ValueError):
    """Fixed local contract code only; never include input or native exceptions."""


def require(ok):
    if not ok:
        raise Invalid('invalid_portable_package_evidence')


def match(pattern, value):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def bounded(value):
    """Bound before canonicalization/copy, including malformed decoded input."""
    stack, nodes, chars = [(value, 0)], 0, 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        require(nodes <= 32768 and depth <= 24)
        if isinstance(item, dict):
            require(len(item) <= 1024 and all(isinstance(k, str) for k in item))
            stack.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif isinstance(item, list):
            require(len(item) <= 1024)
            stack.extend((v, depth + 1) for v in item)
        elif isinstance(item, str):
            require(len(item) <= 4096)
            chars += len(item.encode('utf-8'))
            require(chars <= MAX_JSON_BYTES)
        else:
            require(item is None or type(item) in (bool, int))


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def digest(value):
    return 'sha256:' + hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_context(context):
    bounded(context)
    require(isinstance(context, dict) and set(context) == CONTEXT_KEYS and context['provider'] == 'azure')
    require(match(r'package-capture:[0-9a-f]{32}', context['capture'])
            and match(GUID, context['tenant_id'])
            and match(r'storage-source-principal:[0-9a-f]{64}', context['principal']))
    for field in ('customer_context_id', 'credential_context_id'):
        require(match(r'[A-Za-z0-9_-]{1,128}', context[field]))
    scopes, order = context['scopes'], context['target_order']
    require(isinstance(scopes, list) and 1 <= len(scopes) <= 8
            and all(match(SCOPE, s) for s in scopes) and len(set(scopes)) == len(scopes))
    require(isinstance(order, list) and 1 <= len(order) <= MAX_TARGETS
            and all(match(NATIVE_KIND + r':[0-9a-f]{64}', i) for i in order)
            and len(set(order)) == len(order))
    require(isinstance(context['selection'], dict) and set(context['selection']) == set(scopes)
            and isinstance(context['targets'], dict) and set(context['targets']) == set(order))
    for ident in order:
        target = context['targets'][ident]
        require(isinstance(target, dict) and set(target) == {'scope', 'object_identity', 'selection_mode', 'requests'}
                and target['scope'] in scopes and target['selection_mode'] in ('current', 'versioned')
                and match(r'azure_storage_selected_source:[0-9a-f]{64}', target['object_identity']))
        requests = target['requests']
        require(isinstance(requests, list) and len(requests) == len(OPERATIONS))
        for operation, request in zip(OPERATIONS, requests):
            prefix = 'package-web' if operation.startswith(('site_', 'settings_')) else 'storage-source'
            require(match(prefix + r'-request:[0-9a-f]{64}', request))
        require(requests[2] == requests[8] and requests[3] == requests[7] and requests[4] == requests[6])
    for scope in scopes:
        require(context['selection'][scope] == [i for i in order if context['targets'][i]['scope'] == scope])


def _leaks(rows, path, complete_engines):
    require(isinstance(rows, list) and len(rows) <= MAX_LEAKS)
    previous = ''
    for row in rows:
        require(isinstance(row, dict) and set(row) == {'fingerprint', 'detectors', 'locations'}
                and match(r'[0-9a-f]{64}', row['fingerprint']) and row['fingerprint'] > previous)
        previous = row['fingerprint']
        require(row['locations'] == [{'path': path}])
        detectors = row['detectors']
        require(isinstance(detectors, list) and 1 <= len(detectors) <= 128)
        keys = []
        for detector in detectors:
            require(isinstance(detector, dict) and set(detector) == {'engine', 'rule'}
                    and detector['engine'] in complete_engines
                    and match(r'[A-Za-z0-9_.:/ -]{1,160}', detector['rule'])
                    and '://' not in detector['rule'])
            keys.append((detector['engine'], detector['rule']))
        require(keys == sorted(set(keys)))


def _merged(parts):
    merged = {}
    for part in parts:
        for leak in part['leaks']:
            row = merged.setdefault(leak['fingerprint'], {'fingerprint': leak['fingerprint'], 'detectors': [], 'locations': []})
            for field in ('detectors', 'locations'):
                for value in leak[field]:
                    if value not in row[field]:
                        row[field].append(value)
    for row in merged.values():
        row['detectors'].sort(key=lambda d: (d['engine'], d['rule']))
        row['locations'].sort(key=lambda loc: json.dumps(loc, sort_keys=True))
    return [merged[key] for key in sorted(merged)]


def validate_facts(results, receipts, context):
    """Validate native projection facts; no seal/authenticity assertion here."""
    validate_context(context)
    bounded([results, receipts])
    require(isinstance(results, list) and len(results) == len(context['target_order'])
            and [row['identity'] for row in results] == context['target_order'])
    require(isinstance(receipts, list) and len(receipts) <= MAX_CALLS)
    ids = [r['id'] for r in receipts]
    require(len(set(ids)) == len(ids))
    offset = total_bytes = expanded = members = scanned = 0
    for marker in results:
        require(set(marker) == MARKER_KEYS)
        ident = marker['identity']
        target = context['targets'][ident]
        require(marker['scope'] == target['scope'] and marker['capture'] == context['capture']
                and marker['object_identity'] == target['object_identity']
                and marker['selection_mode'] == target['selection_mode']
                and type(marker['complete']) is bool and type(marker['association_complete']) is bool
                and marker['reason'] in REASONS and marker['verification'] == 'not_attempted'
                and marker['runtime_bytes'] == marker['continuous_immutability'] == 'unknown'
                and marker['coverage'] == 'selected_configured_stored_package_only')
        for field, cap in (('object_bytes', MAX_OBJECT), ('expanded_bytes', MAX_EXPANDED), ('members', MAX_MEMBERS)):
            require(integer(marker[field], 0, cap))
        refs = marker['source_requests']
        require(isinstance(refs, list) and len(refs) <= len(OPERATIONS)
                and all(isinstance(r, str) for r in refs) and len(set(refs)) == len(refs)
                and refs == ids[offset:offset + len(refs)])
        ledger = receipts[offset:offset + len(refs)]
        offset += len(refs)
        for number, (receipt, operation) in enumerate(zip(ledger, OPERATIONS)):
            web = operation.startswith(('site_', 'settings_'))
            prefix = 'package-web' if web else 'storage-source'
            require(isinstance(receipt, dict) and set(receipt) == (RECEIPT_KEYS if web else RECEIPT_KEYS | {'http_status'}))
            require(match(prefix + r'-read:[0-9a-f]{32}', receipt['id'])
                    and receipt['operation'] == operation and receipt['capture'] == context['capture']
                    and receipt['scope'] == target['scope']
                    and receipt['identity'] == (ident if web else target['object_identity'])
                    and receipt['request'] == target['requests'][number]
                    and receipt['method'] == ('POST' if operation.startswith('settings_') else 'HEAD' if operation.startswith('properties_') else 'GET')
                    and receipt['origin'] == ('blob' if operation in ('content', 'properties_before', 'properties_after') else 'arm')
                    and receipt['version'] == ('2025-03-01' if web else '2022-12-01' if operation == 'subscription' else '2025-06-01' if operation == 'account' else '2023-11-03')
                    and receipt['status'] in ('collected', 'unavailable') and type(receipt['bound']) is bool)
            cap = MAX_OBJECT if operation == 'content' else 0 if operation.startswith('properties_') else MAX_ARM
            require(integer(receipt['bytes'], 0, cap))
            total_bytes += receipt['bytes']
            require((receipt['tenant'], receipt['principal']) in ((None, None), (context['tenant_id'], context['principal'])))
            require(receipt['native_request'] is None or match(prefix + r'-response:[0-9a-f]{64}', receipt['native_request']))
            if not web:
                require(receipt['http_status'] is None or integer(receipt['http_status'], 100, 599))
                if receipt['status'] == 'collected':
                    require(receipt['http_status'] == 200)
            if receipt['bound'] or number < len(ledger) - 1 or marker['association_complete']:
                require(receipt['status'] == 'collected' and receipt['bound'] is True
                        and receipt['tenant'] == context['tenant_id'] and receipt['principal'] == context['principal']
                        and receipt['native_request'] is not None
                        and (receipt['bytes'] > 0 or operation.startswith('properties_')))
        parts = marker['parts']
        require(isinstance(parts, list) and len(parts) <= MAX_MEMBERS)
        for number, part in enumerate(parts, 1):
            require(isinstance(part, dict) and set(part) == {'path', 'bytes', 'complete', 'engines', 'leaks'}
                    and part['path'] == target['object_identity'] + '.file-' + str(number)
                    and integer(part['bytes'], 1, MAX_MEMBER) and type(part['complete']) is bool)
            engines = part['engines']
            require(isinstance(engines, list) and len(engines) == 2
                    and [e['engine'] for e in engines] == list(VERSIONS))
            for engine in engines:
                require(set(engine) == {'engine', 'version', 'status'} and engine['version'] == VERSIONS[engine['engine']]
                        and engine['status'] in ('complete', 'unavailable'))
            require(part['complete'] == all(e['status'] == 'complete' for e in engines))
            _leaks(part['leaks'], part['path'], {e['engine'] for e in engines if e['status'] == 'complete'})
        require(sum(p['bytes'] for p in parts) <= MAX_EXPANDED)
        require(isinstance(marker['leaks'], list) and marker['leaks'] == _merged(parts)
                and len(marker['leaks']) <= MAX_LEAKS
                and sum(len(l['locations']) for l in marker['leaks']) <= MAX_LOCATIONS)
        if marker['association_complete']:
            require(len(ledger) == len(OPERATIONS) and marker['tenant'] == context['tenant_id']
                    and marker['principal'] == context['principal'] and marker['hosting'] in ('function', 'app_service')
                    and match(r'package-reference:[0-9a-f]{64}', marker['reference_locator'])
                    and match(r'package-etag:[0-9a-f]{64}', marker['etag_locator'])
                    and match(r'package-version:[0-9a-f]{64}', marker['version_locator'])
                    and marker['object_bytes'] == ledger[5]['bytes'] and marker['object_bytes'] > 0
                    and marker['reason'] in ('complete', 'archive_or_detector_incomplete', 'redaction_incomplete'))
        else:
            require(marker['complete'] is False and parts == marker['leaks'] == []
                    and marker['object_bytes'] == marker['expanded_bytes'] == marker['members'] == 0
                    and all(marker[k] is None for k in ('tenant', 'principal', 'hosting', 'reference_locator', 'etag_locator', 'version_locator'))
                    and marker['reason'] not in ('complete', 'archive_or_detector_incomplete'))
        if marker['reason'] == 'redaction_incomplete':
            require(marker['complete'] is False and not parts and not marker['leaks'])
        if marker['complete']:
            require(marker['association_complete'] and marker['reason'] == 'complete' and parts
                    and all(p['complete'] for p in parts)
                    and sum(p['bytes'] for p in parts) == marker['expanded_bytes']
                    and len(parts) <= marker['members'] <= MAX_MEMBERS)
        else:
            require(marker['reason'] != 'complete')
        expanded += marker['expanded_bytes']
        members += marker['members']
        scanned += sum(p['bytes'] for p in parts)
    require(offset == len(receipts) and total_bytes <= MAX_TOTAL
            and expanded <= MAX_TOTAL_EXPANDED and scanned <= MAX_TOTAL_EXPANDED and members <= MAX_TOTAL_MEMBERS)


def validate_snapshot(snapshot, expected_index_context):
    """Return checked native markers; digest is consistency, never HMAC proof."""
    bounded(snapshot)
    validate_context(expected_index_context)
    require(isinstance(snapshot, dict) and set(snapshot) == {'schema_version', 'provider', 'scopes', 'created_at', 'metadata', 'collections', 'snapshot_id'}
            and snapshot['schema_version'] == '1.0' and snapshot['provider'] == 'azure'
            and snapshot['scopes'] == expected_index_context['scopes'])
    require(isinstance(snapshot['created_at'], str) and len(snapshot['created_at']) <= 40
            and datetime.fromisoformat(snapshot['created_at'].replace('Z', '+00:00')).tzinfo is not None)
    require(snapshot['snapshot_id'] == digest({k: v for k, v in snapshot.items() if k != 'snapshot_id'}))
    metadata = snapshot['metadata']
    require(isinstance(metadata, dict) and set(metadata) == {KIND})
    meta = metadata[KIND]
    require(isinstance(meta, dict) and set(meta) == {'schema', 'trust_boundary', 'native_projection_verified_at_export', 'index_context', 'receipts'}
            and meta['schema'] == SCHEMA and meta['trust_boundary'] == TRUST
            and meta['native_projection_verified_at_export'] is True
            and meta['index_context'] == expected_index_context)
    collections = snapshot['collections']
    require(isinstance(collections, list) and len(collections) == len(snapshot['scopes']))
    rows = {}
    for scope, collection in zip(snapshot['scopes'], collections):
        require(isinstance(collection, dict) and set(collection) == {'type', 'scope', 'service', 'status', 'items'}
                and collection['type'] == KIND and collection['scope'] == scope and collection['service'] == 'Microsoft.Web'
                and isinstance(collection['items'], list))
        items = collection['items']
        require([i['identity'] for i in items] == expected_index_context['selection'][scope]
                and collection['status'] == ('empty' if not items else 'collected' if all(i['complete'] is True for i in items) else 'partial'))
        for item in items:
            require(item['identity'] not in rows)
            rows[item['identity']] = item
    results = [rows[i] for i in expected_index_context['target_order']]
    validate_facts(results, meta['receipts'], expected_index_context)
    return results


def evaluate(snapshot, selected_identity, *, expected_index_context):
    """Pure saved-JSON evaluation against independently retained caller context."""
    unknown = ('UNKNOWN', {'complete': False, 'observed': 'Selected stored package evidence is unavailable, unbound or incomplete.',
                          'coverage': 'selected_configured_stored_package_only', 'credential_validation': 'not_attempted',
                          'runtime_bytes': 'unknown', 'continuous_immutability': 'unknown',
                          'snapshot_trust': TRUST, 'cloud_authenticity': 'not_established'})
    try:
        results = validate_snapshot(snapshot, expected_index_context)
        marker, = [r for r in results if r['identity'] == selected_identity]
        if not marker['association_complete'] or not marker['leaks'] and not marker['complete']:
            return unknown
        return ('FAIL' if marker['leaks'] else 'PASS'), {
            'complete': marker['complete'], 'observed': ('A likely secret was detected; its value is hidden.' if marker['leaks'] else
                'Both offline detectors completed without detecting a supported secret in the selected captured package text files.'),
            'coverage': 'selected_configured_stored_package_only', 'credential_validation': 'not_attempted',
            'secret_leaks': deepcopy(marker['leaks']), 'parts': deepcopy(marker['parts']),
            'selection_mode': marker['selection_mode'], 'runtime_bytes': 'unknown', 'continuous_immutability': 'unknown',
            'snapshot_trust': TRUST, 'cloud_authenticity': 'not_established'}
    except (Invalid, KeyError, TypeError, ValueError, AttributeError, IndexError, UnicodeError, OverflowError):
        return unknown
