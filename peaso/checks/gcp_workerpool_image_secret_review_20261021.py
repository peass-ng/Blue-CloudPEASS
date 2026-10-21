"""Selected Cloud Run worker-pool revision image secret consumer."""
from copy import deepcopy
from peaso.collectors import gcp_workerpool_image_runtime_20261021 as runtime
from peaso.collectors import gcp_workerpool_image_native_20261021 as native
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID, KIND = runtime.CHECK_ID, runtime.KIND


def evaluate(item, index):
    try:
        context = index['context']
        scope = context['scope']
        if context['provider'] != 'gcp': raise ValueError('provider')
        selected = native.selections(context['metadata'][runtime.OPTION], scope)
        proof = item[runtime.MARKER]
        row = proof['row']
        target = row['selection']
        if target not in selected or proof['scope'] != scope or proof['runtime_image_proven'] is not False or proof['association_kind'] != 'immutable_revision_container_declaration': raise ValueError('selection')
        identity = target['revision_name'] + '#container=' + str(target['container_index'])
        if item['name'] != identity or item['_resource_id'] != identity or item['native_id'] != identity: raise ValueError('identity')
        collections = [c for c in index['collections'][KIND] if c['scope'] == scope]
        if len(collections) != 1 or item not in collections[0]['items']: raise ValueError('collection')
        ids = row['source_requests']
        ledger = {r['id']: r for r in context['metadata']['source_requests']}
        if len(ids) != len(set(ids)) or not ids or not set(ids) <= set(ledger) or set(ids) != set(item['_provenance']['source_requests']) or set(ids) != set(proof['source_requests']): raise ValueError('receipts')
        if not row['association_revalidated']: raise ValueError('source drift')
        metadata = [ledger[rid] for rid in ids if ledger[rid]['operation'] == 'cloudrun_worker_pool_selected_image_metadata_get']
        if len(metadata) != 10 or len(row['metadata_captures']) != 10: raise ValueError('before after')
        expected = native.requests_for(target, scope) * 2
        for receipt, capture, (url, fields) in zip(metadata, row['metadata_captures'], expected):
            if capture['url'] != url or capture['fields'] != fields or capture['body_sha256'] != receipt['body_sha256']:
                raise ValueError('capture receipt')
            import hashlib, json
            if hashlib.sha256(json.dumps(capture['body'], sort_keys=True, separators=(',', ':')).encode()).hexdigest() != capture['body_sha256']:
                raise ValueError('capture hash')
            if receipt['method'] != 'GET' or receipt['url'] != url or receipt['query'] != {'fields': fields} or receipt['status'] != 'collected' or receipt['http_status'] != 200: raise ValueError('metadata receipt')
        before = [c['body'] for c in row['metadata_captures'][:5]]
        after = [c['body'] for c in row['metadata_captures'][5:]]
        if before != after: raise ValueError('source drift')
        declaration, image = native.bind(target, scope, before)
        native.bind(target, scope, after)
        if declaration != row['declaration']: raise ValueError('declaration')
        content = row['content']
        leaks = merge_leaks(content['leaks'])
        if leaks != content['leaks'] or any('value' in leak or 'raw' in leak for leak in leaks): raise ValueError('leak redaction')
        image_receipts = [ledger[rid] for rid in ids if ledger[rid]['operation'] == 'artifactregistry.registry_content_get']
        if not image_receipts or image_receipts[0]['category'] != 'manifests' or image_receipts[0]['digest'] != native.native.parse_image_uri(target['immutable_reference'])[2] or image_receipts[0]['status'] != 'collected': raise ValueError('image receipt')
        if content.get('uri') != native.native.parse_image_uri(target['immutable_reference'])[0] or content.get('manifest_digest') != image_receipts[0]['digest']:
            raise ValueError('image identity')
        if 'graph' in content:
            from .gcp_image_stream_review_20261021 import evaluate_index_content
            uri, repo, digest, _ = native.native.parse_image_uri(target['immutable_reference'])
            status, evidence = evaluate_index_content(content, uri, repo, digest, scope,
                receipts=image_receipts)
            if status == 'UNKNOWN' or status != row['status']:
                raise ValueError('index content incomplete or contradictory')
            return status, {**evidence, 'association_kind': proof['association_kind'],
                'runtime_image_proven': False, 'source_requests': deepcopy(ids)}
        descriptors = content.get('descriptors')
        if type(descriptors) is not list or not 2 <= len(descriptors) <= 65:
            raise ValueError('descriptor bound')
        for position, descriptor in enumerate(descriptors):
            native.native._descriptor(descriptor, native.native.CONFIG_TYPES if position == 0 else native.native.TAR_TYPES, native.native.MAX_CONFIG if position == 0 else 512*1024*1024)
        if [r['digest'] for r in image_receipts[1:]] != [d['digest'] for d in descriptors[:len(image_receipts)-1]]:
            raise ValueError('descriptor receipt order')
        successful = {r['digest'] for r in image_receipts[1:] if r['status'] == 'collected' and r.get('http_status') == 200}
        if descriptors[0]['digest'] not in successful:
            raise ValueError('config not verified')
        if any(location.get('layer') not in successful for leak in leaks for location in leak['locations']):
            raise ValueError('unverified leak location')
        engines = content.get('engines')
        versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
        if type(engines) is not list or {e.get('engine') for e in engines} != set(versions) or any(e.get('version') != versions[e['engine']] for e in engines):
            raise ValueError('dual engine proof')
        if content['complete'] and (len(image_receipts) != len(descriptors)+1 or any(r['status'] != 'collected' or r.get('http_status') != 200 for r in image_receipts) or any(e.get('status') != 'complete' for e in engines)):
            raise ValueError('clean coverage incomplete')
        if any(r['method'] != 'GET' or r['scope'] != scope or r['category'] not in ('manifests', 'blobs') for r in image_receipts): raise ValueError('registry receipt')
        status = 'FAIL' if leaks else 'PASS' if content['complete'] and row['complete'] else 'UNKNOWN'
        if status != row['status']: raise ValueError('producer status')
        description = {'FAIL': 'A likely secret was found in the immutable image declared by this worker pool revision. Its value is hidden.',
            'PASS': 'Both detectors completed without finding a supported secret in the immutable image declared by this worker pool revision.',
            'UNKNOWN': 'The declared worker pool image could not be fully inspected.'}[status]
        return status, {'observed': description, 'secret_leaks': deepcopy(leaks), 'complete': status == 'PASS', 'association_kind': proof['association_kind'], 'runtime_image_proven': False, 'source_requests': deepcopy(ids)}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'The selected worker pool revision image could not be associated with verified source content.'}


def install():
    from . import CHECKS, register
    if any(check.id == CHECK_ID for check in CHECKS): return
    from .fixtures import CASES
    from pathlib import Path
    import json
    native_cases = json.loads(Path(__file__).with_name('gcp_workerpool_image_secret_review_20261021_cases.json').read_text())
    if set(native_cases) != {CHECK_ID} or CHECK_ID in CASES:
        raise RuntimeError('Selected native fixture collision or absence')
    CASES[CHECK_ID] = native_cases[CHECK_ID]
    register(CHECK_ID, 'gcp', 'hardening', KIND,
        'Selected Cloud Run worker pool revision image has no detected secrets', 'high', 'security_configuration',
        'Remove embedded secrets from the selected image and rotate affected credentials.',
        dependencies=[KIND], allow_incomplete_failure=True)(evaluate)
