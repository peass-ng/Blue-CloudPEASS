"""Pure consumer of native Job declaration captures and actual OCI observations."""
from copy import deepcopy
import re

from peaso.collectors import gcp_cloudrun_job_image_runtime_20261020 as runtime
from peaso.collectors import gcp_cloudrun_v2_job_declared_images_20261020 as source
from peaso.collectors import gcp_image_secret_indicators as native
from peaso.collectors.gcp_cloudrun_job_image_native_20261020 import bind
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION

CHECK_ID, KIND = runtime.CHECK_ID, runtime.KIND
DECLARATION = {'id': CHECK_ID, 'provider': 'gcp', 'kind': KIND, 'category': 'hardening',
    'severity': 'high', 'finding_type': 'secrets',
    'title': 'Selected Cloud Run Job declared image has no detected secrets',
    'dependencies': [KIND], 'requirements': [],
    'remediation': 'Remove literal secrets from the selected image, rebuild it and rotate exposed credentials.',
    'evidence_sentences': ['A likely secret was detected in bytes of the image declared by the selected Job container.',
                           'The value is hidden; credentials and executed runtime images were not verified.']}


def _require(value):
    if not value:
        raise ValueError('Job declared image evidence is incomplete or unbound')


def _validate(item, index):
    # Frozen snapshot views are thawed once; the sealed proposal uses exact dict types.
    item = deepcopy(item)
    context = index['context']
    scope, metadata = context['scope'], context['metadata']
    _require(context['provider'] == 'gcp')
    selected = source.normalize_selection(deepcopy(metadata[runtime.OPTION]), scope)
    collections = [c for c in index['collections'][KIND] if c['scope'] == scope]
    _require(len(collections) == 1)
    collection, = collections
    _require(collection['status'] in ('collected', 'partial') and item in collection['items'])
    proof = item[runtime.MARKER]
    _require(set(proof) == {'schema', 'scope', 'row', 'metadata_captures', 'capture_reason',
        'association_kind', 'runtime_association_status', 'observed_runtime_digest', 'deployed_bytes_proven'}
        and proof['schema'] == runtime.SCHEMA and proof['scope'] == scope
        and proof['association_kind'] == 'desired_digest_declaration'
        and proof['runtime_association_status'] == 'UNKNOWN'
        and proof['observed_runtime_digest'] is None and proof['deployed_bytes_proven'] is False)
    row, captures = proof['row'], proof['metadata_captures']
    selection = row['selection']
    _require(selection in selected and row['association_revalidated'] is True)
    identity = selection['resource_name'] + '#container=' + selection['container_name']
    _require(item['name'] == item['_resource_id'] == item['native_id'] == identity
        and sum(i.get('name') == identity for i in collection['items']) == 1)
    records = metadata['source_requests']
    ledger = {r['id']: r for r in records}
    _require(len(ledger) == len(records))
    ids = row['source_requests']
    _require(isinstance(ids, list) and len(ids) == len(set(ids)) and set(ids) <= set(ledger)
        and set(ids) == set(item['_provenance']['source_requests'])
        and item['_provenance']['scope'] == scope and set(ids) <= set(collection['source_requests']))
    _require(isinstance(captures, list) and len(captures) == 8)
    expected = source._requests(selection, scope)
    bodies, capture_ids = [], []
    for capture, (url, fields) in zip(captures, expected * 2):
        _require(set(capture) == {'source_request', 'body'})
        rid, body = capture['source_request'], capture['body']
        record = ledger[rid]
        _require(rid in ids and rid not in capture_ids and record['scope'] == scope
            and record['method'] == 'GET' and record['url'] == url
            and record['query'] == {'fields': fields} and record['status'] == 'collected'
            and record['operation'] == 'cloudrun_v2_job_declared_image_metadata_get'
            and type(record['http_attempts']) is int and record['http_attempts'] == 1
            and record['http_status'] == 200 and type(record['bytes']) is int
            and 0 < record['bytes'] <= source.MAX_METADATA_BODY
            and re.fullmatch('[0-9a-f]{64}', record['body_sha256']) is not None)
        source._shape(body, fields)
        bodies.append(body)
        capture_ids.append(rid)
    _require(bodies[:4] == bodies[4:])
    declaration, _ = bind(selection, scope, bodies[:4])
    bind(selection, scope, bodies[4:])
    _require(declaration == row['declaration'])
    content = row['content']
    _require(set(content) == {'complete', 'leaks', 'config_engines', 'layers_scanned', 'layer_coverage',
        'verification', 'reason', 'descriptors', 'byte_status'}
        and type(content['complete']) is bool and row['complete'] is content['complete']
        and content['verification'] == 'not_attempted')
    descriptors = content['descriptors']
    _require(isinstance(descriptors, list) and 2 <= len(descriptors) <= native.MAX_LAYERS + 1)
    for ordinal, descriptor in enumerate(descriptors):
        _require(set(descriptor) == {'digest', 'mediaType', 'size'})
        native._descriptor(descriptor, native.CONFIG_TYPES if ordinal == 0 else native.TAR_TYPES,
                           native.MAX_CONFIG if ordinal == 0 else native.MAX_LAYER)
    _require(sum(d['size'] for d in descriptors) <= native.MAX_IMAGE)
    image_records = [ledger[rid] for rid in ids if rid not in capture_ids]
    _require(2 <= len(image_records) <= native.MAX_LAYERS + 2)
    for record in image_records:
        _require(record['operation'] == 'artifactregistry.registry_content_get'
            and record['method'] == 'GET' and record['scope'] == scope
            and record['category'] in ('manifests', 'blobs')
            and record['status'] in ('collected', 'unavailable', 'denied')
            and type(record['http_attempts']) is int and record['http_attempts'] in (0, 1))
    _require(image_records[0]['category'] == 'manifests'
        and image_records[0]['digest'] == selection['digest']
        and image_records[0]['status'] == 'collected')
    attempted = [r['digest'] for r in image_records[1:]]
    _require(attempted == [d['digest'] for d in descriptors[:len(attempted)]])
    successful = {r['digest'] for r in image_records[1:] if r['status'] == 'collected'
                  and r['http_status'] == 200 and r['http_attempts'] == 1}
    _require(descriptors[0]['digest'] in successful)
    engines = content['config_engines']
    versions = {'kingfisher': KINGFISHER_VERSION, 'trufflehog': TRUFFLEHOG_VERSION}
    _require(isinstance(engines, list) and len(engines) == 2
        and {e['engine'] for e in engines} == set(versions))
    for engine in engines:
        _require(set(engine) == {'engine', 'status', 'version'}
            and engine['version'] == versions[engine['engine']]
            and engine['status'] in ('complete', 'unavailable'))
    coverage = content['layer_coverage']
    _require(isinstance(coverage, list) and len(coverage) <= len(descriptors) - 1)
    _require([c['digest'] for c in coverage] == [d['digest'] for d in descriptors[1:len(coverage) + 1]])
    for layer in coverage:
        _require(set(layer) == {'digest', 'status', 'reason'}
            and layer['status'] in ('complete', 'unavailable')
            and (layer['status'] != 'complete' or layer['digest'] in successful and layer['reason'] is None))
    _require(content['layers_scanned'] == [c['digest'] for c in coverage if c['status'] == 'complete'])
    leaks = merge_leaks(content['leaks'])
    _require(len(leaks) <= native.MAX_LEAKS
        and sum(len(leak['locations']) for leak in leaks) <= native.MAX_LOCATIONS)
    valid_layers = {c['digest'] for c in coverage} | {descriptors[0]['digest']}
    for leak in leaks:
        for location in leak['locations']:
            _require(set(location) <= {'path', 'line', 'layer'}
                and location['layer'] in successful & valid_layers)
            if location['layer'] == descriptors[0]['digest']:
                _require(location['path'] == 'image-config.json')
    complete = content['complete'] and proof['capture_reason'] != 'session_cleanup_incomplete'
    if content['complete']:
        _require(all(e['status'] == 'complete' for e in engines)
            and len(coverage) == len(descriptors) - 1
            and all(c['status'] == 'complete' for c in coverage)
            and len(image_records) == len(descriptors) + 1
            and all(r['status'] == 'collected' and r['http_status'] == 200
                    and r['http_attempts'] == 1 for r in image_records))
    status = 'FAIL' if leaks else 'PASS' if complete else 'UNKNOWN'
    _require(content['byte_status'] == ('FAIL' if leaks else 'PASS' if content['complete'] else 'UNKNOWN')
        and row['status'] == content['byte_status'])
    return status, {'secret_leaks': leaks, 'complete': complete,
        'credential_validation': 'not_attempted', 'association_kind': proof['association_kind'],
        'runtime_association_status': 'UNKNOWN', 'observed_runtime_digest': None,
        'deployed_bytes_proven': False, 'image_uri': selection['immutable_reference'],
        'job_declaration': deepcopy(declaration['selected_artifact_image_hint']['source']),
        'source_requests': deepcopy(ids), 'config_engines': deepcopy(engines),
        'layer_coverage': deepcopy(coverage)}


def evaluate(item, index):
    try:
        status, evidence = _validate(item, index)
        observed = {'FAIL': 'A likely secret was detected in the selected Job declared image bytes.',
            'PASS': 'Both offline detectors completed on the selected Job declared image without detecting a supported secret.',
            'UNKNOWN': 'Selected Job declared image coverage is incomplete.'}[status]
        return status, {**evidence, 'observed': observed}
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'UNKNOWN', {'observed': 'Selected Job declared image evidence is incomplete, unsupported or unbound.'}


def install():
    from . import CHECKS, register
    if any(check.id == CHECK_ID for check in CHECKS):
        return
    register(CHECK_ID, 'gcp', 'hardening', KIND, DECLARATION['title'], 'high',
        'security_configuration', DECLARATION['remediation'], dependencies=[KIND],
        allow_incomplete_failure=True)(evaluate)
