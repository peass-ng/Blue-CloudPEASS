"""Offline selected registry index traversal through the existing image consumer."""
import json
from urllib.parse import quote

import pytest

from test_gcp_image_stream_reader import Response, digest, reader
from test_gcp_image_stream_inspection import image, index, REPO, REPOSITORIES, PROJECTS, SCOPE
from peaso.collectors import gcp_image_stream_inspection_20261021 as inspection
from peaso.collectors import gcp_image_stream_reader_20261021 as streaming
from peaso.checks import gcp_image_stream_review_20261021 as review
from peaso import oci_index_20261021 as oci


def encoded(value):
    return json.dumps(value, separators=(',', ':')).encode()


def two_platforms(kind=oci.OCI_INDEX):
    first, blobs = image(body=b'first child secret')
    first_raw = blobs[first['digest']]
    leaf_type = inspection.native.DOCKER if kind == oci.DOCKER_LIST else inspection.native.OCI
    if kind == oci.DOCKER_LIST:
        first_doc = json.loads(first_raw)
        first_doc['mediaType'] = leaf_type
        first_raw = encoded(first_doc)
        first['digest'] = digest(first_raw)
        blobs[first['digest']] = first_raw
    second_doc = json.loads(first_raw)
    old_config = second_doc['config']['digest']
    config = json.loads(blobs[old_config])
    config['architecture'] = 'arm64'
    config_raw = encoded(config)
    second_doc['config']['digest'] = digest(config_raw)
    second_doc['config']['size'] = len(config_raw)
    second_raw = encoded(second_doc)
    blobs[digest(config_raw)] = config_raw
    blobs[digest(second_raw)] = second_raw
    parent = encoded({'schemaVersion': 2, 'mediaType': kind,
        'manifests': [{'mediaType': leaf_type, 'digest': child_digest,
            'size': len(raw), 'platform': {'os': 'linux', 'architecture': arch}}
            for child_digest, raw, arch in ((first['digest'], first_raw, 'amd64'),
                (digest(second_raw), second_raw, 'arm64'))]})
    parent_digest = digest(parent)
    blobs[parent_digest] = parent
    row = {'name': REPO + '/dockerImages/' + quote('app@' + parent_digest, safe=''),
        'uri': 'https://us-central1-docker.pkg.dev/review/images/app@' + parent_digest,
        'digest': parent_digest, 'repository': REPO}
    return row, blobs


def inspect(row, blobs, *, deny=None, cancel=None):
    current = reader(Response(b''))
    current.__class__ = streaming.Reader
    calls = []
    def request(method, url, **kwargs):
        key = url.rsplit('/', 1)[-1]
        calls.append(key)
        if key == deny:
            result = Response(b'', status_code=403)
        else:
            result = Response(blobs[key])
        result.url = url
        return result
    current.session.request = request
    if cancel is not None:
        current.transport.check_cancelled = cancel
    result = inspection.inspect_image(row, SCOPE, REPOSITORIES, PROJECTS, current)
    return result, current, calls


def detectors(monkeypatch, *, hit=False):
    def scan(data, path, timeout, **kwargs):
        leaks = []
        if hit and b'first child secret' in data:
            leaks = [{'fingerprint': 'a' * 64,
                'detectors': [{'engine': 'kingfisher', 'rule': 'synthetic'}],
                'locations': [{'path': path, 'line': 1}]}]
        return {'complete': True, 'engines': [
            {'engine': 'kingfisher', 'status': 'complete', 'version': inspection.native.KINGFISHER_VERSION},
            {'engine': 'trufflehog', 'status': 'complete', 'version': inspection.native.TRUFFLEHOG_VERSION}],
            'leaks': leaks}
    monkeypatch.setattr(inspection.native, 'scan_content', scan)


@pytest.mark.parametrize('hit,status', [(False, 'PASS'), (True, 'FAIL')])
def test_both_platforms_reach_registered_image_consumer(monkeypatch, hit, status):
    detectors(monkeypatch, hit=hit)
    row, blobs = two_platforms()
    content, current, calls = inspect(row, blobs)
    row[inspection.native.MARKER] = content
    assert content['complete'] is True, (content, current.transport.evidence)
    assert len(content['children']) == 2
    assert [part['platform']['architecture'] for part in content['graph']['children']] == ['amd64', 'arm64']
    assert len(calls) == 1 + 2 * 3
    assert len(current.transport.evidence) == len(calls)
    assert review.evaluate_index_content(content, row['uri'], REPO, row['digest'], SCOPE)[0] == status
    verdict, evidence = review.evaluate(row, index(row))
    assert verdict == status
    assert len(evidence.get('secret_leaks', [])) == int(hit)
    assert 'first child secret' not in repr(content) + repr(evidence)


def test_docker_manifest_list_uses_same_bounded_child_path(monkeypatch):
    detectors(monkeypatch)
    row, blobs = two_platforms(oci.DOCKER_LIST)
    content, _, _ = inspect(row, blobs)
    row[inspection.native.MARKER] = content
    assert content['graph']['media_type'] == oci.DOCKER_LIST
    assert review.evaluate(row, index(row))[0] == 'PASS'


def test_later_child_denial_preserves_verified_positive(monkeypatch):
    detectors(monkeypatch, hit=True)
    row, blobs = two_platforms()
    denied = json.loads(blobs[row['digest']])['manifests'][1]['digest']
    content, _, _ = inspect(row, blobs, deny=denied)
    row[inspection.native.MARKER] = content
    assert content['status'] == 'partial' and not content['complete']
    assert len(content['children']) == 1 and len(content['leaks']) == 1
    assert review.evaluate(row, index(row))[0] == 'FAIL'


@pytest.mark.parametrize('damage', ['parent', 'child', 'platform'])
def test_mismatched_parent_child_or_platform_never_pass(monkeypatch, damage):
    detectors(monkeypatch)
    row, blobs = two_platforms()
    if damage == 'parent':
        blobs[row['digest']] = b'{}'
    elif damage == 'child':
        child = json.loads(blobs[row['digest']])['manifests'][1]['digest']
        blobs[child] = b'{}'
    else:
        parent = json.loads(blobs[row['digest']])
        parent['manifests'][1]['platform']['architecture'] = 'amd64'
        raw = encoded(parent)
        old = row['digest']
        row['digest'] = digest(raw)
        row['name'] = row['name'].replace(quote(old, safe=''), quote(row['digest'], safe=''))
        row['uri'] = row['uri'].replace(old, row['digest'])
        blobs[row['digest']] = raw
    content, _, _ = inspect(row, blobs)
    row[inspection.native.MARKER] = content
    assert review.evaluate(row, index(row))[0] == 'UNKNOWN'


def test_cancelled_child_keeps_incomplete(monkeypatch):
    detectors(monkeypatch)
    row, blobs = two_platforms()
    calls = [0]
    def cancel():
        calls[0] += 1
        if calls[0] > 20:
            raise RuntimeError('cancelled')
    content, _, _ = inspect(row, blobs, cancel=cancel)
    row[inspection.native.MARKER] = content
    assert content['complete'] is False
    assert review.evaluate(row, index(row))[0] == 'UNKNOWN'


def test_existing_single_leaf_still_passes(monkeypatch):
    detectors(monkeypatch)
    row, blobs = image(body=b'clean')
    content, _, _ = inspect(row, blobs)
    row[inspection.native.MARKER] = content
    assert 'graph' not in content
    assert review.evaluate(row, index(row))[0] == 'PASS'


def indexed_blob(reference, blobs):
    """Wrap one real leaf fixture in two platform descriptors in the same repo."""
    first_digest = reference.rsplit('@', 1)[1]
    first_raw = blobs[first_digest]
    second_doc = json.loads(first_raw)
    config = json.loads(blobs[second_doc['config']['digest']])
    config['architecture'] = 'arm64'
    config_raw = encoded(config)
    second_doc['config']['digest'] = digest(config_raw)
    second_doc['config']['size'] = len(config_raw)
    second_raw = encoded(second_doc)
    blobs[digest(config_raw)] = config_raw
    blobs[digest(second_raw)] = second_raw
    parent = encoded({'schemaVersion': 2, 'mediaType': oci.OCI_INDEX,
        'manifests': [{'mediaType': inspection.native.OCI, 'digest': child_digest,
            'size': len(raw), 'platform': {'os': 'linux', 'architecture': arch}}
            for child_digest, raw, arch in ((first_digest, first_raw, 'amd64'),
                (digest(second_raw), second_raw, 'arm64'))]})
    blobs[digest(parent)] = parent
    return reference.rsplit('@', 1)[0] + '@' + digest(parent)


@pytest.mark.parametrize('hit,status', [(False, 'PASS'), (True, 'FAIL')])
def test_workerpool_native_index_to_consumer(monkeypatch, hit, status):
    import test_gcp_workerpool_native_content_20261021 as worker
    original = worker.fixture
    def fixture(secret=False, extra_layer=False, config_secret=False):
        selection, bodies, blobs = original(secret, extra_layer, config_secret)
        reference = indexed_blob(selection['immutable_reference'], blobs)
        selection['immutable_reference'] = reference
        bodies[1]['containers'][0]['image'] = reference
        bodies[4]['uri'] = reference
        bodies[4]['mediaType'] = oci.OCI_INDEX
        bodies[4]['name'] = worker.REPO + '/dockerImages/' + quote(
            reference.rsplit('/', 1)[1], safe='')
        return selection, bodies, blobs
    monkeypatch.setattr(worker, 'fixture', fixture)
    result, _ = worker.collect_case(monkeypatch, secret=hit)
    verdict, evidence = worker.evaluate_result(result)
    assert verdict == status, evidence
    assert len(result['rows'][0]['content']['children']) == 2
    assert 'TESTSECRET' not in repr(result) + repr(evidence)


@pytest.mark.parametrize('hit,status', [(False, 'PASS'), (True, 'FAIL')])
def test_flex_native_index_to_consumer(monkeypatch, hit, status):
    import test_gcp_appengine_flex_image_native_20261021 as flex
    original = flex.fixture
    def fixture(secret=False, extra=False, config_secret=False):
        target, version, bodies, blobs = original(secret, extra, config_secret)
        reference = indexed_blob(target['immutable_reference'], blobs)
        target['immutable_reference'] = reference
        version['deployment']['container']['image'] = reference
        bodies[2]['uri'] = reference
        bodies[2]['mediaType'] = oci.OCI_INDEX
        bodies[2]['name'] = flex.REPO + '/dockerImages/' + quote(
            reference.rsplit('/', 1)[1], safe='')
        return target, version, bodies, blobs
    monkeypatch.setattr(flex, 'fixture', fixture)
    result, transport, _, _ = flex.collect_case(monkeypatch, secret=hit)
    item, evidence_index = flex.item_index(result, transport)
    verdict, evidence = flex.review.evaluate(item, evidence_index, flex.selection.SECRET_KIND)
    assert verdict == status, evidence
    assert len(result['rows'][0]['content']['children']) == 2
    assert 'TESTSECRET' not in repr(result) + repr(evidence)


def test_workerpool_index_private_source_is_selected_parent_and_verified_child(monkeypatch):
    import test_gcp_workerpool_native_content_20261021 as worker
    from peaso import secret_evidence
    original = worker.fixture
    def fixture(secret=False, extra_layer=False, config_secret=False):
        selection, bodies, blobs = original(secret, extra_layer, config_secret)
        reference = indexed_blob(selection['immutable_reference'], blobs)
        selection['immutable_reference'] = reference
        bodies[1]['containers'][0]['image'] = reference
        bodies[4].update(uri=reference, mediaType=oci.OCI_INDEX,
            name=worker.REPO + '/dockerImages/' + quote(reference.rsplit('/', 1)[1], safe=''))
        return selection, bodies, blobs
    monkeypatch.setattr(worker, 'fixture', fixture)
    cipher = secret_evidence.EphemeralCipher()
    with secret_evidence.capture(cipher, tenant='offline', scan_id='gcp-index') as sink:
        result, _ = worker.collect_case(monkeypatch, secret=True)
        assert worker.evaluate_result(result)[0] == 'FAIL'
        records = [cipher.decrypt(raw) for raw in sink.records.values()]
    assert records
    parent = result['rows'][0]['selection']['immutable_reference'].rsplit('@', 1)[1]
    children = {part['digest'] for part in result['rows'][0]['content']['graph']['children']}
    identity = worker.REV + '#container=0'
    assert all(location['resource_id'] == identity and location['scope'] == worker.SCOPE
        and location['image_digest'] in children and location['layer'].startswith('sha256:')
        and location['source'].endswith('@' + parent)
        for record in records for location in record['locations'])
    assert parent not in children
    assert 'TESTSECRET' not in repr(result)
