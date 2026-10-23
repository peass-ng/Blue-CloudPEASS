"""Direct offline tests; callable with pytest.MonkeyPatch without pytest runner."""
from copy import deepcopy
import base64
import gzip
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import zipfile

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_cloudbuild_artifact_secret_indicators as adapter
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_cloudbuild_artifact_secret_review_20261019 as check
from peaso import secret_scanning as scanning

SCOPE = 'projects/review'
NAME = SCOPE + '/locations/us-central1/builds/12345678-abcd-1234-abcd-123456789abc'
BUCKET = 'review-artifact-bucket'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        self.payload = json.dumps(value).encode() if raw is None else raw
        self.content = self.payload
        self.raw = self
        self.stream = io.BytesIO(self.payload)
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.payload)), 'Content-Type': 'application/json', **(headers or {})}
        self.closed = False
        self.reads = []

    def read(self, n, *, decode_content):
        assert decode_content is False and 0 < n <= 16384
        self.reads.append(n)
        return self.stream.read(n)

    def close(self):
        self.closed = True

    def json(self):
        return json.loads(self.payload)


def build():
    return {'name': NAME, 'id': NAME.split('/')[-1], 'projectId': 'review', 'status': 'SUCCESS',
            'createTime': '2026-10-19T10:00:00Z', 'startTime': '2026-10-19T10:00:01Z',
            'finishTime': '2026-10-19T10:00:05Z', 'results': {'artifactManifest': 'gs://' + BUCKET + '/out/artifacts-' + NAME.split('/')[-1] + '.json'}}


def record(name='out/result.txt', generation='20001', bucket=BUCKET):
    # Match the official Go JSON writer, including base64 of gsutil MD5 bytes.
    value = base64.b64encode(base64.b64encode(b'0' * 16)).decode()
    return {'location': 'gs://' + bucket + '/' + name + '#' + generation,
            'file_hash': [{'file_hash': [{'type': 2, 'value': value}]}]}


def metadata(name, payload, generation, mime='text/plain', bucket=BUCKET):
    return {'bucket': bucket, 'name': name, 'generation': generation,
            'size': str(len(payload)), 'contentType': mime}


def replies(payload=b'build completed\n', *, source=None, manifest=None, mime='text/plain', name='out/result.txt'):
    native = source if source is not None else build()
    manifest_payload = manifest if manifest is not None else (json.dumps(record(name)) + '\n').encode()
    manifest_name = 'out/artifacts-' + NAME.split('/')[-1] + '.json'
    mm = metadata(manifest_name, manifest_payload, '10001', 'application/json')
    am = metadata(name, payload, '20001', mime)
    return [Response(native), Response(mm), Response(raw=manifest_payload, headers={'X-Goog-Generation': '10001'}),
            Response(am), Response(am), Response(raw=payload, headers={'Content-Type': mime, 'X-Goog-Generation': '20001'})]


def fixture(monkeypatch, responses=None, *, options=None, mock_engines=True):
    scanning._RESULTS.clear()
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **kw: pytest.fail('unmocked socket'))
    if mock_engines:
        monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
        monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], adapter.OPTION: [NAME],
            'metrics_scopes': False, 'include_inherited': False, 'concurrency': 1, 'retries': 0, **(options or {})}
    auth = []
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer fake-transport-canary'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    c = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
                         requirements=['project', 'bucket'], transport=transport)
    pending = list(responses if responses is not None else replies())
    calls, received = [], []
    def request(method, url, **kw):
        calls.append((method, url, kw))
        assert method == 'GET'
        if kw.get('stream'):
            assert kw['allow_redirects'] is False
            assert kw['headers']['Accept-Encoding'] == 'identity'
            assert 0 < kw['timeout'] <= transport.timeout
            assert url.startswith(('https://cloudbuild.googleapis.com/v1/', 'https://storage.googleapis.com/storage/v1/'))
            response = pending.pop(0)
            response.json = lambda: pytest.fail('content passed through JSON cache')
            received.append(response)
        elif url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            response = Response({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        elif url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
            response = Response({'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}})
        elif url == 'https://storage.googleapis.com/storage/v1/b':
            response = Response({'items': [{'name': BUCKET, 'projectNumber': '10001'}]})
        elif url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            response = Response({'version': 1, 'bindings': []})
        else:
            pytest.fail('unexpected endpoint: ' + url)
        return response
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    for kind, scope, service, fetch in c.scope_jobs(SCOPE):
        if kind in ('project', 'bucket'):
            c.collections[(kind, scope)] = c.envelope(kind, scope, service, fetch)
    return c, calls, received, pending, auth


def produce(c):
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    row, = env['items']
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(c)},
             'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]],
                             'bucket': [c.collections[('bucket', SCOPE)]]}}
    return row, index


def test_clean_native_exact_generation_reads(monkeypatch):
    c, calls, received, pending, _ = fixture(monkeypatch)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', row
    assert evidence['coverage'] == 'observed_manifest_generations_only'
    assert evidence['historical_build_bytes'] == 'not_established'
    assert len(row[adapter.MARKER]['read_receipts']) == 6 and len(evidence['source_requests']) == 8
    streams = [(m, u, kw) for m, u, kw in calls if kw.get('stream')]
    assert len(streams) == 6 and not pending and all(r.closed for r in received)
    assert streams[0][2]['params'] == {'fields': adapter.BUILD_FIELDS}
    assert all(kw['params'].get('generation') == '20001' and kw['params'].get('ifGenerationMatch') == '20001' for _, _, kw in streams[3:])
    assert streams[2][2]['params'] == {'generation': '10001', 'ifGenerationMatch': '10001', 'alt': 'media'}
    persisted = json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
    assert 'build completed' not in persisted and 'gs://' not in persisted and 'out/result.txt' not in persisted


def test_disabled_and_malformed_selection_no_reads(monkeypatch):
    for options in ({'content_secret_scans': False}, {'_content_secret_scan_kinds': []},
                    {adapter.OPTION: []}, {adapter.OPTION: [NAME, NAME]},
                    {adapter.OPTION: ['projects/other/locations/us-central1/builds/a']},
                    {adapter.OPTION: [NAME + '?x=1']}, {adapter.OPTION: [NAME] * 3}):
        with monkeypatch.context() as mp:
            if adapter.OPTION in options:
                with pytest.raises(ValueError):
                    fixture(mp, options=options)
                continue
            c, calls, _, _, auth = fixture(mp, options=options)
            before = len(auth)
            rows = adapter.collect_sources(c, SCOPE)
            assert not any(kw.get('stream') for _, _, kw in calls) and len(auth) == before
            assert not rows or rows[0][adapter.MARKER]['complete'] is False


def test_native_build_rejections(monkeypatch):
    for mutation in ('foreign_project', 'running', 'future_start', 'wrong_name', 'input_only', 'declared_only', 'external', 'signed', 'glob', 'bad_generation'):
        native = build()
        if mutation == 'foreign_project': native['projectId'] = 'other'
        if mutation == 'running': native['status'] = 'WORKING'
        if mutation == 'future_start': native['startTime'] = '2026-10-20T00:00:00Z'
        if mutation == 'wrong_name': native['name'] = NAME + 'x'
        if mutation == 'input_only': native['source'] = {'storageSource': {'bucket': BUCKET, 'object': 'input.zip', 'generation': '1'}}; native.pop('results')
        if mutation == 'declared_only': native['results'] = {'numArtifacts': '1'}
        if mutation == 'external': native['results']['artifactManifest'] = 'https://external.example/a'
        if mutation == 'signed': native['results']['artifactManifest'] += '?X-Goog-Signature=canary'
        if mutation == 'glob': native['results']['artifactManifest'] = 'gs://' + BUCKET + '/*.json'
        if mutation == 'bad_generation': native['results']['artifactManifest'] += '#0'
        with monkeypatch.context() as mp:
            c, calls, _, _, _ = fixture(mp, replies(source=native))
            row, ix = produce(c)
            assert check.evaluate(row, ix)[0] == 'UNKNOWN', mutation
            assert len([kw for _, _, kw in calls if kw.get('stream')]) == 1, mutation


def test_manifest_layout_and_provenance_rejections(monkeypatch):
    valid = record()
    mutations = [b'', b'[]', json.dumps([valid]).encode(), b'{"location":',
        b'{"location":"a","location":"b","file_hash":[]}',
        (json.dumps(valid) + '\n' + json.dumps(valid)).encode(),
        ('\n'.join(json.dumps(record('out/' + str(i))) for i in range(5))).encode()]
    for key, value in [('location', 'gs://' + BUCKET + '/out/a'), ('location', 'https://host/a#2'),
                       ('location', 'gs://foreign-bucket/a#2'), ('location', 'gs://' + BUCKET + '/out/../a#2'),
                       ('location', 'gs://' + BUCKET + '/a?token=x#2'), ('location', 'gs://' + BUCKET + '/a%2fb#2'),
                       ('file_hash', [{'file_hash': [{'type': 1, 'value': 'AA=='}]}])]:
        mutations.append(json.dumps({**valid, key: value}).encode())
    for manifest in mutations:
        with monkeypatch.context() as mp:
            c, calls, _, _, _ = fixture(mp, replies(manifest=manifest))
            row, ix = produce(c)
            assert check.evaluate(row, ix)[0] == 'UNKNOWN', manifest
            assert len([kw for _, _, kw in calls if kw.get('stream')]) <= 3


def test_transport_and_native_binding_fail_closed(monkeypatch):
    for mutation in ('missing_project', 'project_coverage', 'project_receipt', 'foreign_bucket', 'bucket_coverage',
                     'manifest_403', 'manifest_redirect', 'manifest_range', 'manifest_oversize', 'manifest_truncated',
                     'artifact_generation', 'artifact_type', 'media_generation', 'media_truncated', 'media_range', 'call_limit', 'cancel'):
        responses = replies()
        if mutation == 'manifest_403': responses[1].status_code = 403
        if mutation == 'manifest_redirect': responses[1].status_code = 302; responses[1].headers['Location'] = 'https://external.example'
        if mutation == 'manifest_range': responses[2].headers['Content-Range'] = 'bytes 0-1/4'
        if mutation == 'manifest_oversize':
            meta = json.loads(responses[1].payload); meta['size'] = str(adapter.MAX_MANIFEST_BYTES + 1); responses[1] = Response(meta)
        if mutation == 'manifest_truncated': responses[2].headers['Content-Length'] = str(len(responses[2].payload) + 1)
        if mutation == 'artifact_generation':
            meta = json.loads(responses[3].payload); meta['generation'] = '3'; responses[3] = Response(meta)
        if mutation == 'artifact_type':
            meta = json.loads(responses[3].payload); meta['contentType'] = 'application/octet-stream'; responses[3] = Response(meta)
        if mutation == 'media_generation': responses[5].headers['X-Goog-Generation'] = '3'
        if mutation == 'media_truncated': responses[5].stream = io.BytesIO(b'part')
        if mutation == 'media_range': responses[5].headers['Content-Range'] = 'bytes 0-1/4'
        with monkeypatch.context() as mp:
            c, calls, _, _, _ = fixture(mp, responses)
            if mutation == 'missing_project': c.collections[('project', SCOPE)]['items'] = []
            if mutation == 'project_coverage': c.collections[('project', SCOPE)]['items'][0]['_coverage'] = {'projectId': {'status': 'unknown'}}
            if mutation == 'project_receipt': c.collections[('project', SCOPE)]['items'][0]['_provenance']['source_requests'] = ['request-999']
            if mutation == 'foreign_bucket': c.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '999'
            if mutation == 'bucket_coverage': c.collections[('bucket', SCOPE)]['items'][0]['_coverage'] = {'projectNumber': {'status': 'unknown'}}
            if mutation == 'call_limit': c.transport.max_calls = c.transport.calls
            if mutation == 'cancel': mp.setattr(c.transport, 'check_cancelled', lambda: (_ for _ in ()).throw(objects.Incomplete('cancelled')))
            row, ix = produce(c)
            assert check.evaluate(row, ix)[0] == 'UNKNOWN', mutation
            if mutation in ('missing_project', 'project_coverage', 'project_receipt', 'call_limit', 'cancel'):
                assert not any(kw.get('stream') for _, _, kw in calls), mutation


def test_consumer_receipts_and_nested_scans_are_independently_validated(monkeypatch):
    c, _, _, _, _ = fixture(monkeypatch)
    row, ix = produce(c)
    assert check.evaluate(row, ix)[0] == 'PASS'
    for mutation in ('scope', 'complete', 'authorization', 'receipt_owner', 'receipt_status', 'receipt_http', 'receipt_duplicate',
                     'receipt_missing', 'native_missing', 'provenance_missing', 'coverage', 'foreign_selected', 'one_engine', 'wrong_version', 'historical_claim', 'artifact_generation', 'manifest_generation', 'bucket_hash'):
        item, index = deepcopy((row, ix))
        index['collections'][adapter.KIND][0]['items'] = [item]
        m = item[adapter.MARKER]
        if mutation == 'scope': m['scope'] = 'projects/other'
        if mutation == 'complete': m['complete'] = False
        if mutation == 'authorization': index['context']['metadata']['cloudbuild_artifact_source_authorized'] = False
        if mutation == 'receipt_owner': m['read_receipts'][0]['resource_id'] = 'foreign'
        if mutation == 'receipt_status': m['read_receipts'][0]['status'] = 'unavailable'
        if mutation == 'receipt_http': m['read_receipts'][0]['http_status'] = 206
        if mutation == 'receipt_duplicate': m['read_receipts'][1]['id'] = m['read_receipts'][0]['id']
        if mutation == 'receipt_missing': m['read_receipts'].pop()
        if mutation == 'native_missing': m['native_requests'].pop()
        if mutation == 'provenance_missing': item['_provenance']['source_requests'] = []
        if mutation == 'coverage': item['_coverage'][adapter.MARKER]['status'] = 'unknown'
        if mutation == 'foreign_selected': m['artifacts'][0]['selected']['name'] = 'gcs-selected-object:' + 'f' * 64
        if mutation == 'one_engine': m['artifacts'][0]['selected'][objects.MARKER]['engines'].pop()
        if mutation == 'wrong_version': m['artifacts'][0]['selected'][objects.MARKER]['engines'][0]['version'] = 'unknown'
        if mutation == 'historical_claim': m['historical_build_bytes'] = 'established'
        if mutation == 'artifact_generation': m['artifacts'][0]['generation'] = '999'
        if mutation == 'manifest_generation': m['manifest']['generation'] = '999'
        if mutation == 'bucket_hash': m['artifacts'][0]['bucket_sha256'] = 'f' * 64
        assert check.evaluate(item, index)[0] == 'UNKNOWN', mutation


def test_supported_zip_archive_reuses_selected_archive_reader(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('report.txt', 'build completed successfully\n')
    c, calls, _, pending, _ = fixture(monkeypatch, replies(buf.getvalue(), mime='application/zip', name='out/result.zip'))
    row, ix = produce(c)
    status, evidence = check.evaluate(row, ix)
    assert status == 'PASS', row
    assert evidence['artifacts'][0]['format'] == 'zip' and not pending
    assert evidence['artifacts'][0]['inspection']['files'][0]['path'] == 'archive.member-1'
    assert len([kw for _, _, kw in calls if kw.get('stream')]) == 6


def test_real_pinned_offline_kingfisher_trufflehog(monkeypatch):
    for payload, expected in ((('token="' + TOKEN + '"\n').encode(), 'FAIL'), (b'build completed successfully\n', 'PASS')):
        with monkeypatch.context() as mp:
            c, _, _, _, _ = fixture(mp, replies(payload), mock_engines=False)
            row, ix = produce(c)
            status, evidence = check.evaluate(row, ix)
            assert status == expected, row
            inspection = evidence['artifacts'][0]['inspection']
            assert {e['engine'] for e in inspection['engines']} == {'kingfisher', 'trufflehog'}
            if expected == 'FAIL':
                assert {d['engine'] for d in inspection['secret_leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
            assert TOKEN not in json.dumps([row, ix, evidence, c.transport.evidence]) + repr(c.transport.cache) + repr(scanning._RESULTS)


def test_fixture_and_uninstalled_idempotent_consumer():
    import peaso.checks as checks
    from peaso.checks.fixtures import CASES
    path = Path(check.__file__).with_name('gcp_cloudbuild_artifact_secret_review_20261019_fixtures.json.gz')
    cases = json.loads(gzip.decompress(path.read_bytes()))
    assert len(cases) >= 4 and path.stat().st_size < 12000
    for key, expected in (('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')):
        assert check.evaluate(cases[key], cases[key + '_index'])[0] == expected
    original_checks, original_cases = list(checks.CHECKS), deepcopy(CASES)
    try:
        check.install(); check.install()
        assert sum(c.id == check.CHECK_ID for c in checks.CHECKS) == 1
        assert CASES[check.CHECK_ID] == cases
    finally:
        checks.CHECKS[:] = original_checks
        CASES.clear(); CASES.update(original_cases)


def test_all_manifest_records_required_and_bounded(monkeypatch):
    manifest = (json.dumps(record()) + '\n' + json.dumps(record('out/second.txt', '20002')) + '\n').encode()
    responses = replies(manifest=manifest)
    extra = metadata('out/second.txt', b'second\n', '20002')
    responses.extend([Response(extra), Response(extra), Response(raw=b'second\n', headers={'Content-Type': 'text/plain', 'X-Goog-Generation': '20002'})])
    with monkeypatch.context() as mp:
        c, calls, _, pending, _ = fixture(mp, responses)
        row, ix = produce(c)
        assert check.evaluate(row, ix)[0] == 'PASS', row
        assert len(row[adapter.MARKER]['artifacts']) == 2 and not pending
        assert len([kw for _, _, kw in calls if kw.get('stream')]) == 9
    for mutation in ('unsupported_second', 'partial_second', 'calls_exhausted'):
        responses = replies(manifest=manifest)
        responses.extend([Response({**extra, 'contentType': 'application/octet-stream'} if mutation == 'unsupported_second' else extra),
                          Response(extra), Response(raw=b'part', headers={'Content-Type': 'text/plain', 'X-Goog-Generation': '20002'})])
        with monkeypatch.context() as mp:
            c, _, _, _, _ = fixture(mp, responses)
            if mutation == 'calls_exhausted': c.transport.max_calls = c.transport.calls + 7
            row, ix = produce(c)
            assert check.evaluate(row, ix)[0] == 'UNKNOWN', mutation


def test_archive_unsupported_members_and_detector_failure_unknown(monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as z:
        z.writestr('executable.bin', b'\x00\x01\x02')
    with monkeypatch.context() as mp:
        c, _, _, _, _ = fixture(mp, replies(buf.getvalue(), mime='application/zip', name='out/result.zip'))
        row, ix = produce(c)
        assert check.evaluate(row, ix)[0] == 'UNKNOWN'
    with monkeypatch.context() as mp:
        c, _, _, _, _ = fixture(mp)
        mp.setattr(scanning, '_scan_trufflehog', lambda *a: (_ for _ in ()).throw(RuntimeError('private provider error')))
        row, ix = produce(c)
        assert check.evaluate(row, ix)[0] == 'UNKNOWN'
        assert 'private provider error' not in json.dumps([row, ix])


def test_explicit_manifest_metadata_and_total_byte_caps(monkeypatch):
    for mutation in ('metadata_stream_cap', 'media_overlong', 'compressed_encoding', 'total_bytes'):
        responses = replies()
        if mutation == 'metadata_stream_cap':
            responses[1] = Response(raw=b' ' * (objects.MAX_METADATA_BYTES + 100))
            del responses[1].headers['Content-Length']
        if mutation == 'media_overlong': responses[2].stream = io.BytesIO(responses[2].payload + b'x')
        if mutation == 'compressed_encoding': responses[2].headers['Content-Encoding'] = 'gzip'
        with monkeypatch.context() as mp:
            c, _, _, _, _ = fixture(mp, responses)
            if mutation == 'total_bytes':
                import threading, time
                c.transport._selected_object_secret_state = {'started': time.monotonic(), 'bytes': objects.MAX_TOTAL_BYTES,
                    'calls': 0, 'lock': threading.Lock(), 'items': {}}
            row, ix = produce(c)
            assert check.evaluate(row, ix)[0] == 'UNKNOWN', mutation
            if mutation == 'metadata_stream_cap': assert responses[1].stream.tell() == objects.MAX_METADATA_BYTES + 1
