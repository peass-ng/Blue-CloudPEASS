"""Native mocked streaming HTTP through real GCPCollector/Transport seams.

The production job and registry are installed; native API responses are mocked.
Only the two final tests execute installed detection-only engines, on fake data.
"""
from copy import deepcopy
import io
import json
from types import SimpleNamespace
from urllib.parse import quote

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_selected_object_secret_indicators as adapter
from peaso.checks import gcp_selected_object_secret_review_20261019 as check
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
BUCKET = 'selected-review-bucket'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'


def target(name='config/settings.env', scope=SCOPE):
    return {'project_scope': scope, 'bucket': BUCKET, 'object': name, 'generation': '1234'}


class Raw:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)
        self.reads = []

    def read(self, amount, *, decode_content):
        assert decode_content is False
        self.reads.append(amount)
        return self.stream.read(amount)


class Response:
    def __init__(self, payload, headers=None, status=200):
        self.raw = Raw(payload)
        self.headers = {'Content-Length': str(len(payload)), **(headers or {})}
        self.status_code = status
        self.closed = False

    def close(self):
        self.closed = True

    def json(self):
        pytest.fail('raw or error response must never enter JSON transport cache')


def responses(payload=b'STAGE=production\n', obj=None, mime='text/plain'):
    obj = obj or target()
    metadata = {'bucket': obj['bucket'], 'name': obj['object'], 'generation': obj['generation'],
                'size': str(len(payload)), 'contentType': mime}
    return [Response(json.dumps(metadata).encode(), {'Content-Type': 'application/json'}),
            Response(payload, {'Content-Type': mime, 'X-Goog-Generation': obj['generation']})]


def fixture(monkeypatch, replies=None, targets=None, options=None):
    opts = {'inventories': ['project', 'bucket', adapter.KIND], 'include_inherited': False,
            'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
            adapter.OPTION: targets or [target()], 'concurrency': 1, 'retries': 0}
    opts.update(options or {})
    credentials_calls, calls = [], []
    def headers():
        credentials_calls.append(True)
        return {'Authorization': 'Bearer fake-transport-credential'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    pending = list(replies if replies is not None else responses())
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
        assert kwargs['headers']['Accept-Encoding'] == 'identity'
        assert 0 < kwargs['timeout'] <= 20
        return pending.pop(0)
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
                                requirements=[adapter.KIND, 'project', 'bucket'], transport=transport)
    collector.collections[('project', SCOPE)] = {'coverage_status': 'collected',
        'items': [{'name': 'projects/10001', 'projectId': 'review'}]}
    collector.collections[('bucket', SCOPE)] = {'coverage_status': 'collected',
        'items': [{'name': BUCKET, 'projectNumber': '10001'}]}
    return collector, calls, credentials_calls


def index(row, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {
        adapter.KIND: [{'scope': SCOPE, 'status': status, 'items': [row]}]}}


@pytest.fixture(autouse=True)
def cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


@pytest.mark.parametrize('options', [
    {'content_secret_scans': False},
    {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': ['function']},
])
def test_default_no_optin_or_named_kind_performs_zero_additional_calls(monkeypatch, options):
    collector, calls, auth = fixture(monkeypatch, options=options)
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('unexpected scan'))
    assert adapter.collect_selected_objects(collector, SCOPE) == []
    assert calls == auth == []
    assert collector.transport.calls == 0


def test_non_boolean_optin_rejected_before_credentials_or_http(monkeypatch):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('invalid intake reached credentials or HTTP')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    monkeypatch.setattr(gcp.Transport, '_session', forbidden)
    with pytest.raises(ValueError, match='^content_secret_scans must be a boolean$'):
        gcp.GCPCollector({'scopes': [SCOPE], 'options': {'content_secret_scans': 'true',
            'inventories': [adapter.KIND], '_content_secret_scan_kinds': [adapter.KIND],
            adapter.OPTION: [target()]}}, [adapter.KIND])
    assert calls == []


def test_exact_native_read_then_clean_consumer_and_redacted_reuse(monkeypatch, clean):
    replies = responses()
    collector, calls, auth = fixture(monkeypatch, replies)
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'PASS'
    assert len(calls) == len(auth) == collector.transport.calls == 2
    assert calls[0][1] == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/o/' + quote(target()['object'], safe='')
    assert calls[0][2]['params'] == {'generation': '1234', 'ifGenerationMatch': '1234',
                                     'fields': adapter.FIELDS, 'projection': 'noAcl'}
    assert calls[1][2]['params'] == {'generation': '1234', 'ifGenerationMatch': '1234', 'alt': 'media'}
    assert all(response.closed for response in replies)
    assert collector.transport.cache == {}
    assert 'settings.env' not in json.dumps([row, collector.transport.evidence])
    assert adapter.collect_selected_objects(collector, SCOPE) == [row]
    assert len(calls) == 2  # only the redacted result is reused
    envelope = collector.envelope(adapter.KIND, SCOPE, 'storage',
                                 lambda: adapter.collection_pages(collector, SCOPE))
    native_row, = envelope['items']
    native_index = {'context': {'provider': 'gcp', 'scope': SCOPE},
                    'collections': {adapter.KIND: [envelope]}}
    assert check.evaluate(native_row, native_index)[0] == 'PASS'
    assert set(envelope['source_requests']) == {e['id'] for e in collector.transport.evidence}


@pytest.mark.parametrize('mutation', ['foreign_scope', 'duplicate', 'too_many', 'bad_generation', 'unsafe_name'])
def test_invalid_selection_rejected_before_credentials(monkeypatch, mutation):
    targets = [target()]
    if mutation == 'foreign_scope': targets[0]['project_scope'] = 'projects/other'
    if mutation == 'duplicate': targets *= 2
    if mutation == 'too_many': targets = [target(str(i)) for i in range(11)]
    if mutation == 'bad_generation': targets[0]['generation'] = '1234&alt=media'
    if mutation == 'unsafe_name': targets[0]['object'] = 'unsafe\nname'
    collector, calls, auth = fixture(monkeypatch, targets=targets)
    with pytest.raises(adapter.Incomplete):
        adapter.collect_selected_objects(collector, SCOPE)
    assert calls == auth == []


@pytest.mark.parametrize('mutation', ['project_denied', 'bucket_denied', 'project_foreign', 'bucket_foreign',
                                    'missing_native_name', 'nonnumeric_native_name', 'legacy_conflict', 'legacy_only'])
def test_native_project_bucket_binding_required_before_credentials(monkeypatch, mutation):
    collector, calls, auth = fixture(monkeypatch)
    if mutation == 'project_denied': collector.collections[('project', SCOPE)]['coverage_status'] = 'denied'
    if mutation == 'bucket_denied': collector.collections[('bucket', SCOPE)]['coverage_status'] = 'partial'
    if mutation == 'project_foreign': collector.collections[('project', SCOPE)]['items'][0]['projectId'] = 'other'
    if mutation == 'bucket_foreign': collector.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '20002'
    if mutation == 'missing_native_name': del collector.collections[('project', SCOPE)]['items'][0]['name']
    if mutation == 'nonnumeric_native_name': collector.collections[('project', SCOPE)]['items'][0]['name'] = SCOPE
    if mutation == 'legacy_conflict': collector.collections[('project', SCOPE)]['items'][0]['projectNumber'] = '20002'
    if mutation == 'legacy_only':
        row = collector.collections[('project', SCOPE)]['items'][0]
        del row['name']
        row['projectNumber'] = '10001'
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert calls == auth == []


def collect_native_pipeline(monkeypatch, payload=b'STAGE=production\n', *, media_status=200, scope=SCOPE):
    """The installed dependent job and ordinary scope_jobs/collect stay real.

    CRM v3 metadata deliberately has NO projectNumber. Bucket metadata, Compute
    hydration and bucket IAM all flow through the ordinary JSON HTTP transport.
    """
    selected = target(scope=scope)
    options = {'inventories': ['project', 'bucket', adapter.KIND], 'include_inherited': False,
               'metrics_scopes': False, 'concurrency': 1, 'retries': 0,
               'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
               adapter.OPTION: [selected]}
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fake'},
                                             close=lambda: None), options)
    calls, streamed = [], responses(payload, obj=selected)
    streamed[1].status_code = media_status
    class MetadataResponse:
        status_code = 200
        headers = {}
        def __init__(self, data):
            self.data = data
            self.content = json.dumps(data).encode("utf-8")
        def json(self): return deepcopy(self.data)
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        assert method == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + scope:
            return MetadataResponse({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
        if url == 'https://compute.googleapis.com/compute/v1/' + scope:
            return MetadataResponse({'name': 'review', 'id': '10001'})
        if url == 'https://storage.googleapis.com/storage/v1/b':
            assert kwargs['params']['project'] == scope.split('/', 1)[1]
            return MetadataResponse({'items': [{'name': BUCKET, 'projectNumber': '10001'}]})
        if url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/iam':
            return MetadataResponse({'version': 1, 'bindings': []})
        assert url == 'https://storage.googleapis.com/storage/v1/b/' + BUCKET + '/o/' + quote(selected['object'], safe='')
        assert kwargs['stream'] is True and kwargs['allow_redirects'] is False
        return streamed[1] if kwargs['params'].get('alt') == 'media' else streamed[0]
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
    collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [scope], 'options': options},
                                requirements=[adapter.KIND, 'project', 'bucket'], transport=transport)
    snapshot = collector.collect()
    envelope = next(e for e in snapshot['collections'] if e['type'] == adapter.KIND)
    row, = envelope['items']
    collections = {}
    for entry in snapshot['collections']:
        collections.setdefault(entry['type'], []).append(entry)
    context = {'context': {'provider': 'gcp', 'scope': scope}, 'collections': collections}
    return row, context, snapshot, calls, streamed


@pytest.mark.parametrize('scope', [SCOPE, 'projects/10001'])
def test_actual_collect_crm_v3_bucket_stream_to_callback(monkeypatch, clean, scope):
    row, context, snapshot, calls, streamed = collect_native_pipeline(monkeypatch, scope=scope)
    assert check.evaluate(row, context)[0] == 'PASS'
    project = next(e for e in snapshot['collections'] if e['type'] == 'project')['items'][0]
    assert project['name'] == 'projects/10001' and project['projectId'] == 'review'
    assert 'projectNumber' not in project
    assert len(calls) == 6 and all(r.closed for r in streamed)
    media = next(c for c in calls if (c[2].get('params') or {}).get('alt') == 'media')
    assert media[2]['params']['generation'] == media[2]['params']['ifGenerationMatch'] == '1234'


def test_matching_optional_legacy_number_does_not_replace_native_name(monkeypatch, clean):
    collector, calls, _ = fixture(monkeypatch)
    collector.collections[('project', SCOPE)]['items'][0]['projectNumber'] = '10001'
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'PASS' and len(calls) == 2


@pytest.mark.parametrize('case', [
    'redirect', 'denied', 'metadata_generation', 'metadata_size', 'media_generation',
    'missing_length', 'wrong_length', 'overlong', 'encoded', 'partial_content',
    'binary_type', 'archive', 'invalid_utf8', 'binary_bytes', 'stream_error',
    'media_redirect', 'media_denied', 'truncated', 'metadata_encoding', 'foreign_name',
    'customer_encryption', 'media_type',
])
def test_native_incomplete_and_unsupported_never_scan_or_pass(monkeypatch, case):
    replies = responses()
    if case in ('redirect', 'denied'):
        replies[0] = Response(TOKEN.encode(), {'Location': 'https://example.invalid/' + TOKEN},
                              status=302 if case == 'redirect' else 403)
    if case in ('metadata_generation', 'metadata_size'):
        data = json.loads(replies[0].raw.stream.getvalue())
        data['generation' if case == 'metadata_generation' else 'size'] = '999999999'
        replies[0] = Response(json.dumps(data).encode())
    if case == 'media_generation': replies[1].headers['X-Goog-Generation'] = '9999'
    if case == 'missing_length': del replies[1].headers['Content-Length']
    if case == 'wrong_length': replies[1].headers['Content-Length'] = '1'
    if case == 'overlong': replies[1].raw = Raw(b'STAGE=production\n' + TOKEN.encode())
    if case == 'encoded': replies[1].headers['Content-Encoding'] = 'gzip'
    if case == 'partial_content': replies[1].headers['Content-Range'] = 'bytes 0-1/100'
    if case == 'binary_type': replies = responses(b'payload', mime='application/octet-stream')
    if case == 'archive': replies = responses(b'PK\x03\x04' + b'archive', mime='text/plain')
    if case == 'invalid_utf8': replies = responses(b'\xff\xfe', mime='text/plain')
    if case == 'binary_bytes': replies = responses(b'a\x00b', mime='text/plain')
    if case == 'stream_error':
        def broken(*a, **k): raise OSError(TOKEN)
        replies[1].raw.read = broken
    if case in ('media_redirect', 'media_denied'):
        replies[1] = Response(TOKEN.encode(), status=302 if case == 'media_redirect' else 403)
    if case == 'truncated': replies[1].raw = Raw(b'STAGE')
    if case == 'metadata_encoding': replies[0].headers['Content-Encoding'] = 'gzip'
    if case in ('foreign_name', 'customer_encryption'):
        data = json.loads(replies[0].raw.stream.getvalue())
        data.update({'name': 'foreign.env'} if case == 'foreign_name' else {'customerEncryption': {'encryptionAlgorithm': 'AES256'}})
        replies[0] = Response(json.dumps(data).encode())
    if case == 'media_type': replies[1].headers['Content-Type'] = 'application/octet-stream'
    collector, calls, auth = fixture(monkeypatch, replies)
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('invalid bytes scanned'))
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert len(calls) <= 2 and len(auth) == len(calls)
    assert all(r.closed for r in replies[:len(calls)])
    if case in ('redirect', 'denied'):
        assert not replies[0].raw.reads  # no diagnostic/error-body consumption
    assert TOKEN not in json.dumps([row, collector.transport.evidence]) + repr(collector.transport.cache)


def test_cancellation_during_stream_closes_response_and_never_scans(monkeypatch):
    replies = responses()
    collector, _, _ = fixture(monkeypatch, replies)
    read = replies[1].raw.read
    timeouts = []
    replies[1].raw._fp = SimpleNamespace(fp=SimpleNamespace(raw=SimpleNamespace(
        _sock=SimpleNamespace(settimeout=timeouts.append))))
    def cancelled(*args, **kwargs):
        collector.transport.options['_cancel_check'] = lambda: True
        return read(*args, **kwargs)
    replies[1].raw.read = cancelled
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('cancelled scan'))
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert replies[1].closed and timeouts and all(0 < t <= 20 for t in timeouts)


def test_stream_and_total_budget_enforced_before_accumulation(monkeypatch, clean):
    replies = responses(b'a' * adapter.MAX_OBJECT_BYTES)
    replies[1].raw = Raw(b'a' * (adapter.MAX_OBJECT_BYTES + 1))
    collector, calls, _ = fixture(monkeypatch, replies)
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert row[adapter.MARKER]['reason'] == 'oversize'
    assert max(replies[1].raw.reads) <= 16384
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    # A later exact object may not bypass a scan-wide budget by starting anew.
    collector, calls, _ = fixture(monkeypatch, responses(), targets=[target('second.env')])
    collector.transport._selected_object_secret_state = {'started': adapter.time.monotonic(),
        'bytes': adapter.MAX_TOTAL_BYTES, 'calls': 0, 'lock': adapter.threading.Lock(), 'items': {}}
    # Bind metadata to this second selection, then reject before media.
    reply = responses(obj=target('second.env'))[0]
    monkeypatch.setattr(collector.transport, '_session', lambda: SimpleNamespace(request=lambda *a, **k: (calls.append(True) or reply)))
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert row[adapter.MARKER]['reason'] == 'total_byte_limit' and len(calls) == 1


@pytest.mark.parametrize('case', ['call_budget', 'cancelled', 'deadline', 'one_engine'])
def test_transport_budgets_cancel_and_tool_failures_produce_unknown(monkeypatch, clean, case):
    collector, calls, _ = fixture(monkeypatch)
    if case == 'call_budget': collector.transport.max_calls = 1
    if case == 'cancelled': collector.transport.options['_cancel_check'] = lambda: True
    if case == 'deadline': collector.transport.deadline_seconds = 0
    if case == 'one_engine':
        def unavailable(*a): raise OSError(TOKEN)
        monkeypatch.setattr(scanning, '_scan_trufflehog', unavailable)
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert len(calls) <= (2 if case == 'one_engine' else 1)
    assert TOKEN not in json.dumps([row, collector.transport.evidence])


def test_pure_check_rejects_unbound_and_tampered_producer_evidence(monkeypatch, clean):
    collector, _, _ = fixture(monkeypatch)
    row, = adapter.collect_selected_objects(collector, SCOPE)
    assert check.evaluate(row, index(row, 'partial'))[0] == 'UNKNOWN'
    altered = deepcopy(row)
    altered[adapter.MARKER]['scope'] = 'projects/other'
    assert check.evaluate(altered, index(altered))[0] == 'UNKNOWN'
    altered = deepcopy(row)
    altered[adapter.MARKER]['engines'][1] = deepcopy(altered[adapter.MARKER]['engines'][0])
    assert check.evaluate(altered, index(altered))[0] == 'UNKNOWN'


@pytest.fixture(scope='module')
def installed_engines():
    pytest.importorskip('kingfisher_sdk')
    assert scanning._trufflehog()


def test_real_dual_tools_one_hidden_leak_across_two_native_objects(installed_engines, monkeypatch, capsys):
    targets = [target('one.env'), target('two.env')]
    replies = sum((responses(('TOKEN=' + TOKEN + '\n').encode(), obj=t) for t in targets), [])
    collector, calls, _ = fixture(monkeypatch, replies, targets=targets)
    commands, run = [], scanning._run
    def record(argv, payload, timeout):
        commands.append(argv)
        return run(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', record)
    rows = adapter.collect_selected_objects(collector, SCOPE)
    findings = []
    for row in rows:
        status, evidence = check.evaluate(row, index(row))
        assert status == 'FAIL'
        findings.append({'provider': 'gcp', 'check_id': check.CHECK_ID, 'scope': SCOPE,
            'resource_id': row['name'], 'native_resource_id': row['name'], 'resource_type': adapter.KIND,
            'status': status, 'finding_type': 'secrets', 'frameworks': [], 'evidence': evidence})
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1 and len(calls) == 4
    leak, = merged[0]['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert len(leak['locations']) == 2
    assert {loc['resource_id'] for loc in leak['locations']} == {r['name'] for r in rows}
    assert all({'--no-verification', '--no-update', '--no-verification-cache', '--force-skip-archives'} <= set(argv)
               for argv in commands if 'stdin' in argv)
    assert any('stdin' in argv for argv in commands)
    assert TOKEN not in json.dumps([rows, merged, collector.transport.evidence]) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert all(r.closed for r in replies) and collector.transport.cache == {}


def test_real_dual_tools_clean_full_native_text_observation(installed_engines, monkeypatch):
    collector, calls, _ = fixture(monkeypatch)
    row, = adapter.collect_selected_objects(collector, SCOPE)
    status, evidence = check.evaluate(row, index(row))
    assert status == 'PASS' and evidence['complete'] and not evidence['secret_leaks']
    assert len(calls) == 2
