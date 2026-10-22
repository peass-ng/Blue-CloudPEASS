"""Independent native HTTP -> collector -> installed consumer, offline only."""
from copy import deepcopy
import base64
import gzip
import io
import json
from pathlib import Path
import socket
from types import SimpleNamespace
from urllib.parse import urlsplit
import pytest
from peaso import collectors, engine, secret_scanning as scanning
from peaso.collectors import gcp
from peaso.collectors import gcp_selected_task_routine_secret_indicators as source
from peaso.checks import gcp_task_routine_secret_review_20261020 as checks

SCOPE = 'projects/review'
TASK = SCOPE + '/locations/us-central1/queues/example/tasks/selected_task'
ROUTINE = SCOPE + '/datasets/example/routines/selected_routine'
NAMES = {source.TASK_KIND: TASK, source.ROUTINE_KIND: ROUTINE}
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'synthetic-oauth-canary'


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*args, **kwargs):
        pytest.fail('socket/DNS is forbidden in this offline review')
    monkeypatch.setattr(socket.socket, 'connect', blocked)
    monkeypatch.setattr(socket.socket, 'connect_ex', blocked)
    monkeypatch.setattr(socket, 'create_connection', blocked)
    monkeypatch.setattr(socket, 'getaddrinfo', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


class Response:
    def __init__(self, payload, status=200, headers=None):
        self.payload = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.content = self.payload
        self.stream = io.BytesIO(self.payload)
        self.status_code, self.raw, self.closed = status, self, False
        self.headers = {'Content-Type': 'application/json', 'Content-Length': str(len(self.payload)), **(headers or {})}
        self.url, self.history = '', []

    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)

    def close(self):
        self.closed = True

    def json(self, **kwargs):
        return json.loads(self.payload, **kwargs)


def native(kind, payload=b'ready = true\n', *, target='httpRequest'):
    name = NAMES[kind]
    if kind == source.TASK_KIND:
        return {'name': name, 'view': 'FULL', target: {
            'body': base64.b64encode(payload).decode(), 'headers': {'Content-Type': 'text/plain'},
            'url' if target == 'httpRequest' else 'relativeUri': 'https://example.invalid/never-follow' if target == 'httpRequest' else '/never-execute'}}
    return {'routineReference': {'projectId': 'review', 'datasetId': 'example', 'routineId': 'selected_routine'},
            'routineType': 'SCALAR_FUNCTION', 'language': 'SQL', 'definitionBody': payload.decode()}


def capture(monkeypatch, kind, *, data=None, response=None, mocked=True, options=None, parent=None,
            parent_status=200, names=None, collect=True):
    scanning._RESULTS.clear()
    spec = source.SPECS[kind]
    names = names or [NAMES[kind]]
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [kind], spec['option']: names,
            'metrics_scopes': False, 'include_inherited': False, 'concurrency': 1, 'retries': 0, **(options or {})}
    seen, calls, responses, closed, auth = [], [], [], [], []
    if mocked:
        def detector(raw, path, timeout):
            seen.append((raw, path, timeout))
            return [(TOKEN, 'synthetic-github', 1)] if TOKEN.encode() in raw else []
        monkeypatch.setattr(scanning, '_scan_kingfisher', detector)
        monkeypatch.setattr(scanning, '_scan_trufflehog', detector)
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + AUTH}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    c = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts}, requirements=[kind, 'project'], transport=transport)
    project = parent or {'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'}
    def request(method, url, **kw):
        import requests
        calls.append((method, url, deepcopy(kw)))
        parsed = urlsplit(url)
        assert method == 'GET' and parsed.scheme == 'https' and not parsed.query and not parsed.fragment
        if not kw.get('stream'):
            assert (parsed.netloc, parsed.path) in {
                ('cloudresourcemanager.googleapis.com', '/v3/' + SCOPE),
                ('compute.googleapis.com', '/compute/v1/' + SCOPE)}
            if parsed.netloc == 'cloudresourcemanager.googleapis.com':
                return Response(project, status=parent_status)
            return Response({'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}})
        assert (parsed.netloc, parsed.path) == (urlsplit(spec['base']).netloc, urlsplit(spec['base']).path + names[len(responses)])
        assert kw['params'] == ({'responseView': 'FULL'} if kind == source.TASK_KIND else {})
        assert kw['allow_redirects'] is False and kw['headers'] == {
            'Authorization': 'Bearer ' + AUTH, 'Accept': 'application/json',
            'Accept-Encoding': 'identity', 'Cache-Control': 'no-store'}
        assert 0 < kw['timeout'] <= 20
        result = deepcopy(response) if response is not None else Response(data if data is not None else native(kind))
        if len(names) > 1 and isinstance(data, dict):
            adjusted = deepcopy(data)
            if kind == source.TASK_KIND:
                adjusted['name'] = names[len(responses)]
            else:
                adjusted['routineReference']['routineId'] = names[len(responses)].split('/')[-1]
            result = Response(adjusted)
        result.url = getattr(result, 'final_url', requests.Request(method, url, params=kw.get('params')).prepare().url)
        responses.append(result)
        return result
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    monkeypatch.setattr(source.git, '_session', lambda: SimpleNamespace(request=request, close=lambda: closed.append(True)))
    result = c.collect() if collect else c
    return result, SimpleNamespace(c=c, calls=calls, responses=responses, closed=closed, auth=auth, seen=seen)


def findings(snapshot, kind):
    return engine.evaluate_snapshot(snapshot, checks=[source.SPECS[kind]['check']])['findings']


def index_of(snapshot, kind):
    env = next(e for e in snapshot['collections'] if e['type'] == kind)
    item = env['items'][0]
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': snapshot['metadata']},
             'collections': {k: [e for e in snapshot['collections'] if e['type'] == k] for k in (kind, 'project')}}
    return item, index


@pytest.mark.parametrize('kind', NAMES)
def test_native_complete_clean_and_hidden_leak(monkeypatch, kind):
    for payload, expected in [(b'ready = true\n', 'PASS'), (('token=' + TOKEN + '\n').encode(), 'FAIL')]:
        with monkeypatch.context() as patch:
            snapshot, trace = capture(patch, kind, data=native(kind, payload))
            result = findings(snapshot, kind)
            assert len(result) == 1 and result[0]['status'] == expected, result
            item, index = index_of(snapshot, kind)
            assert checks.evaluate(item, index, kind=kind)[1]['coverage'] == 'selected_observed_content_only'
            assert all(r.closed for r in trace.responses) and len(trace.closed) == 1
            assert len(trace.seen) == (4 if kind == source.TASK_KIND else 2)
            assert all(0 < timeout <= 10 for _, _, timeout in trace.seen)
            persisted = json.dumps([snapshot, result, trace.c.transport.evidence]) + repr(trace.c.transport.cache)
            assert AUTH not in persisted and TOKEN not in persisted and 'ready = true' not in persisted
            assert NAMES[kind] not in persisted and 'never-follow' not in persisted
            assert all(m == 'GET' for m, _, _ in trace.calls)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('positive', [False, True])
def test_real_both_scanners_complete_and_unverified(monkeypatch, kind, positive):
    payload = ('token=' + TOKEN + '\n').encode() if positive else b'ready = true\n'
    snapshot, trace = capture(monkeypatch, kind, data=native(kind, payload), mocked=False)
    result = findings(snapshot, kind)
    assert len(result) == 1 and result[0]['status'] == ('FAIL' if positive else 'PASS'), result
    item, index = index_of(snapshot, kind)
    parts = checks.evaluate(item, index, kind=kind)[1]['parts']
    assert all({(e['engine'], e['version'], e['status']) for e in p['engines']} == {
        ('kingfisher', '1.4.0', 'complete'), ('trufflehog', '3.92.5', 'complete')} for p in parts)
    assert result[0]['evidence']['credential_validation'] == 'not_attempted'
    if positive:
        leak, = result[0]['evidence']['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps([snapshot, result]) and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('code', [401, 403, 404, 410, 429, 500])
def test_denied_deleted_unavailable_never_clean(monkeypatch, kind, code):
    snapshot, trace = capture(monkeypatch, kind, response=Response({'error': {'message': TOKEN}}, code))
    assert {r['status'] for r in findings(snapshot, kind)} == {'UNKNOWN'}
    assert trace.seen == [] and all(r.closed for r in trace.responses)
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('options', [{}, {'content_secret_scans': False}, {'content_secret_scans': 'true'},
    {'content_secret_scans': True, '_content_secret_scan_kinds': []},
    {'content_secret_scans': True, '_content_secret_scan_kinds': 'bad'}])
def test_disabled_unselected_without_content_reads(monkeypatch, kind, options):
    if not options:
        options = {'content_secret_scans': False, '_content_secret_scan_kinds': []}
    if options.get('content_secret_scans') == 'true':
        with pytest.raises(ValueError, match='boolean'):
            capture(monkeypatch, kind, options=options)
        return
    snapshot, trace = capture(monkeypatch, kind, options=options)
    assert not trace.responses and not trace.seen
    assert {f['status'] for f in findings(snapshot, kind)} == {'UNKNOWN'}


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('mutation', ['empty', 'duplicate', 'nine', 'foreign', 'number', 'url', 'traversal', 'encoded', 'fragment', 'wrong_type', 'multi_scope', 'no_scope'])
def test_selection_rejected_before_auth(monkeypatch, kind, mutation):
    name = NAMES[kind]
    rows, scopes = [name], [SCOPE]
    if mutation == 'empty': rows = []
    if mutation == 'duplicate': rows *= 2
    if mutation == 'nine': rows = [name + str(n) for n in range(9)]
    if mutation == 'foreign': rows = [name.replace('/review/', '/foreign/')]
    if mutation == 'number': rows = [name.replace('/review/', '/10001/')]
    if mutation == 'url': rows = ['https://example.invalid/' + name]
    if mutation == 'traversal': rows = [name.rsplit('/', 1)[0] + '/../private']
    if mutation == 'encoded': rows = [name + '%2fprivate']
    if mutation == 'fragment': rows = [name + '#private']
    if mutation == 'wrong_type': rows = [{'name': name}]
    if mutation == 'multi_scope': scopes += ['projects/foreign']
    if mutation == 'no_scope': scopes = []
    opts = {source.SPECS[kind]['option']: rows}
    monkeypatch.setattr(gcp, 'Credentials', lambda *a, **k: pytest.fail('invalid selector reached auth'))
    with pytest.raises(ValueError):
        gcp.GCPCollector({'provider': 'gcp', 'scopes': scopes, 'options': opts}, requirements=[kind])
    with pytest.raises(ValueError):
        engine.collect_snapshot({'connector': {'provider': 'gcp', 'scopes': scopes, 'options': opts}, 'checks': [source.SPECS[kind]['check']]})


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('parent,status', [({'name': 'projects/10001', 'projectId': 'foreign'}, 200),
    ({'name': 'projects/10001', 'projectId': 'review', 'projectNumber': '99999'}, 200),
    ({'name': 'projects/10001', 'projectId': 'review'}, 403)])
def test_project_foreign_denied_unbound_never_reads_content(monkeypatch, kind, parent, status):
    snapshot, trace = capture(monkeypatch, kind, parent=parent, parent_status=status)
    assert {f['status'] for f in findings(snapshot, kind)} <= {'UNKNOWN', 'DENIED'}
    assert not trace.responses and not trace.seen


TASK_MUTATIONS = ['basic', 'missing_view', 'missing_body', 'bad_base64', 'binary', 'oversize', 'wrong_name',
                  'no_target', 'both_targets', 'bad_headers', 'duplicate_headers', 'unsupported_target']
@pytest.mark.parametrize('mutation', TASK_MUTATIONS)
def test_full_task_omitted_partial_invalid_never_clean(monkeypatch, mutation):
    data = native(source.TASK_KIND)
    target = data['httpRequest']
    if mutation == 'basic': data['view'] = 'BASIC'
    if mutation == 'missing_view': data.pop('view')
    if mutation == 'missing_body': target.pop('body')
    if mutation == 'bad_base64': target['body'] = 'aA'
    if mutation == 'binary': target['body'] = base64.b64encode(b'\x00private').decode()
    if mutation == 'oversize': target['body'] = base64.b64encode(b'x' * (source.MAX_CONTENT + 1)).decode()
    if mutation == 'wrong_name': data['name'] = TASK + 'foreign'
    if mutation == 'no_target': data.pop('httpRequest')
    if mutation == 'both_targets': data['appEngineHttpRequest'] = deepcopy(target)
    if mutation == 'bad_headers': target['headers'] = {'X-Key': 'value\nprivate'}
    if mutation == 'duplicate_headers': target['headers'] = {'X-Key': 'one', 'x-key': 'two'}
    if mutation == 'unsupported_target': data = {'name': TASK, 'view': 'FULL', 'pullMessage': {'payload': 'private'}}
    snapshot, trace = capture(monkeypatch, source.TASK_KIND, data=data)
    assert {f['status'] for f in findings(snapshot, source.TASK_KIND)} == {'UNKNOWN'}
    assert not trace.seen and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('mutation', ['missing', 'empty', 'binary', 'oversize', 'foreign', 'wrong_dataset', 'wrong_routine',
    'wrong_type', 'wrong_language', 'remote', 'spark'])
def test_routine_omitted_partial_external_invalid_never_clean(monkeypatch, mutation):
    data = native(source.ROUTINE_KIND)
    if mutation == 'missing': data.pop('definitionBody')
    if mutation == 'empty': data['definitionBody'] = ''
    if mutation == 'binary': data['definitionBody'] = '\x00private'
    if mutation == 'oversize': data['definitionBody'] = 'x' * (source.MAX_CONTENT + 1)
    if mutation == 'foreign': data['routineReference']['projectId'] = 'foreign'
    if mutation == 'wrong_dataset': data['routineReference']['datasetId'] = 'foreign'
    if mutation == 'wrong_routine': data['routineReference']['routineId'] = 'foreign'
    if mutation == 'wrong_type': data['routineType'] = 'ROUTINE_TYPE_UNSPECIFIED'
    if mutation == 'wrong_language': data['language'] = 'NEW_LANGUAGE'
    if mutation == 'remote': data['remoteFunctionOptions'] = {'endpoint': 'https://example.invalid/never-follow'}
    if mutation == 'spark': data['sparkOptions'] = {'mainFileUri': 'gs://private/never-read'}
    snapshot, trace = capture(monkeypatch, source.ROUTINE_KIND, data=data)
    assert {f['status'] for f in findings(snapshot, source.ROUTINE_KIND)} == {'UNKNOWN'}
    assert not trace.seen


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('mutation', ['mime', 'compressed', 'range', 'length', 'truncated', 'wire_limit', 'actual_limit',
                                    'redirect', 'history', 'duplicate_json', 'json_array', 'non_json'])
def test_native_response_integrity(monkeypatch, kind, mutation):
    response = Response(native(kind))
    if mutation == 'mime': response.headers['Content-Type'] = 'text/plain'
    if mutation == 'compressed': response.headers['Content-Encoding'] = 'gzip'
    if mutation == 'range': response.headers['Content-Range'] = 'bytes 0-1/10'
    if mutation == 'length': response.headers['Content-Length'] = '-1'
    if mutation == 'truncated': response.headers['Content-Length'] = str(len(response.payload) + 1)
    if mutation == 'wire_limit': response.headers['Content-Length'] = str(source.MAX_WIRE + 1)
    if mutation == 'actual_limit': response = Response(b' ' * (source.MAX_WIRE + 1)); response.headers.pop('Content-Length')
    if mutation == 'redirect': response.final_url = 'https://example.invalid/private'
    if mutation == 'history': response.history = [object()]
    if mutation == 'duplicate_json': response = Response(b'{"name":"one","name":"two"}')
    if mutation == 'json_array': response = Response(b'[]')
    if mutation == 'non_json': response = Response(b'not-json-private')
    snapshot, trace = capture(monkeypatch, kind, response=response)
    assert {f['status'] for f in findings(snapshot, kind)} == {'UNKNOWN'}
    assert not trace.seen and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('failed', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('positive', [False, True])
def test_unavailable_engine_is_unresolved_even_with_other_detection(monkeypatch, kind, failed, positive):
    c, trace = capture(monkeypatch, kind, collect=False,
        data=native(kind, ('token=' + TOKEN).encode() if positive else b'clean'))
    def unavailable(*args):
        raise ImportError('private-exception-' + TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + failed, unavailable)
    snapshot = c.collect()
    result, = findings(snapshot, kind)
    assert result['status'] == ('FAIL' if positive else 'UNKNOWN')
    if positive:
        evidence = result['evidence']
        item, index = index_of(snapshot, kind)
        assert item[source.MARKER]['reason'] == 'detector_unavailable'
        assert evidence['complete'] is False
        status, native_evidence = checks.evaluate(item, index, kind=kind)
        assert status == 'FAIL' and native_evidence['coverage'] == 'partial_selected_observed_content_only'
        assert {d['engine'] for leak in native_evidence['secret_leaks'] for d in leak['detectors']} == ({'kingfisher', 'trufflehog'} - {failed})
    assert TOKEN not in json.dumps(snapshot)


@pytest.mark.parametrize('kind', NAMES)
def test_exact_named_opt_in_and_no_broad_selection(monkeypatch, kind):
    captured = []
    def collect(connector, requirements):
        from peaso.snapshot import make_snapshot
        captured.append((deepcopy(connector), set(requirements)))
        return make_snapshot('gcp', [SCOPE], [])
    monkeypatch.setattr(collectors, 'collect_live', collect)
    connector = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {'content_secret_scans': True,
        source.SPECS[kind]['option']: [NAMES[kind]]}}
    engine.collect_snapshot({'connector': connector, 'checks': [source.SPECS[kind]['check']]})
    bound, requirements = captured.pop()
    assert bound['options']['_content_secret_scan_kinds'] == [kind]
    assert {kind, 'project'} <= requirements
    for selector in ({}, {'categories': ['hardening']}, {'frameworks': ['HackTricks Cloud Best Practices']}):
        engine.collect_snapshot({'connector': connector, **selector})
        bound, _ = captured.pop()
        assert kind not in bound['options']['_content_secret_scan_kinds']


@pytest.mark.parametrize('kind', NAMES)
def test_eight_selected_resources_are_individually_bound(monkeypatch, kind):
    names = [NAMES[kind] + str(n) for n in range(8)]
    snapshot, trace = capture(monkeypatch, kind, data=native(kind), names=names)
    result = findings(snapshot, kind)
    assert len(result) == 8 and {r['status'] for r in result} == {'PASS'}, result
    assert len(trace.responses) == 8 and all(r.closed for r in trace.responses)


@pytest.mark.parametrize('kind', NAMES)
def test_shared_redacted_cache_does_not_reread(monkeypatch, kind):
    snapshot, trace = capture(monkeypatch, kind)
    calls = len(trace.calls)
    row = source.collect_sources(trace.c, SCOPE, kind)[0]
    assert row[source.MARKER]['complete'] is True and len(trace.calls) == calls
    assert TOKEN not in repr(trace.c.transport._task_routine_secret_state)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('mutation', ['authorization', 'selection', 'foreign_scope', 'part_missing', 'engine_missing',
    'engine_wrong_version', 'complete', 'reason', 'receipt_missing', 'receipt_method', 'receipt_route', 'receipt_owner',
    'ledger_missing', 'parent_ledger', 'coverage', 'row_provenance', 'project_alias', 'project_coverage', 'duplicate_row'])
def test_consumer_does_not_trust_unbound_markers(monkeypatch, kind, mutation):
    snapshot, trace = capture(monkeypatch, kind)
    item, index = index_of(snapshot, kind)
    m = item[source.MARKER]
    if mutation == 'authorization': index['context']['metadata'][kind + '_authorized'] = False
    if mutation == 'selection': index['context']['metadata'][kind + '_selection'] = [kind + ':' + '0' * 64]
    if mutation == 'foreign_scope': m['scope'] = 'projects/foreign'
    if mutation == 'part_missing': m['parts'].pop()
    if mutation == 'engine_missing': m['parts'][0]['engines'].pop()
    if mutation == 'engine_wrong_version': m['parts'][0]['engines'][0]['version'] = '0.0.0'
    if mutation == 'complete': m['complete'] = False
    if mutation == 'reason': m['reason'] = 'unavailable'
    if mutation == 'receipt_missing': m['read_receipts'] = []
    if mutation == 'receipt_method': m['read_receipts'][0]['method'] = 'POST'
    if mutation == 'receipt_route': m['read_receipts'][0]['route'] = 'arbitrary'
    if mutation == 'receipt_owner': m['read_receipts'][0]['resource_id'] = 'foreign'
    if mutation == 'ledger_missing': index['context']['metadata']['source_requests'] = []
    if mutation == 'parent_ledger': index['context']['metadata']['source_requests'][0]['url'] = 'https://example.invalid/private'
    if mutation == 'coverage': item['_coverage'][source.MARKER]['status'] = 'unknown'
    if mutation == 'row_provenance': item['_provenance']['source_requests'] = []
    if mutation == 'project_alias': index['collections']['project'][0]['items'][0]['projectId'] = 'foreign'
    if mutation == 'project_coverage': index['collections']['project'][0]['items'][0]['_coverage'] = {'projectId': {'status': 'denied'}}
    if mutation == 'duplicate_row': index['collections'][kind][0]['items'].append(deepcopy(item))
    assert checks.evaluate(item, index, kind=kind)[0] == 'UNKNOWN'


def test_appengine_payload_and_sql_default_are_supported(monkeypatch):
    snapshot, _ = capture(monkeypatch, source.TASK_KIND, data=native(source.TASK_KIND, target='appEngineHttpRequest'))
    assert findings(snapshot, source.TASK_KIND)[0]['status'] == 'PASS'
    data = native(source.ROUTINE_KIND); data.pop('language')
    snapshot, _ = capture(monkeypatch, source.ROUTINE_KIND, data=data)
    assert findings(snapshot, source.ROUTINE_KIND)[0]['status'] == 'PASS'


def test_both_ids_registered_with_narrow_dependencies():
    from peaso.checks import CHECKS
    for kind, spec in source.SPECS.items():
        check, = [c for c in CHECKS if c.id == spec['check']]
        assert check.kind == kind and check.dependencies == ['project', kind]
        assert kind in gcp.CONTENT_ONLY_TYPES and kind in engine.BULK_STREAM_TYPES['gcp']


@pytest.mark.parametrize('kind', NAMES)
def test_real_runner_flags_disable_validation_and_external_reads(monkeypatch, kind):
    calls = []
    original = scanning._run
    def run(argv, payload, timeout):
        calls.append(list(argv))
        return original(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', run)
    snapshot, _ = capture(monkeypatch, kind, data=native(kind, ('token=' + TOKEN).encode()), mocked=False)
    assert findings(snapshot, kind)[0]['status'] == 'FAIL'
    runs = [args for args in calls if 'stdin' in args]
    assert runs
    for argv in runs:
        assert {'stdin', '--json', '--no-verification', '--no-update', '--no-verification-cache',
                '--force-skip-archives', '--fail-on-scan-errors', '--concurrency=1'} <= set(argv)


@pytest.mark.parametrize('kind', NAMES)
def test_aggregate_budget_deadline_and_call_limit_preserve_unknown(monkeypatch, kind):
    with monkeypatch.context() as patch:
        patch.setattr(source, 'MAX_TOTAL', 1)
        snapshot, trace = capture(patch, kind)
        assert findings(snapshot, kind)[0]['status'] == 'UNKNOWN' and not trace.seen
    with monkeypatch.context() as patch:
        c, trace = capture(patch, kind, collect=False)
        c.transport.max_calls = 2  # Native CRM and Compute parent calls consume this budget.
        snapshot = c.collect()
        assert findings(snapshot, kind)[0]['status'] == 'UNKNOWN' and not trace.responses
    with monkeypatch.context() as patch:
        c, trace = capture(patch, kind, collect=False)
        c.transport._task_routine_secret_state = {'lock': __import__('threading').Lock(), 'items': {},
            'deadline': source.time.monotonic() - 1, 'bytes': 0}
        snapshot = c.collect()
        assert findings(snapshot, kind)[0]['status'] == 'UNKNOWN' and not trace.responses


@pytest.mark.parametrize('language', ['SQL', 'JAVASCRIPT', 'PYTHON', 'JAVA', 'SCALA'])
def test_inline_routine_languages_do_not_follow_libraries(monkeypatch, language):
    data = native(source.ROUTINE_KIND)
    data.update(language=language, importedLibraries=['gs://private/never-read.js'])
    snapshot, trace = capture(monkeypatch, source.ROUTINE_KIND, data=data)
    assert findings(snapshot, source.ROUTINE_KIND)[0]['status'] == 'PASS'
    assert len(trace.responses) == 1
    assert 'never-read' not in json.dumps(snapshot)


def test_headers_are_selected_literals_and_managed_auth_is_not_dereferenced(monkeypatch):
    data = native(source.TASK_KIND)
    data['httpRequest']['headers']['Authorization'] = 'Bearer ' + TOKEN
    data['httpRequest']['oidcToken'] = {'serviceAccountEmail': 'reference@review.iam.gserviceaccount.com'}
    snapshot, trace = capture(monkeypatch, source.TASK_KIND, data=data)
    result = findings(snapshot, source.TASK_KIND)
    assert len(result) == 1 and result[0]['status'] == 'FAIL'
    assert result[0]['evidence']['secret_leaks'][0]['locations'][0]['path'].endswith('.headers')
    assert len(trace.responses) == 1 and TOKEN not in json.dumps([snapshot, result])


def test_two_surfaces_deduplicate_the_same_hidden_value(monkeypatch):
    from peaso.secret_findings import deduplicate_secret_findings
    rows = []
    for kind in NAMES:
        snapshot, _ = capture(monkeypatch, kind, data=native(kind, ('token=' + TOKEN).encode()))
        rows.extend(findings(snapshot, kind))
    result = deduplicate_secret_findings(rows)
    assert len(result) == 1 and result[0]['status'] == 'FAIL'
    assert set(result[0]['linked_check_ids']) == {s['check'] for s in source.SPECS.values()}
    assert TOKEN not in json.dumps(result)


@pytest.mark.parametrize('kind', NAMES)
@pytest.mark.parametrize('case,expected', [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')])
def test_native_produced_registry_cases(kind, case, expected):
    from peaso.checks import evaluate_check
    from peaso.checks.fixtures import CASES
    cid = source.SPECS[kind]['check']
    fixture = CASES[cid]
    index = fixture.get(case + '_index', fixture['index'])
    assert evaluate_check(cid, deepcopy(fixture[case]), deepcopy(index))[0] == expected
    encoded = json.dumps(fixture)
    assert TOKEN not in encoded and AUTH not in encoded and NAMES[kind] not in encoded
