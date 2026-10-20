"""Mocked native HTTPS streams, actual producer/predicate and pinned detectors."""
import base64
from copy import deepcopy
import importlib.util
import inspect
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

from peaso.collectors import gcp
from peaso.collectors import gcp_dataform_secret_indicators as adapter
from peaso.checks import gcp_dataform_secret_review_20261019 as check
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
REPO = SCOPE + '/locations/us-central1/repositories/review'
SHA = 'a' * 40
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
OTHER = 'ghp_' + '2Yt9Ec5Zp0Ru6Wq1Aa8Kd3Vx7Mn4Bs5Hj9Lf'
PROPOSALS = Path('/tmp/peasso-gcp-review-20261019/dataform-secret-proposals')


def target(workspace=False, revision=False, path='definitions/config.sqlx'):
    row = {'project_scope': SCOPE, 'repository': REPO, 'path': path}
    if workspace:
        row['workspace'] = REPO + '/workspaces/review'
        if revision:
            row['revision'] = SHA
    else:
        row['commit_sha'] = SHA
    return row


class Raw:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)
        self.reads = []

    def read(self, size, *, decode_content):
        assert decode_content is False
        self.reads.append(size)
        return self.stream.read(size)


class Response:
    def __init__(self, value=None, *, raw=None, status=200, headers=None):
        payload = json.dumps(value).encode() if raw is None else raw
        self.raw = Raw(payload)
        self.status_code = status
        self.headers = {'Content-Length': str(len(payload)), 'Content-Type': 'application/json', **(headers or {})}
        self.url, self.history, self.closed = None, [], False

    def close(self):
        self.closed = True

    def json(self):
        pytest.fail('raw file/metadata must never enter Transport JSON parsing/cache')


def responses(t=None, payload=b'SELECT 1;\n'):
    t = t or target()
    rows = [Response({'name': t['repository']})]
    if 'workspace' in t:
        rows.append(Response({'name': t['workspace']}))
    rows.append(Response({'fileContents' if 'workspace' in t else 'contents': base64.b64encode(payload).decode()}))
    return rows


def fixture(monkeypatch, replies=None, targets=None, options=None, collector_class=None):
    targets = [target()] if targets is None else targets
    options = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
               adapter.OPTION: targets, 'include_inherited': False, 'metrics_scopes': False,
               'concurrency': 1, 'retries': 0, **(options or {})}
    calls, auth, sessions = [], [], []
    pending = list(responses() if replies is None else replies)
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer synthetic-auth-canary'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), options)
    class Session:
        trust_env, auth, closed = True, 'must be cleared', False
        def request(self, method, url, **kw):
            assert self.trust_env is False and self.auth is None
            assert kw['stream'] and kw['allow_redirects'] is False
            assert kw['headers']['Accept-Encoding'] == 'identity'
            assert 0 < kw['timeout'] <= transport.timeout
            calls.append((method, url, kw))
            r = pending.pop(0)
            if r.url is None:
                r.url = requests.Request(method, url, params=kw.get('params')).prepare().url
            return r
        def close(self): self.closed = True
    def session():
        result = Session()
        sessions.append(result)
        return result
    monkeypatch.setattr(requests, 'Session', session)
    if collector_class:
        cls = collector_class
    else:
        cls = gcp.GCPCollector
    collector = cls({'provider': 'gcp', 'scopes': [SCOPE], 'options': options},
                    requirements=[adapter.KIND, 'project'] if collector_class else ['project'], transport=transport)
    collector.collections[('project', SCOPE)] = {'coverage_status': 'collected', 'items': [
        {'name': 'projects/123456789', 'projectId': 'review'}]}
    return collector, calls, auth, sessions


def index(row, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {
        adapter.KIND: [{'scope': SCOPE, 'status': status, 'items': [row],
                        'source_requests': row[adapter.MARKER]['source_requests']}]}}


@pytest.fixture(autouse=True)
def cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'content_secret_scans': 'true'},
                                    {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': ['function']}])
def test_default_unselected_zero_calls_auth_sessions_and_scans(monkeypatch, options):
    if isinstance(options.get('content_secret_scans'), str):
        with pytest.raises(ValueError, match='content_secret_scans must be a boolean'):
            fixture(monkeypatch, options=options)
        return
    collector, calls, auth, sessions = fixture(monkeypatch, options=options)
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('unexpected scan'))
    assert adapter.collect_selected_files(collector, SCOPE) == []
    assert calls == auth == sessions == [] and collector.transport.calls == 0
    assert check.evaluate({}, {})[0] == 'UNKNOWN'


@pytest.mark.parametrize('workspace,revision', [(False, False), (True, False), (True, True)])
def test_native_exact_schemas_revisions_receipts_and_selected_only_negative(monkeypatch, clean, workspace, revision):
    t = target(workspace, revision)
    replies = responses(t)
    collector, calls, auth, sessions = fixture(monkeypatch, replies, [t])
    row, = adapter.collect_selected_files(collector, SCOPE)
    status, evidence = check.evaluate(row, index(row))
    assert status == 'PASS' and evidence['coverage'] == 'selected_file_only'
    assert 'does not establish repository-wide' in evidence['observed']
    assert len(calls) == len(auth) == (3 if workspace else 2)
    assert calls[-1][1] == 'https://dataform.googleapis.com/v1/' + (t.get('workspace') or REPO) + ':readFile'
    assert calls[-1][2]['params'] == {'path': t['path'], **({'revision': SHA} if revision else {}), **({'commitSha': SHA} if not workspace else {})}
    assert row[adapter.MARKER]['read_mode'] == ('revision_sha' if revision else 'observed_workspace' if workspace else 'commit_sha')
    assert row[adapter.MARKER]['revision'] == (SHA if revision or not workspace else None)
    assert all(r.closed for r in replies) and all(s.closed for s in sessions)
    assert collector.transport.cache == {}
    assert adapter.collect_selected_files(collector, SCOPE) == [row] and len(sessions) == 1
    env = collector.envelope(adapter.KIND, SCOPE, 'dataform', lambda: adapter.collection_pages(collector, SCOPE))
    native, = env['items']
    refs = {e['id'] for e in collector.transport.evidence}
    assert set(native['_provenance']['source_requests']) == refs
    assert set(native['_coverage'][adapter.MARKER]['source_requests']) == refs
    assert set(env['source_requests']) == refs
    assert check.evaluate(native, {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {adapter.KIND: [env]}})[0] == 'PASS'
    assert t['path'] not in json.dumps([row, env, collector.transport.evidence])


@pytest.mark.parametrize('case', ['scope', 'repository_parent', 'workspace_parent', 'sha', 'head', 'empty', 'extra', 'duplicate', 'files', 'traversal', 'absolute', 'slash', 'control', 'path_bytes', 'surrogate'])
def test_invalid_selection_before_auth(monkeypatch, case):
    rows = [target(True, True)]
    if case == 'scope': rows[0]['project_scope'] = 'projects/foreign'
    if case == 'repository_parent': rows[0]['repository'] = REPO.replace('projects/review', 'projects/foreign')
    if case == 'workspace_parent': rows[0]['workspace'] = rows[0]['workspace'].replace('/repositories/review/', '/repositories/other/')
    if case == 'sha': rows[0]['revision'] = 'main'
    if case == 'head': rows = [target()]; del rows[0]['commit_sha']
    if case == 'empty': rows = []
    if case == 'extra': rows[0]['url'] = 'https://evil.test'
    if case == 'duplicate': rows *= 2
    if case == 'files': rows = [target(path=str(i)) for i in range(adapter.MAX_FILES + 1)]
    if case == 'traversal': rows[0]['path'] = '../secret'
    if case == 'absolute': rows[0]['path'] = '/secret'
    if case == 'slash': rows[0]['path'] = 'dir\\secret'
    if case == 'control': rows[0]['path'] = 'secret\n'
    if case == 'path_bytes': rows[0]['path'] = 'é' * 600
    if case == 'surrogate': rows[0]['path'] = '\ud800'
    collector, calls, auth, sessions = fixture(monkeypatch, targets=rows)
    with pytest.raises(adapter.Incomplete): adapter.collect_selected_files(collector, SCOPE)
    assert calls == auth == sessions == []


@pytest.mark.parametrize('case', ['denied_project', 'foreign_project', 'invented_project', 'foreign_repository', 'remote_repository', 'foreign_workspace'])
def test_project_and_native_repository_workspace_identity_before_file_read(monkeypatch, clean, case):
    t = target(case == 'foreign_workspace')
    replies = responses(t)
    collector, calls, _, _ = fixture(monkeypatch, replies, [t])
    project = collector.collections[('project', SCOPE)]
    if case == 'denied_project': project['coverage_status'] = 'denied'
    if case == 'foreign_project': project['items'][0]['projectId'] = 'foreign'
    if case == 'invented_project': project['items'][0] = {'projectNumber': '123456789', 'projectId': 'review'}
    if case == 'foreign_repository': replies[0].raw = Raw(json.dumps({'name': REPO + '-other'}).encode())
    if case == 'remote_repository': replies[0].raw = Raw(json.dumps({'name': REPO, 'gitRemoteSettings': {'url': 'https://'+TOKEN+'@evil.test'}}).encode())
    if case == 'foreign_workspace': replies[1].raw = Raw(json.dumps({'name': t['workspace']+'-other'}).encode())
    # Update length so identity/schema checks, rather than truncation checks, execute.
    for r in replies: r.headers['Content-Length'] = str(len(r.raw.stream.getvalue()))
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert len(calls) <= (2 if case == 'foreign_workspace' else 1)
    assert TOKEN not in json.dumps([row, collector.transport.evidence])


@pytest.mark.parametrize('case', ['denied', 'not_found', 'redirect', 'challenge', 'url', 'encoding', 'range', 'mime', 'length', 'truncated', 'overlong', 'wire_cap', 'malformed_json', 'duplicate_json', 'wrong_field', 'missing_field', 'base64', 'padbits', 'binary', 'utf8', 'decoded_cap'])
def test_failed_or_malformed_native_file_never_clean(monkeypatch, clean, case):
    replies = responses()
    r = replies[-1]
    if case == 'denied': r.status_code = 403
    if case == 'not_found': r.status_code = 404
    if case == 'redirect': r.status_code = 302; r.headers['Location'] = 'https://evil.test/' + TOKEN
    if case == 'challenge': r.headers['WWW-Authenticate'] = 'Bearer realm="https://evil.test"'
    if case == 'url': r.url = 'https://evil.test'
    if case == 'encoding': r.headers['Content-Encoding'] = 'gzip'
    if case == 'range': r.headers['Content-Range'] = 'bytes 0-1/20'
    if case == 'mime': r.headers['Content-Type'] = 'text/html'
    if case == 'length': del r.headers['Content-Length']
    if case == 'truncated': r.headers['Content-Length'] = str(int(r.headers['Content-Length'])+1)
    if case == 'overlong': r.headers['Content-Length'] = '1'
    if case == 'wire_cap': r.headers['Content-Length'] = str(adapter.MAX_JSON_BYTES+1)
    if case == 'malformed_json': r.raw = Raw(('not json '+TOKEN).encode())
    if case == 'duplicate_json': r.raw = Raw(b'{"contents":"YQ==","contents":"Yg=="}')
    if case == 'wrong_field': r.raw = Raw(b'{"fileContents":"YQ=="}')
    if case == 'missing_field': r.raw = Raw(b'{}')
    if case == 'base64': r.raw = Raw(b'{"contents":"not base64!"}')
    if case == 'padbits': r.raw = Raw(b'{"contents":"YR=="}')
    if case == 'binary': r.raw = Raw(b'{"contents":"AA=="}')
    if case == 'utf8': r.raw = Raw(b'{"contents":"/w=="}')
    if case == 'decoded_cap': r.raw = Raw(json.dumps({'contents': base64.b64encode(b'a'*(adapter.MAX_FILE_BYTES+1)).decode()}).encode())
    if case in {'malformed_json','duplicate_json','wrong_field','missing_field','base64','padbits','binary','utf8','decoded_cap'}:
        r.headers['Content-Length'] = str(len(r.raw.stream.getvalue()))
    collector, calls, _, sessions = fixture(monkeypatch, replies)
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('invalid content reached detector'))
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert r.closed and sessions[0].closed and collector.transport.cache == {}
    assert TOKEN not in json.dumps([row, collector.transport.evidence])
    assert len(calls) == 2


@pytest.mark.parametrize('case', ['call', 'total', 'deadline', 'cancel', 'tool', 'throw', 'finding'])
def test_bounds_cancel_and_tool_failures_unknown(monkeypatch, clean, case):
    collector, calls, _, _ = fixture(monkeypatch)
    if case == 'call': collector.transport.max_calls = 1
    if case == 'total': monkeypatch.setattr(adapter, 'MAX_TOTAL_BYTES', 1)
    if case == 'deadline': monkeypatch.setattr(adapter, 'MAX_SECONDS', 0)
    if case == 'cancel': collector.transport.options['_cancel_check'] = lambda: True
    if case == 'tool': monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    if case == 'throw': monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: (_ for _ in ()).throw(RuntimeError(TOKEN)))
    if case == 'finding':
        monkeypatch.setattr(adapter, 'MAX_LEAKS', -1)
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([row, collector.transport.evidence])
    assert len(calls) <= 2


def test_cancel_during_raw_stream_and_tighten_socket_deadline(monkeypatch, clean):
    replies = responses()
    collector, _, _, _ = fixture(monkeypatch, replies)
    r, timeouts = replies[-1], []
    original = r.raw.read
    r.raw._fp = SimpleNamespace(fp=SimpleNamespace(raw=SimpleNamespace(_sock=SimpleNamespace(settimeout=timeouts.append))))
    def read(*a, **k):
        value = original(*a, **k)
        collector.transport.options['_cancel_check'] = lambda: True
        return value
    r.raw.read = read
    monkeypatch.setattr(adapter, 'scan_content', lambda *a, **k: pytest.fail('cancelled detector'))
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN' and r.closed and timeouts
    assert all(0 < t <= 20 for t in timeouts)


def test_stream_limit_even_if_content_length_lies(monkeypatch, clean):
    replies = responses()
    r = replies[-1]
    r.raw = Raw(b'a'*(adapter.MAX_JSON_BYTES+1))
    collector, _, _, _ = fixture(monkeypatch, replies)
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert row[adapter.MARKER]['reason'] == 'byte_limit'
    assert max(r.raw.reads) <= 16384 and r.closed


@pytest.mark.parametrize('case', ['provider', 'scope', 'collection', 'engine', 'revision', 'time', 'refs', 'status', 'location'])
def test_consumer_rejects_tampered_evidence(monkeypatch, clean, case):
    collector, _, _, _ = fixture(monkeypatch)
    row, = adapter.collect_selected_files(collector, SCOPE)
    ix = index(row)
    m = row[adapter.MARKER]
    if case == 'provider': ix['context']['provider'] = 'aws'
    if case == 'scope': m['scope'] = 'projects/foreign'
    if case == 'collection': ix['collections'][adapter.KIND][0]['status'] = 'partial'
    if case == 'engine': m['engines'][1] = deepcopy(m['engines'][0])
    if case == 'revision': m['revision'] = 'HEAD'
    if case == 'time': m['observed_at'] = '2026-10-19T00:00:00'
    if case == 'refs': ix['collections'][adapter.KIND][0]['source_requests'] = []
    if case == 'status': m['complete'] = False
    if case == 'location': m['leaks'] = [{'fingerprint': 'a'*64, 'detectors': [{'engine':'kingfisher','rule':'test'}], 'locations':[{'path': 'foreign.content'}]}]
    assert check.evaluate(row, ix)[0] == 'UNKNOWN'


@pytest.fixture(scope='module')
def installed_engines():
    import kingfisher_sdk
    assert kingfisher_sdk is not None
    assert scanning._trufflehog()


def test_real_pinned_tools_duplicate_leak_across_repository_and_workspace_private(monkeypatch, installed_engines, capsys):
    ts = [target(path='definitions/'+OTHER+'.sqlx'), target(True, path='includes/'+OTHER+'.js')]
    replies = sum((responses(t, ('const token = "'+TOKEN+'";\n').encode()) for t in ts), [])
    collector, calls, _, _ = fixture(monkeypatch, replies, ts)
    commands, run = [], scanning._run
    def record(argv, payload, timeout):
        commands.append(argv)
        return run(argv, payload, timeout)
    monkeypatch.setattr(scanning, '_run', record)
    rows = adapter.collect_selected_files(collector, SCOPE)
    findings = []
    for row in rows:
        status, evidence = check.evaluate(row, index(row))
        assert status == 'FAIL'
        findings.append({'provider':'gcp','check_id':check.CHECK_ID,'scope':SCOPE,
            'resource_id':row['name'],'native_resource_id':row['name'],'resource_type':adapter.KIND,
            'status':status,'finding_type':'secrets','frameworks':[],'evidence':evidence})
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1 and len(calls) == 5
    leak, = merged[0]['evidence']['secret_leaks']
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher','trufflehog'}
    assert len(leak['locations']) == 2
    assert {loc['resource_id'] for loc in leak['locations']} == {r['name'] for r in rows}
    assert any('stdin' in argv for argv in commands)
    assert all({'--no-verification','--no-update','--no-verification-cache','--force-skip-archives','--fail-on-scan-errors'} <= set(argv) for argv in commands if 'stdin' in argv)
    # Caller-owned options still hold the selection; persistent result/evidence/cache never do.
    output = json.dumps([rows, merged, collector.transport.evidence]) + repr(scanning._RESULTS) + repr(collector.transport.cache) + str(capsys.readouterr())
    assert TOKEN not in output and OTHER not in output and 'synthetic-auth-canary' not in output
    assert all(r.closed for r in replies)


def test_real_pinned_tools_clean_selected_workspace_read(monkeypatch, installed_engines):
    t = target(True)
    collector, _, _, _ = fixture(monkeypatch, responses(t), [t])
    row, = adapter.collect_selected_files(collector, SCOPE)
    status, evidence = check.evaluate(row, index(row))
    assert status == 'PASS' and evidence['read_mode'] == 'observed_workspace'
    assert len(evidence['engines']) == 2 and not evidence['secret_leaks']


HOOK = """        if 'dataform_selected_file' in self.needed:
            from .gcp_dataform_secret_indicators import collection_pages as dataform_file_pages
            for scope in self.scopes:
                if scope.startswith('projects/'):
                    add('dataform_selected_file', scope, 'dataform',
                        lambda scope=scope: dataform_file_pages(self, scope))
"""


def proposed_collector():
    """Exercise the installed production collector without source injection."""
    return gcp.GCPCollector



def native_case(monkeypatch, mode, canary=False):
    """Full collection and full-index fixture made only from native mocked responses."""
    cls = proposed_collector()
    t = target(True, path='definitions/'+OTHER+'.sqlx' if canary else 'definitions/example.sqlx')
    payload = ('const token="'+TOKEN+'";\n').encode() if mode == 'FAIL' else b'SELECT 1;\n'
    replies = responses(t, payload)
    if mode == 'UNKNOWN':
        replies[-1].status_code = 403
        replies[-1].raw = Raw(('provider-error-snippet '+TOKEN).encode())
    collector, calls, _, _ = fixture(monkeypatch, replies, [t], collector_class=cls)
    # Exercise actual project collection, not a pre-filled hand-built envelope.
    collector.collections.clear()
    metadata_calls = []
    def metadata_request(method, url, **kw):
        metadata_calls.append(url)
        assert method == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/'+SCOPE:
            value = {'name': 'projects/123456789', 'projectId':'review', 'state':'ACTIVE'}
        elif url == 'https://compute.googleapis.com/compute/v1/'+SCOPE:
            value = {'id':'123456789', 'name':'review', 'commonInstanceMetadata':{'items':[]}}
        else:
            pytest.fail('unexpected metadata endpoint: '+url)
        return SimpleNamespace(status_code=200, headers={}, content=json.dumps(value).encode(), json=lambda:value)
    monkeypatch.setattr(collector.transport, '_session', lambda:SimpleNamespace(request=metadata_request))
    snapshot = collector.collect()
    env, = [e for e in snapshot['collections'] if e['type'] == adapter.KIND]
    row, = env['items']
    ix = {'context': {'provider':'gcp','scope':SCOPE}, 'collections':{
        kind:[e for e in snapshot['collections'] if e['type']==kind] for kind in ['project',adapter.KIND]}}
    return row, ix, snapshot, collector, calls, replies


@pytest.mark.parametrize('mode', ['PASS','FAIL','UNKNOWN'])
def test_actual_native_collector_hook_full_index_and_presanitize_privacy(monkeypatch, installed_engines, mode, capsys):
    calls_to_sanitize, original = [], gcp.sanitize
    def sanitize(value):
        serialized = json.dumps(value)
        assert TOKEN not in serialized and OTHER not in serialized
        assert base64.b64encode(TOKEN.encode()).decode() not in serialized
        assert base64.b64encode(('const token="'+TOKEN+'";\n').encode()).decode() not in serialized
        calls_to_sanitize.append(True)
        return original(value)
    monkeypatch.setattr(gcp, 'sanitize', sanitize)
    row, ix, snapshot, collector, calls, replies = native_case(monkeypatch, mode, canary=True)
    assert check.evaluate(row, ix)[0] == mode
    refs = set(row[adapter.MARKER]['source_requests'])
    assert len(refs) == 3 and len(calls) == 3 and calls_to_sanitize
    assert refs <= {e['id'] for e in snapshot['metadata']['source_requests']}
    assert refs == set(row['_provenance']['source_requests'])
    assert refs == set(ix['collections'][adapter.KIND][0]['source_requests'])
    assert refs == set(row['_coverage'][adapter.MARKER]['source_requests'])
    if mode == 'UNKNOWN':
        denied = [e for e in snapshot['metadata']['source_requests'] if e.get('http_status')==403]
        assert len(denied)==1 and denied[0]['reason']=='denied'
        assert replies[-1].raw.reads == []  # provider error bodies never parsed
    output = json.dumps([row, ix, snapshot, collector.transport.evidence]) + repr(scanning._RESULTS) + repr(collector.transport.cache) + str(capsys.readouterr())
    assert TOKEN not in output and OTHER not in output and 'synthetic-auth-canary' not in output
    assert base64.b64encode(('const token="'+TOKEN+'";\n').encode()).decode() not in output
    assert base64.b64encode(b'SELECT 1;\n').decode() not in output
    assert all(r.closed for r in replies)
    assert all('dataform.googleapis.com' not in k for k in collector.transport.cache)


def test_workspace_native_read_supports_remote_backed_repository(monkeypatch, clean):
    t = target(True, True)
    replies = responses(t)
    replies[0] = Response({'name': REPO, 'gitRemoteSettings': {'url': 'https://external.example/repository'}})
    collector, _, _, _ = fixture(monkeypatch, replies, [t])
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'PASS'
    assert 'external.example' not in json.dumps([row, collector.transport.evidence])


def test_repository_and_workspace_name_canaries_do_not_enter_results(monkeypatch, installed_engines):
    t = target(True)
    t['repository'] = REPO.rsplit('/',1)[0] + '/' + OTHER
    t['workspace'] = t['repository'] + '/workspaces/' + OTHER
    replies = responses(t, ('const x="'+TOKEN+'";\n').encode())
    collector, _, _, _ = fixture(monkeypatch, replies, [t])
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'FAIL'
    output = json.dumps([row, collector.transport.evidence]) + repr(scanning._RESULTS)
    assert TOKEN not in output and OTHER not in output


@pytest.mark.parametrize('diagnostic', ['urllib3','http.client','https.client','urllib3.https'])
def test_http_debug_diagnostics_fail_closed_before_authorization(monkeypatch, clean, caplog, diagnostic):
    import logging
    import http.client
    collector, calls, auth, _ = fixture(monkeypatch)
    if diagnostic == 'urllib3':
        caplog.set_level(logging.DEBUG, logger='urllib3.connectionpool')
    elif diagnostic == 'http.client':
        monkeypatch.setattr(http.client.HTTPConnection, 'debuglevel', 1)
    elif diagnostic == 'https.client':
        monkeypatch.setattr(http.client.HTTPSConnection, 'debuglevel', 1)
    else:
        from urllib3.connection import HTTPSConnection
        monkeypatch.setattr(HTTPSConnection, 'debuglevel', 1)
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert row[adapter.MARKER]['reason'] == 'unsafe_http_diagnostics'
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert calls == auth == []
    assert TOKEN not in caplog.text


def test_other_scope_and_invalid_remote_shape(monkeypatch, clean):
    collector, calls, auth, sessions = fixture(monkeypatch)
    assert adapter.collect_selected_files(collector, 'projects/other') == []
    assert calls == auth == sessions == []
    replies = responses()
    replies[0] = Response({'name':REPO,'gitRemoteSettings':{'url':0}})
    collector, calls, _, _ = fixture(monkeypatch, replies)
    row, = adapter.collect_selected_files(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN' and len(calls)==1


def test_adapter_call_bound_shared_across_selected_files(monkeypatch, clean):
    ts = [target(path='one.sqlx'), target(True, path='two.sqlx')]
    replies = responses(ts[0]) + responses(ts[1])
    collector, calls, _, _ = fixture(monkeypatch, replies, ts)
    monkeypatch.setattr(adapter, 'MAX_CALLS', 2)
    rows = adapter.collect_selected_files(collector, SCOPE)
    assert [check.evaluate(r,index(r))[0] for r in rows] == ['PASS','UNKNOWN']
    assert len(calls)==2
