"""Native pinned File GET/download -> bounded offline parsers -> pure check."""
from copy import deepcopy
import base64
import gzip
import hashlib
import io
import json
import socket
import stat
import tarfile
from types import SimpleNamespace
from urllib.parse import quote
import zipfile

import pytest
import requests
from peaso.collectors import gcp
from peaso.collectors import gcp_artifact_file_secret_indicators as a
from peaso.collectors import aws_package_content_indicators as aws
from peaso.checks import gcp_artifact_file_secret_review_20261019 as c
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

SCOPE = 'projects/review'
PARENT = SCOPE + '/locations/us-central1/repositories/source'
TOKEN = 'ghp_' + '7mq2zr9wl4cv8nk1sf6ah3jp5ud0xb2ye9rt'


def block_network(mp):
    def forbidden(*args, **kw): raise AssertionError('Unmocked socket/DNS forbidden')
    for name in ('connect', 'connect_ex'): mp.setattr(socket.socket, name, forbidden)
    mp.setattr(socket, 'create_connection', forbidden); mp.setattr(socket, 'getaddrinfo', forbidden)


@pytest.fixture(autouse=True)
def isolation(monkeypatch):
    block_network(monkeypatch); scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *args: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *args: [])


def payload(format_name='utf8', positive=False, files=None):
    body = ('API_TOKEN=' + (TOKEN if positive else 'production') + '\n').encode()
    if format_name == 'utf8': return body
    files = files if files is not None else {'settings.env': body}
    output = io.BytesIO()
    if format_name == 'zip':
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items(): z.writestr(name, data)
        return output.getvalue()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as z:
        for name, data in files.items():
            info = tarfile.TarInfo(name); info.size = len(data); z.addfile(info, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0) if format_name == 'tar.gz' else output.getvalue()


def target(raw=None, format_name='utf8', file_id='path/settings.env'):
    raw = payload(format_name) if raw is None else raw
    return {'project_scope': SCOPE, 'name': PARENT + '/files/' + quote(file_id, safe='-._~'),
            'sha256': hashlib.sha256(raw).hexdigest(), 'format': format_name}


class Response:
    def __init__(self, url, params, data, status=200, content_type='application/octet-stream'):
        self.url = requests.Request('GET', url, params=params).prepare().url
        self.status_code = status; self.history = []; self.closed = False
        self.headers = {'Content-Length': str(len(data)), 'Content-Type': content_type}
        self.raw = SimpleNamespace(read=lambda amount, decode_content: self.body.read(amount))
        self.body = io.BytesIO(data)
    def close(self): self.closed = True


def native_fixture(mp, raw=None, selected=None, case=None, options=None, native=False):
    block_network(mp)
    raw = payload() if raw is None else raw
    selected = selected if selected is not None else [target(raw)]
    opts = {'inventories': ['project', 'artifact_repository', a.KIND], 'include_inherited': False,
        'metrics_scopes': False, 'concurrency': 1, 'retries': 0, 'artifactregistry_locations': ['us-central1'],
        'content_secret_scans': True, '_content_secret_scan_kinds': [a.KIND], a.OPTION: selected, **(options or {})}
    calls, responses, auth = [], [], []
    def headers(): auth.append(True); return {'authorization': 'Bearer fake-token'}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    project = {'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'}
    repo = {'name': PARENT, 'format': 'GENERIC', 'mode': 'STANDARD_REPOSITORY'}
    class Meta:
        status_code = 200
        headers = {}
        def __init__(self, data): self.data = data
        def json(self): return deepcopy(self.data)
    def ordinary(method, url, **kw):
        assert method == 'GET'
        if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE: return Meta(project)
        if url == 'https://compute.googleapis.com/compute/v1/' + SCOPE: return Meta({'name': 'review', 'id': '10001'})
        if url == 'https://artifactregistry.googleapis.com/v1/' + PARENT + ':getIamPolicy': return Meta({'version': 1, 'bindings': []})
        assert url == 'https://artifactregistry.googleapis.com/v1/' + SCOPE + '/locations/us-central1/repositories'
        return Meta({'repositories': [repo]})
    mp.setattr(transport, '_session', lambda: SimpleNamespace(request=ordinary))
    class Session:
        def __init__(self):
            self.cookies = {}; self.headers = {}; self.proxies = {}; self.closed = False
        def request(self, method, url, **kw):
            assert method == 'GET' and kw['stream'] and kw['allow_redirects'] is False
            assert self.trust_env is False and callable(self.auth) and not self.cookies and not self.proxies
            assert set(kw['headers']) <= {'Authorization', 'Accept', 'Accept-Encoding', 'X-Goog-User-Project'}
            assert kw['headers']['Authorization'] == 'Bearer fake-token' and kw['headers']['Accept-Encoding'] == 'identity'
            calls.append((url, kw))
            media = url.startswith('https://artifactregistry.googleapis.com/download/v1/')
            t = next(t for t in selected if url == 'https://artifactregistry.googleapis.com/' + ('download/v1/' if media else 'v1/') + t['name'] + (':download' if media else ''))
            assert kw['params'] == ({'alt': 'media'} if media else {'fields': a.FIELDS})
            actual_raw = raw[t['name']] if isinstance(raw, dict) else raw
            data = actual_raw
            if not media:
                meta = {'name': t['name'], 'sizeBytes': str(len(actual_raw)), 'hashes': [
                    {'type': 'SHA256', 'value': base64.b64encode(hashlib.sha256(actual_raw).digest()).decode()}]}
                if case == 'missing_digest': meta['hashes'] = []
                if case == 'metadata_digest': meta['hashes'][0]['value'] = base64.b64encode(bytes(32)).decode()
                if case == 'foreign_name': meta['name'] = t['name'].replace('projects/review/', 'projects/foreign/')
                if case == 'size': meta['sizeBytes'] = str(a.MAX_FILE_BYTES + 1)
                if case == 'bad_hash_encoding': meta['hashes'][0]['value'] = t['sha256']
                data = json.dumps(meta).encode()
                if case == 'duplicate_json': data = data[:-1] + b',"sizeBytes":"1"}'
            status = 403 if case == 'denied' else 302 if case == 'redirect' else 200
            r = Response(url, kw['params'], data, status, 'application/octet-stream' if media else 'application/json')
            if media:
                if case == 'media_digest': r.body = io.BytesIO(b'x' * len(data))
                if case == 'truncated': r.body = io.BytesIO(data[:-1])
                if case == 'encoding': r.headers['Content-Encoding'] = 'gzip'
                if case == 'range': r.headers['Content-Range'] = 'bytes 0-1/10'
                if case == 'no_length': r.headers.pop('Content-Length')
                if case == 'foreign_url': r.url = 'https://example.invalid/' + TOKEN
                if case == 'history': r.history = [object()]
            responses.append(r)
            return r
        def close(self): self.closed = True
    sessions = []
    def session(): s = Session(); sessions.append(s); return s
    mp.setattr(requests, 'Session', session)
    if native:
        collector = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
            requirements=[a.KIND, 'project', 'artifact_repository'], transport=transport)
        snapshot = collector.collect(); collections = {}
        for e in snapshot['collections']: collections.setdefault(e['type'], []).append(e)
        envelope, = collections[a.KIND]
    else:
        # Direct producer tests use real envelope/provenance code; independent
        # native pipeline below obtains these dependencies through actual HTTP.
        config = {'provider': 'gcp', 'scopes': [SCOPE], 'options': {**opts, 'inventories': ['project', 'artifact_repository']}}
        collector = gcp.GCPCollector(config, requirements=['project', 'artifact_repository'], transport=transport)
        collector.collections = {('project', SCOPE): {'coverage_status': 'collected', 'items': [project]},
            ('artifact_repository', SCOPE): {'coverage_status': 'collected', 'items': [repo]}}
        envelope = collector.envelope(a.KIND, SCOPE, 'artifactregistry', lambda: a.collection_pages(collector, SCOPE))
        collections = {a.KIND: [envelope]}; snapshot = {'collections': [envelope]}
    index = {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': collections}
    return envelope, index, snapshot, calls, responses, transport, sessions, collector, auth


@pytest.mark.parametrize('format_name', a.FORMATS)
@pytest.mark.parametrize('positive', [False, True])
def test_real_dual_tools_all_formats_native_stream_integrity_and_privacy(monkeypatch, format_name, positive, capsys):
    raw = payload(format_name, positive); t = target(raw, format_name, TOKEN + '/source')
    e, index, snapshot, calls, responses, transport, sessions, *_ = native_fixture(monkeypatch, raw, [t])
    row, = e['items']; status, evidence = c.evaluate(row, index)
    assert status == ('FAIL' if positive else 'PASS')
    if positive:
        leak, = evidence['secret_leaks']; assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert len(calls) == 2 and all(r.closed for r in responses) and all(s.closed for s in sessions)
    assert TOKEN not in json.dumps([snapshot, evidence, transport.evidence]) + repr(transport.cache) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert row['_coverage'][a.MARKER]['source_requests'] == row['_provenance']['source_requests'] == e['source_requests']


@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'content_secret_scans': 'true'}, {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': ['artifact_repository']}])
def test_default_zero_calls_sessions_credentials_and_tools(monkeypatch, options):
    def forbidden(*args, **kw): raise AssertionError('scanner must not run')
    monkeypatch.setattr(a, 'scan_content', forbidden)
    if options.get('content_secret_scans') == 'true':
        assert a.normalize_selection(options, [SCOPE]) == []
        with pytest.raises(ValueError, match='must be a boolean'): native_fixture(monkeypatch, options=options)
        return
    e, _, _, calls, responses, _, sessions, _, auth = native_fixture(monkeypatch, options=options)
    assert not e['items'] and not calls and not responses and not sessions and not auth


@pytest.mark.parametrize('change', ['extra', 'scope', 'name_scope', 'sha', 'format', 'url', 'traversal', 'double_slash', 'noncanonical', 'double_encoded', 'too_many', 'duplicate'])
def test_invalid_entire_selection_is_rejected_before_any_read(monkeypatch, change):
    t = target(); selected = [t]
    if change == 'extra': t['url'] = 'https://example.invalid'
    if change == 'scope': t['project_scope'] = 'projects/foreign'
    if change == 'name_scope': t['name'] = t['name'].replace('projects/review/', 'projects/foreign/')
    if change == 'sha': t['sha256'] = 'A' * 64
    if change == 'format': t['format'] = 'exe'
    if change == 'url': t['name'] = 'https://example.invalid/' + TOKEN
    if change == 'traversal': t['name'] = PARENT + '/files/..%2Fsource'
    if change == 'double_slash': t['name'] = PARENT + '/files/a%2F%2Fb'
    if change == 'noncanonical': t['name'] = PARENT + '/files/%73ource'
    if change == 'double_encoded': t['name'] = PARENT + '/files/path%252Fsource'
    if change == 'too_many': selected = [target(file_id=str(i)) for i in range(a.MAX_FILES + 1)]
    if change == 'duplicate': selected = [t, deepcopy(t)]
    with pytest.raises(a.Incomplete): a.normalize_selection({'content_secret_scans': True, '_content_secret_scan_kinds': [a.KIND], a.OPTION: selected}, [SCOPE])


@pytest.mark.parametrize('case', ['missing_digest','metadata_digest','foreign_name','size','bad_hash_encoding','duplicate_json','media_digest','truncated','encoding','range','no_length','foreign_url','history','denied','redirect'])
def test_missing_or_unbound_native_contracts_never_clean_or_persist_body(monkeypatch, clean, case):
    e, index, snapshot, calls, responses, transport, sessions, *_ = native_fixture(monkeypatch, payload(positive=True), case=case)
    row, = e['items']; assert c.evaluate(row, index)[0] == 'UNKNOWN'
    assert all(r.closed for r in responses) and all(s.closed for s in sessions)
    assert TOKEN not in json.dumps([snapshot, transport.evidence]) + repr(transport.cache)
    if case in ('missing_digest','metadata_digest','foreign_name','size','bad_hash_encoding','duplicate_json','denied','redirect'): assert len(calls) == 1


def test_native_authority_partial_remote_docker_and_legacy_contradictions_zero_calls(monkeypatch, clean):
    for field, value in [('mode','REMOTE_REPOSITORY'), ('mode','VIRTUAL_REPOSITORY'), ('format','DOCKER')]:
        e, _, _, _, _, transport, _, collector, _ = native_fixture(monkeypatch)
        collector.collections[('artifact_repository', SCOPE)]['items'][0][field] = value
        transport._artifact_file_secret_state['items'].clear(); before = transport.calls
        rows = a.collect_selected_files(collector, SCOPE)
        assert not rows[0][a.MARKER]['complete'] and transport.calls == before
    collector.collections[('project', SCOPE)]['items'][0]['projectNumber'] = 'wrong'
    transport._artifact_file_secret_state['items'].clear(); before=transport.calls
    assert not a.collect_selected_files(collector, SCOPE)[0][a.MARKER]['complete'] and transport.calls == before


@pytest.mark.parametrize('case', ['binary','nested','traversal','link','truncated','bomb'])
def test_unsupported_payloads_archives_unknown_without_extraction(monkeypatch, clean, case):
    raw = b'\x00\xff'; format_name = 'utf8'
    if case == 'nested': format_name='zip'; raw=payload('zip', files={'inner.zip':payload('zip')})
    if case == 'traversal': format_name='zip'; raw=payload('zip', files={'../secret.env': b'production'})
    if case == 'truncated': format_name='tar'; raw=payload('tar')[:-1]
    if case == 'bomb': format_name='zip'; raw=payload('zip', files={'bomb.txt':b'a' * 200000})
    if case == 'link':
        format_name='zip'; output=io.BytesIO()
        with zipfile.ZipFile(output,'w') as z:
            info=zipfile.ZipInfo('link');info.external_attr=(stat.S_IFLNK | 0o777) << 16;z.writestr(info,b'target')
        raw=output.getvalue()
    e,index,*_=native_fixture(monkeypatch,raw,[target(raw,format_name)])
    assert c.evaluate(e['items'][0],index)[0]=='UNKNOWN'


def test_exact_value_dual_tool_merge_across_files_and_parser_globals_unchanged(monkeypatch):
    original_scan=aws._scan
    raw1=payload(positive=True);raw2=payload('zip',True,{'copy.env':raw1, 'other.env':raw1})
    t1=target(raw1,file_id='one');t2=target(raw2,'zip','two')
    e,index,snapshot,*_=native_fixture(monkeypatch,{t1['name']:raw1,t2['name']:raw2},[t1,t2])
    findings=[]
    for row in e['items']:
        status,evidence=c.evaluate(row,index);assert status=='FAIL'
        findings.append({'provider':'gcp','check_id':c.CHECK_ID,'scope':SCOPE,'resource_id':row['name'],
            'native_resource_id':row['name'],'resource_type':a.KIND,'status':status,'finding_type':'secrets','frameworks':[],'evidence':evidence})
    assert len(deduplicate_secret_findings(findings))==1 and aws._scan is original_scan
    assert TOKEN not in json.dumps(snapshot)


def test_budgets_cancel_and_detector_failure_unknown(monkeypatch,clean):
    e,index,_,calls,_,transport,_,collector,*_=native_fixture(monkeypatch)
    state=transport._artifact_file_secret_state
    for key,value in [('bytes',a.MAX_TOTAL_BYTES),('calls',a.MAX_CALLS),('started',0),('archive_members',200)]:
        old=state[key];state['items'].clear();state[key]=value
        assert not a.collect_selected_files(collector,SCOPE)[0][a.MARKER]['complete'];state[key]=old
    def absent(*args):raise OSError(TOKEN)
    monkeypatch.setattr(scanning,'_scan_trufflehog',absent)
    scanning._RESULTS.clear()
    state['items'].clear()
    assert not a.collect_selected_files(collector,SCOPE)[0][a.MARKER]['complete']
    state['items'].clear(); before = transport.calls
    transport.options['_cancel_check'] = lambda: True
    assert not a.collect_selected_files(collector,SCOPE)[0][a.MARKER]['complete'] and transport.calls == before
    with pytest.raises(AssertionError,match='forbidden'):socket.create_connection(('example.invalid',443))


def test_actual_collector_existing_native_authority_to_download_and_callback(monkeypatch):
    raw=payload('zip',True);t=target(raw,'zip')
    e,index,snapshot,calls,responses,transport,sessions,*_=native_fixture(monkeypatch,raw,[t],native=True)
    assert c.evaluate(e['items'][0],index)[0]=='FAIL' and len(calls)==2
    assert all(r.closed for r in responses) and all(s.closed for s in sessions)
    assert TOKEN not in json.dumps([snapshot,transport.evidence])+repr(transport.cache)


def test_install_source_produced_fixtures_idempotent():
    from peaso.checks import CHECKS
    from peaso.checks.fixtures import CASES
    c.install();c.install();assert sum(x.id==c.CHECK_ID for x in CHECKS)==1
    f=CASES[c.CHECK_ID]
    for label in ('pass','fail','unknown'):assert c.evaluate(f[label],f[label+'_index'])[0]==label.upper()
    for label in ('missing','malformed'):assert c.evaluate(f[label],{})[0]=='UNKNOWN'


def test_primary_native_file_name_example_keeps_exact_single_escape_on_wire(monkeypatch, clean):
    # Google File.name documents a%2Fb%2Fc.txt; download guide requires the
    # escaped filename in the /download/v1 path, not %252F or raw slash.
    t = target(file_id='a/b/c.txt')
    assert t['name'] == PARENT + '/files/a%2Fb%2Fc.txt'
    e,index,_,calls,*_ = native_fixture(monkeypatch, selected=[t])
    assert c.evaluate(e['items'][0],index)[0] == 'PASS'
    prepared = [requests.Request('GET', url, params=kw['params']).prepare().url for url,kw in calls]
    assert prepared == [
        'https://artifactregistry.googleapis.com/v1/' + t['name'] + '?fields=name%2CsizeBytes%2Chashes',
        'https://artifactregistry.googleapis.com/download/v1/' + t['name'] + ':download?alt=media']
    assert all('%252F' not in url for url in prepared)
