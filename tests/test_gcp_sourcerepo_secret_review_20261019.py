"""Offline synthetic native HTTP and valid PACK tests, callable with MonkeyPatch."""
from copy import deepcopy
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import socket
import struct
from types import SimpleNamespace
import zlib

import pytest
from peaso.collectors import gcp
from peaso.collectors import gcp_sourcerepo_secret_indicators as adapter
from peaso.collectors import gcp_git_transport as git
from peaso.collectors import gcp_git_content as content
from peaso.checks import gcp_sourcerepo_secret_review_20261019 as check
from peaso import secret_scanning as scanning

SCOPE = 'projects/review'
REPO = SCOPE + '/repos/example'
PATH = 'selected-private-config.txt'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'fake-csr-oauth-token-canary'


def oid(kind, data):
    return hashlib.sha1(kind + b' ' + str(len(data)).encode() + b'\0' + data).digest()


def make_pack(payload=b'selected clean content\n', *, mode=b'100644', extra=b'unselected private token = never-scan\n', paths=None):
    tree = b''.join(mode + b' ' + p.encode() + b'\0' + oid(b'blob', payload) for p in sorted(paths or [PATH]))
    commit = (b'tree ' + oid(b'tree', tree).hex().encode() + b'\n'
              b'author Test <test@example.invalid> 1 +0000\n'
              b'committer Test <test@example.invalid> 1 +0000\n\nprivate commit message\n')
    entries = [(3, payload), (3, extra), (2, tree), (1, commit)]
    wire = b'PACK' + struct.pack('!II', 2, len(entries))
    for kind, data in entries:
        size = len(data)
        first = (kind << 4) | (size & 15)
        size >>= 4
        header = bytearray([first | (128 if size else 0)])
        while size:
            header.append((size & 127) | (128 if size >> 7 else 0))
            size >>= 7
        wire += bytes(header) + zlib.compress(data)
    return wire + hashlib.sha1(wire).digest(), oid(b'commit', commit).hex()


def advertise(commit):
    return (git._encode(b'# service=git-upload-pack\n') + b'0000' +
        git._encode(commit.encode() + b' refs/heads/private-ref-name\0ofs-delta no-progress\n') + b'0000')


class Response:
    def __init__(self, payload, mime='application/json', status=200, headers=None):
        self.payload = json.dumps(payload).encode() if isinstance(payload, dict) else payload
        self.content = self.payload
        self.stream = io.BytesIO(self.payload)
        self.status_code, self.raw, self.closed = status, self, False
        self.headers = {'Content-Type': mime, 'Content-Length': str(len(self.payload)), **(headers or {})}
        self.url, self.history = '', []

    def read(self, size, *, decode_content):
        assert decode_content is False and 0 < size <= 16384
        return self.stream.read(size)

    def close(self):
        self.closed = True

    def json(self):
        return json.loads(self.payload)


def fixture(monkeypatch, payload=b'selected clean content\n', *, mode=b'100644', mock_engines=True, mutate=None, options=None, paths=None):
    monkeypatch.setattr(socket.socket, 'connect', lambda *a, **k: pytest.fail('unmocked socket'))
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: pytest.fail('unmocked socket'))
    scanning._RESULTS.clear()
    scanned = []
    if mock_engines:
        def scanner(data, path, timeout):
            scanned.append((data, path, timeout))
            return []
        monkeypatch.setattr(scanning, '_scan_kingfisher', scanner)
        monkeypatch.setattr(scanning, '_scan_trufflehog', scanner)
    pack, commit = make_pack(payload, mode=mode, paths=paths)
    target = {'repository': REPO, 'commit': commit, 'paths': paths or [PATH]}
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
        adapter.OPTION: [target], 'metrics_scopes': False, 'include_inherited': False,
        'concurrency': 1, 'retries': 0, **(options or {})}
    auth = []
    def headers():
        auth.append(True)
        return {'Authorization': 'Bearer ' + AUTH}
    transport = gcp.Transport(SimpleNamespace(headers=headers, close=lambda: None), opts)
    c = gcp.GCPCollector({'provider': 'gcp', 'scopes': [SCOPE], 'options': opts},
        requirements=['project'], transport=transport)
    pending = [Response({'name': REPO, 'url': adapter.clone_url(REPO)}),
        Response(advertise(commit), 'application/x-git-upload-pack-advertisement'),
        Response(git._encode(b'NAK\n') + pack, 'application/x-git-upload-pack-result')]
    if mutate:
        mutate(pending)
    calls, received, closed = [], [], []
    def request(method, url, **kw):
        import requests
        calls.append((method, url, kw))
        if not kw.get('stream'):
            if url == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
                return Response({'name': 'projects/10001', 'projectId': 'review', 'state': 'ACTIVE'})
            if url == 'https://compute.googleapis.com/compute/v1/' + SCOPE:
                return Response({'name': 'review', 'id': '10001', 'commonInstanceMetadata': {'items': []}})
            pytest.fail('unexpected project request')
        assert kw['allow_redirects'] is False and kw['headers']['Accept-Encoding'] == 'identity'
        assert 0 < kw['timeout'] <= 20
        response = pending.pop(0)
        response.url = getattr(response, 'final_url', requests.Request(method, url, params=kw.get('params')).prepare().url)
        received.append(response)
        return response
    monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request, auth=None))
    def session():
        return SimpleNamespace(request=request, cookies=SimpleNamespace(clear=lambda: None),
            close=lambda: closed.append(True))
    monkeypatch.setattr(git, '_session', session)
    for kind, scope, service, fetch in c.scope_jobs(SCOPE):
        if kind == 'project':
            c.collections[(kind, scope)] = c.envelope(kind, scope, service, fetch)
    return c, calls, received, pending, auth, scanned, closed


def produce(c):
    kind, scope, service, fetch = adapter.jobs(c, SCOPE)[0]
    env = c.envelope(kind, scope, service, fetch)
    row, = env['items']
    index = {'context': {'provider': 'gcp', 'scope': SCOPE, 'metadata': adapter.selection_metadata(c)},
        'collections': {kind: [env], 'project': [c.collections[('project', SCOPE)]]}}
    return row, index


def test_exact_native_git_and_selected_blob(monkeypatch):
    c, calls, responses, pending, auth, scanned, closed = fixture(monkeypatch)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'PASS', (row, index)
    assert evidence['coverage'] == 'selected_files_at_advertised_commit_only'
    reads = [(m, u, k) for m, u, k in calls if k.get('stream')]
    assert len(reads) == 3 and not pending
    assert [(m, u) for m, u, _ in reads] == [
        ('GET', 'https://sourcerepo.googleapis.com/v1/' + REPO),
        ('GET', adapter.clone_url(REPO) + '/info/refs?service=git-upload-pack'),
        ('POST', adapter.clone_url(REPO) + '/git-upload-pack')]
    assert reads[0][2]['params'] == {'fields': 'name,url'}
    expected_auth = 'Basic ' + base64.b64encode(('git-service-account:' + AUTH).encode()).decode()
    assert all(k['headers']['Authorization'] == expected_auth for _, _, k in reads[1:])
    assert len(scanned) == 2 and all(p == b'selected clean content\n' for p, _, _ in scanned)
    assert all(path == 'sourcerepo.selected_file.' + adapter.path_identity(PATH) for _, path, _ in scanned)
    assert all(0 < timeout <= 10 for _, _, timeout in scanned)
    assert all(r.closed for r in responses) and len(closed) == 2
    persisted = json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache)
    for raw in (AUTH, PATH, 'private-ref-name', 'private commit message', 'selected clean content', 'unselected private token'):
        assert raw not in persisted
    assert adapter.collect_sources(c, SCOPE)[0][adapter.MARKER] == row[adapter.MARKER]
    assert len([k for _, _, k in calls if k.get('stream')]) == 3


def test_default_off_without_transport():
    for opts in ({}, {'content_secret_scans': False}, {'content_secret_scans': 'true'},
                 {'content_secret_scans': True, '_content_secret_scan_kinds': adapter.KIND},
                 {'content_secret_scans': True, '_content_secret_scan_kinds': None}):
        c = SimpleNamespace(options=opts, scopes=[SCOPE])
        assert adapter.jobs(c, SCOPE) == [] and adapter.collect_sources(c, SCOPE) == []
        assert adapter.selection_metadata(c)['source_repository_file_authorized'] is False


INVALID = [
    ([], [SCOPE]), ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [PATH]}] * 2, [SCOPE]),
    ([{'repository': REPO, 'commit': 'A' * 40, 'paths': [PATH]}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'main', 'paths': [PATH]}], [SCOPE]),
    ([{'repository': REPO, 'commit': '0' * 40, 'paths': [PATH]}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': ['../secret']}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': ['a//b']}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': ['.git/config']}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [PATH] * 2}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': []}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [str(n) for n in range(9)]}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [PATH], 'extra': True}], [SCOPE]),
    ([{'repository': REPO.replace('review', 'foreign'), 'commit': 'a' * 40, 'paths': [PATH]}], [SCOPE]),
    ([{'repository': 'https://source.developers.google.com/p/review/r/example', 'commit': 'a' * 40, 'paths': [PATH]}], [SCOPE]),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [PATH]}], ['projects/10001']),
    ([{'repository': REPO, 'commit': 'a' * 40, 'paths': [PATH]}], [SCOPE, 'projects/foreign']),
]


@pytest.mark.parametrize('rows,scopes', INVALID)
def test_invalid_before_credentials(rows, scopes):
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND], adapter.OPTION: rows}
    with pytest.raises(adapter.Incomplete, match='^invalid_selection$'):
        adapter.selected_targets(opts, scopes)
    c = SimpleNamespace(options=opts, scopes=scopes)
    assert adapter.collect_sources(c, SCOPE)[0][adapter.MARKER]['reason'] == 'invalid_selection'


@pytest.mark.parametrize('case', ['native_denied', 'native_redirect', 'native_wrong_repo', 'native_wrong_clone',
    'native_partial', 'native_gzip', 'native_oversize', 'native_truncated', 'git_denied', 'git_partial',
    'unadvertised', 'bad_pack', 'lfs', 'binary', 'symlink', 'missing_path', 'detector', 'call_limit',
    'project_partial', 'project_identity', 'deadline', 'native_final_url', 'native_history', 'git_final_url'])
def test_incomplete_is_unknown(monkeypatch, case):
    def mutate(rows):
        if case == 'native_denied': rows[0].status_code = 403
        if case == 'native_redirect': rows[0].status_code = 302
        if case == 'native_wrong_repo': rows[0] = Response({'name': REPO + 'x', 'url': adapter.clone_url(REPO)})
        if case == 'native_wrong_clone': rows[0] = Response({'name': REPO, 'url': adapter.clone_url(REPO) + '.git'})
        if case == 'native_partial': rows[0].headers['Content-Range'] = 'bytes 0-1/2'
        if case == 'native_gzip': rows[0].headers['Content-Encoding'] = 'gzip'
        if case == 'native_oversize':
            rows[0] = Response(b' ' * (adapter.MAX_METADATA + 1))
            del rows[0].headers['Content-Length']
        if case == 'native_truncated': rows[0].headers['Content-Length'] = '1'
        if case == 'native_final_url': rows[0].final_url = 'https://foreign.invalid/'
        if case == 'native_history': rows[0].history = [object()]
        if case == 'git_denied': rows[1].status_code = 403
        if case == 'git_final_url': rows[1].final_url = 'https://foreign.invalid/'
        if case == 'git_partial': rows[2].headers['Content-Range'] = 'bytes 0-1/2'
        if case == 'unadvertised': rows[1] = Response(advertise('b' * 40), 'application/x-git-upload-pack-advertisement')
        if case == 'bad_pack': rows[2] = Response(git._encode(b'NAK\n') + b'PACKbroken', 'application/x-git-upload-pack-result')
    payload = b'version https://git-lfs.github.com/spec/v1\n' if case == 'lfs' else b'\x00binary' if case == 'binary' else b'clean\n'
    c, calls, _, _, _, scanned, _ = fixture(monkeypatch, payload, mode=b'120000' if case == 'symlink' else b'100644', mutate=mutate)
    if case == 'missing_path': c.options[adapter.OPTION][0]['paths'] = ['absent.txt']
    if case == 'detector': monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: (_ for _ in ()).throw(RuntimeError('private exception')))
    if case == 'call_limit': c.transport.max_calls = c.transport.calls
    if case == 'project_partial': c.collections[('project', SCOPE)]['coverage_status'] = 'partial'
    if case == 'project_identity': c.collections[('project', SCOPE)]['items'][0]['projectId'] = 'foreign'
    if case == 'deadline': c.transport.deadline_seconds = 0.0000001
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN', (case, row)
    assert row[adapter.MARKER]['complete'] is False
    if case not in ('detector',): assert scanned == []
    if case.startswith('native_') or case.startswith('project_') or case in ('deadline', 'call_limit'):
        assert len([k for _, _, k in calls if k.get('stream')]) <= 1


def test_consumer_rejects_independent_tampering(monkeypatch):
    c, *_ = fixture(monkeypatch)
    original, original_index = produce(c)
    assert check.evaluate(original, original_index)[0] == 'PASS'
    mutations = [
        lambda r, i: i['context']['metadata'].update(source_repository_file_authorized=False),
        lambda r, i: i['context']['metadata']['source_repository_file_selection'].update(commit='a' * 40),
        lambda r, i: r[adapter.MARKER]['selection']['paths_sha256'].append('a' * 64),
        lambda r, i: r[adapter.MARKER]['repository'].update(url='https://foreign.invalid'),
        lambda r, i: r[adapter.MARKER]['read_receipts'][0].update(method='POST'),
        lambda r, i: r[adapter.MARKER]['read_receipts'][1].update(operation='sourcerepo.git.receive_pack'),
        lambda r, i: r[adapter.MARKER]['read_receipts'][2].update(resource_id=r['name']),
        lambda r, i: r[adapter.MARKER]['read_receipts'][2].update(http_status=206),
        lambda r, i: r[adapter.MARKER]['read_receipts'][0].update(final_route_verified=False),
        lambda r, i: r[adapter.MARKER]['read_receipts'][1].update(route='foreign_route'),
        lambda r, i: r[adapter.MARKER]['read_receipts'].pop(),
        lambda r, i: r[adapter.MARKER]['files'][0].update(blob_sha1='not-a-hash'),
        lambda r, i: r[adapter.MARKER]['files'][0].update(blob_sha1='b' * 40),
        lambda r, i: r[adapter.MARKER]['files'][0].update(path_sha256='b' * 64),
        lambda r, i: r[adapter.MARKER]['files'][0].update(bytes=262145),
        lambda r, i: r[adapter.MARKER]['files'][0]['engines'][0].update(version='future'),
        lambda r, i: r[adapter.MARKER]['files'][0]['engines'][1].update(status='unavailable'),
        lambda r, i: r[adapter.MARKER]['files'].append(deepcopy(r[adapter.MARKER]['files'][0])),
        lambda r, i: r[adapter.MARKER]['content_accounting'].update(wire_bytes=999),
        lambda r, i: i['collections']['project'][0]['items'][0].update(projectId='foreign'),
        lambda r, i: i['collections']['project'][0]['items'][0]['_provenance'].update(source_requests=[]),
        lambda r, i: i['collections'][adapter.KIND][0].update(coverage_status='partial'),
        lambda r, i: i['collections'][adapter.KIND][0]['items'].append(deepcopy(r)),
    ]
    for mutate in mutations:
        row, index = deepcopy((original, original_index))
        mutate(row, index)
        assert check.evaluate(row, index)[0] == 'UNKNOWN', mutate


def test_real_offline_scanners_and_redacted_fingerprints(monkeypatch):
    for payload, expected in ((b'ordinary selected text\n', 'PASS'),
                              (('token = ' + TOKEN + '\n').encode(), 'FAIL')):
        c, _, _, _, _, _, _ = fixture(monkeypatch, payload, mock_engines=False)
        row, index = produce(c)
        status, evidence = check.evaluate(row, index)
        assert status == expected, row
        assert all(e['status'] == 'complete' for f in evidence['files'] for e in f['engines'])
        if expected == 'FAIL':
            assert evidence['secret_leaks']
            assert any({d['engine'] for d in l['detectors']} == {'kingfisher', 'trufflehog'} for l in evidence['secret_leaks'])
        assert TOKEN not in json.dumps([row, index, evidence, c.transport.evidence]) + repr(c.transport.cache) + repr(scanning._RESULTS)


def test_redacted_fixture_contract():
    path = Path(check.__file__).with_name('gcp_sourcerepo_secret_review_20261019_fixtures.json.gz')
    raw = gzip.decompress(path.read_bytes())
    assert path.stat().st_size < 8192 and TOKEN.encode() not in raw and PATH.encode() not in raw
    cases = json.loads(raw)
    for label, status in [('pass', 'PASS'), ('fail', 'FAIL'), ('unknown', 'UNKNOWN')]:
        assert check.evaluate(cases[label], cases[label + '_index'])[0] == status
    assert check.evaluate(cases['missing'], {})[0] == 'UNKNOWN'
    assert check.evaluate(cases['malformed'], {})[0] == 'UNKNOWN'


def test_native_quota_header_only_fixed_google_api(monkeypatch):
    c, calls, *_ = fixture(monkeypatch, options={'quota_project': 'billing-project'})
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'PASS'
    reads = [k for _, _, k in calls if k.get('stream')]
    assert reads[0]['headers']['X-Goog-User-Project'] == 'billing-project'
    assert all('X-Goog-User-Project' not in r['headers'] for r in reads[1:])


def test_invalid_native_quota_rejected_without_adapter_credentials(monkeypatch):
    c, calls, _, _, auth, *_ = fixture(monkeypatch, options={'quota_project': 'billing-project\r\nInjected: value'})
    before = len(auth)
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['reason'] == 'quota_project_invalid'
    assert len(auth) == before and not [k for _, _, k in calls if k.get('stream')]


def test_native_credential_quota_header(monkeypatch):
    c, calls, *_ = fixture(monkeypatch)
    c.transport.credentials.headers = lambda: {'Authorization': 'Bearer ' + AUTH,
        'x-goog-user-project': 'billing-project', 'Unrelated-Header': 'never-forward'}
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'PASS'
    reads = [k for _, _, k in calls if k.get('stream')]
    assert reads[0]['headers']['X-Goog-User-Project'] == 'billing-project'
    assert all('Unrelated-Header' not in r['headers'] for r in reads)
    assert all('X-Goog-User-Project' not in r['headers'] for r in reads[1:])


def test_eight_files_merge_exact_value_fingerprints(monkeypatch):
    c, *_ = fixture(monkeypatch, b'same selected content\n', paths=['file-%d.txt' % n for n in range(8)])
    def scanner(payload, path, timeout):
        return [('same exact value', 'fixture', 1)]
    monkeypatch.setattr(scanning, '_scan_kingfisher', scanner)
    monkeypatch.setattr(scanning, '_scan_trufflehog', scanner)
    row, index = produce(c)
    status, evidence = check.evaluate(row, index)
    assert status == 'FAIL' and len(evidence['files']) == 8
    leak, = evidence['secret_leaks']
    assert len(leak['locations']) == 8 and len(leak['detectors']) == 2


def test_selected_file_byte_budget(monkeypatch):
    c, *_ = fixture(monkeypatch, b'x' * (content.MAX_FILE + 1))
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['reason'] == 'git_content_rejected'


def test_shared_deadline_after_credential_refresh(monkeypatch):
    c, calls, *_ = fixture(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(adapter.time, 'monotonic', lambda: clock[0])
    def refreshed():
        clock[0] = 161.0
        return {'Authorization': 'Bearer ' + AUTH}
    c.transport.credentials.headers = refreshed
    row, index = produce(c)
    assert check.evaluate(row, index)[0] == 'UNKNOWN'
    assert not [k for _, _, k in calls if k.get('stream')]


def test_explicit_install_is_idempotent(monkeypatch):
    import peaso.checks as registry
    from peaso.checks import fixtures
    monkeypatch.setattr(registry, 'CHECKS', [c for c in registry.CHECKS if c.id != check.CHECK_ID])
    monkeypatch.setattr(fixtures, 'CASES', dict(fixtures.CASES))
    check.install()
    check.install()
    installed = [c for c in registry.CHECKS if c.id == check.CHECK_ID]
    assert len(installed) == 1
    assert list(installed[0].dependencies) == ['project', adapter.KIND]
    assert check.CHECK_ID in fixtures.CASES
