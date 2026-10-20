"""Native CodeCommit paths stay private: SDK routing -> opaque cache -> engine."""
from copy import deepcopy
import base64
import json
import socket
from types import SimpleNamespace
import pytest
from peaso import engine, secret_scanning as scanning
from peaso.collectors import aws, aws_code_log_content_indicators as adapter
from peaso.checks import aws_code_log_content_review_20261019 as consumer
from peaso.snapshot import make_snapshot

ACCOUNT, REGION = '123456789012', 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
COMMIT = 'a' * 40
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
REPO = {'repositoryName': 'audit', 'Arn': f'arn:aws:codecommit:{REGION}:{ACCOUNT}:audit'}


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    def blocked(*a, **k): pytest.fail('actual network/DNS/auth forbidden')
    for name in ('connect', 'connect_ex'): monkeypatch.setattr(socket.socket, name, blocked)
    for name in ('getaddrinfo', 'create_connection'): monkeypatch.setattr(socket, name, blocked)
    monkeypatch.setenv('AWS_EC2_METADATA_DISABLED', 'true')
    monkeypatch.setattr(aws, '_session', blocked)
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


def clients():
    import boto3
    from botocore.stub import Stubber
    session = boto3.Session(aws_access_key_id='offline-fix', aws_secret_access_key='offline-fix', region_name=REGION)
    client = session.client('codecommit', region_name=REGION)
    requests = aws.Requests({'content_secret_scans': True, 'retry_attempts': 1})
    requests._clients[(id(session), 'codecommit', REGION)] = client
    return requests, session, Stubber(client)


def repo(stub):
    stub.add_response('get_repository', {'repositoryMetadata': {**REPO, 'accountId': ACCOUNT, 'defaultBranch': 'main'}}, {'repositoryName': 'audit'})
    stub.add_response('get_branch', {'branch': {'branchName': 'main', 'commitId': COMMIT}}, {'repositoryName': 'audit', 'branchName': 'main'})


def folder(stub, path='/', files=(), folders=(), **extra):
    args = {'repositoryName': 'audit', 'commitSpecifier': COMMIT, 'folderPath': path}
    stub.add_response('get_folder', {'commitId': COMMIT, 'folderPath': path,
        'files': [{'absolutePath': p} for p in files], 'subFolders': [{'absolutePath': p} for p in folders], **extra}, args)


def file(stub, path, payload, *, denied=False, **extra):
    args = {'repositoryName': 'audit', 'commitSpecifier': COMMIT, 'filePath': path}
    if denied:
        stub.add_client_error('get_file', service_error_code='AccessDeniedException', service_message=TOKEN, expected_params=args)
    else:
        stub.add_response('get_file', {'commitId': COMMIT, 'blobId': 'b' * 40, 'filePath': path,
            'fileMode': 'NORMAL', 'fileSize': len(payload), 'fileContent': payload, **extra}, args)


def evaluate(sample):
    item = {**REPO, 'ContentSecretIndicators': sample}
    env = {'type': 'codecommit_repository', 'scope': SCOPE, 'account_id': ACCOUNT, 'region': REGION,
           'status': 'collected', 'items': [item]}
    index = {'context': {'provider': 'aws', 'scope': SCOPE}, 'collections': {'codecommit_repository': [env]}}
    status, evidence = consumer.repository(item, index)
    report = engine.evaluate_snapshot(make_snapshot('aws', [SCOPE], [env]), checks=[consumer.IDS['repository']])
    assert {f['status'] for f in report['findings']} == {status}
    return status, evidence, report


def retained(requests, sample=None):
    values = []
    for f in requests._cache.values():
        if f.exception() is None: values.append(f.result())
        else:
            assert f.exception().__traceback__ is None
            values.append({'status': f.exception().status, 'code': f.exception().code})
    return json.dumps([sample, list(requests._cache), values,
        getattr(requests, '_codecommit_completed_scans', {})], default=str)


@pytest.mark.parametrize('path', ['/' + TOKEN + '.txt', '/' + base64.b64encode(TOKEN.encode()).decode() + '.txt',
    '/plain.txt', '/space name/../rejected'], ids=['token-name', 'encoded-name', 'plain-name', 'traversal'])
def test_native_file_path_and_cache_keys_are_opaque(monkeypatch, path):
    if '..' in path.split('/'):
        with pytest.raises(aws.ReadFailure):
            adapter.validate_request('codecommit', 'get_file', {'repositoryName': 'audit', 'commitSpecifier': COMMIT, 'filePath': path},
                region=REGION, request_context={'remaining_bytes': adapter.MAX_BYTES})
        return
    requests, session, stub = clients()
    payload = ('token=' + TOKEN).encode()
    with stub:
        file(stub, path, payload)
        result = adapter._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=adapter.MAX_BYTES,
            repositoryName='audit', commitSpecifier=COMMIT, filePath=path)
        again = adapter._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=adapter.MAX_BYTES,
            repositoryName='audit', commitSpecifier=COMMIT, filePath=path)
        stub.assert_no_pending_responses()
    assert result == again and result['scanner_complete'] is True and len(result['leaks']) == 1
    assert {d['engine'] for d in result['leaks'][0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert {l['path'] for l in result['leaks'][0]['locations']} == {adapter.path_locator(REGION, 'audit', COMMIT, path)}
    assert requests.calls == 1 and requests.cache_hits == 1
    exported = retained(requests, result)
    for value in (TOKEN, path, base64.b64encode(TOKEN.encode()).decode()):
        assert value not in exported


@pytest.mark.parametrize('positive', [False, True])
@pytest.mark.parametrize('nested', [False, True])
def test_previously_cached_folder_paths_and_current_scan_are_both_hidden(monkeypatch, positive, nested):
    requests, session, stub = clients()
    parent = '/' + TOKEN if nested else '/'
    path = parent.rstrip('/') + '/' + TOKEN + '.txt'
    sibling = parent.rstrip('/') + '/earlier.txt'
    payload = ('token=' + TOKEN).encode() if positive else b'ready=true'
    route_sinks = []
    original = requests.call
    def call(*a, **kw):
        if '_codecommit_routes' in kw: route_sinks.append(kw['_codecommit_routes'])
        return original(*a, **kw)
    monkeypatch.setattr(requests, 'call', call)
    with stub:
        # A cached native folder exists before any detector knows the token.
        folder(stub, files=[path] if not nested else [], folders=[parent] if nested else [])
        cached = adapter._call(requests, session, REGION, 'codecommit', 'get_folder',
            repositoryName='audit', commitSpecifier=COMMIT, folderPath='/')
        assert TOKEN not in json.dumps(cached) + retained(requests)
        repo(stub)
        if nested: folder(stub, folders=[parent])
        folder(stub, path=parent, files=[sibling, path])
        file(stub, sibling, b'ready=true')
        file(stub, path, payload)
        sample = adapter.scan_repository(requests, session, REGION, REPO)
        count = requests.calls
        replay = adapter.scan_repository(requests, session, REGION, REPO)
        stub.assert_no_pending_responses()
    status, evidence, report = evaluate(sample)
    assert status == ('FAIL' if positive else 'PASS') and sample['complete'] is True
    assert replay == sample and requests.calls == count
    assert route_sinks and all(sink == {} for sink in route_sinks)
    assert TOKEN not in retained(requests, sample) + json.dumps([evidence, report])
    assert all(row['path'].startswith('/codecommit-path/') for row in sample['records'])
    assert len({row['path'] for row in sample['records']}) == 2


@pytest.mark.parametrize('paths', [('/A.txt', '/a.txt'), ('/café.txt', '/café.txt'), ('/folder//name', '/folder/name'), ('/x%2fy', '/x/y')])
def test_locators_preserve_exact_native_path_alias_bytes(paths):
    first, second = paths
    assert adapter.path_locator(REGION, 'audit', COMMIT, first) != adapter.path_locator(REGION, 'audit', COMMIT, second)
    assert adapter.path_locator(REGION, 'audit', COMMIT, first) == adapter.path_locator(REGION, 'audit', COMMIT, first)
    for region, repository, commit in [('eu-west-1', 'audit', COMMIT), (REGION, 'other', COMMIT), (REGION, 'audit', 'b' * 40)]:
        assert adapter.path_locator(region, repository, commit, first) != adapter.path_locator(REGION, 'audit', COMMIT, first)


@pytest.mark.parametrize('field,value', [('commitSpecifier', 'b' * 40), ('repositoryName', 'other'), ('filePath', '/different')])
def test_opaque_projection_binding_rejects_foreign_selector_without_forging_native_request(monkeypatch, field, value):
    requests, session, stub = clients()
    original = requests.call
    def tamper(*a, **kw):
        result = original(*a, **kw)
        raw = {'repositoryName': 'audit', 'commitSpecifier': COMMIT, 'filePath': '/safe.txt', field: value}
        result['binding']['arguments'] = adapter.opaque_arguments(raw)
        return result
    monkeypatch.setattr(requests, 'call', tamper)
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    with stub:
        file(stub, '/safe.txt', b'ready=true')
        with pytest.raises(ValueError, match='binding'):
            adapter._call(requests, session, REGION, 'codecommit', 'get_file', remaining_bytes=adapter.MAX_BYTES,
                repositoryName='audit', commitSpecifier=COMMIT, filePath='/safe.txt')
        stub.assert_no_pending_responses()


@pytest.mark.parametrize('failed', ['kingfisher', 'trufflehog'])
@pytest.mark.parametrize('positive', [False, True])
def test_partial_detector_still_hides_paths_and_never_caches_clean_scan(monkeypatch, failed, positive):
    def good(*a): return [(TOKEN, 'synthetic', 1)] if positive else []
    def bad(*a): raise ImportError('missing engine')
    monkeypatch.setattr(scanning, '_scan_kingfisher', good)
    monkeypatch.setattr(scanning, '_scan_trufflehog', good)
    monkeypatch.setattr(scanning, '_scan_' + failed, bad)
    requests, session, stub = clients();path = '/' + TOKEN + '.txt'
    with stub:
        repo(stub);folder(stub, files=[path]);file(stub, path, ('token=' + TOKEN).encode())
        sample = adapter.scan_repository(requests, session, REGION, REPO)
        stub.assert_no_pending_responses()
    assert evaluate(sample)[0] == ('FAIL' if positive else 'UNKNOWN')
    assert sample['complete'] is False and not getattr(requests, '_codecommit_completed_scans', {})
    assert TOKEN not in retained(requests, sample)


@pytest.mark.parametrize('failure', ['denied', 'foreign_response', 'binary', 'oversize'])
def test_unresolved_native_reads_keep_no_raw_path_or_clean_result(monkeypatch, failure):
    requests, session, stub = clients();path = '/' + TOKEN + '.txt'
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    with stub:
        repo(stub);folder(stub, files=[path])
        if failure == 'denied': file(stub, path, b'', denied=True)
        elif failure == 'foreign_response': file(stub, path, b'clean', filePath='/foreign')
        elif failure == 'binary': file(stub, path, b'\xff\x00')
        else: file(stub, path, b'x' * (adapter.MAX_BYTES + 1))
        sample = adapter.scan_repository(requests, session, REGION, REPO)
        stub.assert_no_pending_responses()
    assert evaluate(sample)[0] == 'UNKNOWN'
    assert sample['complete'] is False and TOKEN not in retained(requests, sample)


@pytest.mark.parametrize('operation', ['get_file', 'get_branch'])
def test_ephemeral_route_sink_is_rejected_outside_exact_folder_operation(operation):
    requests, session, stub = clients()
    with stub:
        with pytest.raises(aws.ReadFailure, match='content_route_sink_invalid'):
            requests.call(session, 'codecommit', REGION, operation, _metadata_profile=adapter.PROFILE,
                _codecommit_routes={'files': [], 'folders': []}, repositoryName='audit')
    assert requests.calls == 0 and not requests._cache


def test_folder_route_mismatch_is_unresolved_and_sink_is_cleared(monkeypatch):
    requests, session, stub = clients();sinks=[]
    original = requests.call
    def mutate(*a, **kw):
        result = original(*a, **kw)
        if '_codecommit_routes' in kw:
            sinks.append(kw['_codecommit_routes'])
            result['value']['files'] = ['/codecommit-path/' + '0' * 64]
        return result
    monkeypatch.setattr(requests, 'call', mutate)
    with stub:
        repo(stub);folder(stub, files=['/' + TOKEN + '.txt'])
        sample = adapter.scan_repository(requests, session, REGION, REPO)
        stub.assert_no_pending_responses()
    assert evaluate(sample)[0] == 'UNKNOWN' and sinks == [{}]
    assert TOKEN not in retained(requests, sample)


def test_redacted_complete_replay_cache_is_bounded():
    requests = aws.Requests({'content_secret_scans': True})
    for n in range(9): adapter._completed_scan(requests, 'opaque-' + str(n), {'complete': True, 'records': []})
    assert len(requests._codecommit_completed_scans) == 4
    adapter._completed_scan(requests, 'oversize', {'complete': True, 'records': ['x' * 2097152]})
    assert 'oversize' not in requests._codecommit_completed_scans


def test_native_case_aliases_keep_separate_routes_and_one_hidden_leak():
    requests, session, stub = clients()
    paths = ['/A-' + TOKEN + '.txt', '/a-' + TOKEN + '.txt']
    with stub:
        repo(stub);folder(stub, files=paths)
        for path in paths: file(stub, path, ('token=' + TOKEN).encode())
        sample = adapter.scan_repository(requests, session, REGION, REPO)
        stub.assert_no_pending_responses()
    status, evidence, report = evaluate(sample)
    assert status == 'FAIL' and len(report['findings']) == 1
    leak, = report['findings'][0]['evidence']['secret_leaks']
    assert len(leak['locations']) == 2
    assert len({r['path'] for r in sample['records']}) == 2
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in retained(requests, sample) + json.dumps([evidence, report])


def test_consumer_rejects_legacy_plaintext_locator_instead_of_exporting_witness(monkeypatch):
    from tests.test_aws_code_log_content_review_20261019 import fixture
    item, index = fixture('repository', positive=True)
    item['ContentSecretIndicators']['records'][0]['path'] = '/' + TOKEN + '.txt'
    status, evidence = consumer.repository(item, index)
    assert status == 'UNKNOWN' and TOKEN not in json.dumps(evidence)
