"""Offline native GCS streaming -> bounded archive parser -> pure callback."""
from copy import deepcopy
import gzip
import io
from pathlib import Path
import runpy
import stat
import tarfile
from types import SimpleNamespace
from urllib.parse import quote
import zipfile
import json

import pytest

from peaso.collectors import gcp
from peaso.collectors import gcp_selected_archive_secret_indicators as adapter
from peaso.collectors import gcp_selected_object_secret_indicators as objects
from peaso.checks import gcp_selected_archive_secret_review_20261019 as check
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings

# Reuse the corrected native HTTP fixture transport, including real CRM v3
# scope_jobs/bucket production, rather than duplicate it with invented fields.
BASE = runpy.run_path(str(Path(__file__).with_name('test_gcp_selected_object_secret_review_20261019.py')))
SCOPE, BUCKET, TOKEN = BASE['SCOPE'], BASE['BUCKET'], BASE['TOKEN']
Response = BASE['Response']


def target(name='source.zip', scope=SCOPE, format_name='zip'):
    return {'project_scope': scope, 'bucket': BUCKET, 'object': name,
            'generation': '1234', 'format': format_name}


def archive(format_name='zip', files=None):
    files = files if files is not None else {'settings.env': b'STAGE=production\n'}
    output = io.BytesIO()
    if format_name == 'zip':
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as container:
            for name, data in files.items(): container.writestr(name, data)
        return output.getvalue()
    with tarfile.open(fileobj=output, mode='w', format=tarfile.USTAR_FORMAT) as container:
        for name, data in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            container.addfile(member, io.BytesIO(data))
    return gzip.compress(output.getvalue(), mtime=0) if format_name == 'tar.gz' else output.getvalue()


def replies(payload, obj):
    mime = {'zip': 'application/zip', 'tar': 'application/x-tar', 'tar.gz': 'application/gzip'}.get(obj['format'], 'application/octet-stream')
    data = {'bucket': obj['bucket'], 'name': obj['object'], 'generation': obj['generation'],
            'size': str(len(payload)), 'contentType': mime}
    return [Response(json.dumps(data).encode()), Response(payload,
        {'Content-Type': mime, 'X-Goog-Generation': obj['generation']})]


def fixture(monkeypatch, payload=None, targets=None, options=None, responses=None):
    targets = targets or [target()]
    responses = responses if responses is not None else replies(payload if payload is not None else archive(), targets[0])
    opts = {'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
            adapter.OPTION: targets, **(options or {})}
    return BASE['fixture'](monkeypatch, responses, options=opts)


def index(row, status='collected'):
    return {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {
        adapter.KIND: [{'scope': SCOPE, 'status': status, 'items': [row]}]}}


def collect_native_pipeline(monkeypatch, payload=None, *, format_name='zip', media_status=200, scope=SCOPE):
    # Derived from the corrected selected-object native fixture, preserving its
    # actual CRM v3/Compute/bucket HTTP rather than hand-populating collections.
    selected = target('source.' + format_name, scope, format_name)
    options = {'inventories': ['project', 'bucket', adapter.KIND], 'include_inherited': False,
               'metrics_scopes': False, 'concurrency': 1, 'retries': 0,
               'content_secret_scans': True, '_content_secret_scan_kinds': [adapter.KIND],
               adapter.OPTION: [selected]}
    transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': 'Bearer fake'}, close=lambda: None), options)
    calls, streamed = [], replies(payload if payload is not None else archive(format_name), selected)
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
    for entry in snapshot['collections']: collections.setdefault(entry['type'], []).append(entry)
    context = {'context': {'provider': 'gcp', 'scope': scope}, 'collections': collections}
    return row, context, snapshot, calls, streamed


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
                                     {'_content_secret_scan_kinds': []}, {'_content_secret_scan_kinds': [objects.KIND]}])
def test_default_off_or_missing_named_archive_kind_performs_zero_calls(monkeypatch, options):
    if isinstance(options.get('content_secret_scans'), str):
        with pytest.raises(ValueError, match='content_secret_scans must be a boolean'):
            fixture(monkeypatch, options=options)
        return
    collector, calls, auth = fixture(monkeypatch, options=options)
    assert adapter.collect_selected_archives(collector, SCOPE) == []
    assert calls == auth == []


@pytest.mark.parametrize('mutation', ['format', 'foreign_scope', 'generation', 'extra_key', 'duplicate'])
def test_selection_is_strict_before_credentials(monkeypatch, mutation):
    selected = [target()]
    if mutation == 'format': selected[0]['format'] = 'auto'
    if mutation == 'foreign_scope': selected[0]['project_scope'] = 'projects/other'
    if mutation == 'generation': selected[0]['generation'] = 'latest'
    if mutation == 'extra_key': selected[0]['url'] = 'https://example.invalid'
    if mutation == 'duplicate': selected *= 2
    collector, calls, auth = fixture(monkeypatch, targets=selected)
    with pytest.raises(objects.Incomplete): adapter.collect_selected_archives(collector, SCOPE)
    assert calls == auth == []


def test_actual_native_collect_with_v3_project_and_provenance_to_callback(monkeypatch, clean):
    row, context, snapshot, calls, streamed = collect_native_pipeline(monkeypatch, format_name='tar.gz')
    assert check.evaluate(row, context)[0] == 'PASS'
    project = context['collections']['project'][0]['items'][0]
    assert project['name'] == 'projects/10001' and 'projectNumber' not in project
    assert len(calls) == 6 and all(r.closed for r in streamed)
    envelope = context['collections'][adapter.KIND][0]
    assert len(envelope['source_requests']) == 2
    assert row[adapter.MARKER]['format'] == 'tar.gz'


@pytest.mark.parametrize('case', ['mime', 'metadata_generation', 'media_generation', 'truncated_media',
                                  'redirect', 'denied', 'encoding', 'length', 'bucket_binding'])
def test_native_read_failures_remain_unknown(monkeypatch, clean, case):
    selected = target()
    responses = replies(archive(), selected)
    if case in ('mime', 'metadata_generation'):
        data = json.loads(responses[0].raw.stream.getvalue())
        data.update({'contentType': 'text/plain'} if case == 'mime' else {'generation': '9999'})
        responses[0] = Response(json.dumps(data).encode())
    if case == 'media_generation': responses[1].headers['X-Goog-Generation'] = '9999'
    if case == 'truncated_media': responses[1].raw = BASE['Raw'](b'PK')
    if case == 'redirect': responses[1].status_code = 302
    if case == 'denied': responses[1].status_code = 403
    if case == 'encoding': responses[1].headers['Content-Encoding'] = 'gzip'
    if case == 'length': responses[1].headers['Content-Length'] = '1'
    collector, calls, auth = fixture(monkeypatch, responses=responses)
    if case == 'bucket_binding': collector.collections[('bucket', SCOPE)]['items'][0]['projectNumber'] = '20002'
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert all(r.closed for r in responses[:len(calls)])
    if case == 'bucket_binding': assert calls == auth == []


def bad_archive(case):
    if case == 'traversal': return archive(files={'../settings.env': b'STAGE=production'})
    if case == 'nested': return archive(files={'nested.zip': archive()})
    if case == 'binary': return archive(files={'file.bin': b'a\x00b'})
    if case == 'utf8': return archive(files={'file.txt': b'\xff\xfe'})
    if case == 'bomb': return archive(files={'huge.txt': b'a' * 100000})
    if case == 'member_count': return archive(files={str(i) + '.txt': b'a' for i in range(101)})
    if case == 'empty': return archive(files={})
    if case == 'truncated': return archive()[:-8]
    if case == 'encrypted':
        raw = bytearray(archive())
        raw[6] |= 1
        central = raw.index(b'PK\x01\x02')
        raw[central + 8] |= 1
        return bytes(raw)
    if case == 'symlink':
        out = io.BytesIO()
        with zipfile.ZipFile(out, 'w') as container:
            member = zipfile.ZipInfo('link.env')
            member.create_system = 3
            member.external_attr = (stat.S_IFLNK | 0o777) << 16
            container.writestr(member, 'settings.env')
        return out.getvalue()
    raise AssertionError(case)


@pytest.mark.parametrize('case', ['traversal', 'nested', 'binary', 'utf8', 'bomb', 'member_count',
                                  'empty', 'truncated', 'encrypted', 'symlink'])
def test_unsafe_or_incomplete_zip_never_becomes_clean(monkeypatch, clean, case):
    collector, _, _ = fixture(monkeypatch, payload=bad_archive(case))
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert row[adapter.MARKER]['leaks'] == []


@pytest.mark.parametrize('case', ['link', 'truncated', 'nested', 'gzip_trailing'])
def test_tar_links_terminators_nested_and_extra_gzip_rejected(monkeypatch, clean, case):
    format_name = 'tar'
    payload = archive('tar')
    if case == 'link':
        out = io.BytesIO()
        with tarfile.open(fileobj=out, mode='w', format=tarfile.USTAR_FORMAT) as container:
            member = tarfile.TarInfo('link.env'); member.type = tarfile.SYMTYPE; member.linkname = 'settings.env'
            container.addfile(member)
        payload = out.getvalue()
    if case == 'truncated': payload = payload[:512]
    if case == 'nested': payload = archive('tar', {'nested.tar': archive('tar')})
    if case == 'gzip_trailing':
        format_name = 'tar.gz'; payload = archive('tar.gz') + gzip.compress(b'extra')
    collector, _, _ = fixture(monkeypatch, payload, targets=[target(format_name=format_name)])
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'


def test_shared_text_archive_budget_and_failed_expansion_reservation(monkeypatch, clean):
    collector, calls, _ = fixture(monkeypatch)
    collector.transport._selected_object_secret_state = {'started': objects.time.monotonic(),
        'bytes': objects.MAX_TOTAL_BYTES, 'calls': 0, 'items': {}, 'lock': objects.threading.Lock()}
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN' and len(calls) == 1
    collector, _, _ = fixture(monkeypatch, payload=bad_archive('nested'))
    adapter.collect_selected_archives(collector, SCOPE)
    state = collector.transport._selected_object_secret_state
    assert state['archive_expanded'] == adapter.MAX_EXPANDED_BYTES
    assert state['archive_members'] == adapter.MAX_MEMBERS


def test_parser_bindings_are_private_and_deadline_reserves_both_tools(monkeypatch, clean):
    before = (adapter.scan_zip.__globals__['_scan'], adapter.scan_zip.__globals__['EXPANDED_LIMIT'])
    observed = []
    original = adapter.scan_content
    def scan(raw, path, *, timeout):
        observed.append(timeout)
        return original(raw, path, timeout=timeout)
    monkeypatch.setattr(adapter, 'scan_content', scan)
    collector, _, _ = fixture(monkeypatch)
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'PASS'
    assert observed and all(0 < t <= 5 for t in observed)
    assert before == (adapter.scan_zip.__globals__['_scan'], adapter.scan_zip.__globals__['EXPANDED_LIMIT'])


def test_missing_engine_or_tampered_consumer_cannot_pass(monkeypatch, clean):
    def unavailable(*a): raise OSError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_trufflehog', unavailable)
    collector, _, _ = fixture(monkeypatch)
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps(row)
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])
    collector, _, _ = fixture(monkeypatch)
    valid, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(valid, index(valid))[0] == 'PASS'
    assert check.evaluate(valid, index(valid, 'partial'))[0] == 'UNKNOWN'
    tampered = deepcopy(valid)
    tampered[adapter.MARKER]['files'][0]['engines'][1] = deepcopy(tampered[adapter.MARKER]['files'][0]['engines'][0])
    assert check.evaluate(tampered, index(tampered))[0] == 'UNKNOWN'
    tampered = deepcopy(valid)
    tampered[adapter.MARKER]['files'][0]['path'] = 'foreign-file'
    assert check.evaluate(tampered, index(tampered))[0] == 'UNKNOWN'


def test_member_bound_empty_file_and_cancellation_inside_parser(monkeypatch, clean):
    collector, _, _ = fixture(monkeypatch, archive(files={'empty.txt': b''}))
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'PASS'
    monkeypatch.setattr(adapter, 'MAX_MEMBER_BYTES', 10)
    collector, _, _ = fixture(monkeypatch, archive(files={'file.txt': b'01234567890'}))
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'
    monkeypatch.setattr(adapter, 'MAX_MEMBER_BYTES', 1048576)
    collector, _, _ = fixture(monkeypatch)
    original = adapter.scan_content
    def cancel_after_scan(*a, **kwargs):
        outcome = original(*a, **kwargs)
        collector.transport.options['_cancel_check'] = lambda: True
        return outcome
    monkeypatch.setattr(adapter, 'scan_content', cancel_after_scan)
    row, = adapter.collect_selected_archives(collector, SCOPE)
    assert check.evaluate(row, index(row))[0] == 'UNKNOWN'


@pytest.fixture(scope='module')
def installed_engines():
    pytest.importorskip('kingfisher_sdk')
    assert scanning._trufflehog()


@pytest.mark.parametrize('format_name', ['zip', 'tar', 'tar.gz'])
@pytest.mark.parametrize('positive', [False, True])
def test_real_dual_tools_native_archive_positive_and_negative(installed_engines, monkeypatch, format_name, positive, capsys):
    data = ('TOKEN=' + TOKEN + '\n').encode() if positive else b'STAGE=production\n'
    row, context, snapshot, calls, responses = collect_native_pipeline(monkeypatch,
        archive(format_name, {'settings.env': data}), format_name=format_name)
    status, evidence = check.evaluate(row, context)
    assert status == ('FAIL' if positive else 'PASS')
    if positive:
        leak, = evidence['secret_leaks']
        assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert all(r.closed for r in responses)
    assert TOKEN not in json.dumps([snapshot, evidence]) + repr(scanning._RESULTS) + str(capsys.readouterr())


def test_real_exact_value_merges_files_archives_and_function_service(installed_engines, monkeypatch):
    targets = [target('one.zip'), target('two.tar.gz', format_name='tar.gz')]
    payload = ('TOKEN=' + TOKEN + '\n').encode()
    responses = sum((replies(archive(t['format'], {TOKEN + '.env': payload, 'copy.env': payload}), t) for t in targets), [])
    collector, _, _ = fixture(monkeypatch, targets=targets, responses=responses)
    findings = []
    def add(row, evaluator, context, check_id, kind):
        status, evidence = evaluator(row, context)
        assert status == 'FAIL'
        findings.append({'provider': 'gcp', 'check_id': check_id, 'scope': SCOPE,
            'resource_id': row['name'], 'native_resource_id': row['name'], 'resource_type': kind,
            'status': status, 'finding_type': 'secrets', 'frameworks': [], 'evidence': evidence})
    for row in adapter.collect_selected_archives(collector, SCOPE):
        add(row, check.evaluate, index(row), check.CHECK_ID, adapter.KIND)
    from peaso.collectors.gcp_function_secret_indicators import project_response
    from peaso.checks import gcp_function_secret_review_20261019 as function_check
    name = SCOPE + '/locations/us-central1/functions/worker'
    native = {'name': name, 'serviceConfig': {'environmentVariables': {'TOKEN': TOKEN}}, 'buildConfig': {}}
    row = project_response({'functions': [native]}, method='GET',
        url='https://cloudfunctions.googleapis.com/v2/' + SCOPE + '/locations/-/functions',
        scope=SCOPE, enabled=True)['functions'][0]
    context = {'context': {'provider': 'gcp', 'scope': SCOPE},
               'collections': {'function': [{'scope': SCOPE, 'status': 'collected', 'items': [row]}]}}
    add(row, function_check.evaluate, context, function_check.CHECK_ID, 'function')
    merged = deduplicate_secret_findings(findings)
    assert len(merged) == 1
    leak, = merged[0]['evidence']['secret_leaks']
    assert len(leak['locations']) == 5 and len(merged[0]['linked_check_ids']) == 2
    assert {d['engine'] for d in leak['detectors']} == {'kingfisher', 'trufflehog'}
    assert TOKEN not in json.dumps([merged, collector.transport.evidence]) + repr(scanning._RESULTS)
