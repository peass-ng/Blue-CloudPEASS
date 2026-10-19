"""Native mock HTTP/real collector envelopes; shared dual adapters stay offline.

Transport-hook and common detector/dedup patterns attributed to the earlier
GCP Function and Logging review tests; these are new native surface proofs.
"""
import base64
from copy import deepcopy
import inspect
import json
import textwrap
from types import SimpleNamespace
from importlib.metadata import version
import pytest
from peaso import secret_scanning as scanning
from peaso.secret_findings import deduplicate_secret_findings
from peaso.collectors import gcp
from peaso.collectors import gcp_additional_literal_secret_indicators as native
from peaso.checks import gcp_additional_literal_secret_review_20261019 as check
from peaso.collectors.gcp_appengine_versions import VERSIONS_FIELDS

SCOPE = 'projects/review'
JOB = SCOPE + '/locations/us-central1/jobs/task'
APP = 'apps/review/services/default/versions/v1'
FLOW = SCOPE + '/locations/us-central1/workflows/task'
REVISION = '000001-a4d'
TOKEN = 'ghp_' + '7mQ2zR9wL4cV8nK1sF6aH3jP5uD0xB2yE9rT'
AUTH = 'Bearer SYNTHETIC_CALLER_AUTH_NEVER_PERSIST'


def b64(value):
    return base64.b64encode(value.encode()).decode()


def scheduler_row(value='public', target='httpTarget'):
    literal = {'headers': {'X-Setting': value}, 'body': b64('setting=' + value), 'httpMethod': 'POST'}
    if target == 'httpTarget':
        literal.update(uri='https://user:password@example.invalid/path?api_key=hidden',
            oidcToken={'serviceAccountEmail': 'worker@review.iam.gserviceaccount.com', 'audience': 'https://example.invalid'})
    if target == 'appEngineHttpTarget': literal.update(relativeUri='/task', appEngineRouting={'service': 'default'})
    if target == 'pubsubTarget': literal = {'attributes': {'Setting': value}, 'data': b64('setting=' + value), 'topicName': SCOPE + '/topics/tasks'}
    return {'name': JOB, 'state': 'ENABLED', 'schedule': '* * * * *', 'timeZone': 'UTC', target: literal}


def app_row(value='public'):
    return {'name': APP, 'id': 'v1', 'envVariables': {'MODE': value}, 'buildEnvVariables': {'BUILD': value}}


def workflow_row(value='public'):
    return {'name': FLOW, 'revisionId': REVISION, 'state': 'ACTIVE',
            'sourceContents': 'main:\n  steps:\n    - answer:\n        return: "' + value + '"\n'}


class Response:
    def __init__(self, data, status=200):
        self.content = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.status_code = status
        self.headers = {'Content-Length': str(len(self.content))}
        self.closed = False
    def iter_content(self, chunk_size):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]
    def json(self): return json.loads(self.content)
    def close(self): self.closed = True


@pytest.fixture(autouse=True)
def clear_cache():
    scanning._RESULTS.clear()
    yield
    scanning._RESULTS.clear()


@pytest.fixture
def clean(monkeypatch):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [])


def install_hooks(monkeypatch):
    # Production hooks and inventory admission are installed in the real class.
    return None


@pytest.fixture
def harness(monkeypatch):
    install_hooks(monkeypatch)
    def collect(kind, row=None, *, pages=None, options=None, scopes=None, source_status='collected', source_items=None, status=200, native_sources=False):
        options = {'inventories': [kind], 'content_secret_scans': True,
            '_content_secret_scan_kinds': [kind], 'retries': 0, 'cloudscheduler_locations': ['us-central1'], **(options or {})}
        transport = gcp.Transport(SimpleNamespace(headers=lambda: {'Authorization': AUTH}), options)
        if pages is None:
            if kind == native.SCHEDULER: pages = [{'jobs': [row or scheduler_row()]}]
            if kind == native.APPENGINE:
                pages = [row or app_row()]
                if native_sources:
                    pages = [{'services': [{'id': 'default', 'name': 'apps/review/services/default'}]},
                             {'versions': [{'name': APP, 'id': 'v1', 'servingStatus': 'SERVING'}]}, *pages]
            if kind == native.WORKFLOW: pages = [
                {'locations': [{'name': SCOPE + '/locations/us-central1'}]},
                {'workflows': [{'name': FLOW, 'revisionId': REVISION}]}, row or workflow_row()]
        responses = [Response(p, status) for p in pages]
        calls = []
        def request(method, url, **kwargs):
            headers = kwargs.pop('headers')
            assert headers in ({'Authorization': AUTH, 'Accept-Encoding': 'identity'}, {'Authorization': AUTH})
            assert kwargs.get('stream', True) is True and kwargs['allow_redirects'] is False
            calls.append({'method': method, 'url': url, **deepcopy(kwargs)})
            return responses[len(calls) - 1]
        monkeypatch.setattr(transport, '_session', lambda: SimpleNamespace(request=request))
        collector = gcp.GCPCollector({'options': options, 'auth': {}, 'scopes': [SCOPE] if scopes is None else scopes}, [kind], transport=transport)
        if SCOPE not in collector.scopes:
            collector.scopes.append(SCOPE)  # Simulated discovery; requested_scopes remains unchanged.
        native.prepare_scope(collector, SCOPE)
        if kind == native.SCHEDULER:
            jobs = [j for j in collector.scope_jobs(SCOPE) if j[0] == kind]
        elif kind == native.APPENGINE:
            items = [{'name': APP, 'id': 'v1', '_field_mask': VERSIONS_FIELDS, '_representation': 'partial'}] if source_items is None else source_items
            collector.collections[('app_engine_version', SCOPE)] = {'type': 'app_engine_version', 'scope': SCOPE,
                'status': source_status, 'coverage_status': source_status, 'items': items}
            if native_sources:
                from peaso.collectors.gcp_appengine_versions import list_services, list_versions
                services = collector.envelope('app_engine_service', SCOPE, 'appengine', lambda: list_services(collector, SCOPE))
                versions = collector.envelope('app_engine_version', SCOPE, 'appengine', lambda: list_versions(collector, SCOPE, services['items']))
                collector.collections[('app_engine_service', SCOPE)] = services
                collector.collections[('app_engine_version', SCOPE)] = versions
            jobs = native.appengine_jobs(collector)
        else:
            jobs = native.workflow_jobs(collector, SCOPE)
        envelope = collector.envelope(*jobs[0])
        item = envelope['items'][0] if envelope['items'] else {}
        index = {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {kind: [envelope]}}
        if kind == native.APPENGINE:
            index['collections']['app_engine_version'] = [deepcopy(collector.collections[('app_engine_version', SCOPE)])]
            if native_sources:
                index['collections']['app_engine_service'] = [deepcopy(collector.collections[('app_engine_service', SCOPE)])]
        return SimpleNamespace(kind=kind, item=item, index=index, envelope=envelope, transport=transport,
            calls=calls, responses=responses, result=check.CALLBACKS[kind](item, index))
    return collect


@pytest.mark.parametrize('kind,row', [(native.SCHEDULER, scheduler_row(TOKEN)),
    (native.SCHEDULER, scheduler_row(TOKEN, 'appEngineHttpTarget')),
    (native.SCHEDULER, scheduler_row(TOKEN, 'pubsubTarget')),
    (native.APPENGINE, app_row(TOKEN)), (native.WORKFLOW, workflow_row(TOKEN))])
def test_real_pinned_positive_same_value_dedup_and_privacy(harness, kind, row, capsys):
    assert version('kingfisher-secret-scanner') == scanning.KINGFISHER_VERSION
    assert scanning._trufflehog()
    result = harness(kind, row)
    assert result.result[0] == 'FAIL'
    leaks = result.result[1]['secret_leaks']
    assert len(leaks) == 1
    assert {d['engine'] for d in leaks[0]['detectors']} == {'kingfisher', 'trufflehog'}
    assert len({loc['path'] for loc in leaks[0]['locations']}) == (1 if kind == native.WORKFLOW else 2)
    base = {'provider': 'gcp', 'check_id': check.CHECK_IDS[kind], 'scope': SCOPE,
        'resource_id': result.item['name'], 'status': 'FAIL', 'evidence': result.result[1]}
    findings = deduplicate_secret_findings([base, dict(base, check_id='other.surface', resource_id='other-resource')])
    assert len(findings) == 1 and len(findings[0]['linked_check_ids']) == 2
    persisted = json.dumps([result.envelope, result.result, findings, result.transport.evidence, result.transport.cache]) + repr(scanning._RESULTS) + str(capsys.readouterr())
    assert TOKEN not in persisted and AUTH not in persisted and b64('setting=' + TOKEN) not in persisted
    assert result.transport.cache == {} and all(r.closed for r in result.responses)


@pytest.mark.parametrize('kind', native.KINDS)
def test_real_pinned_negative_is_only_returned_literals(harness, kind):
    result = harness(kind)
    assert result.result[0] == 'PASS'
    assert 'returned' in result.result[1]['observed'] and 'Other configuration' in result.result[1]['observed']
    assert all(e['status'] == 'complete' for s in result.item[native.MARKER]['surfaces'] for e in s['engines'])


@pytest.mark.parametrize('target', ['httpTarget', 'appEngineHttpTarget', 'pubsubTarget'])
def test_scheduler_all_native_targets_with_decoded_content_and_safe_metadata(harness, clean, target):
    row = scheduler_row(target=target)
    result = harness(native.SCHEDULER, row)
    assert result.result[0] == 'PASS'
    safe = result.item[target]
    assert 'headers' not in safe and 'body' not in safe and 'attributes' not in safe and 'data' not in safe
    assert safe.get('headerNames', safe.get('attributeNames')) == (['Setting'] if target == 'pubsubTarget' else ['X-Setting'])
    if target == 'httpTarget':
        assert safe['uri'] == 'https://example.invalid/path'
        assert safe['oidcToken']['serviceAccountEmail'] == row[target]['oidcToken']['serviceAccountEmail']
    if target == 'appEngineHttpTarget': assert safe['appEngineRouting'] == {'service': 'default'}
    if target == 'pubsubTarget': assert safe['topicName'] == SCOPE + '/topics/tasks'


@pytest.mark.parametrize('case', ['invalid', 'noncanonical', 'binary', 'oversized', 'missing_target', 'union', 'redacted', 'partial', 'foreign', 'location'])
def test_scheduler_unsafe_or_incomplete_native_content_unknown(harness, clean, case):
    row = scheduler_row()
    if case == 'invalid': row['httpTarget']['body'] = 'not base64!'
    if case == 'noncanonical': row['httpTarget']['body'] = 'YQ==' + '\n'
    if case == 'binary': row['httpTarget']['body'] = base64.b64encode(b'\xff\xfe').decode()
    if case == 'oversized': row['httpTarget']['body'] = b64('x' * (native.MAX_VALUE_BYTES + 1))
    if case == 'missing_target': del row['httpTarget']
    if case == 'union': row['pubsubTarget'] = {'attributes': {'a': 'b'}}
    if case == 'redacted': row['httpTarget']['headerNames'] = ['X-Setting']; del row['httpTarget']['headers']
    if case == 'partial': row['_coverage'] = {'httpTarget': {'status': 'partial'}}
    if case == 'foreign': row['name'] = JOB.replace('/review/', '/other/')
    if case == 'location': row['name'] = JOB.replace('/us-central1/', '/europe-west1/')
    assert harness(native.SCHEDULER, row).result[0] == 'UNKNOWN'


@pytest.mark.parametrize('kind', [native.APPENGINE, native.WORKFLOW])
@pytest.mark.parametrize('case', ['foreign', 'missing', 'partial', 'malformed'])
def test_other_native_identity_coverage_and_literal_shape_unknown(harness, clean, kind, case):
    row = app_row() if kind == native.APPENGINE else workflow_row()
    if case == 'foreign': row['name'] = row['name'].replace('/review/', '/other/')
    if case == 'partial': row['_coverage'] = {'value': {'status': 'partial'}}
    if case == 'missing':
        if kind == native.APPENGINE: row['envVariableNames'] = ['MODE']; del row['envVariables']
        else: del row['sourceContents']
    if case == 'malformed': row['envVariables' if kind == native.APPENGINE else 'sourceContents'] = []
    assert harness(kind, row).result[0] == 'UNKNOWN'


def test_appengine_precise_full_view_mask_and_omitted_empty_maps(harness, clean):
    result = harness(native.APPENGINE, {'name': APP, 'id': 'v1'})
    assert result.result[0] == 'PASS'
    assert result.calls[0]['params'] == native.APP_PARAMS
    assert 'envVariables' not in VERSIONS_FIELDS
    assert result.index['collections']['app_engine_version'][0]['items'][0]['_representation'] == 'partial'


@pytest.mark.parametrize('case', ['partial', 'foreign', 'duplicate', 'wrong_mask', 'wrong_id'])
def test_appengine_source_inventory_proof_required_before_extra_call(harness, case):
    rows = [{'name': APP, 'id': 'v1', '_field_mask': VERSIONS_FIELDS}]
    status = 'collected'
    if case == 'partial': status = 'partial'
    if case == 'foreign': rows[0]['name'] = APP.replace('/review/', '/other/')
    if case == 'duplicate': rows.append(deepcopy(rows[0]))
    if case == 'wrong_mask': rows[0]['_field_mask'] = 'name,id'
    if case == 'wrong_id': rows[0]['id'] = 'other'
    result = harness(native.APPENGINE, pages=[], source_status=status, source_items=rows)
    assert result.result[0] == 'UNKNOWN' and not result.calls


@pytest.mark.parametrize('case', ['revision', 'state', 'missing_revision', 'oversized'])
def test_workflow_exact_discovered_revision_and_deployed_source(harness, clean, case):
    row = workflow_row()
    if case == 'revision': row['revisionId'] = '000002-aaa'
    if case == 'state': row['state'] = 'UNAVAILABLE'
    if case == 'missing_revision': del row['revisionId']
    if case == 'oversized': row['sourceContents'] = 'x' * 131073
    result = harness(native.WORKFLOW, row)
    assert result.result[0] == 'UNKNOWN'
    assert result.calls[-1]['params'] == {'revisionId': REVISION}


@pytest.mark.parametrize('kind', [native.APPENGINE, native.WORKFLOW])
@pytest.mark.parametrize('options', [{'content_secret_scans': False}, {'_content_secret_scan_kinds': []}])
def test_disabled_extra_inventories_make_zero_calls(monkeypatch, kind, options):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('disabled content reached credentials or HTTP')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    monkeypatch.setattr(gcp.Transport, '_session', forbidden)
    opts = {'inventories': [kind], 'content_secret_scans': True,
            '_content_secret_scan_kinds': [kind], **options}
    collector = gcp.GCPCollector({'scopes': [SCOPE], 'options': opts}, [kind],
        transport=SimpleNamespace())
    try:
        jobs = native.appengine_jobs(collector) if kind == native.APPENGINE else native.workflow_jobs(collector, SCOPE)
        assert jobs == []
        assert check.CALLBACKS[kind]({}, {'context': {'provider': 'gcp', 'scope': SCOPE}, 'collections': {}})[0] == 'UNKNOWN'
        assert calls == []
    finally:
        collector.hydration_pool.shutdown(wait=True)


@pytest.mark.parametrize('kind', [native.APPENGINE, native.WORKFLOW])
def test_non_boolean_optin_rejected_before_credentials_or_http(monkeypatch, kind):
    calls = []
    def forbidden(*args, **kwargs):
        calls.append(True)
        pytest.fail('invalid intake reached credentials or HTTP')
    monkeypatch.setattr(gcp, 'Credentials', forbidden)
    monkeypatch.setattr(gcp.Transport, '_session', forbidden)
    with pytest.raises(ValueError, match='^content_secret_scans must be a boolean$'):
        gcp.GCPCollector({'scopes': [SCOPE], 'options': {'content_secret_scans': 'true',
            'inventories': [kind], '_content_secret_scan_kinds': [kind]}}, [kind])
    assert calls == []


@pytest.mark.parametrize('kind', [native.APPENGINE, native.WORKFLOW])
def test_discovered_project_is_authorized_after_normal_scope_resolution(harness, clean, kind):
    result = harness(kind, scopes=['organizations/123'], options={'all_projects': True})
    assert result.result[0] == 'PASS' and result.calls


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('engine', ['kingfisher', 'trufflehog'])
def test_either_tool_failure_is_unknown_and_error_text_hidden(harness, monkeypatch, kind, engine):
    monkeypatch.setattr(scanning, '_scan_kingfisher', lambda *a: [(TOKEN, 'synthetic', 1)])
    monkeypatch.setattr(scanning, '_scan_trufflehog', lambda *a: [(TOKEN, 'synthetic', 1)])
    def fail(*a): raise RuntimeError(TOKEN)
    monkeypatch.setattr(scanning, '_scan_' + engine, fail)
    result = harness(kind)
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence])


@pytest.mark.parametrize('kind', native.KINDS)
def test_denied_error_body_and_caller_auth_never_persist(harness, kind):
    result = harness(kind, pages=[{'error': {'message': TOKEN}}], status=403)
    assert result.result[0] == 'UNKNOWN'
    assert result.envelope['status'] == 'denied'
    assert TOKEN not in json.dumps([result.envelope, result.transport.evidence, result.transport.cache])


def test_scheduler_pagination_and_marker_survive_actual_scrub(harness, clean):
    row = scheduler_row()
    second = scheduler_row(); second['name'] = JOB + '2'
    result = harness(native.SCHEDULER, pages=[{'jobs': [row], 'nextPageToken': 'PRIVATE_CURSOR'}, {'jobs': [second]}])
    assert result.result[0] == 'PASS' and len(result.envelope['items']) == 2
    assert result.calls[1]['params']['pageToken'] == 'PRIVATE_CURSOR'
    assert 'PRIVATE_CURSOR' not in json.dumps([result.envelope, result.transport.evidence, result.transport.cache])
    assert all(native.MARKER in row for row in result.envelope['items'])


def test_workflow_empty_cursor_continues_and_repeated_cursor_is_unknown(harness, clean):
    result = harness(native.WORKFLOW, pages=[{'nextPageToken': 'a'},
        {'locations': [{'name': SCOPE + '/locations/us-central1'}]},
        {'workflows': [{'name': FLOW, 'revisionId': REVISION}]}, workflow_row()])
    assert result.result[0] == 'PASS' and len(result.calls) == 4
    result = harness(native.WORKFLOW, pages=[{'nextPageToken': 'a'}, {'nextPageToken': 'a'}])
    assert result.result[0] == 'UNKNOWN' and len(result.calls) == 2


@pytest.mark.parametrize('kind', native.KINDS)
@pytest.mark.parametrize('case', ['provider', 'partial', 'duplicate', 'engines', 'identity', 'paths'])
def test_consumer_rejects_unbound_or_contradictory_proofs(harness, clean, kind, case):
    result = harness(kind)
    assert result.result[0] == 'PASS'
    if case == 'provider': result.index['context']['provider'] = 'aws'
    if case == 'partial': result.envelope['status'] = 'partial'
    if case == 'duplicate': result.envelope['items'].append(deepcopy(result.item))
    if case == 'engines': result.item[native.MARKER]['surfaces'][0]['engines'].pop()
    if case == 'identity': result.item[native.MARKER]['identity'] = 'foreign'
    if case == 'paths': result.item[native.MARKER]['surfaces'][0]['surface'] = TOKEN
    assert check.CALLBACKS[kind](result.item, result.index)[0] == 'UNKNOWN'


def test_default_scheduler_reuses_existing_metadata_read_and_never_scans(harness, monkeypatch):
    monkeypatch.setattr(native, 'scan_content', lambda *a, **kw: pytest.fail('default-off content scan'))
    row = scheduler_row(TOKEN)
    row[native.MARKER] = {'complete': True, 'leaks': []}  # Provider marker is never authority.
    result = harness(native.SCHEDULER, row, options={'content_secret_scans': False})
    assert result.result[0] == 'UNKNOWN' and len(result.calls) == 1
    assert result.envelope['status'] == 'collected'
    assert result.item['httpTarget']['headerNames'] == ['X-Setting']
    assert native.MARKER not in result.item
    assert TOKEN not in json.dumps([result.envelope, result.transport.cache, result.transport.evidence], default=str)
    assert result.item['httpTarget']['uri'] == 'https://example.invalid/path'


@pytest.mark.parametrize('case', ['short', 'long', 'gzip', 'unframed', 'conflicting', 'oversize', 'duplicate_json'])
def test_shared_stream_contracts_fail_closed_before_scanning(harness, clean, monkeypatch, case):
    original = Response.__init__
    def initialize(self, *args, **kwargs):
        original(self, *args, **kwargs)
        if case == 'short': self.headers['Content-Length'] = str(len(self.content) + 1)
        if case == 'long': self.headers['Content-Length'] = str(len(self.content) - 1)
        if case == 'gzip': self.headers['Content-Encoding'] = 'gzip'
        if case == 'unframed': self.headers = {}
        if case == 'conflicting': self.headers['Transfer-Encoding'] = 'chunked'
        if case == 'oversize': self.headers['Content-Length'] = str(native.MAX_HTTP_BYTES + 1)
        if case == 'duplicate_json': self.content = b'{"name":"one","name":"two"}'; self.headers['Content-Length'] = str(len(self.content))
    monkeypatch.setattr(Response, '__init__', initialize)
    assert harness(native.APPENGINE).result[0] == 'UNKNOWN'


@pytest.mark.parametrize('case', ['pages', 'rows', 'budget'])
def test_scheduler_collection_bounds_cannot_produce_complete_verdict(harness, clean, monkeypatch, case):
    if case == 'pages':
        pages = [{'jobs': [dict(scheduler_row(), name=JOB + str(i))], 'nextPageToken': str(i)} for i in range(3)]
    elif case == 'rows': pages = [{'jobs': [scheduler_row()] * 101}]
    else:
        monkeypatch.setattr(native, 'MAX_SCOPE_BYTES', 1)
        pages = [{'jobs': [scheduler_row()]}]
    result = harness(native.SCHEDULER, pages=pages)
    assert result.result[0] == 'UNKNOWN'
    assert len(result.calls) <= native.MAX_PAGES


@pytest.mark.parametrize('case', ['unreachable', 'duplicate', 'foreign_location', 'bad_revision'])
def test_workflow_discovery_must_complete_before_source_get(harness, clean, case):
    locations = {'locations': [{'name': SCOPE + '/locations/us-central1'}]}
    workflows = {'workflows': [{'name': FLOW, 'revisionId': REVISION}]}
    if case == 'unreachable': workflows['unreachable'] = ['us-central1']
    if case == 'duplicate': workflows['workflows'].append(deepcopy(workflows['workflows'][0]))
    if case == 'foreign_location': locations['locations'][0]['name'] = 'projects/other/locations/us-central1'
    if case == 'bad_revision': workflows['workflows'][0]['revisionId'] = TOKEN
    result = harness(native.WORKFLOW, pages=[locations, workflows])
    assert result.result[0] == 'UNKNOWN'
    assert not any(c['params'].get('revisionId') for c in result.calls)


@pytest.mark.parametrize('case', ['pairs', 'value', 'mask_not_honored', 'wrong_id'])
def test_appengine_value_bounds_and_honored_projection(harness, clean, case):
    row = app_row()
    if case == 'pairs': row['envVariables'] = {str(i): 'public' for i in range(native.MAX_PAIRS + 1)}
    if case == 'value': row['envVariables'] = {'SETTING': 'x' * (native.MAX_VALUE_BYTES + 1)}
    if case == 'mask_not_honored': row['deployment'] = {'files': {'code': TOKEN}}
    if case == 'wrong_id': row['id'] = 'other'
    result = harness(native.APPENGINE, row)
    assert result.result[0] == 'UNKNOWN'
    assert TOKEN not in json.dumps([result.envelope, result.transport.cache, result.transport.evidence])


def test_cancellation_and_expired_budget_prevent_extra_reads(harness, clean, monkeypatch):
    result = harness(native.WORKFLOW, pages=[], options={'_cancel_check': lambda: True})
    assert result.result[0] == 'UNKNOWN' and not result.calls
    monkeypatch.setattr(native, 'MAX_SECONDS', 0)
    result = harness(native.APPENGINE, pages=[])
    assert result.result[0] == 'UNKNOWN' and not result.calls


def test_no_unapproved_code_or_secret_endpoint_reaches_credentials():
    transport = gcp.Transport(SimpleNamespace(headers=lambda: pytest.fail('credentials reached')), {
        'content_secret_scans': True, '_content_secret_scan_kinds': [native.APPENGINE]})
    transport._additional_scopes = {(SCOPE, native.APPENGINE)}
    bad_url = 'https://secretmanager.googleapis.com/v1/projects/review/secrets/s/versions/latest:access'
    transport._additional_reads = {(SCOPE, native.APPENGINE, bad_url, '{}')}
    with pytest.raises(gcp.ReadError):
        native.read_projected(transport, 'GET', bad_url, scope=SCOPE, kind=native.APPENGINE)
    assert transport.calls == 0 and transport.cache == {}


@pytest.mark.parametrize('case', ['missing_uri', 'unsafe_uri', 'missing_topic', 'foreign_topic'])
def test_required_native_scheduler_target_references(harness, clean, case):
    row = scheduler_row(target='pubsubTarget' if 'topic' in case else 'httpTarget')
    if case == 'missing_uri': del row['httpTarget']['uri']
    if case == 'unsafe_uri': row['httpTarget']['uri'] = 'file:///etc/passwd'
    if case == 'missing_topic': del row['pubsubTarget']['topicName']
    if case == 'foreign_topic': row['pubsubTarget']['topicName'] = 'projects/other/topics/tasks'
    assert harness(native.SCHEDULER, row).result[0] == 'UNKNOWN'


def test_appengine_real_masked_service_version_producer_to_opt_in_full_env_get(harness, clean):
    from peaso.collectors.gcp_appengine_versions import SERVICES_FIELDS
    result = harness(native.APPENGINE, native_sources=True)
    assert result.result[0] == 'PASS' and len(result.calls) == 3
    assert result.calls[0]['params']['fields'] == SERVICES_FIELDS
    assert result.calls[1]['params']['fields'] == VERSIONS_FIELDS
    assert result.calls[2]['params'] == native.APP_PARAMS
    source = result.index['collections']['app_engine_version'][0]
    assert source['status'] == 'collected'
    assert source['items'][0]['_field_mask'] == VERSIONS_FIELDS
    assert source['items'][0]['_provenance']['representation'] == 'partial'
    assert 'envVariables' not in json.dumps(source)
