"""Metadata-only native audit rows and bounded, scoped logging queries."""
import copy
import json
import pytest
from tests.test_peaso_collectors_gcp import snapshot as collect_fixture, collection
from peaso.collectors.gcp import ReadError
from peaso.engine import evaluate_snapshot, plan_collection

SCOPE = 'projects/p-one'
LOG = SCOPE + '/logs/cloudaudit.googleapis.com%2Factivity'
CID = 'gcp_c5_log_event_fields'

def snapshot(kinds, resolver, **options):
    def resolve(request):
        if request['url'] == 'https://cloudresourcemanager.googleapis.com/v3/' + SCOPE:
            assert request['method'] == 'GET' and request['params']['fields'] == 'name,projectId'
            return {'name': 'projects/123456789012', 'projectId': 'p-one'}
        return resolver(request)
    return collect_fixture(kinds, resolve, **options)

def row():
    return {'logName': LOG, 'insertId': 'row-one', 'timestamp': '2026-10-14T19:00:00Z',
            'resource': {'type': 'audited_resource', 'labels': {'project_id': 'p-one'}},
            'protoPayload': {'@type': 'type.googleapis.com/google.cloud.audit.AuditLog',
                'serviceName': 'compute.googleapis.com', 'methodName': 'v1.compute.instances.get',
                'authenticationInfo': {'principalEmail': 'owner@example.test', 'thirdPartyPrincipal': {'opaque': 'sensitive-marker'}},
                'request': {'arbitrary': 'sensitive-marker'}, 'response': {'arbitrary': 'sensitive-marker'},
                'requestMetadata': {'callerIp': 'sensitive-marker'}},
            'textPayload': 'sensitive-marker', 'jsonPayload': {'arbitrary': 'sensitive-marker'}}

def verdict(result):
    return evaluate_snapshot(result, checks=[CID], include_not_applicable=True)['findings'][0]['status']

@pytest.mark.parametrize('state, expected', [('complete', 'PASS'), ('bad_time', 'FAIL'), ('missing_actor', 'UNKNOWN'), ('redacted_actor', 'UNKNOWN'), ('missing_method', 'UNKNOWN'), ('missing_time', 'UNKNOWN')])
def test_native_audit_fields_and_unclassified_identity(state, expected):
    value = row()
    if state == 'bad_time': value['timestamp'] = 'malformed-date'
    if state == 'missing_actor': value['protoPayload'].pop('authenticationInfo')
    if state == 'redacted_actor': value['protoPayload']['authenticationInfo']['principalEmail'] = ''
    if state == 'missing_method': value['protoPayload'].pop('methodName')
    if state == 'missing_time': value.pop('timestamp')
    result, api = snapshot(['log_entry'], lambda request: {'entries': [value]})
    assert verdict(result) == expected
    native = collection(result, 'log_entry')['items'][0]
    assert 'sensitive-marker' not in json.dumps(result)
    assert native['auditCoverage']['absence_proves_no_event'] is False
    assert native['auditCoverage']['retention_verified'] is False
    request = next(r for r in api.requests if r['method'] == 'POST')
    assert request['method'] == 'POST' and request['url'].endswith('/v2/entries:list')
    assert request['body']['resourceNames'] == [SCOPE]
    assert 'timestamp>=' in request['body']['filter'] and 'timestamp<' in request['body']['filter']
    assert request['body']['orderBy'] == 'timestamp desc'

@pytest.mark.parametrize('state', ['empty', 'denied', 'partial', 'foreign_log', 'foreign_resource', 'wrong_type', 'missing_id', 'duplicate_conflict'])
def test_native_audit_read_failure_and_foreign_identity_boundaries(state):
    value = row()
    if state == 'foreign_log': value['logName'] = LOG.replace('p-one', 'foreign-project')
    if state == 'foreign_resource': value['resource']['labels']['project_id'] = 'foreign-project'
    if state == 'wrong_type': value['protoPayload']['@type'] = 'type.googleapis.com/foreign'
    if state == 'missing_id': value.pop('insertId')
    def resolve(request):
        if state == 'empty': return {'entries': []}
        if state == 'denied': raise ReadError('denied', 'PERMISSION_DENIED', http_status=403)
        if state == 'partial':
            if request['body'].get('pageToken'): raise ReadError('denied', 'PERMISSION_DENIED', http_status=403)
            return {'entries': [value], 'nextPageToken': 'next'}
        if state == 'duplicate_conflict':
            other = copy.deepcopy(value); other['protoPayload']['authenticationInfo']['principalEmail'] = 'other@example.test'
            return {'entries': [value, other]}
        return {'entries': [value]}
    result, _ = snapshot(['log_entry'], resolve)
    native = collection(result, 'log_entry')
    if state == 'empty':
        assert native['status'] == 'empty' and verdict(result) == 'EMPTY'
    else:
        assert native['status'] not in ('collected', 'empty')
        assert verdict(result) in ('UNKNOWN', 'DENIED')

def test_empty_intermediate_page_is_not_complete_empty_and_request_stays_scoped():
    def resolve(request):
        if not request['body'].get('pageToken'): return {'entries': [], 'nextPageToken': 'next'}
        return {'entries': [row()]}
    result, api = snapshot(['log_entry'], resolve)
    assert collection(result, 'log_entry')['status'] == 'collected' and verdict(result) == 'PASS'
    assert len(api.requests) == 3
    before, after = [r['body'] for r in api.requests if r['method'] == 'POST']
    assert {k: v for k, v in after.items() if k != 'pageToken'} == before

def test_page_limit_and_explicit_default_stream_exclusion():
    result, _ = snapshot(['log_entry'], lambda request: {'entries': [row()], 'nextPageToken': 'next'}, max_pages=1)
    assert collection(result, 'log_entry')['status'] == 'partial'
    assert verdict(result) == 'UNKNOWN'
    assert 'log_entry' not in plan_collection({'connector': {'provider': 'gcp'}})
    assert 'log_entry' in plan_collection({'connector': {'provider': 'gcp'}, 'checks': [CID]})

def test_project_number_alias_is_bound_to_resource_manager_identity():
    value = row(); value['resource']['labels']['project_id'] = '123456789012'
    result, api = snapshot(['log_entry'], lambda request: {'entries': [value]})
    assert verdict(result) == 'PASS'
    assert len(api.requests) == 2

@pytest.mark.parametrize('metadata', [{'name': 'projects/123456789012', 'projectId': 'foreign'}, {'name': 'projects/foreign', 'projectId': 'p-one'}, {}])
def test_foreign_or_missing_project_mapping_does_not_authorize_log_capture(metadata):
    def resolve(request):
        assert request['method'] == 'GET'
        return metadata
    result, api = collect_fixture(['log_entry'], resolve)
    assert collection(result, 'log_entry')['status'] == 'malformed'
    assert verdict(result) == 'UNKNOWN'
    assert len(api.requests) == 1

@pytest.mark.parametrize('value', [0, -1, 1441, True, '60', None, [], {}])
def test_invalid_metadata_window_fails_before_credentials_and_api(value):
    from peaso.collectors.gcp import GCPCollector
    with pytest.raises(ValueError):
        GCPCollector({'scopes': [SCOPE], 'options': {'inventories': ['log_entry'], 'log_entry_minutes': value}}, ['log_entry'])
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    from types import SimpleNamespace
    with pytest.raises(HTTPException) as result:
        validate_connector('gcp', {}, {'log_entry_minutes': value}, SimpleNamespace(auth_mode='local'))
    assert result.value.status_code == 422

def test_log_window_is_allowed_for_gcp_and_rejected_for_other_providers():
    from peaso.server.validation import validate_connector
    from fastapi import HTTPException
    from types import SimpleNamespace
    settings = SimpleNamespace(auth_mode='local')
    validate_connector('gcp', {'method': 'gcloud'}, {'log_entry_minutes': 15}, settings)
    for provider in ('aws', 'azure', 'k8s'):
        with pytest.raises(HTTPException):
            validate_connector(provider, {}, {'log_entry_minutes': 15}, settings)

def test_check_planner_requirements_enable_explicit_telemetry_without_inventory_option():
    from peaso.collectors.gcp import GCPCollector
    collector = GCPCollector({'scopes': [SCOPE]}, ['log_entry'])
    assert collector.wanted == {'log_entry'}
    assert collector.transport is None
    collector.hydration_pool.shutdown()
    default = GCPCollector({'scopes': [SCOPE]})
    assert 'log_entry' not in default.wanted
    default.hydration_pool.shutdown()
