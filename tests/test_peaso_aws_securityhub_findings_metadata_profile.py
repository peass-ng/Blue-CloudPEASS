"""SDK and cache contract for scan-local Security Hub metadata."""
import copy
import json
import pytest
from peaso.collectors import aws, aws_bulk_inventory as bulk, aws_wave_semantics_native as wave
from peaso.collectors import aws_securityhub_finding_metadata_native as metadata
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION

MARKER = 'PRIVATE_FINDING_TEXT_SENTINEL'
PARAMS = {'Filters': {'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': ACCOUNT}],
    'Region': [{'Comparison': 'EQUALS', 'Value': REGION}],
    'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}


def finding(**changes):
    row = {'SchemaVersion': '2018-10-08', 'Id': 'finding-1',
        'ProductArn': f'arn:aws:securityhub:{REGION}::product/aws/securityhub',
        'GeneratorId': 'qa', 'AwsAccountId': ACCOUNT, 'Region': REGION,
        'CreatedAt': '2026-01-01T00:00:00Z', 'UpdatedAt': '2026-01-01T01:00:00Z',
        'Title': MARKER, 'Description': MARKER, 'Resources': [],
        'Note': {'Text': MARKER, 'UpdatedBy': 'reviewer', 'UpdatedAt': '2026-01-01T01:00:00Z'},
        'Remediation': {'Recommendation': {'Text': MARKER}},
        'Severity': {'Label': 'HIGH', 'Original': MARKER},
        'Workflow': {'Status': 'NEW'}, 'RecordState': 'ACTIVE'}
    row.update(changes)
    return row


def test_raw_sdk_payload_is_removed_before_future_and_shared_by_metadata_consumers(sdk):
    session, add = sdk
    stub = add('securityhub')
    stub.add_response('get_findings', {'Findings': [finding()]}, PARAMS)
    reader = aws.Requests({})
    bulk_read = bulk.FETCHERS['securityhub_finding'](reader, session, REGION, ACCOUNT)
    wave_read = wave.collect(reader, session, REGION, ACCOUNT)
    enriched = wave.enrich_securityhub_findings(reader, session, REGION, copy.deepcopy(bulk_read.items))
    assert bulk_read.status == wave_read.status == 'collected'
    assert enriched[0]['ProductArn'] == finding()['ProductArn']
    assert reader.calls == 1 and reader.cache_hits == 2
    assert len(reader._cache) == 1
    key, future = next(iter(reader._cache.items()))
    assert len(key) == 6 and key[-1] == metadata.PROFILE
    payload = future.result()
    assert set(payload) == {'Findings'}
    assert set(payload['Findings'][0]) == {'Id', 'AwsAccountId', 'Region', 'ProductArn',
        'CreatedAt', 'UpdatedAt', 'RecordState', 'Severity', 'Workflow'}
    assert MARKER not in json.dumps(payload)
    stub.assert_no_pending_responses()


def test_legacy_and_profiled_requests_have_distinct_futures_and_schema(sdk):
    session, add = sdk
    stub = add('securityhub')
    raw = {'Findings': [finding()]}
    stub.add_response('get_findings', raw, PARAMS)
    stub.add_response('get_findings', raw, PARAMS)
    reader = aws.Requests({})
    projected = reader.call(session, 'securityhub', REGION, 'get_findings',
        _metadata_profile=metadata.PROFILE, **PARAMS)
    legacy = reader.call(session, 'securityhub', REGION, 'get_findings', **PARAMS)
    assert MARKER not in str(projected) and legacy == raw
    assert {len(key) for key in reader._cache} == {5, 6}
    assert reader.calls == 2
    stub.assert_no_pending_responses()


def test_profile_is_bound_before_client_creation(monkeypatch):
    reader = aws.Requests({})
    monkeypatch.setattr(reader, 'client', lambda *args: pytest.fail('unexpected client'))
    with pytest.raises(aws.ReadFailure) as failure:
        reader.call(object(), 'sts', REGION, 'get_caller_identity', _metadata_profile=metadata.PROFILE)
    assert failure.value.code == 'metadata_profile_operation_not_allowed'
    assert reader._cache == {} and reader.calls == 0


@pytest.mark.parametrize('bad', [None, {'Findings': [finding(Description=123)]}])
def test_malformed_source_does_not_survive_in_cached_failure(monkeypatch, bad):
    class Client:
        def get_findings(self, **params):
            return bad
    reader = aws.Requests({'retry_attempts': 1})
    monkeypatch.setattr(reader, 'client', lambda *args: Client())
    with pytest.raises(aws.ReadFailure) as failure:
        reader.call(object(), 'securityhub', REGION, 'get_findings',
            _metadata_profile=metadata.PROFILE, **PARAMS)
    assert (failure.value.status, failure.value.code) == ('malformed', 'securityhub_finding_metadata_invalid')
    cached = next(iter(reader._cache.values())).exception()
    assert (cached.status, cached.code) == ('malformed', 'securityhub_finding_metadata_invalid')
    assert cached.__traceback__ is None and cached.__context__ is None and cached.__cause__ is None
    assert MARKER not in repr(vars(cached))


@pytest.mark.parametrize('mode,expected', [('duplicate', 'partial'), ('foreign', 'malformed')])
def test_native_negative_scope_reasons_are_preserved(sdk, mode, expected):
    session, add = sdk
    stub = add('securityhub')
    row = finding()
    if mode == 'foreign':
        row['AwsAccountId'] = '999999999999'
    stub.add_response('get_findings', {'Findings': [finding(), row] if mode == 'duplicate' else [row]}, PARAMS)
    read = bulk.FETCHERS['securityhub_finding'](aws.Requests({}), session, REGION, ACCOUNT)
    assert read.status == expected
    assert read.error['code'] == 'invalid_security_finding_scope_or_identity'
    stub.assert_no_pending_responses()


def test_normal_registered_workflow_node_remains_conservative(sdk):
    session, add = sdk
    stub = add('securityhub')
    stub.add_response('get_findings', {'Findings': [finding()]}, PARAMS)
    read = bulk.FETCHERS['securityhub_finding'](aws.Requests({}), session, REGION, ACCOUNT)
    scope = ACCOUNT + '/' + REGION
    snapshot = make_snapshot('aws', [scope], [{'type': 'securityhub_finding', 'scope': scope,
        'status': read.status, 'items': read.items}], created_at='2026-10-16T00:00:00Z',
        metadata={'parameters': {'approved_response_hours': 4}})
    verdict = evaluate_snapshot(snapshot, checks=['aws_incident_workflow_sla'])['findings'][0]
    assert verdict['status'] == 'UNKNOWN'
    assert 'workflow transition history' in str(verdict['evidence'])
    stub.assert_no_pending_responses()
