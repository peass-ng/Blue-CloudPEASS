"""Stubbed SDK to normal AWS snapshot/evaluator path for workflow SLA."""

from datetime import datetime, timedelta, timezone
import json

import pytest
from botocore.stub import ANY

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from peaso.collectors import aws, aws_wave_semantics_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from tests.archived_check_contract import evaluate_snapshot


SCOPE = ACCOUNT + '/' + REGION
PRODUCT = f'arn:aws:securityhub:{REGION}::product/aws/securityhub'
ACTOR = f'arn:aws:iam::{ACCOUNT}:role/response-team'
MARKER = 'PRIVATE-NOTE-MUST-NOT-BE-CACHED'
FILTERS = {'Filters': {'AwsAccountId': [{'Comparison': 'EQUALS', 'Value': ACCOUNT}],
    'Region': [{'Comparison': 'EQUALS', 'Value': REGION}],
    'RecordState': [{'Comparison': 'EQUALS', 'Value': 'ACTIVE'}]}}


def finding(created, status):
    return {'SchemaVersion': '2018-10-08', 'Id': 'finding-1', 'ProductArn': PRODUCT,
        'GeneratorId': 'fixture', 'AwsAccountId': ACCOUNT, 'Region': REGION,
        'CreatedAt': created.isoformat(), 'UpdatedAt': (created + timedelta(minutes=20)).isoformat(),
        'Title': MARKER, 'Description': MARKER, 'Resources': [], 'RecordState': 'ACTIVE',
        'Severity': {'Label': 'HIGH'}, 'Workflow': {'Status': status}}


def history_record(created, *, offset=None, status='NOTIFIED', actor=ACTOR):
    if offset is None:
        return {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT},
            'FindingCreated': True, 'UpdateTime': created + timedelta(seconds=1),
            'UpdateSource': {'Type': 'BATCH_IMPORT_FINDINGS', 'Identity': PRODUCT}, 'Updates': []}
    return {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT},
        'FindingCreated': False, 'UpdateTime': created + timedelta(hours=offset),
        'UpdateSource': {'Type': 'BATCH_UPDATE_FINDINGS', 'Identity': actor},
        'Updates': [{'UpdatedField': 'Workflow.Status', 'OldValue': 'NEW', 'NewValue': status},
                    {'UpdatedField': 'Note.Text', 'OldValue': MARKER, 'NewValue': MARKER}]}


@pytest.mark.parametrize('mode,expected', [
    ('on_time', 'PASS'), ('late', 'FAIL'), ('never', 'FAIL'),
    ('unapproved_actor', 'FAIL'), ('history_denied', 'UNKNOWN'),
    ('page_limit', 'UNKNOWN'), ('old_finding', 'UNKNOWN'),
    ('missing_creation', 'UNKNOWN'), ('foreign_history', 'UNKNOWN'),
])
def test_normal_snapshot_and_registered_sla(sdk, monkeypatch, mode, expected):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    hub = add('securityhub')
    created = datetime.now(timezone.utc) - timedelta(days=91 if mode == 'old_finding' else 1)
    status = 'NEW' if mode in {'never', 'history_denied', 'page_limit', 'old_finding'} else 'NOTIFIED'
    hub.add_response('get_findings', {'Findings': [finding(created, status)]}, FILTERS)
    query = {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT}, 'EndTime': ANY, 'MaxResults': 100}
    if mode == 'history_denied':
        hub.add_client_error('get_finding_history', 'AccessDeniedException', expected_params=query)
    elif mode != 'old_finding':
        if mode == 'never':
            records = [history_record(created)]
        elif mode == 'page_limit':
            records = [history_record(created, offset=2)]
        elif mode == 'missing_creation':
            records = [history_record(created, offset=2)]
        else:
            records = [history_record(created, offset=5 if mode == 'late' else 2,
                actor=f'arn:aws:iam::{ACCOUNT}:role/automation' if mode == 'unapproved_actor' else ACTOR)]
        if mode == 'foreign_history':
            records[0]['FindingIdentifier']['Id'] = 'different'
        hub.add_response('get_finding_history', {'Records': records,
            **({'NextToken': 'next'} if mode not in {'never', 'missing_creation', 'foreign_history'} else {})}, query)
        if mode not in {'page_limit', 'never', 'missing_creation', 'foreign_history'}:
            hub.add_response('get_finding_history', {'Records': [history_record(created)]},
                {**query, 'NextToken': 'next'})
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {
        'service_concurrency': 1, 'retries': 0, **({'max_pages': 1} if mode == 'page_limit' else {}),
        'compliance_parameters': {'approved_response_hours': 4,
            'approved_response_identity_arns': [ACTOR]}}},
        ['securityhub_finding', native.KIND])
    row = next(part for part in snapshot['collections'] if part['type'] == native.KIND)
    assert row['status'] == 'collected' and len(row['items']) == 1
    assert row['items'][0]['complete'] is (mode not in {
        'history_denied', 'page_limit', 'old_finding', 'missing_creation', 'foreign_history'})
    assert MARKER not in json.dumps(row)
    finding_row = next(part for part in snapshot['collections'] if part['type'] == 'securityhub_finding')['items'][0]
    assert finding_row.get('ProductArn') == PRODUCT, finding_row
    if row['items'][0]['complete']:
        assert all(record['FindingIdentifier'] == {'Id': finding_row['Id'], 'ProductArn': finding_row['ProductArn']}
                   for record in row['items'][0]['Records']), (finding_row, row['items'][0]['Records'])
    result = evaluate_snapshot(snapshot, checks=['aws_incident_workflow_sla'])['findings'][0]
    assert result['status'] == expected, result
    if expected == 'UNKNOWN':
        assert result['evidence'] and ('unavailable' in str(result['evidence']).lower()
               or 'history' in str(result['evidence']).lower())
    hub.assert_no_pending_responses(); sts.assert_no_pending_responses()


def test_history_profile_scrubs_other_asff_values_before_cache(sdk):
    session, add = sdk; hub = add('securityhub')
    created = datetime.now(timezone.utc) - timedelta(hours=6)
    query = {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT}, 'EndTime': ANY, 'MaxResults': 100}
    hub.add_response('get_finding_history', {'Records': [history_record(created, offset=2)]}, query)
    requests = aws.Requests({'retries': 0})
    result = requests.pages(session, 'securityhub', REGION, 'get_finding_history', 'Records',
        _metadata_profile=native.PROFILE, FindingIdentifier=query['FindingIdentifier'],
        EndTime=requests.observed_at, MaxResults=100)
    assert result.status == 'collected' and result.items[0]['Updates'] == [
        {'UpdatedField': 'Workflow.Status', 'OldValue': 'NEW', 'NewValue': 'NOTIFIED'}]
    cached = [value.result() for value in requests._cache.values()]
    assert MARKER not in json.dumps(cached, default=str)
    assert all('Identity' in record['UpdateSource'] for item in cached for record in item['Records'])
    hub.assert_no_pending_responses()


def test_history_cannot_enter_shared_cache_without_reviewed_profile(sdk):
    session, add = sdk; hub = add('securityhub')
    requests = aws.Requests({'retries': 0})
    with pytest.raises(aws.ReadFailure, match='securityhub_history_requires_safe_projection'):
        requests.call(session, 'securityhub', REGION, 'get_finding_history',
            FindingIdentifier={'Id': 'finding-1', 'ProductArn': PRODUCT})
    assert requests.calls == 0 and requests._cache == {}
    hub.assert_no_pending_responses()


def test_malformed_workflow_value_is_removed_before_cache(sdk):
    session, add = sdk; hub = add('securityhub')
    created = datetime.now(timezone.utc) - timedelta(hours=6)
    record = history_record(created, offset=2)
    record['Updates'][0]['NewValue'] = MARKER
    query = {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT}, 'EndTime': ANY, 'MaxResults': 100}
    hub.add_response('get_finding_history', {'Records': [record]}, query)
    requests = aws.Requests({'retries': 0})
    read = requests.pages(session, 'securityhub', REGION, 'get_finding_history', 'Records',
        _metadata_profile=native.PROFILE, FindingIdentifier=query['FindingIdentifier'],
        EndTime=requests.observed_at, MaxResults=100)
    assert read.status == 'collected' and read.items[0]['Updates'] == [
        {'UpdatedField': 'Workflow.Status', 'OldValue': 'NEW'}]
    assert MARKER not in json.dumps([future.result() for future in requests._cache.values()], default=str)
    hub.assert_no_pending_responses()
