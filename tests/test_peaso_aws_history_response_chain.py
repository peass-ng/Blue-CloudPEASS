"""Focused authorized-response chains; all events are local fixture data."""
from datetime import datetime, timedelta, timezone

from botocore.stub import ANY

from test_peaso_aws_bulk_inventory import sdk, ACCOUNT, REGION
from test_peaso_aws_wave_semantics_native_integration import finding, history_record, FILTERS, SCOPE, PRODUCT, ACTOR
from peaso.collectors import aws, aws_wave_semantics_native as native
from peaso.collectors.bulk_evidence import collect as collect_bulk
from peaso.engine import evaluate_snapshot

AUTOMATION = f'arn:aws:iam::{ACCOUNT}:role/automation'
BASE = datetime(2026, 10, 10, tzinfo=timezone.utc)
CAPTURE = BASE + timedelta(hours=12)


def transition(offset, old, new, actor):
    row = history_record(BASE, offset=offset, status=new, actor=actor)
    row['Updates'][0]['OldValue'] = old
    return row


def assess(records, status):
    return native.workflow_sla_from_history(finding(BASE, status),
        [history_record(BASE), *records], history_complete=True, capture_at=CAPTURE,
        response_hours=4, authorized_response_identities=[ACTOR])


def test_approved_resolution_after_automatic_notification_is_first_response():
    result = assess([transition(1, 'NEW', 'NOTIFIED', AUTOMATION),
                     transition(2, 'NOTIFIED', 'RESOLVED', ACTOR)], 'RESOLVED')
    assert result['status'] == 'PASS', result
    assert result['reason'] == 'customer workflow transition observed'
    assert result['first_response_at'] == (BASE + timedelta(hours=2)).isoformat()
    assert result['first_response_status'] == 'RESOLVED'


def test_approved_resolution_after_automatic_notification_registered(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'unit-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    hub = add('securityhub')
    created = datetime.now(timezone.utc) - timedelta(days=1)
    hub.add_response('get_findings', {'Findings': [finding(created, 'RESOLVED')]}, FILTERS)
    identity = {'Id': 'finding-1', 'ProductArn': PRODUCT}
    query = {'FindingIdentifier': identity, 'EndTime': ANY, 'MaxResults': 100}
    first = history_record(created, offset=1, status='NOTIFIED', actor=AUTOMATION)
    second = history_record(created, offset=2, status='RESOLVED', actor=ACTOR)
    second['Updates'][0]['OldValue'] = 'NOTIFIED'
    hub.add_response('get_finding_history', {'Records': [first, second, history_record(created)]}, query)
    snapshot = collect_bulk(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {
        'service_concurrency': 1, 'retries': 0,
        'compliance_parameters': {'approved_response_hours': 4,
                                  'approved_response_identity_arns': [ACTOR]}}},
        ['securityhub_finding', native.KIND])
    result = evaluate_snapshot(snapshot, checks=['aws_incident_workflow_sla'])['findings'][0]
    assert result['status'] == 'PASS', result
    assert result['evidence']['reason'] == 'customer workflow transition observed', result
    assert result['evidence']['response_status'] == 'RESOLVED', result
    hub.assert_no_pending_responses(); sts.assert_no_pending_responses()


def test_suppression_then_resolution_never_proves_response():
    result = assess([transition(1, 'NEW', 'SUPPRESSED', AUTOMATION),
                     transition(2, 'SUPPRESSED', 'RESOLVED', ACTOR)], 'RESOLVED')
    assert result['status'] == 'FAIL' and 'no customer workflow response' in result['reason']


def test_discontinuous_history_remains_unknown():
    result = assess([transition(1, 'NEW', 'NOTIFIED', AUTOMATION),
                     transition(2, 'NEW', 'RESOLVED', ACTOR)], 'RESOLVED')
    assert result['status'] == 'UNKNOWN' and 'discontinuous' in result['reason']


def test_reopened_finding_does_not_turn_later_resolution_into_first_response():
    result = assess([transition(0.5, 'NEW', 'SUPPRESSED', AUTOMATION),
                     transition(1, 'SUPPRESSED', 'NEW', AUTOMATION),
                     transition(1.5, 'NEW', 'NOTIFIED', AUTOMATION),
                     transition(2, 'NOTIFIED', 'RESOLVED', ACTOR)], 'RESOLVED')
    assert result['status'] == 'FAIL' and 'no customer workflow response' in result['reason']


def test_late_approved_resolution_after_automatic_notification_fails_with_time():
    result = assess([transition(1, 'NEW', 'NOTIFIED', AUTOMATION),
                     transition(5, 'NOTIFIED', 'RESOLVED', ACTOR)], 'RESOLVED')
    assert result['status'] == 'FAIL' and result['first_response_at'] == (BASE + timedelta(hours=5)).isoformat()
    assert result['reason'] == 'customer workflow transition observed'
