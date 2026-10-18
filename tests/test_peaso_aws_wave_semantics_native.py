"""Directed, pure history cases; fixtures are local examples, not cloud observations."""

import pytest

from peaso.collectors.aws_wave_semantics_native import workflow_sla_from_history


FINDING = {'Id': 'finding-1', 'ProductArn': 'arn:aws:securityhub:eu-west-1::product/aws/securityhub',
           'CreatedAt': '2026-10-10T00:00:00Z', 'UpdatedAt': '2026-10-10T00:30:00Z',
           'Workflow': {'Status': 'NOTIFIED'}}
CAPTURE = '2026-10-11T00:00:00Z'
ACTOR = 'arn:aws:iam::111111111111:role/response-team'


def creation():
    return {'FindingIdentifier': {'Id': FINDING['Id'], 'ProductArn': FINDING['ProductArn']},
            'UpdateTime': '2026-10-10T00:00:01Z', 'FindingCreated': True,
            'UpdateSource': {'Type': 'BATCH_IMPORT_FINDINGS'}, 'Updates': []}


def event(at='2026-10-10T02:00:00Z', *, new='NOTIFIED', source='BATCH_UPDATE_FINDINGS', old='NEW'):
    return {'FindingIdentifier': {'Id': FINDING['Id'], 'ProductArn': FINDING['ProductArn']},
            'UpdateTime': at, 'UpdateSource': {'Type': source, 'Identity': ACTOR},
            'Updates': [{'UpdatedField': 'Workflow.Status', 'OldValue': old, 'NewValue': new}]}


def assess(records, **options):
    finding = options.pop('finding', FINDING)
    return workflow_sla_from_history(finding, [creation(), *records],
        history_complete=options.pop('history_complete', True),
        capture_at=options.pop('capture_at', CAPTURE), response_hours=options.pop('response_hours', 4),
        authorized_response_identities=options.pop('authorized_response_identities', [ACTOR]), **options)


def test_customer_transition_before_deadline_passes_with_transition_proof():
    result = assess([event()])
    assert result['status'] == 'PASS'
    assert result['first_response_at'] == '2026-10-10T02:00:00+00:00'
    assert result['first_response_status'] == 'NOTIFIED'


def test_complete_history_with_late_response_fails():
    result = assess([event('2026-10-10T05:00:00Z')])
    assert result['status'] == 'FAIL' and result['first_response_at'].endswith('05:00:00+00:00')


def test_complete_empty_history_past_deadline_fails_with_reason():
    result = assess([], finding={**FINDING, 'Workflow': {'Status': 'NEW'}})
    assert result['status'] == 'FAIL' and 'complete finding history' in result['reason']


@pytest.mark.parametrize('change', [
    {'history_complete': False},
    {'finding': {**FINDING, 'Id': 'different'}},
    {'capture_at': '2026-10-09T00:00:00Z'},
])
def test_unproved_scope_or_history_remains_unknown(change):
    result = assess([event()], **change)
    assert result['status'] == 'UNKNOWN' and result['reason']


def test_updated_at_cannot_start_or_prove_response():
    finding = {**FINDING, 'UpdatedAt': '2026-10-10T00:01:00Z', 'Workflow': {'Status': 'NEW'}}
    result = assess([], finding=finding)
    assert result['status'] == 'FAIL' and 'history' in result['reason']


@pytest.mark.parametrize('source,new', [
    ('BATCH_IMPORT_FINDINGS', 'NOTIFIED'),
    ('AutomationRule', 'NOTIFIED'),
    ('BATCH_UPDATE_FINDINGS', 'SUPPRESSED'),
])
def test_provider_automation_or_suppression_does_not_prove_incident_response(source, new):
    result = assess([event(source=source, new=new)], finding={**FINDING, 'Workflow': {'Status': new}})
    assert result['status'] == 'FAIL' and 'no customer workflow response' in result['reason']


def test_missing_new_value_never_infers_transition():
    row = event(); row['Updates'][0].pop('NewValue')
    result = assess([row])
    assert result['status'] == 'UNKNOWN' and 'transition value' in result['reason']


def test_before_deadline_without_response_is_not_yet_due():
    result = assess([], capture_at='2026-10-10T03:00:00Z', finding={**FINDING, 'Workflow': {'Status': 'NEW'}})
    assert result['status'] == 'NOT_APPLICABLE' and 'not elapsed' in result['reason']


def test_unapproved_automation_actor_cannot_prove_response():
    row = event(); row['UpdateSource']['Identity'] = 'arn:aws:iam::111111111111:role/automation'
    result = assess([row])
    assert result['status'] == 'FAIL' and 'no customer workflow response' in result['reason']


def test_missing_creation_never_proves_negative():
    result = workflow_sla_from_history({**FINDING, 'Workflow': {'Status': 'NEW'}}, [],
        history_complete=True, capture_at=CAPTURE, response_hours=4,
        authorized_response_identities=[ACTOR])
    assert result['status'] == 'UNKNOWN' and 'creation record' in result['reason']
