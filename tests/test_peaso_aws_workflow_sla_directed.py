"""Directed Security Hub SLA contract cases; all facts are local SDK-shaped fixtures."""
import pytest

from peaso.collectors.aws_wave_semantics_native import PROFILE
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = ACCOUNT + '/' + REGION
PRODUCT = f'arn:aws:securityhub:{REGION}::product/aws/securityhub'
ACTOR = f'arn:aws:iam::{ACCOUNT}:role/responder'
CREATED = '2026-10-10T00:00:00Z'


def _finding(status='NOTIFIED'):
    return {'id': 'finding-1', 'Id': 'finding-1', 'AccountId': ACCOUNT,
            'AwsAccountId': ACCOUNT, 'Region': REGION, 'ProductArn': PRODUCT,
            'CreatedAt': CREATED, 'UpdatedAt': '2026-10-10T00:30:00Z',
            'Severity': {'Label': 'HIGH'}, 'Workflow': {'Status': status}}


def _record(at, *, created=False, old='NEW', new='NOTIFIED', actor=ACTOR):
    return {'FindingIdentifier': {'Id': 'finding-1', 'ProductArn': PRODUCT},
            'UpdateTime': at, 'FindingCreated': created,
            'UpdateSource': {'Type': 'BATCH_IMPORT_FINDINGS' if created else 'BATCH_UPDATE_FINDINGS',
                             'Identity': PRODUCT if created else actor},
            'Updates': [] if created else [{'UpdatedField': 'Workflow.Status',
                                           'OldValue': old, 'NewValue': new}]}


def _evaluate(*, capture='2026-10-10T03:00:00Z', records=None, status='NOTIFIED',
              history=True, history_complete=True, history_changes=None, actors=None, updated_at=None):
    finding = _finding(status)
    if updated_at is not None:
        finding['UpdatedAt'] = updated_at
    collections = [{'type': 'securityhub_finding', 'scope': SCOPE,
                    'status': 'collected', 'items': [finding]}]
    if history:
        row = {'id': finding['Id'], 'ProductArn': PRODUCT, 'AccountId': ACCOUNT,
               'Region': REGION, 'CreatedAt': CREATED, 'capture_at': capture,
               'complete': history_complete, '_metadata_projection': PROFILE,
               'Records': records if records is not None else [
                   _record('2026-10-10T00:00:01Z', created=True),
                   _record('2026-10-10T02:00:00Z')]}
        row.update(history_changes or {})
        collections.append({'type': 'securityhub_finding_history', 'scope': SCOPE,
                            'status': 'collected', 'items': [row]})
    snapshot = make_snapshot('aws', [SCOPE], collections, created_at=capture,
                             metadata={'parameters': {'approved_response_hours': 4,
                                 'approved_response_identity_arns': [ACTOR] if actors is None else actors}})
    return evaluate_snapshot(snapshot, checks=['aws_incident_workflow_sla'])['findings'][0]


def test_observed_approved_response_before_deadline_is_pass():
    assert _evaluate()['status'] == 'PASS'


def test_missing_history_before_deadline_is_provisional_not_applicable():
    verdict = _evaluate(history=False)
    assert verdict['status'] == 'NOT_APPLICABLE'
    assert 'window has not elapsed' in verdict['evidence']['reason']
    assert 'no observed response timing certified' in verdict['evidence']['reason']


@pytest.mark.parametrize('change', [
    {'AccountId': '999999999999'},
    {'Region': 'us-west-2'},
    {'CreatedAt': '2026-10-09T00:00:00Z'},
])
def test_history_row_must_match_finding_scope_and_creation(change):
    assert _evaluate(history_changes=change)['status'] == 'UNKNOWN'


def test_missing_approved_actor_before_deadline_is_unknown():
    assert _evaluate(actors=[])['status'] == 'UNKNOWN'


def test_duplicate_creation_marker_is_unknown():
    records = [_record('2026-10-10T00:00:01Z', created=True),
               _record('2026-10-10T00:00:02Z', created=True),
               _record('2026-10-10T02:00:00Z')]
    assert _evaluate(records=records)['status'] == 'UNKNOWN'


def test_discontinuous_current_workflow_is_unknown():
    assert _evaluate(status='NEW')['status'] == 'UNKNOWN'


def test_late_response_at_deadline_boundary_fails():
    records = [_record('2026-10-10T00:00:01Z', created=True),
               _record('2026-10-10T04:00:01Z')]
    assert _evaluate(capture='2026-10-10T05:00:00Z', records=records)['status'] == 'FAIL'


def test_response_exactly_at_deadline_passes():
    records = [_record('2026-10-10T00:00:01Z', created=True),
               _record('2026-10-10T04:00:00Z')]
    assert _evaluate(capture='2026-10-10T05:00:00Z', records=records)['status'] == 'PASS'


def test_complete_no_response_before_deadline_is_not_yet_due():
    records = [_record('2026-10-10T00:00:01Z', created=True)]
    assert _evaluate(records=records, status='NEW')['status'] == 'NOT_APPLICABLE'


def test_partial_history_before_deadline_is_unknown():
    assert _evaluate(history_complete=False)['status'] == 'UNKNOWN'


def test_foreign_product_history_is_unknown():
    records = [_record('2026-10-10T00:00:01Z', created=True),
               _record('2026-10-10T02:00:00Z')]
    records[1]['FindingIdentifier']['ProductArn'] = (
        f'arn:aws:securityhub:{REGION}::product/other/vendor')
    assert _evaluate(records=records)['status'] == 'UNKNOWN'


@pytest.mark.parametrize('age_seconds,expected_complete,history_reads', [
    (90 * 86400, False, 0),
    (90 * 86400 - 1, True, 1),
])
def test_native_collector_retention_boundary_is_conservative(
        age_seconds, expected_complete, history_reads):
    from datetime import datetime, timedelta, timezone
    from peaso.collectors.aws import ReadResult
    from peaso.collectors.aws_wave_semantics_native import collect

    capture = datetime(2026, 10, 16, tzinfo=timezone.utc)
    created = capture - timedelta(seconds=age_seconds)
    finding = _finding('NEW')
    finding.update(CreatedAt=created.isoformat(), Severity={'Label': 'HIGH'})
    creation = _record((created + timedelta(seconds=1)).isoformat(), created=True)

    class LocalPages:
        observed_at = capture
        calls = []

        def pages(self, session, service, region, operation, expression, **kwargs):
            self.calls.append(operation)
            if operation == 'get_findings':
                return ReadResult([finding], 'collected')
            assert operation == 'get_finding_history'
            assert kwargs['FindingIdentifier'] == {'Id': finding['Id'], 'ProductArn': PRODUCT}
            assert kwargs['EndTime'] == capture
            return ReadResult([creation], 'collected')

    stub = LocalPages()
    read = collect(stub, None, REGION, ACCOUNT)
    assert read.status == 'collected'
    assert read.items[0]['complete'] is expected_complete
    assert stub.calls.count('get_finding_history') == history_reads


def _callback_without_history(*, capture='2026-10-10T03:00:00Z',
                              updated_at='2026-10-10T00:30:00Z'):
    from peaso.checks import CHECKS
    finding = _finding('NEW')
    finding['UpdatedAt'] = updated_at
    index = {'context': {'provider': 'aws', 'scope': SCOPE, 'created_at': capture,
                         'settings': {'approved_response_hours': 4}},
             'collections': {'securityhub_finding': [{'type': 'securityhub_finding',
                 'scope': SCOPE, 'status': 'collected', 'items': [finding]}]},
             'securityhub_finding': [{'type': 'securityhub_finding', 'scope': SCOPE,
                                      'data': finding}]}
    check = next(check for check in CHECKS if check.id == 'aws_incident_workflow_sla')
    return check.evaluate(finding, index)[0]


def test_callback_without_history_keeps_provisional_not_yet_due():
    assert _callback_without_history() == 'NOT_APPLICABLE'


def test_callback_without_history_after_deadline_is_unknown():
    assert _callback_without_history(capture='2026-10-10T05:00:00Z') == 'UNKNOWN'


def test_future_provider_updated_at_complete_history_is_unknown():
    assert _evaluate(updated_at='2026-10-10T04:00:00Z')['status'] == 'UNKNOWN'


def test_future_provider_updated_at_absent_history_callback_is_unknown():
    assert _callback_without_history(updated_at='2026-10-10T04:00:00Z') == 'UNKNOWN'
