"""Native EventBridge event and schedule evidence through the registered engine."""
import json
import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.snapshot import seal

ACCOUNT = '123456789012'
REGION = 'us-east-1'
CHECKS = ['aws_securityhub_findings_alerted', 'aws_securityhub_medium_findings_alert',
          'aws_inspector_critical_image_findings_alert']

def pattern(check, partial=False):
    if check == CHECKS[2]:
        return {'source': ['aws.inspector2'], 'detail-type': ['Inspector2 Finding'],
                'detail': {'severity': ['CRITICAL'], 'resources': {'type':
                    ['AWS_EC2_INSTANCE'] if partial else ['AWS_EC2_INSTANCE', 'AWS_ECR_CONTAINER_IMAGE']}}}
    labels = ['HIGH', 'CRITICAL'] if check == CHECKS[0] else ['MEDIUM', 'LOW', 'INFORMATIONAL']
    return {'source': ['aws.securityhub'], 'detail-type': ['Security Hub Findings - Imported'],
            'detail': {'findings': {'Severity': {'Label': labels[:1] if partial else labels}}}}

def evaluate(monkeypatch, check, patterns, denied_target=None, states=None, partial_inventory=False, schedules=None, managed=None, mutate=None):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients = {name: session.client(name, region_name=REGION) for name in ('sts', 'events')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values(): stub.activate()
    stubs['sts'].add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture', 'UserId': 'AIDAFIXTURE'}, {})
    rows = [{'Name': f'rule{i}', 'Arn': f'arn:aws:events:{REGION}:{ACCOUNT}:rule/rule{i}',
             'State': (states or {}).get(i, 'ENABLED'), **({'EventPattern': json.dumps(value)} if value is not None else {}),
             **({'ScheduleExpression': (schedules or {})[i]} if i in (schedules or {}) else {}),
             **({'ManagedBy': (managed or {})[i]} if i in (managed or {}) else {})}
            for i, value in enumerate(patterns)]
    stubs['events'].add_response('list_rules', {'Rules': rows, **({'NextToken': 'next'} if partial_inventory else {})}, {'EventBusName': 'default'})
    if partial_inventory:
        stubs['events'].add_client_error('list_rules', service_error_code='AccessDeniedException',
            http_status_code=403, expected_params={'EventBusName': 'default', 'NextToken': 'next'})
    for i, row in enumerate(rows):
        args = {'Rule': row['Name'], 'EventBusName': 'default'}
        if i == denied_target:
            stubs['events'].add_client_error('list_targets_by_rule', service_error_code='AccessDeniedException',
                                             http_status_code=403, expected_params=args)
        else:
            stubs['events'].add_response('list_targets_by_rule', {'Targets': [
                {'Id': 'alert', 'Arn': f'arn:aws:sns:{REGION}:{ACCOUNT}:alert'}]}, args)
    monkeypatch.setattr(aws.Requests, 'client', lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
    try:
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'fixture'},
            'options': {'regions': [REGION], 'max_calls': 10, 'service_concurrency': 1,
                        'scope_concurrency': 1}}, ['event_rule'])
        for stub in stubs.values(): stub.assert_no_pending_responses()
        if mutate is not None:
            mutate(snapshot)
            snapshot = seal(snapshot)
        findings = evaluate_snapshot(snapshot, checks=[check])['findings']
        rows = [f for f in findings if f['check_id'] == check and not f['resource_id'].startswith('inventory:')]
        assert 1 <= len(rows) <= len(patterns)  # engine may deduplicate equal scope-level evidence
        return {row['status'] for row in rows}
    finally:
        for stub in stubs.values(): stub.deactivate()

def opaque(check):
    # Native EventBridge prefix operator may match the required event source.
    return {'source': [{'prefix': 'aws.'}], 'detail-type': [
        'Inspector2 Finding' if check == CHECKS[2] else 'Security Hub Findings - Imported']}


@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('good_first', [True, False])
def test_complete_alert_witness_is_independent(monkeypatch, check, good_first):
    patterns = [pattern(check), opaque(check)] if good_first else [opaque(check), pattern(check)]
    assert evaluate(monkeypatch, check, patterns) == {'PASS'}

@pytest.mark.parametrize('check', CHECKS)
def test_opaque_rule_without_complete_witness_is_unknown(monkeypatch, check):
    assert evaluate(monkeypatch, check, [opaque(check)]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_partial_required_coverage_is_not_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check, partial=True), opaque(check)]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_complete_nonmatching_inventory_is_negative(monkeypatch, check):
    assert evaluate(monkeypatch, check, [{'source': ['aws.s3'], 'detail-type': ['Other']}]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_denied_targets_cannot_prove_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check), opaque(check)], denied_target=0) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_wrong_literal_type_excludes_missing_source(monkeypatch, check):
    assert evaluate(monkeypatch, check, [{'detail-type': ['Unrelated native event']}]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_wrong_literal_source_excludes_missing_type_and_unknown_clause(monkeypatch, check):
    assert evaluate(monkeypatch, check, [{'source': ['aws.s3'], 'account': [{'anything-but': ['fixture']}]}]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_wrong_literal_type_excludes_complex_source(monkeypatch, check):
    assert evaluate(monkeypatch, check, [{'source': [{'prefix': 'aws.'}], 'detail-type': ['Other'],
                                         'account': [{'prefix': '123'}]}]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_relevant_complex_selector_remains_unknown(monkeypatch, check):
    assert evaluate(monkeypatch, check, [opaque(check)]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_missing_or_malformed_relevant_pattern_remains_unknown(monkeypatch, check):
    expected_type = 'Inspector2 Finding' if check == CHECKS[2] else 'Security Hub Findings - Imported'
    assert evaluate(monkeypatch, check, [{'detail-type': [expected_type]}]) == {'UNKNOWN'}
    assert evaluate(monkeypatch, check, [None]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_disabled_opaque_pattern_cannot_poison_negative(monkeypatch, check):
    assert evaluate(monkeypatch, check, [None], states={0: 'DISABLED'}) == {'FAIL'}
    assert evaluate(monkeypatch, check, [opaque(check)], states={0: 'DISABLED'}) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_complete_positive_with_disabled_or_denied_unrelated_rule(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check), None], states={1: 'DISABLED'}) == {'PASS'}
    assert evaluate(monkeypatch, check, [pattern(check), opaque(check)], denied_target=1) == {'PASS'}

@pytest.mark.parametrize('check', CHECKS)
def test_incomplete_inventory_cannot_prove_negative_or_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check)], partial_inventory=True) in ({'UNKNOWN'}, {'DENIED'})

def test_high_and_critical_must_share_one_rule(monkeypatch):
    high = pattern(CHECKS[0], partial=True)
    critical = pattern(CHECKS[0], partial=True)
    critical['detail']['findings']['Severity']['Label'] = ['CRITICAL']
    assert evaluate(monkeypatch, CHECKS[0], [high, critical]) == {'FAIL'}


@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('schedule', ['rate(5 minutes)', 'cron(0 12 * * ? *)'])
def test_complete_native_scheduled_only_rule_is_nonmatching(monkeypatch, check, schedule):
    assert evaluate(monkeypatch, check, [None], schedules={0: schedule}) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_both_schedule_and_pattern_still_match_events(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check)], schedules={0: 'rate(5 minutes)'}) == {'PASS'}

@pytest.mark.parametrize('check', CHECKS)
def test_schedule_without_native_absence_proof_stays_unknown(monkeypatch, check):
    assert evaluate(monkeypatch, check, [None]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('schedule', ['', 'garbage', 'rate(1 hours)', 'cron(bad)'])
def test_malformed_native_schedule_does_not_prove_absence(monkeypatch, check, schedule):
    assert evaluate(monkeypatch, check, [None], schedules={0: schedule}) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_managed_schedule_without_pattern_stays_unknown(monkeypatch, check):
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'},
                    managed={0: 'events.amazonaws.com'}) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_partial_inventory_schedule_cannot_prove_negative(monkeypatch, check):
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'},
                    partial_inventory=True) in ({'UNKNOWN'}, {'DENIED'})

@pytest.mark.parametrize('check', CHECKS)
def test_scheduled_only_rule_cannot_poison_independent_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [None, pattern(check)],
                    schedules={0: 'rate(5 minutes)'}) == {'PASS'}


def _mutate_native_rule(snapshot, mutate_row):
    collections = [row for row in snapshot['collections'] if row['type'] == 'event_rule'
                   and row['status'] == 'collected']
    assert len(collections) == 1
    mutate_row(collections[0]['items'][0])


@pytest.mark.parametrize('check', CHECKS)
def test_denied_or_contradictory_absence_marker_stays_unknown(monkeypatch, check):
    def denied(snapshot):
        _mutate_native_rule(snapshot, lambda row: row['_coverage']['EventPattern'].update(status='denied'))
    def foreign(snapshot):
        _mutate_native_rule(snapshot, lambda row: row['_coverage']['EventPattern'].update(rule_arn='foreign'))
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'}, mutate=denied) == {'UNKNOWN'}
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'}, mutate=foreign) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_null_native_fields_do_not_prove_scheduled_only(monkeypatch, check):
    def null_schedule(snapshot):
        _mutate_native_rule(snapshot, lambda row: row.update(ScheduleExpression=None))
    def null_pattern(snapshot):
        _mutate_native_rule(snapshot, lambda row: row.update(EventPattern=None))
    def malformed_schedule(snapshot):
        _mutate_native_rule(snapshot, lambda row: row.update(ScheduleExpression='garbage'))
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'}, mutate=null_schedule) == {'UNKNOWN'}
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'}, mutate=null_pattern) == {'UNKNOWN'}
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'}, mutate=malformed_schedule) == {'UNKNOWN'}


def _annotate_pattern(snapshot, annotation):
    def add(row):
        pattern_value = json.loads(row['EventPattern'])
        pattern_value['_coverage'] = annotation
        row['EventPattern'] = json.dumps(pattern_value)
    _mutate_native_rule(snapshot, add)


@pytest.mark.parametrize('check', CHECKS)
def test_denied_retained_wrong_source_cannot_prove_nonmatch(monkeypatch, check):
    candidate = pattern(check)
    candidate['source'] = ['aws.s3']
    assert evaluate(monkeypatch, check, [candidate], mutate=lambda snapshot:
        _annotate_pattern(snapshot, {'source': {'status': 'denied'}})) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_denied_retained_wrong_type_cannot_prove_nonmatch(monkeypatch, check):
    candidate = pattern(check)
    candidate['detail-type'] = ['Unrelated native event']
    assert evaluate(monkeypatch, check, [candidate], mutate=lambda snapshot:
        _annotate_pattern(snapshot, {'detail-type': {'status': 'denied'}})) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_other_readable_mismatch_still_excludes_denied_selector(monkeypatch, check):
    candidate = pattern(check)
    candidate['source'] = ['aws.s3']
    candidate['detail-type'] = ['Unrelated native event']
    assert evaluate(monkeypatch, check, [candidate], mutate=lambda snapshot:
        _annotate_pattern(snapshot, {'source': {'status': 'denied'}})) == {'FAIL'}


@pytest.mark.parametrize('check', CHECKS)
def test_global_malformed_pattern_coverage_remains_unknown(monkeypatch, check):
    candidate = pattern(check)
    candidate['source'] = ['aws.s3']
    assert evaluate(monkeypatch, check, [candidate], mutate=lambda snapshot:
        _annotate_pattern(snapshot, ['malformed'])) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_denied_relevant_selector_cannot_support_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check)], mutate=lambda snapshot:
        _annotate_pattern(snapshot, {'source': {'status': 'denied'}})) == {'UNKNOWN'}


@pytest.mark.parametrize('check', CHECKS)
def test_denied_schedule_field_cannot_prove_scheduled_only(monkeypatch, check):
    def denied(snapshot):
        _mutate_native_rule(snapshot, lambda row:
            row['_coverage'].update(ScheduleExpression={'status': 'denied'}))
    assert evaluate(monkeypatch, check, [None], schedules={0: 'rate(5 minutes)'},
                    mutate=denied) == {'UNKNOWN'}
