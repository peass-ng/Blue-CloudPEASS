"""A complete alert witness is independent of an unresolved unrelated rule."""
import json
import boto3
import pytest
from botocore.stub import Stubber
from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

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

def evaluate(monkeypatch, check, patterns, denied_target=None):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients = {name: session.client(name, region_name=REGION) for name in ('sts', 'events')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values(): stub.activate()
    stubs['sts'].add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture', 'UserId': 'AIDAFIXTURE'}, {})
    rows = [{'Name': f'rule{i}', 'Arn': f'arn:aws:events:{REGION}:{ACCOUNT}:rule/rule{i}',
             'State': 'ENABLED', 'EventPattern': json.dumps(value)} for i, value in enumerate(patterns)]
    stubs['events'].add_response('list_rules', {'Rules': rows}, {'EventBusName': 'default'})
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
        findings = evaluate_snapshot(snapshot, checks=[check])['findings']
        rows = [f for f in findings if f['check_id'] == check and not f['resource_id'].startswith('inventory:')]
        assert 1 <= len(rows) <= len(patterns)  # engine may deduplicate equal scope-level evidence
        return {row['status'] for row in rows}
    finally:
        for stub in stubs.values(): stub.deactivate()

OPAQUE = {'detail-type': ['Unrelated native event']}

@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('good_first', [True, False])
def test_complete_alert_witness_is_independent(monkeypatch, check, good_first):
    patterns = [pattern(check), OPAQUE] if good_first else [OPAQUE, pattern(check)]
    assert evaluate(monkeypatch, check, patterns) == {'PASS'}

@pytest.mark.parametrize('check', CHECKS)
def test_opaque_rule_without_complete_witness_is_unknown(monkeypatch, check):
    assert evaluate(monkeypatch, check, [OPAQUE]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_partial_required_coverage_is_not_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check, partial=True), OPAQUE]) == {'UNKNOWN'}

@pytest.mark.parametrize('check', CHECKS)
def test_complete_nonmatching_inventory_is_negative(monkeypatch, check):
    assert evaluate(monkeypatch, check, [{'source': ['aws.s3'], 'detail-type': ['Other']}]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
def test_denied_targets_cannot_prove_positive(monkeypatch, check):
    assert evaluate(monkeypatch, check, [pattern(check), OPAQUE], denied_target=0) == {'UNKNOWN'}


def test_high_requires_one_complete_rule(monkeypatch):
    high = pattern(CHECKS[0], partial=True)
    critical = pattern(CHECKS[0], partial=True)
    critical['detail']['findings']['Severity']['Label'] = ['CRITICAL']
    assert evaluate(monkeypatch, CHECKS[0], [high, critical]) == {'FAIL'}

@pytest.mark.parametrize('check', CHECKS)
@pytest.mark.parametrize('good_first', [True, False])
def test_complete_witness_survives_unrelated_denied_targets(monkeypatch, check, good_first):
    patterns = [pattern(check), OPAQUE] if good_first else [OPAQUE, pattern(check)]
    denied = 1 if good_first else 0
    assert evaluate(monkeypatch, check, patterns, denied_target=denied) == {'PASS'}
