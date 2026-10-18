"""Portable Secrets Manager DescribeSecret -> collector -> signed-check regressions."""
import copy

import boto3
from botocore.stub import Stubber
import pytest

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot
from peaso.checks import evaluate_check

CHECK = 'aws_nist_secretsmanager_secret_automatic_rotation_enabled'
ACCOUNT = '123456789012'
REGION = 'us-east-1'
ARN = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:db-AbCdEf'
LAMBDA = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:rotate'


def _collect(monkeypatch, detail, *, stale=None, denied=False):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients = {service: session.client(service, region_name=REGION) for service in ('sts', 'secretsmanager')}
    stubs = {service: Stubber(client) for service, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs['sts'].add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture', 'UserId': 'AIDAFIXTURE'}, {})
    listed = {'ARN': ARN, 'Name': 'db', **(stale or {})}
    stubs['secretsmanager'].add_response('list_secrets', {'SecretList': [listed]}, {})
    if denied:
        stubs['secretsmanager'].add_client_error('describe_secret',
            service_error_code='AccessDeniedException', http_status_code=403,
            expected_params={'SecretId': ARN})
    else:
        stubs['secretsmanager'].add_response('describe_secret',
            {'ARN': ARN, 'Name': 'db', **detail}, {'SecretId': ARN})
    stubs['secretsmanager'].add_response('get_resource_policy', {}, {'SecretId': ARN})
    monkeypatch.setattr(aws.Requests, 'client', lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
    try:
        snap = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'fixture'},
            'options': {'regions': [REGION], 'max_calls': 4, 'service_concurrency': 1,
                        'scope_concurrency': 1}}, ['secret'])
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        return snap
    finally:
        for stub in stubs.values():
            stub.deactivate()


def _item(snapshot):
    return next(c for c in snapshot['collections'] if c['type'] == 'secret' and
        c['scope'] == f'{ACCOUNT}/{REGION}')['items'][0]


def _status(snapshot):
    report = evaluate_snapshot(snapshot, checks=[CHECK])
    rows = [r for r in report['findings'] if r['check_id'] == CHECK and r['resource_id'] != 'inventory:secret']
    assert len(rows) == 1
    return rows[0]['status']


@pytest.mark.parametrize('extra,expected', [
    ({'OwningService': 'rds'}, 'PASS'),
    ({'RotationLambdaARN': LAMBDA}, 'PASS'),
    ({}, 'UNKNOWN'),
    ({'OwningService': 'other-service'}, 'UNKNOWN'),
])
def test_sdk_owner_or_lambda_witness(monkeypatch, extra, expected):
    detail = {'RotationEnabled': True, 'RotationRules': {'AutomaticallyAfterDays': 30}, **extra}
    snap = _collect(monkeypatch, detail, stale={'OwningService': 'rds', 'RotationEnabled': False,
        'RotationRules': {'AutomaticallyAfterDays': 1}, 'RotationLambdaARN': LAMBDA})
    item = _item(snap)
    assert item['RotationEnabled'] is True
    assert item.get('OwningService') == extra.get('OwningService')
    assert item.get('RotationLambdaARN') == extra.get('RotationLambdaARN')
    assert 'RotationLambdaRequired' not in item
    if 'OwningService' in extra:
        assert item['_coverage']['OwningService']['source_operation'] == 'secretsmanager:DescribeSecret'
    assert _status(snap) == expected
    assert snap['metadata']['calls'] == 4


@pytest.mark.parametrize('detail,expected', [
    ({'RotationEnabled': False}, 'FAIL'),
    ({'RotationEnabled': True, 'OwningService': 'rds'}, 'FAIL'),
])
def test_sdk_negative_and_malformed(monkeypatch, detail, expected):
    assert _status(_collect(monkeypatch, detail)) == expected


def test_sdk_denied_and_foreign_cannot_reuse_stale_list(monkeypatch):
    stale = {'OwningService': 'rds', 'RotationEnabled': True,
        'RotationRules': {'AutomaticallyAfterDays': 30}}
    denied = _collect(monkeypatch, {}, stale=stale, denied=True)
    assert 'OwningService' not in _item(denied)
    assert _status(denied) == 'UNKNOWN'
    foreign = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'AutomaticallyAfterDays': 30}, 'ARN': ARN.replace(ACCOUNT, '999999999999')})
    assert _status(foreign) == 'UNKNOWN'


def test_partial_and_nested_denied_cannot_pass(monkeypatch):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'AutomaticallyAfterDays': 30}})
    item = _item(snap)
    item['RotationRules']['_coverage'] = {'AutomaticallyAfterDays': {'status': 'denied'}}
    snap.pop('snapshot_id', None)
    assert _status(snap) == 'UNKNOWN'
    del item['RotationRules']['_coverage']
    item['_coverage']['OwningService']['status'] = 'partial'
    assert _status(snap) == 'UNKNOWN'


def test_legacy_explicit_lambda_required_compatibility():
    row = {'ARN': ARN, 'RotationEnabled': True, 'RotationRules': {'AutomaticallyAfterDays': 30},
        'RotationLambdaRequired': True, 'RotationLambdaARN': LAMBDA}
    scope = f'{ACCOUNT}/{REGION}'
    index = {'context': {'provider': 'aws', 'scope': scope},
             'collections': {'secret': [{'type': 'secret', 'scope': scope,
                 'status': 'collected', 'items': [row]}]},
             'secret': [{'type': 'secret', 'scope': scope, 'data': row}]}
    assert evaluate_check(CHECK, row, index)[0] == 'PASS'
    row2 = copy.deepcopy(row)
    del row2['RotationLambdaARN']
    index['collections']['secret'][0]['items'] = [row2]
    index['secret'][0]['data'] = row2
    assert evaluate_check(CHECK, row2, index)[0] == 'FAIL'


def test_partial_inventory_and_denied_method_facts_stay_unknown(monkeypatch):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'AutomaticallyAfterDays': 30}})
    collection = next(c for c in snap['collections'] if c['type'] == 'secret' and
        c['scope'] == f'{ACCOUNT}/{REGION}')
    collection['status'] = 'partial'
    snap.pop('snapshot_id', None)
    assert _status(snap) == 'UNKNOWN'
    collection['status'] = 'collected'
    item = collection['items'][0]
    item['_coverage']['RotationLambdaARN'] = {'status': 'denied'}
    assert _status(snap) == 'UNKNOWN'
    del item['_coverage']['RotationLambdaARN']
    item['_coverage']['RotationLambdaRequired'] = {'status': 'denied'}
    assert _status(snap) == 'UNKNOWN'


def test_explicit_legacy_flag_conflict_and_malformed_owner():
    scope = f'{ACCOUNT}/{REGION}'
    row = {'ARN': ARN, 'RotationEnabled': True, 'RotationRules': {'AutomaticallyAfterDays': 30},
        'RotationLambdaRequired': True, 'OwningService': 'rds'}
    index = {'context': {'provider': 'aws', 'scope': scope},
             'collections': {'secret': [{'type': 'secret', 'scope': scope,
                 'status': 'collected', 'items': [row]}]},
             'secret': [{'type': 'secret', 'scope': scope, 'data': row}]}
    assert evaluate_check(CHECK, row, index)[0] == 'UNKNOWN'
    row['RotationLambdaRequired'] = 'false'
    assert evaluate_check(CHECK, row, index)[0] == 'UNKNOWN'
    row['RotationLambdaRequired'] = False
    row['OwningService'] = ''
    assert evaluate_check(CHECK, row, index)[0] == 'UNKNOWN'


def test_unbound_owner_and_lambda_are_not_positive_witnesses():
    scope = f'{ACCOUNT}/{REGION}'
    row = {'ARN': ARN, 'RotationEnabled': True,
           'RotationRules': {'AutomaticallyAfterDays': 30}, 'OwningService': 'rds'}
    index = {'context': {'provider': 'aws', 'scope': scope},
             'collections': {'secret': [{'type': 'secret', 'scope': scope,
                 'status': 'collected', 'items': [row]}]},
             'secret': [{'type': 'secret', 'scope': scope, 'data': row}]}
    assert evaluate_check(CHECK, row, index)[0] == 'UNKNOWN'
    del row['OwningService']
    row['RotationLambdaARN'] = LAMBDA
    assert evaluate_check(CHECK, row, index)[0] == 'UNKNOWN'


def test_legacy_explicit_lambda_not_required_without_owner_or_lambda():
    scope = f'{ACCOUNT}/{REGION}'
    row = {'ARN': ARN, 'RotationEnabled': True,
           'RotationRules': {'AutomaticallyAfterDays': 30},
           'RotationLambdaRequired': False}
    index = {'context': {'provider': 'aws', 'scope': scope},
             'collections': {'secret': [{'type': 'secret', 'scope': scope,
                 'status': 'collected', 'items': [row]}]},
             'secret': [{'type': 'secret', 'scope': scope, 'data': row}]}
    assert evaluate_check(CHECK, row, index)[0] == 'PASS'


@pytest.mark.parametrize('rules', [
    {'ScheduleExpression': None, 'AutomaticallyAfterDays': 30},
    {'ScheduleExpression': 'rate(30 days)', 'AutomaticallyAfterDays': None},
])
def test_explicit_null_alternative_remains_unknown_after_sdk_collection(monkeypatch, rules):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'AutomaticallyAfterDays': 30}})
    _item(snap)['RotationRules'] = rules
    snap.pop('snapshot_id', None)
    assert _status(snap) == 'UNKNOWN'


@pytest.mark.parametrize('expression', [
    'rate(4 hours)', 'rate(1 day)', 'rate(10 days)', 'rate(999 days)',
    'cron(0 /8 * * ? *)', 'cron(0 8/8 * * ? *)',
    'cron(0 2/10 * * ? *)', 'cron(0 10 * * ? *)',
    'cron(0 18 ? * SAT *)', 'cron(0 8 1 * ? *)',
    'cron(0 8 ? * MON-FRI *)', 'cron(0 16 1,15 * ? *)',
    'cron(0 8 1-15 JAN-MAR ? *)',
])
def test_sdk_documented_rate_and_supported_cron(monkeypatch, expression):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'ScheduleExpression': expression}})
    assert _item(snap)['RotationRules']['ScheduleExpression'] == expression
    assert _status(snap) == 'PASS'


@pytest.mark.parametrize('expression', [
    'rate(0 hours)', 'rate(1 hour)', 'rate(1 hours)', 'rate(3 hours)',
    'rate(1000 days)', 'rate(4 minutes)', 'rate(4 hour)',
    'cron(0 10 * * ?)', 'cron(0 10 * * ? * extra)',
    'cron(1 10 * * ? *)', 'cron(0 10 * * ? 2026)',
    'cron(0 24 * * ? *)', 'cron(0 0-23 * * ? *)',
    'cron(0 1/2 * * ? *)', 'cron(0 10 32 * ? *)',
    'cron(0 10 1 13 ? *)', 'cron(0 10 1 3-1 ? *)',
    'cron(0 10 ? * FOO *)',
    'cron(0 10 ? * 8 *)', 'cron(0 10 ? * 5-2 *)',
    'cron(0 10 1 * MON *)', 'cron(0 10 ? * ? *)',
    'cron(0 10 L * ? *)', 'cron(0 0 ? * SUN#1 *)',
])
def test_sdk_malformed_or_unsupported_schedule_stays_unknown(monkeypatch, expression):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'ScheduleExpression': expression}})
    assert _status(snap) == 'UNKNOWN'


def test_sdk_denied_and_explicit_null_schedule_cannot_pass(monkeypatch):
    detail = {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'ScheduleExpression': 'rate(4 hours)'}}
    assert _status(_collect(monkeypatch, detail, denied=True)) == 'UNKNOWN'
    snap = _collect(monkeypatch, detail)
    _item(snap)['RotationRules']['ScheduleExpression'] = None
    snap.pop('snapshot_id', None)
    assert _status(snap) == 'UNKNOWN'


def test_sdk_current_days_regression_remains_pass(monkeypatch):
    snap = _collect(monkeypatch, {'RotationEnabled': True, 'OwningService': 'rds',
        'RotationRules': {'AutomaticallyAfterDays': 30}})
    assert _status(snap) == 'PASS'
