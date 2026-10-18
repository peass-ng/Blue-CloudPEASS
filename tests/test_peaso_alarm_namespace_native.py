import copy
import hashlib
import json

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.checks.batch_remaining_aws import _alarm_source_namespaces
from peaso.engine import evaluate_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = f'{ACCOUNT}/{REGION}'
QUEUE = f'https://sqs.{REGION}.amazonaws.com/{ACCOUNT}/target-queue'
ARN = f'arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:example'
CHECK = 'aws_sqs_queue_depth_alarm_present'
IDENTITY = {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/test-reader', 'UserId': 'AIDAEXAMPLE'}


def alarm(**fields):
    suffix = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:12]
    return {'AlarmName': 'example-' + suffix, 'AlarmArn': ARN + '-' + suffix, 'ActionsEnabled': True,
            'AlarmActions': [f'arn:aws:sns:{REGION}:{ACCOUNT}:notify'],
            'EvaluationPeriods': 1, 'Threshold': 10.0, 'ComparisonOperator': 'GreaterThanThreshold', **fields}


def metric_stat(namespace, ident='source'):
    return {'Id': ident, 'MetricStat': {'Metric': {'Namespace': namespace, 'MetricName': 'Observed',
                                                 'Dimensions': [{'Name': 'Source', 'Value': 'sample'}]},
                                        'Period': 60, 'Stat': 'Sum'}, 'ReturnData': False}


def direct():
    return alarm(Namespace='AWS/SQS', MetricName='ApproximateNumberOfMessagesVisible',
                 Dimensions=[{'Name': 'QueueName', 'Value': 'target-queue'}])


def math(namespace='AWS/ApiGateway'):
    return alarm(Metrics=[metric_stat(namespace, 'm1'),
                          {'Id': 'result', 'Expression': 'FILL(m1, 0) / (m1 + 1)', 'ReturnData': True}])


def sql(expression='SELECT SUM(EventCount) FROM SCHEMA("Example/Telemetry", source)'):
    return alarm(Metrics=[{'Id': 'result', 'Expression': expression, 'ReturnData': True, 'Period': 60}])


def collect_native(monkeypatch, rows):
    session = boto3.Session(aws_access_key_id='fixture-key', aws_secret_access_key='fixture-secret',
                            aws_session_token='fixture-token', region_name=REGION)
    clients = {name: session.client(name, region_name=REGION) for name in ('sts', 'sqs', 'cloudwatch')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs['sts'].add_response('get_caller_identity', IDENTITY, {})
    stubs['sqs'].add_response('list_queues', {'QueueUrls': [QUEUE]}, {'MaxResults': 1000})
    stubs['sqs'].add_response('get_queue_attributes', {'Attributes': {'QueueArn':f'arn:aws:sqs:{REGION}:{ACCOUNT}:target-queue'}},
                              {'QueueUrl': QUEUE, 'AttributeNames': ['All']})
    stubs['cloudwatch'].add_response('describe_alarms', {'MetricAlarms': rows}, {})
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture-static'))
    monkeypatch.setattr(aws.Requests, 'client', lambda self, sdk_session, service, region: clients[service])
    try:
        snapshot = aws.collect({'provider':'aws', 'scopes':[SCOPE], 'auth':{},
                                'options':{'service_concurrency':1}}, ['sqs_queue','cloudwatch_alarm'])
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        assert snapshot['metadata']['calls'] == 4
        return snapshot
    finally:
        for stub in stubs.values():
            stub.deactivate()


def status(snapshot):
    snapshot = dict(snapshot)
    snapshot.pop('snapshot_id', None)  # Re-seal intentional native-field counterexamples.
    report = evaluate_snapshot(snapshot, checks=[CHECK])
    findings = [f for f in report['findings'] if f['check_id'] == CHECK and f['scope'] == SCOPE]
    assert len(findings) == 1
    return findings[0]['status'], findings[0]['evidence']


@pytest.mark.parametrize('rows,expected', [
    ([math(), sql()], 'FAIL'),
    ([direct(), math()], 'PASS'),
    ([math('AWS/SQS')], 'UNKNOWN'),
    ([alarm(Namespace='AWS/SQS', MetricName='ApproximateNumberOfMessagesVisible', Dimensions=[{'Name':'QueueName','Value':'target-queue'}], Metrics=[metric_stat('AWS/ApiGateway')])], 'UNKNOWN'),
    ([sql('SELECT SUM(Observed) FROM SCHEMA("AWS/SQS", QueueName)')], 'UNKNOWN'),
    ([sql('SEARCH(\'{AWS/SQS,QueueName} MetricName="ApproximateNumberOfMessagesVisible"\', \'Sum\')')], 'UNKNOWN'),
    ([sql('SELECT SUM(Observed) FROM SCHEMA("Example/Telemetry", source) WHERE source = \'x\'')], 'UNKNOWN'),
    ([alarm(Metrics=[metric_stat('AWS/ApiGateway','m1'), {'Id':'result','Expression':'m1 + SEARCH(\'x\', \'Sum\')', 'ReturnData':True}])], 'UNKNOWN'),
    ([alarm(Metrics=[metric_stat('AWS/ApiGateway','m1'), {'Id':'result','Expression':'m1 + missing', 'ReturnData':True}])], 'UNKNOWN'),
])
def test_sdk_collector_engine_namespace_boundary(monkeypatch, rows, expected):
    snapshot = collect_native(monkeypatch, rows)
    actual, evidence = status(snapshot)
    assert actual == expected, evidence
    if expected == 'FAIL':
        assert evidence['matching_alarm_arns'] == []


def test_sdk_collector_engine_denied_and_foreign_guards(monkeypatch):
    snapshot = collect_native(monkeypatch, [math()])
    alarms = next(c for c in snapshot['collections'] if c['type'] == 'cloudwatch_alarm')
    assert status(snapshot)[0] == 'FAIL'
    denied = copy.deepcopy(snapshot)
    next(c for c in denied['collections'] if c['type'] == 'cloudwatch_alarm')['items'][0]['Metrics'] = {'collection_status':'denied'}
    assert status(denied)[0] == 'UNKNOWN'
    foreign = copy.deepcopy(snapshot)
    next(c for c in foreign['collections'] if c['type'] == 'cloudwatch_alarm')['items'][0]['AlarmArn'] = f'arn:aws:cloudwatch:us-west-2:{ACCOUNT}:alarm:foreign'
    assert status(foreign)[0] == 'UNKNOWN'
    partial = copy.deepcopy(snapshot)
    next(c for c in partial['collections'] if c['type'] == 'cloudwatch_alarm')['status'] = 'partial'
    assert status(partial)[0] == 'UNKNOWN'


def test_sdk_collector_engine_positive_precedence(monkeypatch):
    snapshot = collect_native(monkeypatch, [direct(), math('AWS/SQS')])
    assert status(snapshot)[0] == 'PASS'



@pytest.mark.parametrize('marker', ['denied', 'partial', 'malformed'])
@pytest.mark.parametrize('field', ['Metrics', 'MetricStat', 'MetricStat.Metric', 'Metric.Namespace', 'Metric.MetricName', 'Metric.Dimensions', 'Dimension.Name', 'Dimension.Value', 'MetricStat.Period', 'MetricStat.Stat', 'Expression', 'Id', 'Namespace', 'MetricName'])
def test_stale_field_with_unread_coverage_never_proves_absence(monkeypatch, field, marker):
    row = sql() if field == 'Expression' else math()
    snapshot = collect_native(monkeypatch, [row])
    affected = next(c for c in snapshot['collections'] if c['type'] == 'cloudwatch_alarm')['items'][0]
    query = affected['Metrics'][0]
    if field == 'Metrics':
        container, name = affected, 'Metrics'
    elif field == 'MetricStat':
        container, name = query, 'MetricStat'
    elif field == 'MetricStat.Metric':
        container, name = query['MetricStat'], 'Metric'
    elif field in ('Metric.Namespace', 'Metric.MetricName', 'Metric.Dimensions'):
        container, name = query['MetricStat']['Metric'], field.split('.')[1]
    elif field in ('Dimension.Name', 'Dimension.Value'):
        container, name = query['MetricStat']['Metric']['Dimensions'][0], field.split('.')[1]
    elif field in ('MetricStat.Period', 'MetricStat.Stat'):
        container, name = query['MetricStat'], field.split('.')[1]
    elif field in ('Expression', 'Id'):
        container = affected['Metrics'][-1] if field == 'Expression' and len(affected['Metrics']) > 1 else query
        name = field
    else:
        container, name = affected, field
        if name == 'Namespace':
            container[name] = 'AWS/ApiGateway'  # Stale, unrelated value beside denial.
    container.setdefault('_coverage', {})[name] = {'status': marker}
    verdict, evidence = status(snapshot)
    assert verdict == 'UNKNOWN', (field, marker, evidence)
    assert evidence['unresolved_alarm_count'] == 1


@pytest.mark.parametrize('value', [None, 'AWS/ApiGateway'])
def test_explicit_direct_namespace_on_math_cannot_narrow_absence(monkeypatch, value):
    snapshot = collect_native(monkeypatch, [math()])
    row = next(c for c in snapshot['collections'] if c['type'] == 'cloudwatch_alarm')['items'][0]
    row['Namespace'] = value
    assert status(snapshot)[0] == 'UNKNOWN'


def test_direct_match_survives_denied_math_sibling(monkeypatch):
    snapshot = collect_native(monkeypatch, [direct(), math()])
    math_row = next(row for c in snapshot['collections'] if c['type'] == 'cloudwatch_alarm'
                    for row in c['items'] if row.get('Metrics'))
    math_row.setdefault('_coverage', {})['Metrics'] = {'status': 'denied'}
    assert status(snapshot)[0] == 'PASS'


@pytest.mark.parametrize('marker', ['denied', 'partial', 'malformed'])
def test_omitted_namespace_with_unread_marker_stays_unknown(monkeypatch, marker):
    snapshot = collect_native(monkeypatch, [math()])
    row = next(c for c in snapshot['collections'] if c['type'] == 'cloudwatch_alarm')['items'][0]
    assert 'Namespace' not in row
    row.setdefault('_coverage', {})['Namespace'] = {'status': marker}
    verdict, evidence = status(snapshot)
    assert verdict == 'UNKNOWN'
    assert evidence['unresolved_alarm_count'] == 1


@pytest.mark.parametrize('length,expected', [(2048, 'FAIL'), (2049, 'UNKNOWN')])
def test_sql_expression_length_boundary_never_false_fails(monkeypatch, length, expected):
    base = 'SELECT SUM(EventCount) FROM SCHEMA("Example/Telemetry", source)'
    expression = base + ' ' * (length - len(base))
    assert len(expression) == length
    snapshot = collect_native(monkeypatch, [sql(expression)])
    verdict, evidence = status(snapshot)
    assert verdict == expected, evidence
    if expected == 'UNKNOWN':
        assert evidence['unresolved_alarm_count'] == 1


def test_empty_expression_has_no_namespace_proof():
    assert _alarm_source_namespaces({'Metrics': [{'Id': 'result', 'Expression': ''}]}) is None


def test_empty_native_direct_namespace_cannot_prove_alarm_absence(monkeypatch):
    snapshot = collect_native(monkeypatch, [direct()])
    row = next(c for c in snapshot["collections"] if c["type"] == "cloudwatch_alarm")["items"][0]
    row["Namespace"] = ""
    assert status(snapshot)[0] == "UNKNOWN"
