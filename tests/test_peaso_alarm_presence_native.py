"""A proved native alarm match survives unsupported sibling expressions."""
import copy
import pytest
from peaso.checks import CHECKS

REGISTRY = {check.id: check for check in CHECKS}
SCOPE = '111111111111/us-east-1'
CASES = [
    ('aws_sqs_queue_depth_alarm_present', 'sqs_queue',
     {'QueueUrl': 'https://sqs.us-east-1.amazonaws.com/111111111111/jobs'},
     'AWS/SQS', 'ApproximateNumberOfMessagesVisible', 'QueueName', 'jobs'),
    ('aws_ec2_running_instance_cpu_alarm_present', 'instance',
     {'InstanceId': 'i-1', 'State': {'Name': 'running'}},
     'AWS/EC2', 'CPUUtilization', 'InstanceId', 'i-1'),
]


def evaluate(case, rows, status=None):
    cid, kind, item, *_ = case
    index = {'context': {'provider': 'aws', 'scope': SCOPE}, 'collections': {}}
    for typ, values in [(kind, [item]), ('cloudwatch_alarm', rows)]:
        index['collections'][typ] = [{'type': typ, 'scope': SCOPE,
            'status': status if typ == 'cloudwatch_alarm' and status else ('collected' if values else 'empty'),
            'items': copy.deepcopy(values)}]
        index[typ] = [{'provider': 'aws', 'type': typ, 'scope': SCOPE,
                      'data': copy.deepcopy(value)} for value in values]
    return REGISTRY[cid].evaluate(copy.deepcopy(item), index)[0]


def match(case):
    _, _, _, namespace, metric, dimension, value = case
    return {'AlarmArn': 'arn:aws:cloudwatch:us-east-1:111111111111:alarm:match',
            'Namespace': namespace, 'MetricName': metric,
            'Dimensions': [{'Name': dimension, 'Value': value}],
            'ActionsEnabled': True,
            'AlarmActions': ['arn:aws:sns:us-east-1:111111111111:alerts']}


def expression():
    return {'AlarmArn': 'arn:aws:cloudwatch:us-east-1:111111111111:alarm:math',
            'Metrics': [{'Id': 'e1', 'Expression': 'SUM(METRICS())', 'ReturnData': True}],
            'ActionsEnabled': True,
            'AlarmActions': ['arn:aws:sns:us-east-1:111111111111:alerts']}


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('first', [False, True])
def test_valid_match_proves_presence_despite_expression(case, first):
    rows = [expression(), match(case)]
    assert evaluate(case, rows if first else rows[::-1]) == 'PASS'


@pytest.mark.parametrize('case', CASES)
def test_expression_does_not_prove_absence(case):
    assert evaluate(case, [expression()]) == 'UNKNOWN'


@pytest.mark.parametrize('case', CASES)
def test_complete_empty_inventory_proves_absence(case):
    assert evaluate(case, []) == 'FAIL'


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('status', ['denied', 'partial', 'unknown'])
def test_complete_scope_required_even_with_matching_row(case, status):
    assert evaluate(case, [match(case)], status) == 'UNKNOWN'


@pytest.mark.parametrize('case', CASES)
def test_foreign_alarm_inventory_cannot_prove_presence(case):
    foreign = expression()
    foreign['AlarmArn'] = foreign['AlarmArn'].replace('111111111111', '222222222222')
    assert evaluate(case, [match(case), foreign]) == 'UNKNOWN'


@pytest.mark.parametrize('case', CASES)
@pytest.mark.parametrize('field', ['Namespace', 'ActionsEnabled', 'AlarmActions'])
def test_denied_selected_matching_fields_cannot_prove_presence(case, field):
    row = match(case)
    row['_coverage'] = {field: {'status': 'denied'}}
    assert evaluate(case, [row, expression()]) == 'UNKNOWN'


@pytest.mark.parametrize('case', CASES)
def test_other_valid_metric_does_not_prove_presence(case):
    row = match(case)
    row['MetricName'] = 'DifferentMetric'
    assert evaluate(case, [row]) == 'FAIL'


@pytest.mark.parametrize('case', CASES)
def test_known_inactive_alarm_is_not_coverage(case):
    row = match(case)
    row['ActionsEnabled'] = False
    assert evaluate(case, [row]) == 'FAIL'
