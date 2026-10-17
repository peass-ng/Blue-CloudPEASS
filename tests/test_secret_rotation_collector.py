"""Portable collector-to-active-check regression; no cloud calls or private inputs."""
import json

import pytest

from peaso.checks import evaluate_check
from peaso.collectors import aws

ARN = 'arn:aws:secretsmanager:us-east-1:111111111111:secret:rotation-abc123'
ROW = {'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': False,
       'RotationRules': {'AutomaticallyAfterDays': 90}}


class FakeRequests:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def detail(self, session, service, region, operation, **kwargs):
        assert service == 'secretsmanager' and region == 'us-east-1'
        assert operation in {'describe_secret', 'get_resource_policy'}
        assert kwargs == {'SecretId': ARN}
        self.calls.append(operation)
        return (self.response if operation == 'describe_secret' else
                {'collection_status': 'collected', 'ARN': ARN})


@pytest.mark.parametrize('detail,expected', [
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': True,
      'RotationRules': {'AutomaticallyAfterDays': 30}}, 'PASS'),
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': False}, 'FAIL'),
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation'}, 'UNKNOWN'),
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': None}, 'UNKNOWN'),
    ({'collection_status': 'denied', 'error': {'code': 'AccessDeniedException'}}, 'UNKNOWN'),
    ({'collection_status': 'unknown', 'error': {'code': 'ThrottlingException'}}, 'UNKNOWN'),
    ({'collection_status': 'partial', 'error': {'code': 'partial_detail'}}, 'UNKNOWN'),
    ({'collection_status': 'malformed', 'error': {'code': 'malformed_response'}}, 'UNKNOWN'),
    ({'collection_status': 'collected', 'ARN': ARN.replace('111111111111', '222222222222'),
      'Name': 'rotation', 'RotationEnabled': True}, 'UNKNOWN'),
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': 'true'}, 'UNKNOWN'),
    ({'collection_status': 'collected', 'ARN': ARN, 'Name': 'rotation', 'RotationEnabled': True}, 'PASS'),
])
def test_detail_overrides_stale_list_and_active_check(detail, expected):
    request = FakeRequests(detail)
    item = aws._enrich(request, object(), 'us-east-1', 'secret', [ROW],
                       account='111111111111', partition='aws')[0]
    assert request.calls == ['describe_secret', 'get_resource_policy']
    assert ROW['RotationEnabled'] is False and ROW['RotationRules'] == {'AutomaticallyAfterDays': 90}
    assert evaluate_check('aws.secretsmanager.rotation', item)[0] == expected
    assert 'SecretString' not in json.dumps(item)
    if detail.get('collection_status') != 'collected' or detail.get('ARN') != ARN:
        assert item['_coverage']['RotationEnabled']['status'] not in ('collected', 'empty')


@pytest.mark.parametrize('foreign', [
    ARN.replace('us-east-1', 'eu-west-1'),
    ARN.replace('111111111111', '222222222222'),
    ARN.replace('aws:secretsmanager', 'aws-cn:secretsmanager'),
])
def test_foreign_list_arn_never_queried(foreign):
    class NoCalls:
        def detail(self, *args, **kwargs):
            pytest.fail('foreign ARN must not be queried')

    item = aws._enrich(NoCalls(), object(), 'us-east-1', 'secret',
                       [{'ARN': foreign, 'RotationEnabled': True}],
                       account='111111111111', partition='aws')[0]
    assert evaluate_check('aws.secretsmanager.rotation', item)[0] == 'UNKNOWN'


def test_read_allowlist_excludes_secret_contents():
    assert ('secretsmanager', 'describe_secret') in aws.READ_ACTIONS
    assert ('secretsmanager', 'get_secret_value') not in aws.READ_ACTIONS
    assert ('secretsmanager', 'batch_get_secret_value') not in aws.READ_ACTIONS


def test_main_collect_binds_identity_and_snapshot(monkeypatch):
    import boto3
    from botocore.stub import Stubber

    session = boto3.Session(aws_access_key_id='inert-key', aws_secret_access_key='inert-secret',
                            region_name='us-east-1')
    clients = {service: session.client(service, region_name='us-east-1') for service in ('sts', 'secretsmanager')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs['sts'].add_response('get_caller_identity', {'Account': '111111111111',
        'Arn': 'arn:aws:iam::111111111111:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
    stubs['secretsmanager'].add_response('list_secrets', {'SecretList': [ROW]}, {})
    stubs['secretsmanager'].add_response('describe_secret', {'ARN': ARN, 'Name': 'rotation',
        'RotationEnabled': True, 'RotationRules': {'AutomaticallyAfterDays': 30}}, {'SecretId': ARN})
    stubs['secretsmanager'].add_response('get_resource_policy', {'ARN': ARN, 'Name': 'rotation'}, {'SecretId': ARN})
    monkeypatch.setattr(aws.Requests, 'client', lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'inert'))
    snap = aws.collect({'provider': 'aws', 'scopes': ['111111111111'],
        'auth': {'method': 'access_keys', 'aws_access_key_id': 'inert-key', 'aws_secret_access_key': 'inert-secret'},
        'options': {'regions': ['us-east-1'], 'max_calls': 4}}, ['secret'])
    collection = next(x for x in snap['collections'] if x['type'] == 'secret' and
                      x['scope'] == '111111111111/us-east-1')
    assert collection['status'] == 'collected' and len(collection['items']) == 1
    item = collection['items'][0]
    assert item['RotationEnabled'] is True
    assert item['RotationRules'] == {'AutomaticallyAfterDays': 30}
    assert evaluate_check('aws.secretsmanager.rotation', item)[0] == 'PASS'
    assert snap['metadata']['calls'] == 4
    for stub in stubs.values():
        stub.assert_no_pending_responses()
        stub.deactivate()
