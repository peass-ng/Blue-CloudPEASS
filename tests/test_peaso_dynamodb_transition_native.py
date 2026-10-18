"""Synthetic DynamoDB SDK responses through the registered collector and engine."""

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

CHECK = 'aws_nist_dynamodb_table_encrypted_with_kms'
ACCOUNT = '123456789012'
REGION = 'us-east-1'
TABLE = 'payments'
TABLE_ARN = f'arn:aws:dynamodb:{REGION}:{ACCOUNT}:table/{TABLE}'
KEY_ARN = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/12345678-1234-1234-1234-123456789abc'


def _collect(monkeypatch, *, state='ENABLED', sse_type='KMS', key=KEY_ARN,
             table_arn=TABLE_ARN, denied=False):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients = {name: session.client(name, region_name=REGION) for name in ('sts', 'dynamodb')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs['sts'].add_response('get_caller_identity', {
        'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture', 'UserId': 'AIDAFIXTURE'}, {})
    stubs['dynamodb'].add_response('list_tables', {'TableNames': [TABLE]}, {})
    if denied:
        stubs['dynamodb'].add_client_error('describe_table', service_error_code='AccessDeniedException',
            http_status_code=403, expected_params={'TableName': TABLE})
    else:
        sse = {'Status': state, 'SSEType': sse_type}
        if key is not None:
            sse['KMSMasterKeyArn'] = key
        stubs['dynamodb'].add_response('describe_table', {'Table': {
            'TableName': TABLE, 'TableArn': table_arn, 'SSEDescription': sse}}, {'TableName': TABLE})
    stubs['dynamodb'].add_response('describe_continuous_backups', {}, {'TableName': TABLE})
    if not denied:
        stubs['dynamodb'].add_response('get_resource_policy', {}, {'ResourceArn': table_arn})
        stubs['dynamodb'].add_response('list_tags_of_resource', {'Tags': []}, {'ResourceArn': table_arn})
    monkeypatch.setattr(aws.Requests, 'client', lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
    try:
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'fixture'},
            'options': {'regions': [REGION], 'max_calls': 8, 'service_concurrency': 1,
                        'scope_concurrency': 1}}, ['dynamodb_table'])
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        return snapshot
    finally:
        for stub in stubs.values():
            stub.deactivate()


def _result(snapshot):
    collection = next(c for c in snapshot['collections'] if c['type'] == 'dynamodb_table'
                      and c['scope'] == f'{ACCOUNT}/{REGION}')
    assert collection['status'] in ('collected', 'partial')
    assert len(collection['items']) == 1
    findings = evaluate_snapshot(snapshot, checks=[CHECK])['findings']
    rows = [f for f in findings if f['check_id'] == CHECK and f['resource_id'] != 'inventory:dynamodb_table']
    assert len(rows) == 1
    return collection['items'][0], rows[0]['status']


def test_native_enabled_kms_pass(monkeypatch):
    item, status = _result(_collect(monkeypatch))
    assert item['Table']['Table']['SSEDescription']['KMSMasterKeyArn'] == KEY_ARN
    assert status == 'PASS'


@pytest.mark.parametrize('state', ['ENABLING', 'DISABLING', 'UPDATING'])
def test_native_transition_is_unknown(monkeypatch, state):
    item, status = _result(_collect(monkeypatch, state=state))
    assert item['Table']['Table']['SSEDescription']['Status'] == state
    assert status == 'UNKNOWN'


@pytest.mark.parametrize('state,sse_type', [('DISABLED', 'KMS'), ('ENABLED', 'AES256')])
def test_native_negative_state_or_type(monkeypatch, state, sse_type):
    _, status = _result(_collect(monkeypatch, state=state, sse_type=sse_type))
    assert status == 'FAIL'


def test_native_denied_detail_is_unknown(monkeypatch):
    item, status = _result(_collect(monkeypatch, denied=True))
    assert item['Table']['collection_status'] == 'denied'
    assert status == 'UNKNOWN'


@pytest.mark.parametrize('table_arn', [TABLE_ARN.replace(ACCOUNT, '999999999999'),
    TABLE_ARN.replace(REGION, 'us-west-2'), 'not-an-arn'])
def test_native_foreign_or_malformed_table_is_unknown(monkeypatch, table_arn):
    _, status = _result(_collect(monkeypatch, table_arn=table_arn))
    assert status == 'UNKNOWN'


def test_native_missing_key_is_unknown(monkeypatch):
    _, status = _result(_collect(monkeypatch, key=None))
    assert status == 'UNKNOWN'


def test_native_malformed_sse_state_is_unknown(monkeypatch):
    _, status = _result(_collect(monkeypatch, state='BROKEN'))
    assert status == 'UNKNOWN'


@pytest.mark.parametrize('key', [KEY_ARN.replace(ACCOUNT, '999999999999'),
    KEY_ARN.replace(REGION, 'us-west-2'), 'not-an-arn'])
def test_native_unbound_or_malformed_kms_key_is_unknown(monkeypatch, key):
    _, status = _result(_collect(monkeypatch, key=key))
    assert status == 'UNKNOWN'
