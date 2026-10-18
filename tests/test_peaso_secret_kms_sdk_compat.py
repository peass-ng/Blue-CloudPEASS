"""Native SDK-to-engine KMS authority for the sw48 compatibility fixture."""
import boto3
from botocore.stub import Stubber
import pytest

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SECRET = f'arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:fixture-abcdef'
KEY_ID = '11111111-2222-3333-4444-555555555555'
KEY = f'arn:aws:kms:{REGION}:{ACCOUNT}:key/{KEY_ID}'
CHECK = 'aws.pci.secretsmanager.kms_encryption_any'


def _collect(monkeypatch, state):
    session = boto3.Session(aws_access_key_id='inert', aws_secret_access_key='inert', region_name=REGION)
    clients = {name: session.client(name, region_name=REGION) for name in ('sts', 'secretsmanager', 'kms')}
    stubs = {name: Stubber(client) for name, client in clients.items()}
    for stub in stubs.values():
        stub.activate()
    stubs['sts'].add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAFIXTURE'}, {})
    stubs['secretsmanager'].add_response('list_secrets', {'SecretList': [
        {'ARN': SECRET, 'Name': 'fixture', 'KmsKeyId': 'alias/stale'}]}, {})
    stubs['secretsmanager'].add_response('describe_secret', {'ARN': SECRET,
        'Name': 'fixture', 'KmsKeyId': KEY, 'RotationEnabled': False}, {'SecretId': SECRET})
    stubs['secretsmanager'].add_response('get_resource_policy', {}, {'SecretId': SECRET})
    stubs['kms'].add_response('list_keys', {'Keys': [{'KeyArn': KEY, 'KeyId': KEY_ID}],
        'Truncated': False}, {})
    stubs['kms'].add_response('describe_key', {'KeyMetadata': {
        'AWSAccountId': ACCOUNT, 'KeyId': KEY_ID, 'Arn': KEY, 'CreationDate': 1,
        'Enabled': state == 'Enabled', 'KeyUsage': 'ENCRYPT_DECRYPT', 'KeyState': state,
        'Origin': 'AWS_KMS', 'KeyManager': 'CUSTOMER'}}, {'KeyId': KEY_ID})
    stubs['kms'].add_response('get_key_rotation_status', {'KeyRotationEnabled': False}, {'KeyId': KEY_ID})
    stubs['kms'].add_response('get_key_policy', {'Policy': '{}'}, {'KeyId': KEY_ID, 'PolicyName': 'default'})
    monkeypatch.setattr(aws.Requests, 'client', lambda self, _session, service, region: clients[service])
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'inert'))
    try:
        snap = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'inert'},
            'options': {'regions': [REGION], 'service_concurrency': 1,
                        'scope_concurrency': 1, 'max_calls': 16}}, ['secret', 'kms_key'])
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        return snap
    finally:
        for stub in stubs.values():
            stub.deactivate()


def _finding(snapshot):
    report = evaluate_snapshot(snapshot, checks=[CHECK])
    rows = [row for row in report['findings'] if row['check_id'] == CHECK and
            row['resource_id'] != 'inventory:secret']
    assert len(rows) == 1
    return rows[0]['status']


@pytest.mark.parametrize('state,expected', [('Enabled', 'PASS'), ('Disabled', 'FAIL')])
def test_native_describe_key_join(monkeypatch, state, expected):
    snap = _collect(monkeypatch, state)
    secret = next(c for c in snap['collections'] if c['type'] == 'secret' and
        c['scope'] == f'{ACCOUNT}/{REGION}')['items'][0]
    assert secret['KmsKeyId'] == KEY
    assert secret['_coverage']['KmsKeyId']['source_operation'] == 'secretsmanager:DescribeSecret'
    assert _finding(snap) == expected
    assert snap['metadata']['calls'] == 9


def test_native_detail_denial_stays_unknown(monkeypatch):
    snap = _collect(monkeypatch, 'Enabled')
    secret = next(c for c in snap['collections'] if c['type'] == 'secret' and
        c['scope'] == f'{ACCOUNT}/{REGION}')['items'][0]
    secret['_coverage']['KmsKeyId']['status'] = 'denied'
    snap.pop('snapshot_id', None)
    assert _finding(snap) == 'UNKNOWN'
