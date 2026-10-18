"""Normal planner -> AWS SDK collector -> engine for mapped customer policies."""
import json
import boto3
import pytest
from botocore.stub import Stubber
from peaso import engine
from peaso.collectors import aws
from peaso.checks.aws_all_policies import MODES


@pytest.mark.parametrize('action, expected', [('s3:GetObject', 'PASS'), ('*', 'FAIL')])
def test_normal_native_customer_policy_pipeline(monkeypatch, action, expected):
    account = '123456789012'
    region = 'us-east-1'
    arn = f'arn:aws:iam::{account}:policy/UnattachedCustomer'
    session = boto3.Session(aws_access_key_id='fixture', aws_secret_access_key='fixture', region_name=region)
    clients = {name: session.client(name) for name in ('sts', 'iam')}
    monkeypatch.setattr(aws, '_session', lambda auth, selected_region: (session, 'fixture'))
    monkeypatch.setattr(aws.Requests, 'client', lambda self, session, service, selected_region: clients[service])
    request = {'connector': {'provider': 'aws', 'scopes': [account + '/' + region],
        'auth': {}, 'options': {'service_concurrency': 1}}, 'checks': list(MODES)}
    assert engine.plan_collection(request) == ['iam_customer_policy']
    with Stubber(clients['sts']) as sts, Stubber(clients['iam']) as iam:
        sts.add_response('get_caller_identity', {'Account': account,
            'Arn': f'arn:aws:iam::{account}:user/Reader', 'UserId': 'READONLYFIXTURE'}, {})
        iam.add_response('list_policies', {'Policies': [{'Arn': arn, 'DefaultVersionId': 'v1',
            'AttachmentCount': 0}], 'IsTruncated': False}, {'Scope': 'Local', 'OnlyAttached': False})
        iam.add_response('get_policy_version', {'PolicyVersion': {'VersionId': 'v1',
            'IsDefaultVersion': True, 'Document': json.dumps({'Statement': [{'Effect': 'Allow',
                'Action': action, 'Resource': '*'}]})}}, {'PolicyArn': arn, 'VersionId': 'v1'})
        snapshot = engine.collect_snapshot(request)
        findings = engine.evaluate_snapshot(snapshot, checks=list(MODES))['findings']
        assert len(findings) == 6
        assert {finding['status'] for finding in findings} == {expected}
        sts.assert_no_pending_responses()
        iam.assert_no_pending_responses()
    envelope, = [row for row in snapshot['collections'] if row['type'] == 'iam_customer_policy']
    assert envelope['scope'] == account + '/global'
    assert envelope['status'] == 'collected'
    assert envelope['items'][0]['AttachmentCount'] == 0
    assert snapshot['metadata']['authorized_evidence_generation']['generation_requests'] == 0
