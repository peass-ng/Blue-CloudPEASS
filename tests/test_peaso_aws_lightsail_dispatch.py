"""Public collector boundary: normative input + native IAM + frozen evaluator."""
import copy
import json
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
import boto3
from botocore.stub import Stubber
import pytest
from peaso.collectors import aws, collect_live
from peaso.engine import evaluate_snapshot
from peaso.aws_lightsail_owner_policy import NAMESPACE, owner_metadata
from tests import test_peaso_aws_lightsail_iam_native as fixture


@pytest.mark.parametrize('requirements', [[fixture.CHECK], ['lightsail_iam_policy_attachment'], ['lightsail_bucket', 'lightsail_iam_policy_attachment']])
@pytest.mark.parametrize('mode,expected', [('inline', 'PASS'), ('wider', 'FAIL'), ('condition', 'UNKNOWN'), ('stale', 'UNKNOWN'), ('absent', 'UNKNOWN')])
def test_public_lightsail_dispatch(monkeypatch, requirements, mode, expected):
    if requirements == [fixture.CHECK]:
        from peaso.engine import plan_collection
        requirements = plan_collection({'provider': 'aws', 'checks': [fixture.CHECK], 'connector': {'provider': 'aws', 'scopes': [fixture.SCOPE], 'options': {}}})
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT', region_name=fixture.REGION)
    approved = {'status': 'collected', 'scope': fixture.SCOPE, 'observed_at': datetime.now(timezone.utc).isoformat(),
                'max_age_seconds': 86400, 'parameters': {
                    'iam_required_lightsail_bucket_arns': [fixture.ARN],
                    'approved_lightsail_principals': [fixture.ROLE],
                    'approved_lightsail_actions': ['lightsail:UpdateBucket']}}
    if mode == 'stale':
        approved['observed_at'] = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    options = {'retry_attempts': 1, 'service_concurrency': 1,
               'compliance_parameters': {NAMESPACE: approved}}
    if mode == 'absent':
        options.pop('compliance_parameters')
    original = copy.deepcopy(options)
    clients = {s: session.client(s, region_name=fixture.REGION) for s in ('sts', 'iam', 'lightsail')}
    monkeypatch.setattr(session, 'client', lambda service, **kw: clients[service])
    monkeypatch.setattr(aws, '_session', lambda *args, **kw: (session, 'inert_stub_fixture'))
    calls = []
    original_call = aws.Requests.call
    def call(requests, session, service, region, operation, **kwargs):
        calls.append((service, operation))
        return original_call(requests, session, service, region, operation, **kwargs)
    monkeypatch.setattr(aws.Requests, 'call', call)
    with ExitStack() as stack:
        stubs = {s: stack.enter_context(Stubber(c)) for s, c in clients.items()}
        stubs['sts'].add_response('get_caller_identity', {'Account': fixture.ACCOUNT, 'Arn': fixture.ROLE, 'UserId': 'INERT'}, {})
        stubs['lightsail'].add_response('get_buckets', {'buckets': [{'name': 'owned-bucket', 'arn': fixture.ARN,
            'resourceType': 'Bucket', 'location': {'regionName': fixture.REGION}}]}, {})
        if mode not in ('stale', 'absent'):
            stubs['iam'].add_response('get_account_authorization_details', fixture.response(mode), {})
        snapshot = collect_live({'provider': 'aws', 'scopes': [fixture.SCOPE], 'auth': {}, 'options': options}, requirements)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
    collections = {c['type']: c for c in snapshot['collections'] if c['scope'] == fixture.SCOPE}
    assert collections['lightsail_bucket']['status'] == 'collected'
    assert collections['lightsail_iam_policy_attachment']['status'] == ('not_collected' if mode in ('stale', 'absent', 'condition') else 'collected'), collections['lightsail_iam_policy_attachment']
    expected_calls = {('sts', 'get_caller_identity'), ('lightsail', 'get_buckets')}
    if mode not in ('stale', 'absent'):
        expected_calls.add(('iam', 'get_account_authorization_details'))
    assert set(calls) == expected_calls
    # Four IAM projections call the same native-response cache; only one SDK request.
    assert len(calls) == (2 if mode in ('stale', 'absent') else 6)
    assert snapshot['metadata']['calls'] == len(expected_calls)
    assert options == original
    if mode != 'absent':
        policy = snapshot['metadata']['compliance_policy']
        assert policy == owner_metadata(approved, snapshot['created_at'])
        assert policy['observed_at'] == approved['observed_at']
    assert 'get_bucket_access_keys' not in str(calls)
    assert 'native_evidence_projection_unavailable' not in json.dumps(collections['lightsail_iam_policy_attachment'])
    findings = evaluate_snapshot(snapshot, checks=[fixture.CHECK], include_not_applicable=True)['findings']
    assert len(findings) == 1 and findings[0]['status'] == expected
