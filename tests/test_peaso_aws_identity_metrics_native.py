"""SDK-native IAM attachments and own-account CloudWatch metric metadata."""
from __future__ import annotations

import copy
import json

import pytest
from test_peaso_aws_bulk_inventory import sdk, ACCOUNT
from peaso.collectors import aws, aws_identity_metrics_native as native
from peaso.collectors.bulk_evidence import collect
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

REGION = 'eu-west-1'
SCOPE = ACCOUNT + '/' + REGION
POLICY = 'arn:aws:iam::aws:policy/SecurityAudit'
CHECK = 'aws.pci.iam.policy_arn_attachment'


def iam_response():
    return {'IsTruncated': False,
        'UserDetailList': [{'UserName': 'reviewer', 'UserId': 'AIDAREVIEWER0000000000', 'Path': '/',
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'CreateDate': '2026-10-01T00:00:00Z',
            'AttachedManagedPolicies': [{'PolicyArn': POLICY, 'PolicyName': 'SecurityAudit'}]}],
        'GroupDetailList': [], 'RoleDetailList': []}


def identity_decision(read, policy=POLICY):
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'iam_identity', 'scope': ACCOUNT + '/global',
        'account_id': ACCOUNT, 'global': True, 'status': read.status,
        'items': [{**row, 'AccountId': ACCOUNT, 'id': row['Arn']} for row in read.items]}])
    from types import SimpleNamespace
    module = SimpleNamespace(AWS_TYPES={'iam_identity'}, collect=lambda connector, requirements: snapshot)
    wrapped = collect(module, {'provider': 'aws', 'options': {'compliance_parameters': {'required_policy_arn': policy}}}, ['iam_identity'])
    findings = evaluate_snapshot(wrapped, checks=[CHECK])['findings']
    return [row['status'] for row in findings]


@pytest.mark.parametrize('mode', ['complete', 'missing_attachment', 'denied', 'foreign_user', 'foreign_policy',
                                   'wrong_kind', 'duplicate_policy', 'truncated', 'empty_first_page'])
def test_iam_attachment_inventory_and_global_real_check(sdk, mode):
    session, add = sdk
    stub = add('iam')
    response = iam_response()
    user = response['UserDetailList'][0]
    if mode == 'missing_attachment': user.pop('AttachedManagedPolicies')
    if mode == 'foreign_user': user['Arn'] = user['Arn'].replace(ACCOUNT, '999999999999')
    if mode == 'foreign_policy': user['AttachedManagedPolicies'][0]['PolicyArn'] = POLICY.replace('::aws:', '::999999999999:')
    if mode == 'wrong_kind': user['Arn'] = user['Arn'].replace(':user/', ':role/')
    if mode == 'duplicate_policy': user['AttachedManagedPolicies'] *= 2
    if mode == 'denied':
        stub.add_client_error('get_account_authorization_details', 'AccessDenied', expected_params={'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000})
    elif mode in ('truncated', 'empty_first_page'):
        first = {'IsTruncated': True, 'Marker': 'next', 'UserDetailList': [], 'GroupDetailList': [], 'RoleDetailList': []}
        stub.add_response('get_account_authorization_details', first, {'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000})
        if mode == 'empty_first_page':
            stub.add_response('get_account_authorization_details', response, {'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000, 'Marker': 'next'})
    else:
        stub.add_response('get_account_authorization_details', response, {'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000})
    read = native.identities(aws.Requests({'retry_attempts': 1, **({'max_pages': 1} if mode == 'truncated' else {})}),
                              session, REGION, ACCOUNT)
    if mode in ('complete', 'empty_first_page'):
        assert read.status == 'collected'
        assert identity_decision(read) == ['PASS']
    elif mode == 'missing_attachment':
        assert read.status == 'collected' and identity_decision(read) == ['FAIL']
    else:
        assert read.status not in ('collected', 'empty')
        assert not any(value in ('PASS', 'NOT_APPLICABLE') for value in identity_decision(read))
    stub.assert_no_pending_responses()


def test_complete_iam_collector_no_usage_report_generation_and_global_managed_policy(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    iam = add('iam')
    iam.add_response('get_account_authorization_details', iam_response(), {'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000})
    snapshot = collect(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1,
        'compliance_parameters': {'required_policy_arn': POLICY}}}, ['iam_identity'])
    assert evaluate_snapshot(snapshot, checks=[CHECK])['findings'][0]['status'] == 'PASS'
    assert snapshot['metadata']['calls'] == 2
    assert snapshot['metadata']['authorized_evidence_generation']['service_last_accessed_generation_requests'] == 0
    iam.assert_no_pending_responses()
    sts.assert_no_pending_responses()


def metric():
    return {'Namespace': 'Security/ECR', 'MetricName': 'ScanFindings',
            'Dimensions': [{'Name': 'Repository', 'Value': 'production'}]}


@pytest.mark.parametrize('mode', ['complete', 'empty', 'denied', 'paginated', 'truncated', 'duplicate', 'duplicate_dimensions'])
def test_metrics_are_own_account_complete_and_have_stable_native_ids(sdk, mode):
    session, add = sdk
    stub = add('cloudwatch')
    item = metric()
    if mode == 'duplicate_dimensions': item['Dimensions'] *= 2
    args = {'IncludeLinkedAccounts': False}
    if mode == 'denied':
        stub.add_client_error('list_metrics', 'AccessDenied', expected_params=args)
    else:
        response = {'Metrics': [] if mode == 'empty' else [item] * (2 if mode == 'duplicate' else 1)}
        if mode in ('paginated', 'truncated'): response['NextToken'] = 'next'
        stub.add_response('list_metrics', response, args)
        if mode == 'paginated':
            stub.add_response('list_metrics', {'Metrics': []}, {**args, 'NextToken': 'next'})
    read = native.metrics(aws.Requests({'retry_attempts': 1, **({'max_pages': 1} if mode == 'truncated' else {})}),
                          session, REGION, ACCOUNT)
    if mode in ('complete', 'paginated'):
        assert read.status == 'collected'
        assert read.items[0]['id'].startswith('cloudwatch-metric:')
        assert read.items[0]['_provenance']['include_linked_accounts'] is False
    elif mode == 'empty':
        assert read.status == 'empty'
    else:
        assert read.status not in ('collected', 'empty')
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('present,expected', [(True, 'PASS'), (False, 'FAIL')])
def test_native_metric_metadata_drives_published_ecr_export_check(sdk, present, expected):
    session, add = sdk
    stub = add('cloudwatch')
    stub.add_response('list_metrics', {'Metrics': [metric()] if present else []}, {'IncludeLinkedAccounts': False})
    read = native.metrics(aws.Requests({}), session, REGION, ACCOUNT)
    target = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:ingest'
    rule = {'Arn': f'arn:aws:events:{REGION}:{ACCOUNT}:rule/ecr', 'State': 'ENABLED', 'EventBusName': 'default',
            'EventPattern': json.dumps({'source': ['aws.ecr'], 'detail-type': ['ECR Image Scan']}),
            'Targets': {'collection_status': 'collected', 'items': [{'Arn': target}]}}
    snapshot = make_snapshot('aws', [SCOPE], [{'type': 'cloudwatch_metric', 'scope': SCOPE,
        'status': read.status, 'items': read.items}, {'type': 'event_rule', 'scope': SCOPE,
        'status': 'collected', 'items': [rule]}])
    from types import SimpleNamespace
    module = SimpleNamespace(AWS_TYPES={'event_rule', 'cloudwatch_metric'}, collect=lambda connector, requirements: snapshot)
    snapshot = collect(module, {'provider': 'aws', 'options': {'compliance_parameters': {
        'metric_ingestion_target_arn': target, 'ecr_scan_metric_namespace': 'Security/ECR',
        'ecr_scan_metric_name': 'ScanFindings'}}}, ['event_rule', 'cloudwatch_metric'])
    findings = evaluate_snapshot(snapshot, checks=['aws_ecr_scan_findings_metric_export'])['findings']
    assert len(findings) == 1
    assert findings[0]['status'] == expected, findings[0]['evidence']
    stub.assert_no_pending_responses()


def test_full_native_metric_and_eventbridge_collection_drives_export_check(sdk, monkeypatch):
    session, add = sdk
    monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'test-pinned'))
    sts = add('sts')
    sts.add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/auditor', 'UserId': 'reviewer'}, {})
    metrics = add('cloudwatch')
    metrics.add_response('list_metrics', {'Metrics': [metric()]}, {'IncludeLinkedAccounts': False})
    events = add('events')
    target = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:ingest'
    events.add_response('list_rules', {'Rules': [{'Name': 'ecr', 'Arn': f'arn:aws:events:{REGION}:{ACCOUNT}:rule/ecr',
        'State': 'ENABLED', 'EventPattern': json.dumps({'source': ['aws.ecr'], 'detail-type': ['ECR Image Scan']})}]},
        {'EventBusName': 'default'})
    events.add_response('list_targets_by_rule', {'Targets': [{'Id': 'ingestion', 'Arn': target}]},
                        {'Rule': 'ecr', 'EventBusName': 'default'})
    snapshot = collect(aws, {'provider': 'aws', 'scopes': [SCOPE], 'options': {'service_concurrency': 1,
        'compliance_parameters': {'metric_ingestion_target_arn': target,
            'ecr_scan_metric_namespace': 'Security/ECR', 'ecr_scan_metric_name': 'ScanFindings'}}},
        ['event_rule', 'cloudwatch_metric'])
    finding, = evaluate_snapshot(snapshot, checks=['aws_ecr_scan_findings_metric_export'])['findings']
    assert finding['status'] == 'PASS', finding['evidence']
    assert snapshot['metadata']['calls'] == 4
    metrics.assert_no_pending_responses()
    events.assert_no_pending_responses()
    sts.assert_no_pending_responses()


@pytest.mark.parametrize('policy', ['arn:aws:iam::999999999999:policy/SecurityAudit', 'arn:aws-cn:iam::aws:policy/SecurityAudit'])
def test_foreign_approved_iam_policy_is_unknown(sdk, policy):
    session, add = sdk
    stub = add('iam')
    stub.add_response('get_account_authorization_details', iam_response(), {'Filter': ['User', 'Group', 'Role'], 'MaxItems': 1000})
    read = native.identities(aws.Requests({}), session, REGION, ACCOUNT)
    assert identity_decision(read, policy) == ['UNKNOWN']
    stub.assert_no_pending_responses()
