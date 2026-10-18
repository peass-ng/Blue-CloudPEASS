"""Lambda signing omission through pinned SDK, native collector, and engine."""
from __future__ import annotations

from copy import deepcopy

import boto3
import pytest
from botocore.stub import Stubber

from peaso.collectors import aws
from peaso.engine import evaluate_snapshot

ACCOUNT = '123456789012'
REGION = 'us-east-1'
SCOPE = f'{ACCOUNT}/{REGION}'
NAME = 'sample'
ARN = f'arn:aws:lambda:{REGION}:{ACCOUNT}:function:{NAME}'
CID = 'aws_lambda_code_signing_configured'


class SigningOmissionStubber(Stubber):
    """The pinned SDK model requires fields omitted by real unattached reads."""

    def _validate_operation_response(self, operation_name, service_response):
        if operation_name == 'GetFunctionCodeSigningConfig':
            return
        return super()._validate_operation_response(operation_name, service_response)


def status(snapshot):
    row = collection(snapshot)['items'][0]
    target = row.get('id', row['FunctionArn'])
    all_rows = evaluate_snapshot(snapshot, checks=[CID])['findings']
    rows = [f for f in all_rows
            if f['check_id'] == CID and f.get('native_resource_id') == target]
    assert len(rows) == 1, [(f['check_id'], f['status'], f.get('native_resource_id')) for f in all_rows]
    return rows[0]['status']


def collection(snapshot):
    rows = [c for c in snapshot['collections']
            if c['type'] == 'lambda_function' and c['scope'] == SCOPE]
    assert len(rows) == 1 and len(rows[0]['items']) == 1
    return rows[0]


def collect(monkeypatch, response=None, *, error=None, state='Active', package='Zip'):
    session = boto3.Session(aws_access_key_id='INERT', aws_secret_access_key='INERT', region_name=REGION)
    sts, lam = session.client('sts'), session.client('lambda')
    with Stubber(sts) as sts_stub, SigningOmissionStubber(lam) as lam_stub:
        sts_stub.add_response('get_caller_identity', {'Account': ACCOUNT,
            'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
        lam_stub.add_response('list_functions', {'Functions': [
            {'FunctionName': NAME, 'FunctionArn': ARN, 'State': state, 'PackageType': package}]}, {})
        lam_stub.add_client_error('get_policy', 'ResourceNotFoundException',
                                  expected_params={'FunctionName': NAME})
        lam_stub.add_client_error('get_function_url_config', 'ResourceNotFoundException',
                                  expected_params={'FunctionName': NAME})
        lam_stub.add_response('get_function_concurrency', {}, {'FunctionName': NAME})
        lam_stub.add_response('get_function_configuration', {
            'FunctionName': NAME, 'FunctionArn': ARN, 'State': state, 'PackageType': package},
            {'FunctionName': NAME})
        if error:
            lam_stub.add_client_error('get_function_code_signing_config', error,
                                      expected_params={'FunctionName': NAME})
        else:
            lam_stub.add_response('get_function_code_signing_config',
                                  response if response is not None else {},
                                  {'FunctionName': NAME})
        if package != 'Image':
            lam_stub.add_response('get_runtime_management_config',
                {'UpdateRuntimeOn': 'Auto'}, {'FunctionName': NAME})
        clients = {('sts', REGION): sts, ('lambda', REGION): lam}
        monkeypatch.setattr(aws, '_session', lambda auth, region: (session, 'fixture'))
        monkeypatch.setattr(aws.Requests, 'client',
                            lambda self, _session, service, region: clients[(service, region)])
        snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT],
            'auth': {'profile': 'fixture'}, 'options': {'regions': [REGION],
            'service_concurrency': 1, 'scope_concurrency': 1}}, ['lambda_function'])
        sts_stub.assert_no_pending_responses()
        lam_stub.assert_no_pending_responses()
    return snapshot


def test_sdk_omission_full_native_pipeline(monkeypatch):
    snapshot = collect(monkeypatch)
    assert collection(snapshot)['status'] == 'collected'
    row = collection(snapshot)['items'][0]
    assert row['Configuration']['State'] == 'Active'
    assert row['PackageType'] == row['Configuration']['PackageType'] == 'Zip'
    assert row['CodeSigning']['collection_status'] == 'collected'
    assert row['CodeSigning']['CodeSigningConfigArn'] == ''
    assert 'FunctionName' not in row['CodeSigning']
    assert 'FunctionArn' not in row['CodeSigning']
    assert row['CodeSigning']['_request'] == {
        'operation': 'get_function_code_signing_config', 'FunctionName': NAME}
    assert status(snapshot) == 'FAIL'


@pytest.mark.parametrize('response', [
    {'FunctionName': 'foreign'},
    {'FunctionArn': ARN.replace(':sample', ':foreign')},
    {'FunctionName': NAME, 'FunctionArn': ARN.replace(':sample', ':foreign')},
])
def test_returned_identity_conflicts_stay_unknown(monkeypatch, response):
    assert status(collect(monkeypatch, response)) == 'UNKNOWN'


def test_denied_and_unbound_details_stay_unknown(monkeypatch):
    denied = collect(monkeypatch, error='AccessDeniedException')
    assert '_request' not in collection(denied)['items'][0]['CodeSigning']
    assert status(denied) == 'UNKNOWN'
    snapshot = collect(monkeypatch)
    signing = collection(snapshot)['items'][0]['CodeSigning']
    signing.pop('_request')
    snapshot.pop('snapshot_id', None)
    assert status(snapshot) == 'UNKNOWN'
    signing['_request'] = {'operation': 'get_function_code_signing_config', 'FunctionName': 'foreign'}
    assert status(snapshot) == 'UNKNOWN'
    signing['_request'] = {'operation': 'get_function_code_signing_config', 'FunctionName': NAME}
    signing['collection_status'] = 'malformed'
    assert status(snapshot) == 'UNKNOWN'


def test_inventory_and_scope_guards(monkeypatch):
    snapshot = collect(monkeypatch)
    partial = deepcopy(snapshot)
    collection(partial)['status'] = 'partial'
    partial.pop('snapshot_id', None)
    assert status(partial) == 'UNKNOWN'
    wrong = deepcopy(snapshot)
    collection(wrong)['items'][0]['FunctionArn'] = ARN.replace(f':{ACCOUNT}:', ':999999999999:')
    wrong.pop('snapshot_id', None)
    assert status(wrong) == 'UNKNOWN'


def test_inactive_and_container_applicability(monkeypatch):
    assert status(collect(monkeypatch, state='Inactive')) == 'NOT_APPLICABLE'
    assert status(collect(monkeypatch, package='Image')) == 'NOT_APPLICABLE'
    conflicting = collect(monkeypatch, package='Image')
    collection(conflicting)['items'][0]['Configuration']['PackageType'] = 'Zip'
    conflicting.pop('snapshot_id', None)
    assert status(conflicting) == 'UNKNOWN'


def test_native_configuration_package_type_is_used_when_list_member_absent(monkeypatch):
    snapshot = collect(monkeypatch, package='Image')
    collection(snapshot)['items'][0].pop('PackageType')
    snapshot.pop('snapshot_id', None)
    assert status(snapshot) == 'NOT_APPLICABLE'
