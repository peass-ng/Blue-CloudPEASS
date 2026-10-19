"""Explicit native enum and SDK -> public collector -> sealed snapshot consumer."""
from copy import deepcopy
import importlib
import json

import pytest

from peaso import engine
from peaso.checks import Check
from peaso.checks import aws_cognito_rotation_review_20261019 as review
from peaso.collectors import aws
from peaso.snapshot import validate
from tests.test_peaso_collectors_aws import sdk

ACCOUNT, REGION, POOL, CLIENT = '123456789012', 'us-east-1', 'us-east-1_Example', 'exampleclient123'
SECRET = 'SyntheticClientSecretNeverPersist123456789'


@pytest.mark.parametrize('feature,status', [('ENABLED', 'PASS'), ('DISABLED', 'FAIL'),
    ('enabled', 'UNKNOWN'), ('FUTURE', 'UNKNOWN'), ('', 'UNKNOWN'), (None, 'UNKNOWN'),
    (False, 'UNKNOWN'), ({}, 'UNKNOWN')])
def test_exact_native_feature_enum(feature, status):
    item, index = review.fixture(feature)
    original = deepcopy((item, index))
    outcome, evidence = review.evaluate(item, index)
    assert outcome == status
    assert (item, index) == original
    assert len(evidence['observed']) <= 150


@pytest.mark.parametrize('grace,status', [(0, 'PASS'), (60, 'PASS'), (12, 'PASS'),
    (-1, 'UNKNOWN'), (61, 'UNKNOWN'), (True, 'UNKNOWN'), ('0', 'UNKNOWN'), (None, 'UNKNOWN')])
def test_optional_grace_validates_sdk_shape_without_policy_threshold(grace, status):
    item, index = review.fixture()
    item['ClientDetail']['UserPoolClient']['RefreshTokenRotation']['RetryGracePeriodSeconds'] = grace
    assert review.evaluate(item, index)[0] == status


@pytest.mark.parametrize('mutation', ['missing_object', 'missing_feature', 'not_object', 'detail_missing',
    'detail_denied', 'detail_partial', 'foreign_pool', 'foreign_client', 'foreign_account', 'foreign_region',
    'foreign_scope', 'foreign_provider', 'foreign_envelope_account', 'foreign_envelope_scope',
    'global_envelope', 'denied_feature_coverage', 'duplicate', 'unbound', 'bad_source', 'bad_read_only',
    'detail_error', 'empty_inventory', 'bad_id', 'bad_pool', 'bad_client'])
def test_missing_malformed_or_foreign_observation_never_passes(mutation):
    item, index = review.fixture()
    detail = item['ClientDetail']
    config = detail['UserPoolClient']
    envelope = index['collections'][review.KIND][0]
    if mutation == 'missing_object': config.pop('RefreshTokenRotation')
    elif mutation == 'missing_feature': config['RefreshTokenRotation'] = {}
    elif mutation == 'not_object': config['RefreshTokenRotation'] = []
    elif mutation == 'detail_missing': item.pop('ClientDetail')
    elif mutation == 'detail_denied': detail['collection_status'] = 'denied'
    elif mutation == 'detail_partial': detail['collection_status'] = 'partial'
    elif mutation == 'foreign_pool': config['UserPoolId'] = 'eu-west-1_Foreign'
    elif mutation == 'foreign_client': config['ClientId'] = 'foreignclient'
    elif mutation == 'foreign_account': item['AccountId'] = '999999999999'
    elif mutation == 'foreign_region': item['Region'] = 'eu-west-1'
    elif mutation == 'foreign_scope': index['context']['scope'] = '999999999999/' + REGION
    elif mutation == 'foreign_provider': index['context']['provider'] = 'azure'
    elif mutation == 'foreign_envelope_account': envelope['account_id'] = '999999999999'
    elif mutation == 'foreign_envelope_scope': envelope['scope'] = ACCOUNT + '/eu-west-1'
    elif mutation == 'global_envelope': envelope['global'] = True
    elif mutation == 'denied_feature_coverage': config['RefreshTokenRotation']['_coverage'] = {'Feature': {'status': 'denied'}}
    elif mutation == 'duplicate': envelope['items'].append(deepcopy(item))
    elif mutation == 'unbound': envelope['items'] = []
    elif mutation == 'bad_source': item['_provenance']['source_operation'] = 'external'
    elif mutation == 'bad_read_only': item['_provenance']['read_only'] = False
    elif mutation == 'detail_error': detail['error'] = {'code': 'AccessDeniedException'}
    elif mutation == 'empty_inventory': envelope['status'] = 'empty'
    elif mutation == 'bad_id': item['id'] = 'other'
    elif mutation == 'bad_pool': item['UserPoolId'] = 'malformed'
    else: item['ClientId'] = 'bad/id'
    assert review.evaluate(item, index)[0] == 'UNKNOWN', mutation


@pytest.mark.parametrize('status', ['partial', 'denied', 'not_collected', 'unknown', 'malformed'])
def test_incomplete_inventory_stays_unknown(status):
    item, index = review.fixture()
    index['collections'][review.KIND][0]['status'] = status
    assert review.evaluate(item, index)[0] == 'UNKNOWN'


def test_authentication_flows_and_token_lifetimes_are_not_rotation_evidence():
    item, index = review.fixture('DISABLED')
    config = item['ClientDetail']['UserPoolClient']
    config.update(ExplicitAuthFlows=['ALLOW_REFRESH_TOKEN_AUTH'], RefreshTokenValidity=1,
                  EnableTokenRevocation=True)
    assert review.evaluate(item, index)[0] == 'FAIL'
    config.pop('RefreshTokenRotation')
    assert review.evaluate(item, index)[0] == 'UNKNOWN'


def test_exports_have_no_registration_side_effects_and_no_invented_formal_links():
    before = {row.id for row in engine._registry()}
    importlib.reload(review)
    assert {row.id for row in engine._registry()} == before
    declaration, = review.DECLARATIONS
    admission, = review.ADMISSION_DATA['checks']
    assert len(admission['spec']) == 10 and len(admission['description']) == 5
    assert admission['requirements'] == []
    assert admission['dependencies'] == declaration['dependencies'] == [review.KIND]
    for name, status in [('pass', 'PASS'), ('fail', 'FAIL'), ('missing', 'UNKNOWN'), ('malformed', 'UNKNOWN')]:
        case = review.RUNTIME_CASES[review.CHECK_ID]
        assert review.evaluate(case[name], case.get(name + '_index', {}))[0] == status


@pytest.mark.parametrize('mode,expected', [('enabled', 'PASS'), ('disabled', 'FAIL'), ('omitted', 'UNKNOWN'),
    ('denied', 'UNKNOWN'), ('foreign', 'UNKNOWN')])
def test_sdk_public_collector_and_sealed_engine_consumer(sdk, monkeypatch, mode, expected):
    _session, add, _clients = sdk
    add('sts').add_response('get_caller_identity', {'Account': ACCOUNT,
        'Arn': f'arn:aws:iam::{ACCOUNT}:user/reviewer', 'UserId': 'AIDAREVIEWER'}, {})
    stub = add('cognito-idp')
    stub.add_response('list_user_pools', {'UserPools': [{'Id': POOL}]}, {'MaxResults': 60})
    stub.add_response('list_user_pool_clients', {'UserPoolClients': [{'UserPoolId': POOL, 'ClientId': CLIENT}]},
                      {'UserPoolId': POOL, 'MaxResults': 60})
    params = {'UserPoolId': POOL, 'ClientId': CLIENT}
    if mode == 'denied':
        stub.add_client_error('describe_user_pool_client', 'AccessDeniedException', expected_params=params)
    else:
        client = {'UserPoolId': POOL, 'ClientId': CLIENT, 'ClientSecret': SECRET}
        if mode != 'omitted':
            client['RefreshTokenRotation'] = {'Feature': 'DISABLED' if mode == 'disabled' else 'ENABLED'}
        if mode == 'foreign': client['UserPoolId'] = 'eu-west-1_Foreign'
        stub.add_response('describe_user_pool_client', {'UserPoolClient': client}, params)
    requests_used = []
    original_init = aws.Requests.__init__
    def capture_requests(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        requests_used.append(self)
    monkeypatch.setattr(aws.Requests, '__init__', capture_requests)
    snapshot = aws.collect({'provider': 'aws', 'scopes': [ACCOUNT], 'auth': {'profile': 'chosen'},
        'options': {'regions': [REGION], 'service_concurrency': 1, 'retry_attempts': 1}}, [review.KIND])
    assert validate(snapshot) == snapshot  # Public collector returns a sealed snapshot.
    declaration, = review.DECLARATIONS
    check = Check(review.CHECK_ID, 'aws', 'hardening', review.KIND, review.TITLE, 'medium',
                  declaration['control'], review.REMEDIATION, review.evaluate, 'resource', (review.KIND,))
    monkeypatch.setattr(engine, '_registry', lambda: [check])
    report = engine.evaluate_snapshot(snapshot, checks=[review.CHECK_ID])
    findings = [row for row in report['findings'] if row['check_id'] == review.CHECK_ID]
    assert len(findings) == 1 and findings[0]['status'] == expected, findings
    assert snapshot['metadata']['calls'] == 4
    for artifact in (snapshot, report):
        assert SECRET not in json.dumps(artifact, default=str)
    for requests in requests_used:
        for future in requests._cache.values():
            if future.exception() is None:
                assert SECRET not in json.dumps(future.result(), default=str)
    envelope = next(row for row in snapshot['collections'] if row['type'] == review.KIND)
    item = envelope['items'][0]
    if mode == 'enabled':
        assert item['ClientDetail']['UserPoolClient']['RefreshTokenRotation'] == {'Feature': 'ENABLED'}
        assert item['ClientDetail']['UserPoolClient']['ClientSecretPresent'] is True
    assert 'ClientSecret' not in item.get('ClientDetail', {}).get('UserPoolClient', {})
    stub.assert_no_pending_responses()


def test_installed_sdk_requires_feature_only_when_rotation_object_is_returned():
    from botocore.exceptions import ParamValidationError
    from botocore.session import Session
    from botocore.validate import validate_parameters
    shape = Session().get_service_model('cognito-idp').operation_model('DescribeUserPoolClient').output_shape
    client = {'UserPoolId': POOL, 'ClientId': CLIENT}
    validate_parameters({'UserPoolClient': client}, shape)
    client['RefreshTokenRotation'] = {'RetryGracePeriodSeconds': 0}
    with pytest.raises(ParamValidationError):
        validate_parameters({'UserPoolClient': client}, shape)
