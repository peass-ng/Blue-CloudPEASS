"""Environment-name controls need metadata, never cached credential values."""
import json

import pytest

from test_peaso_aws_bulk_inventory import sdk, REGION
from peaso.collectors import aws

PRIVATE = 'private-environment-value-must-not-enter-cache'


def cached(requests):
    return [future.result() for future in requests._cache.values()]


def test_lambda_configuration_values_removed_before_singleflight_cache(sdk):
    session, add = sdk
    stub = add('lambda')
    stub.add_response('get_function_configuration', {'FunctionName': 'f',
        'Environment': {'Variables': {'TOKEN': PRIVATE, 'STAGE': 'production'}}}, {'FunctionName': 'f'})
    requests = aws.Requests({})
    first = requests.call(session, 'lambda', REGION, 'get_function_configuration', FunctionName='f')
    again = requests.call(session, 'lambda', REGION, 'get_function_configuration', FunctionName='f')
    assert first == again and requests.calls == 1
    assert PRIVATE not in json.dumps(cached(requests))
    assert first['Environment']['Variables'] == {'TOKEN': None, 'STAGE': None}
    assert first['Environment']['_provenance']['values_omitted'] is True
    stub.assert_no_pending_responses()


def test_lambda_function_listing_projection_preserves_actual_pagination(sdk):
    session, add = sdk
    stub = add('lambda')
    stub.add_response('list_functions', {'Functions': [{'FunctionName': 'f',
        'Environment': {'Variables': {'TOKEN': PRIVATE}}}], 'NextMarker': 'second'}, {})
    stub.add_response('list_functions', {'Functions': [{'FunctionName': 'g'}]}, {'Marker': 'second'})
    requests = aws.Requests({})
    result = requests.pages(session, 'lambda', REGION, 'list_functions', 'Functions')
    assert result.status == 'collected'
    assert [row['FunctionName'] for row in result.items] == ['f', 'g']
    assert requests.calls == 2 and PRIVATE not in json.dumps(cached(requests))
    stub.assert_no_pending_responses()


@pytest.mark.parametrize('environment', [None, [], {'Variables': []}, {'Error': {'Message': PRIVATE}},
    {'Variables': {}, 'Error': {'Message': PRIVATE}}])
def test_unreadable_environment_cannot_become_zero_variables(environment):
    from peaso.collectors.aws_lambda_environment_metadata import project_response
    incoming = {'FunctionName': 'f', 'Environment': environment}
    response = project_response(incoming, 'get_function_configuration')
    assert response['Environment']['Error']
    assert 'Variables' not in response['Environment']
    assert PRIVATE not in json.dumps(response)


def test_projection_preserves_inputs_and_unrelated_configuration():
    from peaso.collectors.aws_lambda_environment_metadata import project_response
    original = {'FunctionName': 'f', 'KMSKeyArn': 'arn:kms:key',
                'Environment': {'Variables': {'TOKEN': PRIVATE}}}
    projected = project_response(original, 'get_function_configuration')
    assert projected['KMSKeyArn'] == original['KMSKeyArn']
    assert original['Environment']['Variables']['TOKEN'] == PRIVATE
    assert PRIVATE not in json.dumps(projected)


def test_native_environment_read_error_never_yields_false_empty_environment_pass(sdk):
    from peaso.checks import evaluate_check
    from peaso.collectors import aws_facts_compute_edge as edge, aws_facts_ext as ext
    session, add = sdk
    stub = add('lambda')
    stub.add_response('get_function_configuration', {'FunctionName': 'f', 'Environment': {
        'Variables': {}, 'Error': {'ErrorCode': 'KMSAccessDeniedException', 'Message': PRIVATE}}},
        {'FunctionName': 'f'})
    requests = aws.Requests({})
    item = {'FunctionName': 'f', 'FunctionArn': 'arn:aws:lambda:' + REGION + ':123456789012:function:f',
            'PackageType': 'Image'}
    counted, = edge.ENRICHERS['lambda_function'](requests, session, REGION, [item])
    named, = ext.ENRICHERS['lambda_function'](requests, session, REGION, [item])
    assert counted['Environment'] == {}
    assert evaluate_check('aws.c2b.lambda.env_vars_cmk', counted)[0] == 'UNKNOWN'
    assert named['EnvironmentVariableNames']['collection_status'] == 'not_collected'
    assert requests.calls == 1 and PRIVATE not in json.dumps(cached(requests))
    stub.assert_no_pending_responses()
