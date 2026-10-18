"""Successful Lambda signing reads may omit both response identity fields."""
from copy import deepcopy

from peaso.checks import CHECKS
from peaso.collectors import aws_facts_swc

CHECK = next(check for check in CHECKS if check.id == 'aws_lambda_code_signing_configured')
SCOPE = '111111111111/us-east-1'
ARN = 'arn:aws:lambda:us-east-1:111111111111:function:sample'
BASE = {'FunctionName': 'sample', 'FunctionArn': ARN,
        'Configuration': {'State': 'Active'}}


def evaluate(row):
    index = {'context': {'provider': 'aws', 'scope': SCOPE},
             'collections': {'lambda_function': [{'type': 'lambda_function',
                'scope': SCOPE, 'status': 'collected', 'items': [row]}]},
             'lambda_function': [{'type': 'lambda_function', 'scope': SCOPE,
                                  'data': row}]}
    return CHECK.evaluate(row, index)[0]


def collected(response):
    class Stub:
        def detail(self, _session, service, region, operation, **kwargs):
            assert (service, region, operation, kwargs['FunctionName']) == (
                'lambda', 'us-east-1', 'get_function_code_signing_config', 'sample')
            return deepcopy(response)
    return aws_facts_swc._lambda(Stub(), object(), 'us-east-1', [BASE])[0]


def test_successful_no_attachment_uses_request_binding():
    row = collected({'collection_status': 'collected'})
    assert row['CodeSigning']['CodeSigningConfigArn'] == ''
    assert 'FunctionName' not in row['CodeSigning']
    assert 'FunctionArn' not in row['CodeSigning']
    assert evaluate(row) == 'FAIL'
    missing = deepcopy(row)
    del missing['CodeSigning']['_request']
    assert evaluate(missing) == 'UNKNOWN'
    tampered = deepcopy(row)
    tampered['CodeSigning']['_request']['FunctionName'] = 'other'
    assert evaluate(tampered) == 'UNKNOWN'


def test_foreign_response_identity_and_denied_read_remain_unknown():
    foreign_name = collected({'collection_status': 'collected',
                              'FunctionName': 'other'})
    assert evaluate(foreign_name) == 'UNKNOWN'
    foreign_arn = collected({'collection_status': 'collected',
                             'FunctionArn': ARN.replace(':sample', ':other')})
    assert evaluate(foreign_arn) == 'UNKNOWN'
    denied = collected({'collection_status': 'denied',
                        'error': {'code': 'AccessDeniedException'}})
    assert '_request' not in denied['CodeSigning']
    assert evaluate(denied) == 'UNKNOWN'
