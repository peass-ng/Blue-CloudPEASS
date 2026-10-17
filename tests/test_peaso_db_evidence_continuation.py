"""Inert imported evidence cannot establish a complete SQL endpoint inventory twice."""

from copy import deepcopy

import pytest

from peaso.checks import CHECKS


CHECK_ID = 'azure.other.database_default_login_restricted'
SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
SERVER = SUB + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sql'
ENDPOINT = 'sql.database.windows.net'


def _case():
    row = {'id': SERVER, 'defaultCredentialAssessment': {
        'status': 'collected',
        'authorization': {'approved': True, 'serverId': SERVER},
        'baseline': {'version': 'v1', 'credentialIds': ['default1']},
        'sqlCatalog': {'status': 'collected', 'loginNames': ['admin']},
        'endpointInventoryStatus': 'collected',
        'endpoints': [{'id': ENDPOINT, 'serverId': SERVER, 'authenticationPaths': ['sql-password']}],
        'testResultsStatus': 'collected',
        'tests': [{'endpointId': ENDPOINT, 'authenticationPath': 'sql-password',
                   'credentialId': 'default1', 'baselineVersion': 'v1', 'outcome': 'AccessDenied'}],
    }}
    wrapper = {'provider': 'azure', 'type': 'database_server', 'scope': SUB, 'data': row}
    index = {'context': {'provider': 'azure', 'scope': SUB},
             'collections': {'database_server': [{'type': 'database_server', 'scope': SUB,
                                                  'status': 'collected', 'items': [row]}]},
             'database_server': [wrapper]}
    return row, index


def _status(row, index):
    check = next(check for check in CHECKS if check.id == CHECK_ID)
    return check.evaluate(row, index)[0]


@pytest.mark.parametrize('duplicate_id', [ENDPOINT, ENDPOINT.upper()])
def test_duplicate_endpoint_identity_cannot_prove_denial(duplicate_id):
    row, index = _case()
    assessment = row['defaultCredentialAssessment']
    assessment['endpoints'].append({'id': duplicate_id, 'serverId': SERVER,
                                    'authenticationPaths': ['entra-proxy']})
    assessment['tests'].append({'endpointId': duplicate_id, 'authenticationPath': 'entra-proxy',
                                'credentialId': 'default1', 'baselineVersion': 'v1',
                                'outcome': 'AccessDenied'})
    original = deepcopy((row, index))
    assert _status(row, index) == 'UNKNOWN'
    assert (row, index) == original


def test_single_endpoint_complete_denials_still_pass():
    row, index = _case()
    assert _status(row, index) == 'PASS'


@pytest.mark.parametrize('identity', ['endpoint', 'baseline'])
def test_blank_evidence_identity_cannot_prove_denial(identity):
    row, index = _case()
    assessment = row['defaultCredentialAssessment']
    if identity == 'endpoint':
        assessment['endpoints'][0]['id'] = '  '
        assessment['tests'][0]['endpointId'] = '  '
    else:
        assessment['baseline']['version'] = '  '
        assessment['tests'][0]['baselineVersion'] = '  '
    original = deepcopy((row, index))
    assert _status(row, index) == 'UNKNOWN'
    assert (row, index) == original


@pytest.mark.parametrize('damage', [
    'unbound_test', 'contradictory_duplicate_test', 'untested_path',
    'duplicate_credential_identity', 'invalid_path_type', 'partial_outcome_coverage',
    'contradictory_tests_coverage',
])
def test_other_incomplete_or_contradictory_evidence_stays_unknown(damage):
    row, index = _case()
    assessment = row['defaultCredentialAssessment']
    if damage == 'unbound_test':
        extra = deepcopy(assessment['tests'][0])
        extra['endpointId'] = 'foreign.database.windows.net'
        assessment['tests'].append(extra)
    elif damage == 'contradictory_duplicate_test':
        extra = deepcopy(assessment['tests'][0])
        extra['outcome'] = 'Authenticated'
        assessment['tests'].append(extra)
    elif damage == 'untested_path':
        assessment['endpoints'][0]['authenticationPaths'].append('entra-proxy')
    elif damage == 'duplicate_credential_identity':
        assessment['baseline']['credentialIds'].append('DEFAULT1')
    elif damage == 'invalid_path_type':
        assessment['endpoints'][0]['authenticationPaths'] = ['sql-password', 7]
    elif damage == 'partial_outcome_coverage':
        assessment['tests'][0]['_coverage'] = {'outcome': {'status': 'partial'}}
    else:
        assessment['_coverage'] = {'tests': {'status': 'empty'}}
    original = deepcopy((row, index))
    assert _status(row, index) == 'UNKNOWN'
    assert (row, index) == original
