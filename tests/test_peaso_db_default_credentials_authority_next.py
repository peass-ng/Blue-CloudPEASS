"""Defensive authority boundaries for imported SQL default-credential evidence."""

from copy import deepcopy

import pytest

from peaso.checks import CHECKS


CHECK_ID = 'azure.other.database_default_login_restricted'
SUB = '/subscriptions/11111111-1111-1111-1111-111111111111'
SERVER = SUB + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sql'
OTHER_SUB = '/subscriptions/22222222-2222-2222-2222-222222222222'
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


@pytest.mark.parametrize('damage', [
    'foreign_assessment_scope', 'unapproved_baseline', 'foreign_test_server',
    'unapproved_test', 'unavailable_test_authorization',
])
def test_explicit_authority_contradictions_cannot_prove_denial(damage):
    row, index = _case()
    assessment = row['defaultCredentialAssessment']
    test = assessment['tests'][0]
    if damage == 'foreign_assessment_scope':
        assessment['scope'] = OTHER_SUB
    elif damage == 'unapproved_baseline':
        assessment['baseline']['approved'] = False
    elif damage == 'foreign_test_server':
        test['serverId'] = OTHER_SUB + '/resourceGroups/rg/providers/Microsoft.Sql/servers/sql'
    elif damage == 'unapproved_test':
        test['authorized'] = False
    else:
        test['_coverage'] = {'authorized': {'status': 'partial'}}
    original = deepcopy((row, index))
    assert _status(row, index) == 'UNKNOWN'
    assert (row, index) == original


def test_complete_existing_authorized_denials_still_pass():
    row, index = _case()
    assert _status(row, index) == 'PASS'
