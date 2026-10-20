"""Defender's unassessed/disabled result is not a healthy recommendation."""
from copy import deepcopy
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES

IDS = tuple(sorted(c.id for c in CHECKS if c.id.startswith("azure.claude.defender_assessment_")))
SUB = "11111111-2222-3333-4444-555555555555"
SCOPE = "/subscriptions/" + SUB


def selected(check_id, statuses):
    names = [r['data']['properties']['displayName'] for r in CASES[check_id]['pass_index']['security_assessment']]
    rows = []
    for number, status in enumerate(statuses):
        name = names[number % len(names)]
        vm = SCOPE + '/resourceGroups/review/providers/Microsoft.Compute/virtualMachines/vm' + str(number)
        key = '00000000-0000-4000-8000-' + str(number).zfill(12)
        state = {} if status == 'missing_status' else {'code': status}
        if status == 'OffByPolicy': state = {'code': 'NotApplicable', 'cause': 'OffByPolicy'}
        row = {'id': vm + '/providers/Microsoft.Security/assessments/' + key,
               'name': key, 'type': 'Microsoft.Security/assessments',
               'properties': {'displayName': name, 'resourceDetails': {'source': 'Azure', 'id': vm}, 'status': state}}
        rows.append({'data': row})
    # Repeat the state matrix for every named prerequisite in a multi-assessment
    # check, without deriving the expected verdict from implementation output.
    if len(names) > 1 and statuses:
        for number, name in enumerate(names[1:], len(rows)):
            row = deepcopy(rows[0]); row['data']['properties']['displayName'] = name
            row['data']['id'] = row['data']['id'][:-12] + str(number).zfill(12)
            row['data']['name'] = row['data']['name'][:-12] + str(number).zfill(12)
            rows.append(row)
    index = {'context': {'provider': 'azure', 'scope': SCOPE},
             'collections': {'security_assessment': [{'scope': SCOPE, 'status': 'collected' if rows else 'empty'}]},
             'security_assessment': rows}
    return {'scope': SCOPE}, index


@pytest.mark.parametrize('check_id', IDS)
@pytest.mark.parametrize('states, expected', [
    (['Healthy'], 'PASS'), (['Unhealthy'], 'FAIL'),
    (['NotApplicable'], 'UNKNOWN'), (['OffByPolicy'], 'UNKNOWN'),
    ([], 'UNKNOWN'), (['Healthy', 'NotApplicable'], 'UNKNOWN'),
    (['missing_status'], 'UNKNOWN'), (['Unrecognized'], 'UNKNOWN'),
    (['Unhealthy', 'NotApplicable'], 'FAIL'),
])
def test_actual_native_assessment_states(check_id, states, expected):
    check = next(c for c in CHECKS if c.id == check_id)
    item, index = selected(check_id, states)
    assert check.evaluate(item, index)[0] == expected


@pytest.mark.parametrize('check_id', IDS)
def test_non_subscription_anchor_remains_inapplicable(check_id):
    check = next(c for c in CHECKS if c.id == check_id)
    item, index = selected(check_id, ['Healthy'])
    item['scope'] = '/providers/Microsoft.Management/managementGroups/review'
    assert check.evaluate(item, index)[0] == 'NOT_APPLICABLE'


def test_measured_unhealthy_assessment_survives_another_missing_name():
    cid = 'azure.claude.defender_assessment_system_updates'
    check = next(c for c in CHECKS if c.id == cid)
    item, index = selected(cid, ['Unhealthy'])
    index['security_assessment'] = index['security_assessment'][:1]
    assert check.evaluate(item, index)[0] == 'FAIL'
