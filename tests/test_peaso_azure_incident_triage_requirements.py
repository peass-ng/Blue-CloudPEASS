"""Approved incident procedure input never supplies observed incident history."""
from copy import deepcopy
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso.server.validation import validate_connector
from peaso.checks import evaluate_check
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot

SCOPE = '/subscriptions/11111111-1111-1111-1111-111111111111'
CID = 'azure.other.incident_triage_trace'


def review():
    return {'status': 'collected', 'scope': SCOPE, 'incidentTriage': {
        'approvedTriageHours': 2, 'observationWindowHours': 48,
        'requiredResponseSteps': ['assess', 'contain']}}


def intake(policy, mode='cognito', provider='azure'):
    return validate_connector(provider, {'method': 'token', 'arm_token': 'inert'} if provider == 'azure' else {},
        {'compliance_policy': {'sw27': policy}}, SimpleNamespace(auth_mode=mode))


@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_approved_procedure_is_admitted_without_modifying_input(mode):
    value = review(); before = deepcopy(value)
    intake(value, mode)
    assert value == before


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mutation', ['bool_hours', 'zero_window', 'float_hours', 'huge_hours',
    'empty_steps', 'duplicate_step', 'control_character', 'observed_history', 'outcome',
    'unapproved', 'missing_scope', 'missing_field', 'top_history'])
def test_invalid_or_observed_procedure_input_is_rejected_before_any_cloud_call(mode, mutation):
    value = review(); criteria = value['incidentTriage']
    if mutation == 'bool_hours': criteria['approvedTriageHours'] = True
    elif mutation == 'zero_window': criteria['observationWindowHours'] = 0
    elif mutation == 'float_hours': criteria['approvedTriageHours'] = 2.0
    elif mutation == 'huge_hours': criteria['approvedTriageHours'] = 2 ** 40
    elif mutation == 'empty_steps': criteria['requiredResponseSteps'] = []
    elif mutation == 'duplicate_step': criteria['requiredResponseSteps'] = ['assess', 'assess']
    elif mutation == 'control_character': criteria['requiredResponseSteps'] = ['assess\n']
    elif mutation == 'observed_history': criteria['triageHistoryComplete'] = True
    elif mutation == 'outcome': criteria['outcome'] = 'PASS'
    elif mutation == 'unapproved': value['status'] = 'pending'
    elif mutation == 'missing_scope': value.pop('scope')
    elif mutation == 'missing_field': criteria.pop('observationWindowHours')
    else: value['triageHistory'] = []
    with pytest.raises(HTTPException) as error:
        intake(value, mode)
    assert error.value.status_code == 422


@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_incident_procedure_cannot_be_supplied_to_another_provider(mode):
    with pytest.raises(HTTPException) as error:
        intake(review(), mode, 'aws')
    assert error.value.status_code == 422


def incident_snapshot(policy, *, history=False):
    incident = {'id': SCOPE + '/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/w'
        '/providers/Microsoft.SecurityInsights/incidents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        'type': 'Microsoft.SecurityInsights/incidents',
        'properties': {'createdTimeUtc': '2026-10-12T10:00:00Z', 'status': 'Active', 'severity': 'High'}}
    if history:
        incident.update(triageHistoryComplete=True, triageHistory=[
            {'type': 'triage', 'at': '2026-10-12T10:30:00Z'},
            {'type': 'response', 'step': 'assess'}, {'type': 'response', 'step': 'contain'}],
            _coverage={'triageHistory': {'status': 'collected'}})
    return make_snapshot('azure', [SCOPE], [{'type': 'defender_incident', 'scope': SCOPE,
        'status': 'collected', 'items': [incident]}], created_at='2026-10-12T12:00:00Z',
        metadata={'compliance_policy': {'sw27': policy}})


@pytest.mark.parametrize('history,expected', [(False, 'UNKNOWN'), (True, 'PASS')])
def test_approved_procedure_does_not_substitute_for_observed_history(history, expected):
    value = review(); intake(value)
    findings = evaluate_snapshot(incident_snapshot(value, history=history), checks=[CID])['findings']
    assert findings and {finding['status'] for finding in findings} == {expected}


def test_explicit_foreign_approval_cannot_certify_an_incident_in_another_subscription():
    value = review(); value['scope'] = SCOPE.replace('11111111-', '22222222-', 1)
    intake(value)
    findings = evaluate_snapshot(incident_snapshot(value, history=True), checks=[CID])['findings']
    assert findings and {finding['status'] for finding in findings} == {'UNKNOWN'}


def test_existing_local_normative_baseline_can_coexist_with_triage_requirements():
    value = review(); value['expectedDiskVmIds'] = {}
    intake(value, 'local')
