"""An observed regional violation does not require a deployment/secret probe."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from peaso.collectors import azure, collect_live
from tests.archived_check_contract import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_bulk_native import Transport, SCOPE, SUB, BASE

CHECK = 'azure.other.region_allowlist'
RID = BASE + 'Microsoft.Compute/virtualMachines/vm'


def requirements():
    return {'approvedRegions': ['westeurope'], 'globalResourceTypes': [],
            'approvedZones': {'microsoft.compute/virtualmachines': ['1']}}


def snapshot(location='eastus', zones=None, evidence_status='not_collected', resource_status='collected'):
    row = {'id': RID, 'type': 'Microsoft.Compute/virtualMachines',
           'location': location, 'zones': ['1'] if zones is None else zones}
    proof = {'id': SCOPE + '/regionalControlEvidence/review', 'properties': {
        'disallowedDeploymentDenied': True, 'unauthorizedRegionSecretDenied': True,
        'euOperationsVerified': True}}
    return make_snapshot('azure', [SCOPE], [
        {'type': 'resource', 'scope': SCOPE, 'status': resource_status,
         'items': [row] if resource_status in ('collected', 'partial') else []},
        {'type': 'regional_control_evidence', 'scope': SCOPE, 'status': evidence_status,
         'items': [proof] if evidence_status == 'collected' else []},
    ], metadata={'compliance_policy': {'sw31': requirements()}})


def status(capture):
    rows = [f for f in evaluate_snapshot(capture, checks=[CHECK])['findings'] if f['check_id'] == CHECK]
    assert len(rows) == 1
    return rows[0]['status']


@pytest.mark.parametrize('evidence_status', ['not_collected', 'denied'])
@pytest.mark.parametrize('location,zones', [('eastus', ['1']), ('westeurope', ['2'])])
def test_confirmed_region_or_zone_violation_is_failure_without_probes(evidence_status, location, zones):
    assert status(snapshot(location, zones, evidence_status)) == 'FAIL'


@pytest.mark.parametrize('evidence_status,expected', [('not_collected', 'UNKNOWN'), ('denied', 'DENIED'), ('collected', 'PASS')])
def test_no_violation_never_waives_regional_controls(evidence_status, expected):
    assert status(snapshot('westeurope', evidence_status=evidence_status)) == expected


@pytest.mark.parametrize('resource_status', ['partial', 'denied', 'not_collected'])
def test_incomplete_resource_inventory_does_not_supply_a_conclusive_violation(resource_status):
    assert status(snapshot(resource_status=resource_status)) in {'UNKNOWN', 'DENIED'}


@pytest.mark.parametrize('mutation', ['empty_location', 'missing_location', 'foreign_id', 'type_identity', 'foreign_policy'])
def test_unresolved_location_or_identity_cannot_claim_a_violation(mutation):
    capture = snapshot()
    row = capture['collections'][0]['items'][0]
    if mutation == 'empty_location': row['location'] = ''
    if mutation == 'missing_location': del row['location']
    if mutation == 'foreign_id': row['id'] = RID.replace(SUB, '99999999-9999-9999-9999-999999999999')
    if mutation == 'type_identity': row['type'] = 'Microsoft.Storage/storageAccounts'
    if mutation == 'foreign_policy': capture['metadata']['compliance_policy']['sw31']['scope'] = '/subscriptions/foreign'
    capture = make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])
    assert status(capture) == 'UNKNOWN'


def test_actual_readonly_collector_to_engine_reveals_out_of_region_resource(monkeypatch):
    api = Transport({SCOPE + '/resources': {'value': [
        {'id': RID, 'type': 'Microsoft.Compute/virtualMachines', 'location': 'eastus', 'zones': ['1']}]}})
    original = azure.collect
    monkeypatch.setattr(azure, 'collect', lambda c, kinds: original(c, kinds, transport=api))
    connector = {'provider': 'azure', 'scopes': [SUB], 'options': {
        'retries': 0, 'compliance_policy': {'sw31': requirements()}}}
    capture = collect_live(connector, ['resource', 'regional_control_evidence'])
    assert status(capture) == 'FAIL'
    assert api.calls and all('/resources?' in url for url in api.calls)


@pytest.mark.parametrize('duplicate,expected', [(False, 'FAIL'), (True, 'UNKNOWN')])
def test_zone_policy_resource_type_casing_and_ambiguous_duplicates(duplicate, expected):
    capture = snapshot('westeurope', ['2'])
    zones = {'Microsoft.Compute/virtualMachines': ['1']}
    if duplicate:
        zones['microsoft.compute/virtualmachines'] = ['2']
    capture['metadata']['compliance_policy']['sw31']['approvedZones'] = zones
    capture = make_snapshot('azure', capture['scopes'], capture['collections'], metadata=capture['metadata'])
    assert status(capture) == expected


@pytest.mark.parametrize('mode', ['local', 'cognito'])
def test_normative_region_criteria_supported_at_normal_connector_intake(mode):
    from peaso.server.validation import validate_connector
    validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
                       {'compliance_policy': {'sw31': requirements()}}, SimpleNamespace(auth_mode=mode))


@pytest.mark.parametrize('field,value', [('regional_control_evidence', []), ('approvedRegions', []), ('approvedZones', {'microsoft.compute/virtualmachines': [True]})])
def test_intake_rejects_observation_injection_and_malformed_criteria(field, value):
    from fastapi import HTTPException
    from peaso.server.validation import validate_connector
    review = requirements()
    review[field] = deepcopy(value)
    with pytest.raises(HTTPException) as error:
        validate_connector('azure', {}, {'compliance_policy': {'sw31': review}}, SimpleNamespace(auth_mode='local'))
    assert error.value.status_code == 422


@pytest.mark.parametrize('mode', ['local', 'cognito'])
@pytest.mark.parametrize('mixed', [False, True])
def test_other_sw31_normative_requirements_remain_usable_with_region_policy(mode, mixed):
    from peaso.server.validation import validate_connector
    review = {'requiredBackupItemIds': [RID], 'minRetentionDays': 30}
    if mixed:
        review.update(requirements())
    validate_connector('azure', {'method': 'token', 'arm_token': 'inert'},
                       {'compliance_policy': {'sw31': review}}, SimpleNamespace(auth_mode=mode))
