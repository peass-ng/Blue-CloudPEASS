"""Offline evaluation enforces the same zone criteria as normal intake."""
import pytest
from test_peaso_azure_region_counterexample import snapshot, status
from peaso.snapshot import make_snapshot


def evaluated(capture):
    return status(make_snapshot(
        "azure", capture["scopes"], capture["collections"], metadata=capture["metadata"]))


@pytest.mark.parametrize('values', [[True], ['1', '1'], ['0'], ['west']])
def test_malformed_approved_zones_cannot_pass_zoneless_resource(values):
    capture = snapshot('westeurope', zones=[], evidence_status='collected')
    capture['metadata']['compliance_policy']['sw31']['approvedZones'] = {
        'microsoft.compute/virtualmachines': values}
    assert evaluated(capture) == 'UNKNOWN'


def test_unused_invalid_zone_criteria_are_not_accepted_as_valid_policy():
    capture = snapshot('westeurope', evidence_status='collected')
    capture['metadata']['compliance_policy']['sw31']['approvedZones'][
        'microsoft.storage/storageaccounts'] = [False]
    assert evaluated(capture) == 'UNKNOWN'


def test_explicit_valid_empty_zone_criteria_allow_non_zonal_resource():
    capture = snapshot('westeurope', zones=[], evidence_status='collected')
    capture['metadata']['compliance_policy']['sw31']['approvedZones'] = {
        'Microsoft.Compute/virtualMachines': []}
    assert evaluated(capture) == 'PASS'


@pytest.mark.parametrize('zones', [['0'], ['west'], ['1', '1']])
def test_malformed_measured_zone_values_never_claim_compliance(zones):
    capture = snapshot('westeurope', zones=zones, evidence_status='collected')
    assert status(capture) == 'UNKNOWN'
