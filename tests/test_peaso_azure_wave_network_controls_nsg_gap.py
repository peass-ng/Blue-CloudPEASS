"""Executable current-behavior witness for the NSG service-name evidence gap."""
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_azure_nsg_direction_priority import SCOPE, NSG, PAIRS, native_nsg


def test_equal_unproven_service_strings_remain_unknown_snapshot():
    path_id = NSG + '/effectiveInternetPaths/tcp443'
    path = {'id': path_id, 'parent_id': NSG,
            'properties': {'protocol': 'Tcp', 'destinationPort': 443,
                           'worldSource': True, 'allowed': True}}
    measurement = {'id': path_id + '/measurement', 'path_id': path_id,
                   'parent_id': NSG, 'properties': {'protocol': 'Tcp', 'port': 443,
                   'measuredService': 'https', 'ianaAssignedService': 'https'}}
    assert '_provenance' not in measurement
    snapshot = make_snapshot('azure', [SCOPE], [
        {'type': 'nsg', 'scope': SCOPE, 'status': 'collected', 'items': [native_nsg()]},
        {'type': 'nsg_effective_internet_path', 'scope': SCOPE, 'status': 'collected', 'items': [path]},
        {'type': 'nsg_service_measurement', 'scope': SCOPE, 'status': 'collected', 'items': [measurement]},
    ], metadata={'compliance_policy': {'sw31': {'approvedInternetPorts': [443]}}})
    findings = [row for row in evaluate_snapshot(snapshot, checks=[PAIRS])['findings']
                if row['check_id'] == PAIRS]
    assert len(findings) == 1
    # Bare matching labels remain insufficient even when they match IANA.
    assert findings[0]['status'] == 'UNKNOWN'
