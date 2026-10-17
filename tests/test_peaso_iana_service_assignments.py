"""Focused registry binding of externally supplied NSG service measurements."""
from copy import deepcopy

from peaso.checks import evaluate_check

CHECK = 'azure.other.nsg_port_protocol_assignment'
SCOPE = '/subscriptions/iana-regression'
NSG = SCOPE + '/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/n'
SOURCE_SHA = 'b6afeefdc6b2c616f9a515d57819a558ebe33250b59b2700b3afc4a4ba1923f2'


def evaluate(protocol='Tcp', port=443, measured='https', claim='https', *, measurement=True):
    path = NSG + f'/effectiveInternetPaths/{protocol.lower()}{port}'
    rows = {
        'nsg': [{'id': NSG, 'properties': {'securityRules': [], 'defaultSecurityRules': []}}],
        'nsg_effective_internet_path': [{'id': path, 'parent_id': NSG,
            'properties': {'protocol': protocol, 'destinationPort': port, 'worldSource': True, 'allowed': True}}],
        'nsg_service_measurement': ([{'id': path + '/measurement', 'path_id': path, 'parent_id': NSG,
            'properties': {'protocol': protocol, 'port': port,
                           'measuredService': measured, 'ianaAssignedService': claim}}] if measurement else []),
    }
    index = {'context': {'provider': 'azure', 'scope': SCOPE,
                         'created_at': '2026-10-12T00:00:00Z',
                         'metadata': {'compliance_policy': {'sw31': {}}}},
             'collections': {kind: [{'scope': SCOPE, 'status': 'collected' if items else 'empty',
                                     'items': deepcopy(items)}] for kind, items in rows.items()},
             **{kind: [{'scope': SCOPE, 'data': deepcopy(item)} for item in items]
                for kind, items in rows.items()}}
    from tests.nsg_service_observation_fixture import authorize_fixture_index
    authorize_fixture_index(index)
    return evaluate_check(CHECK, {'scope': SCOPE}, index)


def test_fabricated_matching_labels_fail_against_tcp443_registry():
    status, evidence = evaluate(measured='made-up-service', claim='made-up-service')
    assert status == 'FAIL'
    assert evidence['iana_source_sha256'] == SOURCE_SHA
    assert evidence['evaluated'] == 1


def test_correct_service_with_wrong_registry_claim_is_unknown():
    status, evidence = evaluate(measured='https', claim='made-up-service')
    assert status == 'UNKNOWN'
    assert evidence['iana_source_sha256'] == SOURCE_SHA
    assert evidence['reason'] == 'one or more required facts unresolved'


def test_all_tcp80_aliases_are_accepted():
    status, evidence = evaluate(port=80, measured='www', claim='http')
    assert status == 'PASS'
    assert evidence['iana_source_sha256'] == SOURCE_SHA
    assert evidence['evaluated'] == 1


def test_official_range_assignment_is_accepted():
    status, evidence = evaluate(port=6001, measured='x11', claim='x11')
    assert status == 'PASS'
    assert evidence['iana_source_sha256'] == SOURCE_SHA


def test_missing_external_measurement_is_unknown():
    status, evidence = evaluate(measurement=False)
    assert status == 'UNKNOWN'
    assert evidence['reason'] == 'one or more required facts unresolved'


def test_udp_assignment_uses_udp_registry_row():
    status, evidence = evaluate(protocol='Udp', port=443, measured='https', claim='https')
    assert status == 'PASS'
    assert evidence['iana_source_sha256'] == SOURCE_SHA
