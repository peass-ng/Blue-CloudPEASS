"""Staged SW13 tests: a native measured mismatch survives unrelated missing evidence."""
from __future__ import annotations

import pytest
from peaso.checks import CHECKS

CID = 'azure_app_service_app_function_latest_runtime_version_f50215a'
APP = '/subscriptions/sub-13/resourceGroups/rg/providers/Microsoft.Web/sites/app'
SUB = '/subscriptions/sub-13'
EVALUATE = next(check.evaluate for check in CHECKS if check.id == CID)


def evaluate(item, index):
    return EVALUATE(item, index)


def flex_memory_case():
    item = {'id': APP, 'kind': 'functionapp', '_provenance': {'tenant_id': 'tenant-13', 'read_only': True}}
    observed = {
        'id': APP + '/functionConfiguration/current', 'scope': SUB,
        '_provenance': {'read_only': True},
        'document_id': 'approved-document', 'authorized_by': 'security-owner',
        'observed_at': '2026-10-01T00:00:00Z', 'expires_at': '2026-11-01T00:00:00Z',
        'appId': APP, 'packageType': 'Code', 'runtimeType': 'Language',
        'hostingModel': 'FlexConsumption', 'runtimeResolved': False,
        'settings': {'runtime': 'python|3.12.7', 'role': 'worker-role',
                     'timeoutSeconds': 300, 'memoryMB': 512},
        'sources': {field: {'status': 'unavailable', 'operation': 'unknown', 'nativePath': 'unknown'}
                    for field in ('runtime', 'role', 'timeoutSeconds', 'memoryMB')},
    }
    wanted = {'hostingModel': 'FlexConsumption', 'runtime': 'python|3.12.7',
              'role': 'worker-role', 'timeoutSeconds': 300, 'memoryMB': 2048}
    observed['sources']['memoryMB'] = {
        'status': 'collected', 'operation': 'Microsoft.Web/sites GET',
        'nativePath': 'properties.functionAppConfig.scaleAndConcurrency.instanceMemoryMB',
        'apiVersion': '2024-11-01', 'representation': 'full', 'resourceId': APP,
    }
    policy = {'status': 'collected', 'scope': SUB, 'document_id': 'approved-document',
              'authorized_by': 'security-owner', 'observed_at': '2026-10-01T00:00:00Z',
              'expires_at': '2026-11-01T00:00:00Z',
              'checks': {CID.replace('.', '|'): {'expectedFunctionSettings': {APP: wanted}}}}
    index = {
        'context': {'provider': 'azure', 'scope': SUB, 'created_at': '2026-10-12T12:00:00Z',
                    'metadata': {'compliance_policy': {'sw13': policy}}},
        'collections': {
            'app_service': [{'type': 'app_service', 'scope': SUB, 'status': 'collected', 'items': [item]}],
            'function_app_configuration': [{'type': 'function_app_configuration', 'scope': SUB,
                                             'status': 'collected', 'items': [observed]}],
        },
        'app_service': [{'type': 'app_service', 'scope': SUB, 'data': item}],
        'function_app_configuration': [{'type': 'function_app_configuration', 'scope': SUB, 'data': observed}],
    }
    return item, index, observed, wanted


def test_documented_flex_instance_memory_mismatch_survives_missing_peers():
    item, index, _, _ = flex_memory_case()
    status, evidence = evaluate(item, index)
    assert status == 'FAIL', evidence
    assert evidence['mismatched_settings'] == ['memoryMB']


@pytest.mark.parametrize('mutation', ['same_value', 'foreign_resource', 'wrong_path', 'untrusted_source',
                                      'missing_baseline', 'stale', 'foreign_classification', 'floating_runtime'])
def test_unproven_or_non_mismatch_cannot_be_negative_witness(mutation):
    item, index, observed, wanted = flex_memory_case()
    if mutation == 'same_value':
        observed['settings']['memoryMB'] = wanted['memoryMB']
    elif mutation == 'foreign_resource':
        observed['sources']['memoryMB']['resourceId'] = item['id'] + '-other'
    elif mutation == 'wrong_path':
        observed['sources']['memoryMB']['nativePath'] = 'properties.siteConfig.numberOfWorkers'
    elif mutation == 'untrusted_source':
        observed['sources']['memoryMB']['operation'] = 'custom observation'
    elif mutation == 'missing_baseline':
        wanted.pop('memoryMB')
    elif mutation == 'stale':
        observed['expires_at'] = '2026-10-11T00:00:00Z'
    elif mutation == 'foreign_classification':
        observed['appId'] = item['id'] + '-other'
    else:
        observed['settings']['runtime'] = '~4'
        observed['sources']['runtime']['status'] = 'collected'
    assert evaluate(item, index)[0] == 'UNKNOWN'


def test_no_field_measured_is_unknown():
    item, index, observed, _ = flex_memory_case()
    observed['sources']['memoryMB']['status'] = 'unavailable'
    assert evaluate(item, index)[0] == 'UNKNOWN'
