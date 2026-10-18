"""Legacy sw17 native installation branch, separate from staged registrar tests."""
from tests.compliance_draft_isolation import staged_registry


with staged_registry(('compliance_new_sw17',)):
    from test_peaso_compliance_new_sw17 import case, run, normalized_fact, VM


SUFFIX = 'system_updates_installed'


def _native_case():
    machine, index = case(SUFFIX)
    policy = index['context']['metadata']['compliance_policy']['checks']['azure.gap.compute_vm_' + SUFFIX]
    policy['requireActualInstallation'] = True
    machine['properties']['instanceView']['patchStatus']['lastPatchInstallationSummary'] = {
        'status': 'Succeeded', 'installationActivityId': 'operation-1',
        'lastModifiedTime': '2026-10-12T09:30:00Z', 'installedPatchCount': 2,
        'failedPatchCount': 0, 'pendingPatchCount': 0,
        'maintenanceWindowExceeded': False,
    }
    normalized_fact(index, 'vm_patch_installation_result',
                    id=VM + '/patchInstallationResults/operation-1',
                    type='patchinstallationresults',
                    _provenance={'source_operation': 'ResourceGraph:patchinstallationresources',
                                 'read_only': True, 'observed_at': '2026-10-12T10:00:00Z'},
                    properties={'installationActivityId': 'operation-1',
                                'lastModifiedDateTime': '2026-10-12T09:45:00Z',
                                'status': 'Succeeded', 'installedPatchCount': 2,
                                'failedPatchCount': 0, 'pendingPatchCount': 0,
                                'maintenanceWindowExceeded': False,
                                'rebootStatus': 'NotNeeded'})
    return machine, index


def test_native_success_and_later_zero_assessment_pass():
    machine, index = _native_case()
    status, proof = run(SUFFIX, machine, index)
    assert status == 'PASS'
    assert proof['native_installation']['installation_activity_id'] == 'operation-1'


def test_zero_available_without_installation_remains_unknown():
    machine, index = _native_case()
    del machine['properties']['instanceView']['patchStatus']['lastPatchInstallationSummary']
    status, proof = run(SUFFIX, machine, index)
    assert status == 'UNKNOWN'
    assert 'installation summary absent' in proof['reason']


def test_vm_summary_without_bound_update_manager_result_is_unknown():
    machine, index = _native_case()
    del index['collections']['vm_patch_installation_result']
    del index['vm_patch_installation_result']
    status, proof = run(SUFFIX, machine, index)
    assert status == 'UNKNOWN'
    assert 'completed Update Manager installation result unavailable' in proof['reason']


def test_failed_installation_count_cannot_pass():
    machine, index = _native_case()
    machine['properties']['instanceView']['patchStatus']['lastPatchInstallationSummary']['failedPatchCount'] = 1
    status, proof = run(SUFFIX, machine, index)
    assert status == 'UNKNOWN'
    assert 'installation incomplete' in proof['reason']


def test_positive_missing_patch_assessment_is_fail():
    machine, index = _native_case()
    machine['properties']['instanceView']['patchStatus']['availablePatchSummary']['criticalAndSecurityPatchCount'] = 1
    status, proof = run(SUFFIX, machine, index)
    assert status == 'FAIL'
    assert proof['critical_and_security_patch_count'] == 1
