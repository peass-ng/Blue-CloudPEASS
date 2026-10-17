"""Directed native patch result tests; no cloud or guest execution."""
from copy import deepcopy

from peaso.collectors.azure_wave_compute_native import evaluate_vm_patch_installation


NOW = "2026-10-16T10:00:00Z"


def _vm():
    return {
        "id": "/subscriptions/s/resourceGroups/r/providers/Microsoft.Compute/virtualMachines/v",
        "properties": {"instanceView": {"patchStatus": {
            "availablePatchSummary": {
                "status": "Succeeded", "lastModifiedTime": "2026-10-16T09:30:00Z",
                "criticalAndSecurityPatchCount": 0,
            },
            "lastPatchInstallationSummary": {
                "status": "Succeeded", "installationActivityId": "operation-1",
                "lastModifiedTime": "2026-10-16T09:00:00Z",
                "installedPatchCount": 3, "failedPatchCount": 0,
                "pendingPatchCount": 0, "maintenanceWindowExceeded": False,
            },
        }}},
    }


def _check(vm, **kw):
    result = {
        "id": vm["id"] + "/patchInstallationResults/operation-1",
        "type": "patchinstallationresults",
        "_provenance": {"source_operation": "ResourceGraph:patchinstallationresources", "read_only": True},
        "properties": {"installationActivityId": "operation-1",
                       "lastModifiedDateTime": "2026-10-16T09:20:00Z",
                       "status": "Succeeded", "installedPatchCount": 3,
                       "failedPatchCount": 0, "pendingPatchCount": 0,
                       "maintenanceWindowExceeded": False, "rebootStatus": "NotNeeded"},
    }
    kw.setdefault("installation_result", result)
    return evaluate_vm_patch_installation(
        vm, observed_at=NOW, max_age_seconds=7200, **kw)


def test_successful_native_installation_followed_by_clean_assessment():
    verdict = _check(_vm())
    assert verdict["state"] == "PASS"
    assert verdict["proof"]["installation_activity_id"] == "operation-1"
    assert verdict["proof"]["installed_patch_count"] == 3


def test_current_missing_patches_are_a_real_failure():
    vm = _vm()
    vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]["criticalAndSecurityPatchCount"] = 2
    verdict = _check(vm)
    assert verdict["state"] == "FAIL"
    assert verdict["proof"]["missing_patch_count"] == 2


def test_zero_available_without_actual_installation_is_unproven():
    vm = _vm()
    del vm["properties"]["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "installation summary absent" in verdict["reason"]


def test_vm_summary_without_completed_result_cannot_prove_post_installation_assessment():
    verdict = _check(_vm(), installation_result=None)
    assert verdict["state"] == "UNKNOWN"
    assert "completed Update Manager installation result absent" in verdict["reason"]


def test_wrong_operation_result_cannot_pass():
    vm = _vm()
    result = {"id": vm["id"] + "/patchInstallationResults/other",
              "type": "patchinstallationresults",
              "_provenance": {"source_operation": "ResourceGraph:patchinstallationresources", "read_only": True},
              "properties": {"installationActivityId": "other"}}
    verdict = _check(vm, installation_result=result)
    assert verdict["state"] == "UNKNOWN"
    assert "operation or source unbound" in verdict["reason"]


def test_assessment_must_follow_installation():
    vm = _vm()
    vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]["lastModifiedTime"] = "2026-10-16T08:30:00Z"
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "predates" in verdict["reason"]


def test_failed_patch_count_blocks_installation_proof():
    vm = _vm()
    vm["properties"]["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]["failedPatchCount"] = 1
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "installation incomplete" in verdict["reason"]


def test_operation_without_installed_patches_is_unproven():
    vm = _vm()
    vm["properties"]["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]["installedPatchCount"] = 0
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "did not report an installed patch" in verdict["reason"]


def test_stale_assessment_cannot_pass():
    vm = _vm()
    vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]["lastModifiedTime"] = "2026-10-15T09:30:00Z"
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "assessment stale" in verdict["reason"]


def test_no_installation_requirement_uses_assessment_only():
    vm = deepcopy(_vm())
    del vm["properties"]["instanceView"]["patchStatus"]["lastPatchInstallationSummary"]
    verdict = _check(vm, require_actual_installation=False)
    assert verdict["state"] == "PASS"
    assert "installation_activity_id" not in verdict["proof"]


def test_separate_native_instance_view_requires_complete_coverage():
    vm = _vm()
    vm["instanceView"] = vm["properties"].pop("instanceView")
    vm["_coverage"] = {"instanceView": {"status": "partial"}}
    verdict = _check(vm)
    assert verdict["state"] == "UNKNOWN"
    assert "instance view incomplete" in verdict["reason"]
    vm["_coverage"]["instanceView"]["status"] = "collected"
    assert _check(vm)["state"] == "PASS"
