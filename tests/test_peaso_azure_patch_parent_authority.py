"""Patch evaluator cannot trust explicitly unreadable parent status metadata."""
import pytest
from tests.test_peaso_azure_wave_compute_native_patch import _vm,_check

@pytest.mark.parametrize("coverage",["denied","partial","malformed","empty"])
def test_unreadable_or_contradictory_parent_status_cannot_prove_patch_success(coverage):
    vm=_vm();summary=vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]
    summary["collection_status"]="collected";summary["_coverage"]={"collection_status":{"status":coverage}}
    assert _check(vm)["state"]=="UNKNOWN"

@pytest.mark.parametrize("value",[None,1,True])
def test_malformed_present_parent_status_cannot_prove_patch_success(value):
    vm=_vm();summary=vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]
    summary["collection_status"]=value
    assert _check(vm)["state"]=="UNKNOWN"

def test_default_omitted_and_readable_explicit_parent_status_remain_valid():
    vm=_vm();assert _check(vm)["state"]=="PASS"
    summary=vm["properties"]["instanceView"]["patchStatus"]["availablePatchSummary"]
    summary["collection_status"]="collected";summary["_coverage"]={"collection_status":{"status":"collected"}}
    assert _check(vm)["state"]=="PASS"
