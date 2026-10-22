"""Native DevTest Labs inventory retains only script availability metadata."""
from __future__ import annotations

from copy import deepcopy
import importlib.util
from pathlib import Path
from urllib.parse import quote

spec = importlib.util.spec_from_file_location(
    "azure_devtestlab_native_reviewed", Path(__file__).resolve().parents[1] /
    "peaso/collectors/azure_devtestlab_native.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)
SUB = "/subscriptions/00000000-0000-0000-0000-00000000aaaa"
RG = SUB + "/resourceGroups/rg"
LAB = RG + "/providers/Microsoft.DevTestLab/labs/lab"
LAB_VM_1 = LAB + "/virtualMachines/one"
SOURCE = LAB + "/artifactSources/public repo"
WINDOWS_ARTIFACT = SOURCE + "/artifacts/windows-run-powershell"
COMPUTE_1 = RG + "/providers/Microsoft.Compute/virtualMachines/host1"


def _collect(source_status="Enabled", artifact_name=WINDOWS_ARTIFACT, source_uri="https://github.com/Azure/azure-devtestlab"):
    version = "?api-version=2018-09-15"
    pages = {
        native.ARM + LAB + "/virtualmachines" + version: {"value": [
            {"id": LAB_VM_1, "name": "one", "type": "Microsoft.DevTestLab/labs/virtualMachines",
             "properties": {"computeId": COMPUTE_1, "osType": "Windows",
                            "provisioningState": "Succeeded", "lastKnownPowerState": "Running",
                            "password": "SECRET-MUST-NOT-SURVIVE"}}]},
        native.ARM + LAB + "/artifactsources" + version: {"value": [
            {"id": SOURCE, "name": "public repo", "type": "Microsoft.DevTestLab/labs/artifactSources",
             "properties": {"status": source_status, "sourceType": "GitHub", "uri": source_uri,
                            "securityToken": "SECRET-MUST-NOT-SURVIVE"}}]},
        native.ARM + quote(SOURCE, safe="/") + "/artifacts" + version: {"value": [
            {"id": artifact_name, "name": artifact_name.rsplit("/", 1)[-1],
             "type": "Microsoft.DevTestLab/labs/artifactSources/artifacts",
             "properties": {"targetOsType": "Windows", "title": "Run PowerShell",
                            "parameters": {"script": {"defaultValue": "SECRET-MUST-NOT-SURVIVE"}}}}]},
    }
    calls = []

    def request(url, *, body=None, audience=None):
        calls.append(url)
        return deepcopy(pages[url])

    class Reader:
        def __init__(self):
            self.collections = []

        def pages(self, callback, url):
            yield callback(url)["value"]

        def run(self, jobs):
            for kind, scope, service, fetch in jobs:
                try:
                    rows = [item for page in fetch() for item in page]
                    status = "collected" if rows else "empty"
                except ValueError:
                    rows, status = [], "error"
                self.collections.append({"type": kind, "scope": scope, "service": service,
                                         "status": status, "items": rows})

    reader = Reader()
    reader.collections.append({"type": "devtest_lab", "scope": SUB, "service": "Microsoft.DevTestLab",
                               "status": "collected", "items": [
                                   {"id": LAB, "name": "lab", "type": "Microsoft.DevTestLab/labs"}]})
    native.collect(reader, request, [SUB], native.CHILDREN)
    return reader.collections, calls


def test_exact_native_vm_source_and_artifact_are_collected_without_secrets():
    assert native.required_types(["devtest_lab_vm"]) == {
        "devtest_lab", "devtest_lab_artifact_source", "devtest_lab_artifact"}
    collections, calls = _collect()
    assert len(calls) == 3
    assert "SECRET-MUST-NOT-SURVIVE" not in str(collections)
    by_type = {row["type"]: row for row in collections}
    assert by_type["devtest_lab_vm"]["items"][0]["properties"]["computeId"] == COMPUTE_1
    assert by_type["devtest_lab_artifact_source"]["items"][0]["properties"]["officialPublicRepository"] is True
    assert by_type["devtest_lab_artifact"]["items"][0]["id"] == WINDOWS_ARTIFACT


def test_disabled_source_skips_artifact_read_and_untrusted_repo_is_not_official():
    collections, calls = _collect(source_status="Disabled")
    assert len(calls) == 2
    assert not any(row["type"] == "devtest_lab_artifact" for row in collections)
    collections, _ = _collect(source_uri="https://github.com/attacker/azure-devtestlab")
    source = next(row for row in collections if row["type"] == "devtest_lab_artifact_source")
    assert source["items"][0]["properties"]["officialPublicRepository"] is False


def test_foreign_artifact_cannot_enter_complete_inventory():
    collections, _ = _collect(artifact_name=LAB + "/artifactSources/other/artifacts/windows-run-powershell")
    artifact = next(row for row in collections if row["type"] == "devtest_lab_artifact")
    assert artifact["status"] not in ("collected", "empty")
    assert artifact["items"] == []
