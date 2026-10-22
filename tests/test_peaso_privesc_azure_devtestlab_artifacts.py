"""A lab artifact path must reach only the identity on the writable lab VM."""
from __future__ import annotations

from pathlib import Path

import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_schema_ext_azure import RG, ROLE_ID, _vm, az


ENTRY = yaml.safe_load((Path(__file__).resolve().parents[1] /
                        "peaso/privesc/catalog/azure/devtest_labs.yaml").read_text())[0]
ACTION = "Microsoft.DevTestLab/labs/virtualMachines/applyArtifacts/action"
LAB = f"{RG}/providers/Microsoft.DevTestLab/labs/lab"
LAB_VM_1 = f"{LAB}/virtualMachines/one"
LAB_VM_2 = f"{LAB}/virtualMachines/two"
COMPUTE_1 = f"{RG}/providers/Microsoft.Compute/virtualMachines/host1"
COMPUTE_2 = f"{RG}/providers/Microsoft.Compute/virtualMachines/host2"
SOURCE = f"{LAB}/artifactSources/public repo"
WINDOWS_ARTIFACT = f"{SOURCE}/artifacts/windows-run-powershell"


def snapshot(grant=LAB_VM_1, first=COMPUTE_1, second=COMPUTE_2, state="Succeeded",
             power="Running", graph=True, source_enabled=True, artifact=True):
    rows = [
        {"id": LAB, "type": "Microsoft.DevTestLab/labs", "name": "lab"},
        {"id": LAB_VM_1, "type": "Microsoft.DevTestLab/labs/virtualMachines",
         "properties": {"computeId": first, "provisioningState": state,
                        "lastKnownPowerState": power, "osType": "Windows"}},
        {"id": LAB_VM_2, "type": "Microsoft.DevTestLab/labs/virtualMachines",
         "properties": {"computeId": second, "provisioningState": "Succeeded",
                        "lastKnownPowerState": "Running", "osType": "Windows"}},
    ] if graph else []
    extra = [
        ("devtest_lab_artifact_source", LAB,
         [{"id": SOURCE, "type": "Microsoft.DevTestLab/labs/artifactSources",
           "properties": {"status": "Enabled" if source_enabled else "Disabled",
                          "officialPublicRepository": True}}], "collected"),
        ("devtest_lab_artifact", SOURCE,
         [{"id": WINDOWS_ARTIFACT,
           "type": "Microsoft.DevTestLab/labs/artifactSources/artifacts",
           "properties": {"targetOsType": "Windows"}}] if artifact else [],
         "collected" if artifact else "empty"),
    ]
    return az(assignments=[("u-alice", "User", grant, ROLE_ID)],
              roles={ROLE_ID: ([ACTION], [])},
              vms=[_vm("host1", "mi-host1"), _vm("host2", "mi-host2")], graph=rows,
              extra=extra)


def targets(snap):
    result = privesc.analyze(snap, entries=[ENTRY])
    return reached(result, "u-alice", ENTRY["id"])


def test_exact_lab_vm_permission_reaches_only_its_compute_identity():
    assert validate_entry(ENTRY)[0] == []
    assert targets(snapshot()) == {"mi-host1": "conditional"}
    assert targets(snapshot(grant=LAB_VM_2)) == {"mi-host2": "conditional"}
    assert targets(snapshot(grant=LAB)) == {"mi-host1": "conditional", "mi-host2": "conditional"}


def test_missing_wrong_or_stopped_lab_vm_does_not_name_identity():
    for kwargs in (
        {"first": ""}, {"first": COMPUTE_2},
        {"first": f"{RG}/providers/Microsoft.Compute/virtualMachineScaleSets/host1"},
        {"state": "Failed"}, {"power": "Stopped"}, {"power": "Deallocated"},
        {"graph": False}, {"source_enabled": False}, {"artifact": False},
    ):
        result = targets(snapshot(**kwargs))
        assert "mi-host1" not in result, kwargs


def test_unrelated_role_scope_does_not_reach_a_lab_vm():
    other = f"{RG}/providers/Microsoft.DevTestLab/labs/other/virtualMachines/one"
    assert targets(snapshot(grant=other)) == {}


def test_native_lab_vm_record_can_supply_compute_link():
    snap = snapshot(graph=False)
    snap["collections"].append({"type": "devtest_lab_vm", "scope": RG,
                                "status": "collected", "items": [
                                    {"id": LAB_VM_1,
                                     "type": "Microsoft.DevTestLab/labs/virtualMachines",
                                     "properties": {"computeId": COMPUTE_1,
                                                    "osType": "Windows"}}]})
    assert targets(snap) == {"mi-host1": "conditional"}


def test_incompatible_artifact_and_unverified_source_do_not_emit_path():
    snap = snapshot()
    source = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact_source")
    source["items"][0]["properties"]["officialPublicRepository"] = False
    assert targets(snap) == {}
    snap = snapshot()
    artifact = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact")
    artifact["items"][0]["properties"]["targetOsType"] = "Linux"
    assert targets(snap) == {}


def test_linux_run_bash_artifact_reaches_the_linux_vm_identity():
    snap = snapshot()
    graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")
    for row in graph["items"]:
        if row["id"] == LAB_VM_1:
            row["properties"]["osType"] = "Linux"
    artifact = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact")
    artifact["items"][0]["id"] = SOURCE + "/artifacts/linux-run-bash"
    artifact["items"][0]["properties"]["targetOsType"] = "Linux"
    assert targets(snap) == {"mi-host1": "conditional"}


def test_custom_script_artifact_needs_fresh_exact_reviewed_evidence():
    snap = snapshot()
    source = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact_source")
    source["items"][0]["properties"]["officialPublicRepository"] = False
    artifact = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact")
    custom_id = SOURCE + "/artifacts/run-custom-script"
    artifact["items"][0]["id"] = custom_id
    snap["created_at"] = "2026-10-22T11:00:00Z"
    evidence = {"ArtifactId": custom_id, "LabVmId": LAB_VM_1, "TargetOsType": "Windows",
                "Status": "verified", "ScriptExecutionSemanticsVerified": True,
                "InputControllableBySource": True, "EvidenceRef": "artifact-definition-review-1",
                "EvidenceObservedAt": "2026-10-22T10:00:00Z",
                "EvidenceExpiresAt": "2026-10-22T12:00:00Z"}
    snap["collections"].append({"type": "devtest_lab_script_artifact_evidence",
                                "scope": SOURCE, "status": "collected", "items": [evidence]})
    assert targets(snap) == {"mi-host1": "conditional"}
    evidence["InputControllableBySource"] = False
    assert targets(snap) == {}
    evidence["InputControllableBySource"] = True
    evidence["EvidenceObservedAt"] = "2026-10-20T10:00:00Z"
    assert targets(snap) == {}
    evidence["EvidenceObservedAt"] = "2026-10-22T10:00:00Z"
    snap["collections"][-1]["status"] = "partial"
    assert targets(snap) == {}


def test_authoritative_native_vm_state_overrides_stale_graph_state():
    snap = snapshot()
    snap["collections"].append({"type": "devtest_lab_vm", "scope": LAB,
                                "status": "collected", "items": [
                                    {"id": LAB_VM_1,
                                     "type": "Microsoft.DevTestLab/labs/virtualMachines",
                                     "properties": {"computeId": COMPUTE_1, "osType": "Windows",
                                                    "provisioningState": "Succeeded",
                                                    "lastKnownPowerState": "Stopped"}}]})
    assert targets(snap) == {}


def test_explicit_artifact_and_extension_blockers_do_not_emit_path():
    snap = snapshot()
    graph = next(c for c in snap["collections"] if c["type"] == "resource_graph")
    next(row for row in graph["items"] if row["id"] == LAB_VM_1)["properties"]["canApplyArtifacts"] = False
    assert targets(snap) == {}

    snap = snapshot()
    source = next(c for c in snap["collections"] if c["type"] == "devtest_lab_artifact_source")
    source["items"][0]["properties"]["provisioningState"] = "Failed"
    assert targets(snap) == {}

    snap = snapshot()
    vm = next(c for c in snap["collections"] if c["type"] == "vm")
    next(row for row in vm["items"] if row["id"] == COMPUTE_1).setdefault("properties", {})["osProfile"] = {
        "allowExtensionOperations": False
    }
    assert targets(snap) == {}
