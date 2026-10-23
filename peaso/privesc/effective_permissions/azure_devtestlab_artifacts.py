"""Bind a writable DevTest Labs VM to its exact backing compute identity."""
from __future__ import annotations

import re
from datetime import datetime

from . import inventory_status, items


LAB_VM = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.devtestlab/labs/[^/]+/virtualmachines/[^/]+"
)
COMPUTE_VM = re.compile(
    r"/subscriptions/[^/]+/resourcegroups/[^/]+/providers/microsoft\.compute/virtualmachines/[^/]+"
)
SCRIPT_ARTIFACT = {"windows": "windows-run-powershell", "linux": "linux-run-bash"}


def _extensions_disabled(snapshot, compute_vm):
    native = [item for _, item in items(snapshot, "vm")
              if isinstance(item, dict) and str(item.get("id") or "").casefold() == compute_vm]
    records = native or [item for _, item in items(snapshot, "resource_graph")
                         if isinstance(item, dict) and str(item.get("id") or "").casefold() == compute_vm]
    return any((item.get("properties") or {}).get("osProfile", {}).get("allowExtensionOperations") is False
               for item in records if isinstance((item.get("properties") or {}).get("osProfile", {}), dict))


def _reviewed_custom_artifact(snapshot, lab_vm, artifact_id, os_type):
    source_id = artifact_id.rsplit("/artifacts/", 1)[0]
    status = {scope.casefold(): value for scope, value in
              inventory_status(snapshot, "devtest_lab_script_artifact_evidence").items()}
    if status.get(source_id) != "collected":
        return False
    matches = [row for scope, row in items(snapshot, "devtest_lab_script_artifact_evidence")
               if (str(scope).casefold() == source_id and isinstance(row, dict)
                   and str(row.get("ArtifactId") or "").casefold() == artifact_id)]
    if len(matches) != 1:
        return False
    row = matches[0]
    if (str(row.get("LabVmId") or "").casefold() != lab_vm
            or str(row.get("TargetOsType") or "").casefold() != os_type
            or row.get("Status") != "verified"
            or row.get("ScriptExecutionSemanticsVerified") is not True
            or row.get("InputControllableBySource") is not True
            or not isinstance(row.get("EvidenceRef"), str) or not row["EvidenceRef"].strip()):
        return False
    try:
        observed = datetime.fromisoformat(row["EvidenceObservedAt"].replace("Z", "+00:00"))
        expires = datetime.fromisoformat(row["EvidenceExpiresAt"].replace("Z", "+00:00"))
        captured = datetime.fromisoformat(snapshot["created_at"].replace("Z", "+00:00"))
        return (all(time.tzinfo is not None for time in (observed, expires, captured))
                and observed <= captured < expires
                and (captured - observed).total_seconds() <= 86400)
    except (KeyError, TypeError, ValueError):
        return False


def _script_available(snapshot, lab_vm, os_type):
    expected = SCRIPT_ARTIFACT.get(os_type)
    if expected is None:
        return False
    lab = lab_vm.rsplit("/virtualmachines/", 1)[0]
    sources_status = {scope.casefold(): status for scope, status in
                      inventory_status(snapshot, "devtest_lab_artifact_source").items()}
    artifacts_status = {scope.casefold(): status for scope, status in
                        inventory_status(snapshot, "devtest_lab_artifact").items()}
    if sources_status.get(lab) not in ("collected", "empty"):
        return False
    for scope, source in items(snapshot, "devtest_lab_artifact_source"):
        source_id = str(source.get("id") or "").casefold()
        props = source.get("properties") or {}
        if (str(scope).casefold() != lab
                or not re.fullmatch(re.escape(lab) + r"/artifactsources/[^/?#%\\]+", source_id)
                or str(source.get("type") or "").casefold() != "microsoft.devtestlab/labs/artifactsources"
                or str(props.get("status") or "").casefold() != "enabled"
                or str(props.get("provisioningState") or "Succeeded").casefold() != "succeeded"
                or artifacts_status.get(source_id) not in ("collected", "empty")):
            continue
        for artifact_scope, artifact in items(snapshot, "devtest_lab_artifact"):
            artifact_id = str(artifact.get("id") or "").casefold()
            if (str(artifact_scope).casefold() == source_id
                    and re.fullmatch(re.escape(source_id) + r"/artifacts/[^/?#%\\]+", artifact_id)
                    and str(artifact.get("type") or "").casefold()
                    == "microsoft.devtestlab/labs/artifactsources/artifacts"
                    and str((artifact.get("properties") or {}).get("targetOsType") or "").casefold() == os_type
                    and ((props.get("officialPublicRepository") is True
                          and artifact_id == source_id + "/artifacts/" + expected)
                         or _reviewed_custom_artifact(snapshot, lab_vm, artifact_id, os_type))):
                return True
    return False


def select(model, candidates, pivots):
    """Only a VM with a successful exact ApplyArtifacts grant can reach its identity."""
    allowed = {str(row.get("pivot") or "").casefold() for row in (pivots or []) if isinstance(row, dict)}
    native_status = {scope.casefold(): status for scope, status in
                     inventory_status(model.snapshot, "devtest_lab_vm").items()}
    native_ids = {str(item.get("id") or "").casefold()
                  for scope, item in items(model.snapshot, "devtest_lab_vm")
                  if native_status.get(str(scope).casefold()) == "collected" and isinstance(item, dict)}
    records, blocked = {}, set()
    for kind in ("resource_graph", "devtest_lab_vm"):
        for _, item in items(model.snapshot, kind):
            if not isinstance(item, dict):
                continue
            lab_vm = str(item.get("id") or "").casefold()
            if (lab_vm not in allowed or (kind == "resource_graph" and lab_vm in native_ids)
                    or not LAB_VM.fullmatch(lab_vm)
                    or str(item.get("type") or "").casefold() != "microsoft.devtestlab/labs/virtualmachines"):
                continue
            props = item.get("properties") or {}
            compute_vm = str(props.get("computeId") or "").casefold()
            state = str(props.get("provisioningState") or "").casefold()
            power = str(props.get("lastKnownPowerState") or "").casefold()
            os_type = str(props.get("osType") or "").casefold()
            if (state in {"failed", "canceled", "deleted"}
                    or power in {"stopped", "deallocated", "powerstate/stopped", "powerstate/deallocated"}
                    or props.get("canApplyArtifacts") is False):
                blocked.add(lab_vm)
                continue
            if (not COMPUTE_VM.fullmatch(compute_vm)
                    or not _script_available(model.snapshot, lab_vm, os_type)):
                continue
            records.setdefault(lab_vm, set()).add(compute_vm)
    linked = set()
    for lab_vm, targets in records.items():
        if lab_vm in blocked or len(targets) != 1:
            continue
        compute_vm = next(iter(targets))
        if (model.resources.get(compute_vm, {}).get("type") == "microsoft.compute/virtualmachines"
                and not _extensions_disabled(model.snapshot, compute_vm)):
            linked.add(compute_vm)
    return {target_id: ("conditional", "artifact_payload_and_guest_execution_not_verified")
            for target_id, target in candidates.items()
            if target.kind == "azure_managed_identity"
            and linked.intersection(str(host).casefold() for host in target.attrs.get("hosts") or ())}
