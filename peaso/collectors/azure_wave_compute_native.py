"""Read-only Update Manager result collection and VM patch evaluation.

Collection performs bounded, approved Resource Graph reads. Evaluation does
not make API calls or turn operation success into a compliance status. The
caller supplies the full VM GET representation with instanceView expanded.
"""
from __future__ import annotations

from datetime import datetime, timezone
import re
import json


ARM = "https://management.azure.com"
KIND = "vm_patch_installation_result"
NATIVE_TYPES = frozenset({KIND})
MAX_OPERATIONS = 256
MAX_PAGES = 8
MAX_QUERY_BYTES = 60000
CHECK_ID = "azure.gap.compute_vm_system_updates_installed"
_VM_ID = re.compile(r"/subscriptions/[^/?#]+/resourceGroups/[^/?#]+/providers/Microsoft\.Compute/virtualMachines/[^/?#]+", re.I)


def required_types(wanted):
    return {"vm"} if KIND in wanted else set()


def _selected(row, key, default=None):
    """Read one selected native field only when its source says it was observed."""
    if not isinstance(row, dict):
        raise ValueError("selected native patch parent malformed")
    coverage = row.get("_coverage", {})
    if not isinstance(coverage, dict):
        raise ValueError("selected native patch coverage malformed")
    if "collection_status" in coverage:
        status_proof = coverage["collection_status"]
        if not isinstance(status_proof, dict) or status_proof.get("status") not in ("collected", "empty"):
            raise ValueError("native patch parent status unavailable")
        if (status_proof["status"] == "empty") != ("collection_status" not in row):
            raise ValueError("native patch parent status contradicts field coverage")
    if "collection_status" in row and row["collection_status"] != "collected":
        raise ValueError("selected native patch parent unavailable")
    if key in coverage:
        entry = coverage[key]
        if not isinstance(entry, dict) or entry.get("status") not in ("collected", "empty"):
            raise ValueError("selected native patch field unavailable: " + key)
        if entry["status"] == "empty":
            if key in row:
                raise ValueError("selected native patch field contradicts empty coverage: " + key)
            return default
        if key not in row:
            raise ValueError("selected native patch field missing despite collected coverage: " + key)
    return row.get(key, default)


def _approved(options, scope):
    try:
        outer = _selected(options, "compliance_policy")
        if (not isinstance(outer, dict) or _selected(outer, "status") != "collected"
                or str(_selected(outer, "scope", "")).casefold() != scope.casefold()):
            return False
        checks = _selected(outer, "checks")
        policy = _selected(checks, CHECK_ID) if isinstance(checks, dict) else None
        return (isinstance(policy, dict)
                and _selected(policy, "requireActualInstallation") is True
                and type(_selected(policy, "requirePciCompliance")) is bool)
    except ValueError:
        return False


def _selected_operations(reader, scope):
    collections = [row for row in reader.collections if row.get("type") == "vm"
                   and str(row.get("scope", "")).casefold() == scope.casefold()]
    if len(collections) != 1:
        raise ValueError("complete scoped VM inventory unavailable for patch results")
    collection = collections[0]
    if (_selected(collection, "type") != "vm"
            or str(_selected(collection, "scope", "")).casefold() != scope.casefold()):
        raise ValueError("scoped VM inventory identity unavailable")
    status = _selected(collection, "status")
    items = _selected(collection, "items")
    if (status not in ("collected", "empty") or not isinstance(items, list)
            or (status == "empty" and items)):
        raise ValueError("complete scoped VM inventory unavailable for patch results")
    selected, seen_vm_ids = {}, set()
    for vm in items:
        rid = _selected(vm, "id")
        if (not isinstance(rid, str) or not _VM_ID.fullmatch(rid)
                or not rid.casefold().startswith(scope.casefold() + "/resourcegroups/")):
            raise ValueError("patch result VM identity malformed or foreign")
        if rid.casefold() in seen_vm_ids:
            raise ValueError("duplicate patch result VM identity")
        seen_vm_ids.add(rid.casefold())
        try:
            coverage = vm.get("_coverage", {})
            entry = coverage.get("instanceView", {}) if isinstance(coverage, dict) else {}
            if not isinstance(entry, dict) or entry.get("status") != "collected":
                continue
            view = _selected(vm, "instanceView")
            patch = _selected(view, "patchStatus") if isinstance(view, dict) else None
            summary = _selected(patch, "lastPatchInstallationSummary") if isinstance(patch, dict) else None
            operation = _selected(summary, "installationActivityId") if isinstance(summary, dict) else None
        except ValueError:
            continue
        if isinstance(operation, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", operation):
            selected[rid.casefold()] = (rid, operation)
            if len(selected) > MAX_OPERATIONS:
                raise ValueError("Update Manager operation limit exceeded")
    return selected


def _project_result(raw, selected, scope):
    if not isinstance(raw, dict) or str(_selected(raw, "type", "")).casefold() != "patchinstallationresults":
        raise ValueError("non-summary Update Manager installation result")
    rid = _selected(raw, "id")
    if not isinstance(rid, str) or not rid.casefold().startswith(scope.casefold() + "/"):
        raise ValueError("foreign Update Manager installation result")
    match = re.fullmatch(r"(.+)/patchInstallationResults/([^/?#]+)", rid, re.I)
    if match is None or not _VM_ID.fullmatch(match[1]):
        raise ValueError("malformed Update Manager installation result identity")
    if match[1].casefold() not in selected:
        return None  # Another VM in the subscription, outside this exact operation set.
    vm_id, expected_operation = selected[match[1].casefold()]
    if match[2] != expected_operation:
        return None  # Another completed operation for this VM, not its latest Compute summary.
    props = _selected(raw, "properties")
    if not isinstance(props, dict) or _selected(props, "installationActivityId") != expected_operation:
        raise ValueError("Update Manager result operation identity mismatch")
    fields = ("installationActivityId", "lastModifiedDateTime", "status", "installedPatchCount",
              "failedPatchCount", "pendingPatchCount", "maintenanceWindowExceeded", "rebootStatus")
    projected = {key: _selected(props, key) for key in fields if key in props or key in props.get("_coverage", {})}
    return {"id": rid, "type": "patchinstallationresults", "vm_id": vm_id,
            "properties": {key: value for key, value in projected.items() if key in props},
            "_provenance": {"source_operation": "ResourceGraph:patchinstallationresources",
                            "api_version": "2024-04-01", "read_only": True,
                            "representation": "full", "observed_at": datetime.now(timezone.utc).isoformat()}}


def collect(reader, request, scopes, wanted, options):
    """Collect exact latest-operation ARG summaries for VMs with approved actual-installation requirements.

    ``reader.pages`` enforces the shared call, page, time and item budgets.
    No result is created from an operator declaration or Compute start time.
    """
    if KIND not in wanted:
        return
    jobs = []
    for scope in scopes:
        if not _approved(options, scope):
            envelope = {"type": KIND, "scope": scope, "service": "Microsoft.ResourceGraph",
                        "status": "unknown", "items": [],
                        "error": {"code": "actual_installation_policy_not_approved"}}
            reader.collections.append(envelope)
            reader.progress(scope=scope, settled=envelope)
            continue

        def fetch(scope=scope):
            selected = _selected_operations(reader, scope)
            if not selected:
                yield []
                return
            expected_ids = [vm.rstrip("/") + "/patchInstallationResults/" + operation
                            for vm, operation in selected.values()]
            query = ("patchinstallationresources | where type =~ 'patchinstallationresults' "
                     "| where id in~ (" + ",".join(json.dumps(value) for value in expected_ids)
                     + ") | project id, type, properties | order by id asc")
            if len(query.encode("utf-8")) > MAX_QUERY_BYTES:
                raise ValueError("Update Manager query exceeds hard byte limit")
            body = {"subscriptions": [scope.rsplit("/", 1)[-1]], "query": query,
                    "options": {"resultFormat": "objectArray", "$top": 1000}}
            requests_made = 0
            def bounded_request(*args, **kwargs):
                nonlocal requests_made
                if requests_made >= MAX_PAGES:
                    raise ValueError("Update Manager hard request/page limit exceeded")
                requests_made += 1
                return request(*args, **kwargs)
            seen = set()
            for number, page in enumerate(reader.pages(bounded_request, ARM + "/providers/Microsoft.ResourceGraph/resources?api-version=2024-04-01",
                                     body=body, key="data", next_key="$skipToken"), 1):
                if number > MAX_PAGES:
                    raise ValueError("Update Manager hard page limit exceeded")
                projected = []
                for raw in page:
                    rid = raw.get("id") if isinstance(raw, dict) else None
                    if not isinstance(rid, str) or not rid or rid.casefold() in seen:
                        raise ValueError("missing or duplicate Update Manager installation result")
                    seen.add(rid.casefold())
                    row = _project_result(raw, selected, scope)
                    if row is None:
                        raise ValueError("Update Manager result outside requested operation set")
                    projected.append(row)
                yield projected

        jobs.append((KIND, scope, "Microsoft.ResourceGraph", fetch))
    reader.run(jobs)


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            return None
        return parsed
    except ValueError:
        return None


def _decision(state, reason, **proof):
    return {"state": state, "reason": reason, "proof": proof}


def _evaluate_vm_patch_installation(vm, *, observed_at, max_age_seconds,
                                   require_actual_installation=True,
                                   installation_result=None):
    """Return PASS, FAIL or UNKNOWN from one VM's native patch status.

    PASS with ``require_actual_installation`` needs a successful installation
    with installedPatchCount > 0, a VM-bound completed Update Manager record,
    and a later successful zero-pending assessment.
    These fields prove only the VM's most recent reported operation and
    assessment; they are not an independent guest package inventory.
    """
    now = _time(observed_at)
    if now is None or type(max_age_seconds) is not int or max_age_seconds <= 0:
        return _decision("UNKNOWN", "observation time or approved freshness limit unavailable")
    if not isinstance(vm, dict) or not isinstance(_selected(vm, "id"), str) or not vm["id"]:
        return _decision("UNKNOWN", "VM identity unavailable")
    props = _selected(vm, "properties")
    if "instanceView" in vm:
        coverage = vm.get("_coverage", {})
        entry = coverage.get("instanceView", {}) if isinstance(coverage, dict) else {}
        if not isinstance(entry, dict) or entry.get("status") != "collected":
            return _decision("UNKNOWN", "native VM instance view incomplete")
        view = _selected(vm, "instanceView")
    else:
        view = _selected(props, "instanceView") if isinstance(props, dict) else None
    patch = _selected(view, "patchStatus") if isinstance(view, dict) else None
    assessment = _selected(patch, "availablePatchSummary") if isinstance(patch, dict) else None
    if not isinstance(assessment, dict):
        return _decision("UNKNOWN", "native available-patch assessment absent")
    assessment_at = _time(_selected(assessment, "lastModifiedTime"))
    if _selected(assessment, "status") != "Succeeded":
        return _decision("UNKNOWN", "native available-patch assessment not Succeeded")
    if assessment_at is None or not 0 <= (now - assessment_at).total_seconds() <= max_age_seconds:
        return _decision("UNKNOWN", "native available-patch assessment stale or future dated")
    count = _selected(assessment, "criticalAndSecurityPatchCount")
    if type(count) is not int or count < 0:
        return _decision("UNKNOWN", "critical and security patch count unavailable")
    if count > 0:
        return _decision("FAIL", "successful current assessment reports missing critical or security patches",
                         vm_id=vm["id"], missing_patch_count=count)
    if not require_actual_installation:
        return _decision("PASS", "successful current assessment reports zero missing critical or security patches",
                         vm_id=vm["id"], assessment_at=assessment_at.isoformat())
    # A newer assessment can contradict a historical installation's terminal
    # reboot status. Missing optional metadata preserves existing proof; an
    # explicit pending or malformed value cannot certify completed installation.
    reboot_pending = _selected(assessment, "rebootPending") if ("rebootPending" in assessment or "rebootPending" in assessment.get("_coverage", {})) else False
    if reboot_pending is not False:
        return _decision("UNKNOWN", "current assessment reboot completion unresolved")
    installation = _selected(patch, "lastPatchInstallationSummary")
    if not isinstance(installation, dict):
        return _decision("UNKNOWN", "native patch installation summary absent")
    operation_id = _selected(installation, "installationActivityId")
    installation_at = _time(_selected(installation, "lastModifiedTime"))
    installed = _selected(installation, "installedPatchCount")
    failed = _selected(installation, "failedPatchCount")
    pending = _selected(installation, "pendingPatchCount")
    if not isinstance(operation_id, str) or not operation_id.strip() or installation_at is None:
        return _decision("UNKNOWN", "installation operation identity or timestamp absent")
    if not 0 <= (now - installation_at).total_seconds() <= max_age_seconds:
        return _decision("UNKNOWN", "native patch installation stale or future dated")
    if assessment_at <= installation_at:
        return _decision("UNKNOWN", "zero-pending assessment predates patch installation")
    if _selected(installation, "status") != "Succeeded":
        return _decision("UNKNOWN", "latest native patch installation not Succeeded")
    if any(type(value) is not int or value < 0 for value in (installed, failed, pending)):
        return _decision("UNKNOWN", "native patch installation counts unavailable")
    if installed == 0:
        return _decision("UNKNOWN", "successful operation did not report an installed patch")
    if failed or pending or _selected(installation, "maintenanceWindowExceeded") is not False:
        return _decision("UNKNOWN", "installation incomplete or maintenance-window outcome unresolved")
    # Compute documents lastModifiedTime on LastPatchInstallationSummary as the
    # operation START, so it cannot by itself order assessment after completion.
    if not isinstance(installation_result, dict):
        return _decision("UNKNOWN", "completed Update Manager installation result absent")
    result_id = _selected(installation_result, "id")
    expected_id = vm["id"].rstrip("/") + "/patchInstallationResults/" + operation_id
    provenance = _selected(installation_result, "_provenance")
    if (not isinstance(result_id, str) or result_id.casefold() != expected_id.casefold()
            or str(_selected(installation_result, "type", "")).casefold() != "patchinstallationresults"
            or not isinstance(provenance, dict)
            or _selected(provenance, "source_operation") != "ResourceGraph:patchinstallationresources"
            or _selected(provenance, "read_only") is not True):
        return _decision("UNKNOWN", "completed installation result VM, operation or source unbound")
    result_props = _selected(installation_result, "properties")
    if not isinstance(result_props, dict) or _selected(result_props, "installationActivityId") != operation_id:
        return _decision("UNKNOWN", "completed installation result operation mismatch")
    completed_at = _time(_selected(result_props, "lastModifiedDateTime"))
    if completed_at is None or not installation_at <= completed_at < assessment_at:
        return _decision("UNKNOWN", "post-installation assessment chronology unproven")
    if not 0 <= (now - completed_at).total_seconds() <= max_age_seconds:
        return _decision("UNKNOWN", "completed installation result stale or future dated")
    if _selected(result_props, "status") != "Succeeded":
        return _decision("UNKNOWN", "completed installation result not Succeeded")
    counts = (_selected(result_props, "installedPatchCount"), _selected(result_props, "failedPatchCount"),
              _selected(result_props, "pendingPatchCount"))
    if any(type(value) is not int for value in counts) or counts != (installed, failed, pending):
        return _decision("UNKNOWN", "completed installation result counts mismatch")
    if _selected(result_props, "maintenanceWindowExceeded") is not False:
        return _decision("UNKNOWN", "completed installation result exceeded maintenance window")
    if _selected(result_props, "rebootStatus") not in ("NotNeeded", "Completed"):
        return _decision("UNKNOWN", "post-installation reboot completion unproven")
    return _decision("PASS", "successful native installation followed by zero-pending assessment",
                     vm_id=vm["id"], installation_activity_id=operation_id,
                     installed_patch_count=installed, installation_started_at=installation_at.isoformat(),
                     installation_completed_record_at=completed_at.isoformat(),
                     assessment_at=assessment_at.isoformat())


def evaluate_vm_patch_installation(vm, *, observed_at, max_age_seconds,
                                   require_actual_installation=True, installation_result=None):
    """Evaluate only observed native patch fields; unreadable proof is unknown."""
    try:
        return _evaluate_vm_patch_installation(
            vm, observed_at=observed_at, max_age_seconds=max_age_seconds,
            require_actual_installation=require_actual_installation,
            installation_result=installation_result)
    except ValueError as exc:
        return _decision("UNKNOWN", "selected native patch evidence unavailable", detail=str(exc))
