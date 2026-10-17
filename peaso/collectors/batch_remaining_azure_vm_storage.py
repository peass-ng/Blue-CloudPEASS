"""Read-only Azure VM guest report extension for signed native checks.

The caller runs this only after a complete VM inventory with its paged embedded
Guest Configuration assignments. All requests use the caller's retry and budget.
"""
from __future__ import annotations

from datetime import datetime, timezone
from .azure import ARM, AzureReadError

KIND = "guest_configuration_report"
VERSION = "2024-04-05"


def _bounded_text(value, *, maximum=256):
    if (not isinstance(value, str) or not value or len(value) > maximum or
            any(ord(char) < 32 or ord(char) == 127 for char in value)):
        raise ValueError("guest report text field malformed")
    return value


def _project_resource(raw):
    if not isinstance(raw, dict):
        raise ValueError("guest report resource malformed")
    rid = raw.get("resourceId")
    if rid is not None:
        rid = _bounded_text(rid)
    status = raw.get("complianceStatus")
    if status not in ("Compliant", "NonCompliant"):
        raise ValueError("guest report resource compliance unavailable")
    original = raw.get("properties")
    if not isinstance(original, dict):
        raise ValueError("guest report resource properties unavailable")
    projected = {}
    literal = {"group": {"Administrators"}, "store": {"LocalMachine\\Root"},
               "serviceName": {"TermService"}, "state": {"Running", "Stopped", "Disabled"},
               "path": {"/etc/passwd"}}
    for key, allowed in literal.items():
        if key in original:
            value = _bounded_text(original[key])
            if value not in allowed:
                raise ValueError("guest report resource enum unsupported")
            projected[key] = value
    for key in ("membershipComplete", "certificateSetComplete"):
        if key in original:
            if type(original[key]) is not bool:
                raise ValueError("guest report resource completeness malformed")
            projected[key] = original[key]
    for key in ("observedMembers", "observedThumbprints"):
        if key in original:
            values = original[key]
            if not isinstance(values, list) or len(values) > 1024:
                raise ValueError("guest report observed set malformed")
            projected[key] = [_bounded_text(value) for value in values]
    if "mode" in original:
        value = _bounded_text(original["mode"], maximum=4)
        if len(value) != 4 or value[0] != "0" or any(char not in "01234567" for char in value[1:]):
            raise ValueError("guest report mode malformed")
        projected["mode"] = value
    if "settingName" in original:
        projected["settingName"] = _bounded_text(original["settingName"], maximum=128)
    safe_settings = {"NotConfigured", "Enabled", "Disabled", "Allow", "Block", "True", "False"}
    for key in ("expected", "observed"):
        if key in original:
            value = original[key]
            if type(value) is str:
                value = _bounded_text(value, maximum=64)
                if value not in safe_settings:
                    raise ValueError("guest report setting value unsupported")
            elif type(value) not in (bool, int) or type(value) is int and not 0 <= value <= 100000:
                raise ValueError("guest report setting value malformed")
            projected[key] = value
    return {**({"resourceId": rid} if rid is not None else {}),
            "complianceStatus": status, "properties": projected}


def _matching_parent(reader, scope):
    parents = [row for row in reader.collections if row.get("type") == "vm" and
               str(row.get("scope", "")).casefold() == scope.casefold()]
    if len(parents) != 1 or parents[0].get("status") not in ("collected", "empty"):
        raise AzureReadError("parent_vm_inventory_unavailable")
    return parents[0]


def _report_job(reader, request, scope, vm, assignment):
    vm_id, aid = vm.get("id"), assignment.get("id")
    if (not isinstance(vm_id, str) or not vm_id.casefold().startswith(scope.casefold() + "/") or
            not isinstance(aid, str) or not aid.casefold().startswith(vm_id.casefold() +
                "/providers/microsoft.guestconfiguration/guestconfigurationassignments/")):
        raise ValueError("foreign VM or guest assignment identity")
    properties = assignment.get("properties")
    config = properties.get("guestConfiguration") if isinstance(properties, dict) else None
    latest = properties.get("latestReportId") if isinstance(properties, dict) else None
    if not isinstance(latest, str) or not latest or "/" in latest and not latest.casefold().startswith(aid.casefold() + "/reports/"):
        raise AzureReadError("latest_guest_report_id_unavailable")
    expected = latest if latest.startswith("/") else aid + "/reports/" + latest
    suffix = expected[len(aid + "/reports/"):]
    if (not expected.casefold().startswith(aid.casefold() + "/reports/") or
            not suffix or "/" in suffix or "?" in suffix or "#" in suffix or
            not isinstance(config, dict) or not all(isinstance(config.get(k), str) and config[k] for k in ("name", "version"))):
        raise ValueError("malformed report or baseline identity")
    name = assignment.get("name")
    if not isinstance(name, str) or not name or aid.rsplit("/", 1)[-1].casefold() != name.casefold():
        raise ValueError("assignment name differs from ARM identity")
    url = ARM + expected + "?api-version=" + VERSION

    def fetch():
        row = reader.call(request, url)
        if not isinstance(row, dict) or str(row.get("id", "")).casefold() != expected.casefold():
            raise ValueError("guest report identity differs from requested report")
        props = row.get("properties")
        if not isinstance(props, dict):
            raise ValueError("guest report properties absent")
        details = props.get("details")
        resources = details.get("resources") if isinstance(details, dict) else None
        if not isinstance(resources, list) or not resources or len(resources) > 10000:
            raise ValueError("guest report resource details incomplete")
        resources = [_project_resource(value) for value in resources]
        # These are identity joins from the paged VM and assignment parents,
        # never guessed VM or policy content from a report summary.
        observed_vm = props.get("vm")
        if isinstance(observed_vm, dict) and "id" in observed_vm and str(observed_vm["id"]).casefold() != vm_id.casefold():
            raise ValueError("guest report VM identity conflicts with parent")
        observed_assignment = props.get("assignment")
        if isinstance(observed_assignment, dict) and "name" in observed_assignment and observed_assignment["name"] != name:
            raise ValueError("guest report assignment conflicts with parent")
        end_time = _bounded_text(props.get("endTime"), maximum=64)
        report_id = _bounded_text(props.get("reportId"), maximum=256)
        if report_id.casefold() != suffix.casefold():
            raise ValueError("guest reportId differs from requested latest report")
        compliance = props.get("complianceStatus")
        if compliance not in ("Compliant", "NonCompliant"):
            raise ValueError("guest report compliance status unavailable")
        operation = _bounded_text(details.get("operationType"), maximum=128)
        props = {"endTime": end_time, "reportId": report_id, "complianceStatus": compliance,
                 "details": {"resources": resources, "operationType": operation}, "vm": {"id": vm_id},
                 "assignment": {"name": name, "configuration": {"name": config["name"], "version": config["version"]}}}
        now = datetime.now(timezone.utc).isoformat()
        yield [{"id": expected, "properties": props,
                "_coverage": {"resources": {"status": "collected"}},
                "_provenance": {"read_only": True, "source_operation": "GET", "observed_at": now,
                                "api_version": VERSION, "parent_vm_id": vm_id, "assignment_id": aid}}]
    return KIND, scope, "Microsoft.GuestConfiguration", fetch


def collect_guest_configuration_reports(reader, request, scopes):
    """Append complete, partial, or denied report coverage per selected scope."""
    for scope in scopes:
        try:
            parent = _matching_parent(reader, scope)
            jobs = []
            for vm in parent["items"]:
                coverage = vm.get("_coverage", {}).get("guestConfigurationAssignments", {})
                assignments = vm.get("guestConfigurationAssignments")
                if (coverage.get("status") not in ("collected", "empty") or not isinstance(assignments, list) or
                        any(not isinstance(x, dict) for x in assignments) or
                        (coverage["status"] == "empty") != (not assignments)):
                    raise AzureReadError("guest_assignment_inventory_unavailable")
                for assignment in assignments:
                    jobs.append(_report_job(reader, request, scope, vm, assignment))
            if jobs:
                reader.run(jobs)
            else:
                reader.collections.append({"type": KIND, "scope": scope,
                                           "service": "Microsoft.GuestConfiguration", "status": "empty", "items": [],
                                           "parent_inventory": "vm"})
        except Exception as exc:
            reader.unavailable(KIND, scope, "Microsoft.GuestConfiguration", exc)

GUEST_CHECK_IDS = frozenset({
    "azure.gap.compute_vm_administrators_group_with_extra_accounts_windows",
    "azure.gap.compute_vm_administrators_group_with_no_specified_members_windows",
    "azure.gap.compute_vm_administrators_group_with_specified_members_windows",
    "azure.gap.compute_vm_meet_firewall_properties_windows",
    "azure.gap.compute_vm_password_file_permissions_0644_linux",
    "azure.gap.compute_vm_with_no_specified_certificates_in_trusted_root_windows",
})
GUEST_POLICY_FIELDS = frozenset({
    "assignmentName", "configurationName", "configurationVersion", "maxReportAgeSeconds",
    "approvedAdministrators", "requiredAdministrators", "prohibitedAdministrators",
    "requiredThumbprints", "emptyRequiredSetApproved", "requiredSettings",
})


def project_guest_policy(options, scopes):
    """Project only explicit, scope-bound non-secret baseline inputs."""
    from .azure import _metadata_only
    parent = options.get("compliance_policy")
    raw = parent.get("azure_vm_storage") if isinstance(parent, dict) else None
    if not isinstance(raw, dict) or raw.get("status") != "collected":
        return None
    scope = raw.get("scope")
    if not isinstance(scope, str) or scope.casefold() not in {s.casefold() for s in scopes}:
        return None
    checks = raw.get("checks")
    if not isinstance(checks, dict) or not checks or set(checks) - GUEST_CHECK_IDS:
        return None
    projected = {}
    for check_id, policy in checks.items():
        if not isinstance(policy, dict):
            return None
        projected[check_id] = _metadata_only({key: value for key, value in policy.items()
                                              if key in GUEST_POLICY_FIELDS})
    return {"status": "collected", "scope": scope, "checks": projected}


def merge_guest_policy(existing, guest):
    """Keep existing owner policy intact; reject conflicting scope or keys."""
    if guest is None:
        return existing, None
    if existing is None:
        return guest, None
    if not isinstance(existing, dict):
        return existing, "existing_policy_malformed"
    scope = guest["scope"]
    owner_scope = existing.get("scope")
    sw03 = existing.get("sw03")
    if (owner_scope is not None and (not isinstance(owner_scope, str) or owner_scope.casefold() != scope.casefold()) or
            isinstance(sw03, dict) and isinstance(sw03.get("scope"), str) and sw03["scope"].casefold() != scope.casefold()):
        return existing, "owner_policy_scope_conflict"
    status = existing.get("status")
    if status is not None and status != "collected":
        return existing, "owner_policy_status_conflict"
    old_checks = existing.get("checks", {})
    if not isinstance(old_checks, dict):
        return existing, "existing_check_policy_malformed"
    if any(key in old_checks and old_checks[key] != value for key, value in guest["checks"].items()):
        return existing, "owner_check_policy_conflict"
    return {**existing, "status": "collected", "scope": scope,
            "checks": {**old_checks, **guest["checks"]}}, None
