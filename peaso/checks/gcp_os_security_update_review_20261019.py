"""Pure consumer of native OS Config assessment metadata.

A result describes the collected report at updateTime. It makes no current
patch-compliance, freshness, package-age, installation or publication claim.
Explicit registration is available; source mappings and presentation remain root-owned.
"""
from collections import Counter
from datetime import datetime
import json
import re

from .facts import Unavailable, get, guard, list_of_objects

CANDIDATE_ID = "gcp.compute.os_config_fixable_vulnerabilities"
KIND = "instance"
DEPENDENCIES = ("instance", "project", "os_vulnerability_report")
CLAIM = "Fixable known vulnerabilities in this VM's collected OS Config assessment at assessment_time"
DECLARATION = {
    "id": CANDIDATE_ID, "provider": "gcp", "category": "hardening", "kind": KIND,
    "finding_type": "vulnerabilities", "severity": "high", "dependencies": list(DEPENDENCIES),
    "requirements": [], "title": "VM assessment has no fixable known vulnerabilities",
    "remediation": "Apply applicable updates for the assessed fixable findings, then collect a new OS Config assessment.",
    "evidence_sentences": ["The OS Config assessment at {assessment_time} reports {fixable_finding_count} fixable known vulnerability findings for this VM.",
        "Current patch state and assessment freshness were not assessed."],
}
_SUPPORTED_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
_TIMESTAMP = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})\Z")


def _timestamp_ns(value):
    if not isinstance(value, str) or not (match := _TIMESTAMP.fullmatch(value)):
        raise Unavailable("native timestamp requires an explicit RFC3339 timezone")
    base, fraction, offset = match.groups()
    if offset != "Z" and (offset == "-00:00" or int(offset[1:3]) > 23 or int(offset[4:6]) > 59):
        raise Unavailable("native timestamp timezone offset is malformed or unknown")
    parsed = datetime.fromisoformat(base + ("+00:00" if offset == "Z" else offset))
    # Preserve nanoseconds: rounding to Python microseconds could hide a future report.
    return int(parsed.timestamp()) * 1_000_000_000 + int((fraction or "").ljust(9, "0"))


def _inventory(index, kind, scope):
    envelopes = get(index, "collections", dict).get(kind)
    if not isinstance(envelopes, list) or len(envelopes) != 1:
        raise Unavailable("one exact scoped inventory is required: " + kind)
    envelope = get({"envelope": envelopes[0]}, "envelope", dict)
    if (get(envelope, "type", str) != kind or get(envelope, "scope", str) != scope
            or envelope.get("status") not in ("collected", "empty")
            or envelope.get("coverage_status") != envelope["status"] or envelope.get("error")):
        raise Unavailable("native inventory is incomplete, denied, malformed or foreign: " + kind)
    rows = list_of_objects(get(envelope, "items", list))
    if (envelope["status"] == "empty") != (not rows):
        raise Unavailable("empty native inventory contradicts its rows: " + kind)
    wrappers = list_of_objects(get(index, kind, list))
    projected = []
    for wrapper in wrappers:
        if (get(wrapper, "type", str) != kind or get(wrapper, "provider", str) != "gcp"
                or get(wrapper, "scope", str) != scope):
            raise Unavailable("native resource wrapper belongs to another subject: " + kind)
        row = get(wrapper, "data", dict)
        if get(row, "_provenance.scope", str) != scope:
            raise Unavailable("native provenance belongs to another project: " + kind)
        projected.append(row)
    encode = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    if Counter(map(encode, rows)) != Counter(map(encode, projected)):
        raise Unavailable("native collection and resource projection disagree: " + kind)
    return projected


def _read_proof(row, ledger, url):
    refs = get(row, "_provenance.source_requests", list)
    if not refs or any(not isinstance(ref, str) or not ref for ref in refs) or len(refs) != len(set(refs)):
        raise Unavailable("native source request references are unavailable or duplicated")
    if not any(ref in ledger and ledger[ref].get("method") == "GET"
               and ledger[ref].get("url") == url and ledger[ref].get("status") == "collected"
               for ref in refs):
        raise Unavailable("native read request is unavailable or bound to another subject")


def _vm_identity(vm, aliases):
    name, number = get(vm, "name", str), get(vm, "id", str)
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name) or not re.fullmatch(r"[1-9][0-9]{0,19}", number):
        raise Unavailable("native VM name or numeric instance ID is malformed")
    if "zone" in vm or "zone" in vm.get("_coverage", {}):
        zone = get(vm, "zone", str)
        match = re.fullmatch(r"https://(?:www\.googleapis\.com|compute\.googleapis\.com)/compute/v1/projects/([^/]+)/zones/([^/]+)", zone)
        if not match or match[1] not in aliases:
            raise Unavailable("native VM zone project is unresolved or foreign")
        zone = match[2]
    else:
        aggregate = get(vm, "_aggregated_scope", str)
        if not aggregate.startswith("zones/") or aggregate.count("/") != 1:
            raise Unavailable("native VM aggregate zone is unresolved")
        zone = aggregate.split("/", 1)[1]
    if not re.fullmatch(r"[a-z][a-z0-9-]+-[a-z]", zone):
        raise Unavailable("native VM zone is malformed")
    if "selfLink" in vm or "selfLink" in vm.get("_coverage", {}):
        link = get(vm, "selfLink", str)
        match = re.fullmatch(r"https://(?:www\.googleapis\.com|compute\.googleapis\.com)/compute/v1/projects/([^/]+)/zones/([^/]+)/instances/([^/]+)", link)
        if not match or (match[1] not in aliases or match[2] != zone or match[3] != name):
            raise Unavailable("native VM self identity contradicts its project, zone or name")
    return zone, number, name


def _evaluate(item, index):
    guard(item)
    if get(index, "context.provider", str) != "gcp":
        raise Unavailable("GCP context is required")
    scope = get(index, "context.scope", str)
    if not re.fullmatch(r"projects/[A-Za-z0-9][A-Za-z0-9_-]*", scope):
        raise Unavailable("one exact project scope is required")
    captured = _timestamp_ns(get(index, "context.created_at", str))
    operations = list_of_objects(get(index, "context.metadata.source_requests", list))
    ledger = {}
    for operation in operations:
        ref = get(operation, "id", str)
        if not ref or ref in ledger:
            raise Unavailable("native operation identities are missing or ambiguous")
        ledger[ref] = operation
    projects = _inventory(index, "project", scope)
    if len(projects) != 1:
        raise Unavailable("independent project alias identity is missing or ambiguous")
    project = projects[0]
    project_id, numeric_name = get(project, "projectId", str), get(project, "name", str)
    if (not re.fullmatch(r"[a-z][a-z0-9-]{4,61}[a-z0-9]", project_id)
            or not re.fullmatch(r"projects/[1-9][0-9]*", numeric_name)):
        raise Unavailable("independent native project ID and number are required")
    aliases = {project_id, numeric_name.split("/", 1)[1]}
    if scope.split("/", 1)[1] not in aliases:
        raise Unavailable("selected project does not match independent project aliases")
    _read_proof(project, ledger, "https://cloudresourcemanager.googleapis.com/v3/" + scope)
    instances = _inventory(index, "instance", scope)
    if sum(row == item for row in instances) != 1:
        raise Unavailable("VM subject is not unique in the complete native inventory")
    identities = {}
    for vm in instances:
        zone, number, name = _vm_identity(vm, aliases)
        if (zone, number) in identities:
            raise Unavailable("numeric VM subject is ambiguous in its zone")
        identities[(zone, number)] = (name, vm)
        _read_proof(vm, ledger, "https://compute.googleapis.com/compute/v1/" + scope + "/aggregated/instances")
    target_zone, target_number, target_name = _vm_identity(item, aliases)
    reports = _inventory(index, "os_vulnerability_report", scope)
    if not reports or len(reports) != len(instances):
        raise Unavailable("complete VM-bound assessment reports are unavailable; empty inventory is not a clean assessment")
    selected, subjects = None, set()
    for report in reports:
        if get(report, "native_model", str) != "osconfig_v1":
            raise Unavailable("unsupported assessment representation")
        native_name = get(report, "name", str)
        match = re.fullmatch(r"projects/([^/]+)/locations/([^/]+)/instances/([1-9][0-9]*)/vulnerabilityReport", native_name)
        if not match or match[1] not in aliases:
            raise Unavailable("assessment project, zone or instance identity is unresolved")
        subject = (match[2], match[3])
        if subject in subjects or subject not in identities or get(report, "instanceName", str) != identities[subject][0]:
            raise Unavailable("assessment subject is duplicated, unmatched or contradictory")
        subjects.add(subject)
        expected = scope + "/locations/" + match[2] + "/instances/" + match[3] + "/vulnerabilityReport"
        _read_proof(report, ledger, "https://osconfig.googleapis.com/v1/" + expected)
        assessed = _timestamp_ns(get(report, "updateTime", str))
        collected = _timestamp_ns(get(report, "_provenance.collected_at", str))
        if assessed > collected or collected > captured:
            raise Unavailable("assessment time or native capture time is in the future")
        if subject == (target_zone, target_number):
            selected = report
    if selected is None:
        raise Unavailable("no assessment is bound to this VM")
    findings = list_of_objects(get(selected, "vulnerabilities", list))
    fixable_findings, reference_count, available_ids = 0, 0, set()
    for finding in findings:
        if get(finding, "severity", str) not in _SUPPORTED_SEVERITIES:
            raise Unavailable("assessment includes an unknown or unsupported vulnerability severity")
        entries = list_of_objects(get(finding, "items", list))
        if not entries:
            raise Unavailable("assessment vulnerability has no supported fix-item representation")
        fixable = False
        for entry in entries:
            # The native producer always emits this key. Native omission of the
            # empty provider string becomes None through dict.get; do not invent
            # package metadata or require an inventory join that may have aged out.
            reference = get(entry, "availableInventoryItemId")
            if reference is None or reference == "":
                continue
            if not isinstance(reference, str) or reference != reference.strip() or not reference or any(ord(c) < 32 for c in reference):
                raise Unavailable("available package reference is malformed")
            fixable = True
            reference_count += 1
            available_ids.add(reference)
        fixable_findings += int(fixable)
    evidence = {"claim": CLAIM, "instance": target_name, "instance_id": target_number,
                "project_id": project_id, "project_number": numeric_name.split("/", 1)[1],
                "zone": target_zone, "assessment_name": selected["name"], "assessment_time": selected["updateTime"],
                "captured_at": get(index, "context.created_at", str), "assessed_finding_count": len(findings),
                "fixable_finding_count": fixable_findings, "fixable_item_reference_count": reference_count,
                "available_inventory_item_ids": sorted(available_ids),
                "scope": "this matched collected assessment; current patch compliance and freshness are not assessed"}
    evidence["observed"] = " ".join(DECLARATION["evidence_sentences"]).format(**evidence)
    return ("FAIL" if fixable_findings else "PASS"), evidence


def evaluate(item, index):
    """Return an assessment-only verdict; expected native uncertainty is UNKNOWN."""
    try:
        return _evaluate(item, index)
    except (Unavailable, ValueError, TypeError, KeyError, IndexError, AttributeError, OverflowError) as exc:
        return "UNKNOWN", {"claim": CLAIM, "reason": str(exc) if isinstance(exc, Unavailable) else "malformed native assessment facts"}


def install():
    """Register once with native-produced assessment-only fixtures."""
    import gzip
    from pathlib import Path
    from . import CHECKS, register
    from .fixtures import CASES
    if any(check.id == CANDIDATE_ID for check in CHECKS):
        return
    cases = json.loads(gzip.decompress(Path(__file__).with_name(
        "gcp_os_security_update_fixtures.json.gz").read_bytes()))
    register(CANDIDATE_ID, "gcp", "hardening", KIND, DECLARATION["title"], "high",
             "security_configuration", DECLARATION["remediation"],
             dependencies=list(DEPENDENCIES))(evaluate)
    CASES[CANDIDATE_ID] = cases
