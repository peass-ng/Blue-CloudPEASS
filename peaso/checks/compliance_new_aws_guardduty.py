"""Signed GuardDuty high-finding predicate over complete cached inventories."""
from __future__ import annotations

import math
import re

from . import register, result, unknown
from .aws_a_facts import scope_subject
from .facts import Unavailable, complete_items, get
from .fixtures import CASES


def _scoped_items(index, kind, scope):
    envelopes = index.get("collections", {}).get(kind, [])
    if any(get(envelope, "scope", str) != scope for envelope in envelopes):
        raise Unavailable("foreign or mismatched collection scope: " + kind)
    return complete_items(index, kind)


@register(
    "aws_guardduty_no_active_high_findings", "aws", "hardening", "guardduty_finding",
    "Enabled GuardDuty detectors have no active high-severity findings", "high", "SI-4",
    "Investigate each active high-severity GuardDuty finding and remediate its affected resource before archiving it.",
    target="scope", dependencies=["guardduty_detector", "guardduty_finding"],
)
def no_active_high_findings(item, index):
    scope = scope_subject(item)
    account, region = scope.split("/", 1)
    detectors = _scoped_items(index, "guardduty_detector", scope)
    findings = _scoped_items(index, "guardduty_finding", scope)
    enabled = set()
    expected_ids = {}
    seen = set()
    for detector in detectors:
        detector_id = get(detector, "DetectorId", str)
        if not detector_id or detector_id in seen:
            return unknown("missing or duplicate GuardDuty detector ID")
        seen.add(detector_id)
        status = get(detector, "Configuration.Status", str)
        if status not in ("ENABLED", "DISABLED"):
            return unknown("unrecognized GuardDuty detector status", detector_id=detector_id)
        if status == "ENABLED":
            enabled.add(detector_id)
            listing_status = get(detector, "FindingIds.collection_status", str)
            if listing_status not in ("collected", "empty"):
                return unknown("detector finding-ID inventory incomplete", detector_id=detector_id)
            ids = get(detector, "FindingIds.items", list)
            if (any(not isinstance(value, str) or not value for value in ids) or
                    len(ids) != len(set(ids)) or (listing_status == "empty" and ids)):
                return unknown("malformed detector finding-ID inventory", detector_id=detector_id)
            expected_ids[detector_id] = set(ids)

    if not enabled:
        return "NOT_APPLICABLE", {"reason": "no enabled GuardDuty detector in this complete account/Region inventory"}

    active_high = []
    observed_ids = {detector_id: set() for detector_id in enabled}
    for finding in findings:
        finding_id = get(finding, "Id", str)
        finding_account = get(finding, "AccountId", str)
        finding_region = get(finding, "Region", str)
        detector_id = get(finding, "Service.DetectorId", str)
        if (not finding_id or not detector_id or not re.fullmatch(r"[0-9]{12}", finding_account)
                or not re.fullmatch(r"[a-z]{2}(?:-[a-z]+)+-[0-9]", finding_region)):
            return unknown("malformed GuardDuty finding identity")
        if detector_id not in seen:
            return unknown("finding detector not in complete scoped detector inventory", detector_id=detector_id)
        if detector_id not in enabled:
            continue
        if finding_id in observed_ids[detector_id]:
            return unknown("duplicate GuardDuty finding ID", detector_id=detector_id)
        observed_ids[detector_id].add(finding_id)
        # Delegated administrators can see member-account findings. Count them
        # for inventory completeness, but do not grade another account/Region.
        if finding_account != account or finding_region != region:
            continue
        archived = get(finding, "Service.Archived", bool)
        severity = get(finding, "Severity")
        if isinstance(severity, bool) or not isinstance(severity, (int, float)) or not math.isfinite(severity):
            return unknown("malformed GuardDuty finding severity")
        if not archived and 7.0 <= severity < 9.0:
            active_high.append(finding_id)

    # The collector's independent finding-ID and GetFindings reads can race.
    # A mismatch cannot prove a clean inventory; it also catches malformed
    # IDs that the current GetFindings fetcher skips while chunking.
    if observed_ids != expected_ids:
        return unknown("detector finding IDs differ from projected finding inventory")

    return result(bool(active_high), enabled_detector_ids=sorted(enabled),
                  active_high_finding_ids=sorted(active_high),
                  high_severity_range="7.0 <= Severity < 9.0",
                  semantics="Only unarchived findings for this account/Region; critical 9.0+ is a separate severity")


def _guardduty_index(finding=None, *, finding_status="collected"):
    scope = "123456789012/us-east-1"
    detector = {"DetectorId": "det-inert", "Configuration": {"Status": "ENABLED"},
        "FindingIds": {"collection_status": "collected" if finding else "empty",
            "items": [finding["Id"]] if finding else []}}
    return {"collections": {
        "guardduty_detector": [{"scope": scope, "status": "collected"}],
        "guardduty_finding": [{"scope": scope, "status": finding_status}]},
        "guardduty_detector": [{"data": detector}],
        "guardduty_finding": [{"data": finding}] if finding else []}


_high_finding = {"Id": "finding-inert", "AccountId": "123456789012",
    "Region": "us-east-1", "Severity": 7.5,
    "Service": {"DetectorId": "det-inert", "Archived": False}}
CASES["aws_guardduty_no_active_high_findings"] = {
    "pass": {"scope": "123456789012/us-east-1"},
    "pass_index": _guardduty_index(),
    "fail": {"scope": "123456789012/us-east-1"},
    "fail_index": _guardduty_index(_high_finding),
    "unknown": {"scope": "123456789012/us-east-1"},
    "unknown_index": _guardduty_index(finding_status="partial"),
    "index": _guardduty_index(),
}
