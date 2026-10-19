"""GuardDuty filter and detector changes with concrete request predicates."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import Any


def normalize_aws_guardduty_controls(record: Mapping[str, Any]) -> dict[str, Any] | None:
    if record.get("eventSource") != "guardduty.amazonaws.com":
        return None
    name = record.get("eventName")
    if name not in {"CreateFilter", "UpdateFilter", "UpdateDetector", "CreateIPSet", "UpdateIPSet"}:
        return None
    if (record.get("eventCategory") != "Management" or record.get("eventType") != "AwsApiCall"
            or record.get("managementEvent") is not True or record.get("readOnly") is not False):
        return None
    request = record.get("requestParameters")
    if not isinstance(request, Mapping):
        return None
    detector = request.get("detectorId")
    if not isinstance(detector, str) or not re.fullmatch(r"[0-9a-f]{32}", detector):
        return None
    response = record.get("responseElements")
    failed = bool(record.get("errorCode") or record.get("errorMessage")
                  or isinstance(response, Mapping) and (response.get("errorCode") or response.get("errorMessage")))
    filter_name = request.get("name" if name == "CreateFilter" else "filterName")
    filter_accepted = (name in {"CreateFilter", "UpdateFilter"}
                       and isinstance(filter_name, str) and bool(filter_name)
                       and isinstance(response, Mapping) and response.get("name") == filter_name)
    criteria = request.get("findingCriteria")
    criterion = criteria.get("criterion") if isinstance(criteria, Mapping) else None
    features = request.get("features")
    feature_disabled = (isinstance(features, list)
                        and any(isinstance(f, Mapping) and isinstance(f.get("name"), str)
                                and f.get("status") == "DISABLED" for f in features))
    identity = record.get("userIdentity")
    identity = identity if isinstance(identity, Mapping) else {}
    return {
        "cloud.provider": "aws", "event.source": "guardduty.amazonaws.com",
        "event.name": name, "event.outcome": "failure" if failed else "success",
        "event.id": record.get("eventID"), "event.time": record.get("eventTime"),
        "account.id": record.get("recipientAccountId"), "actor.id": identity.get("arn"),
        "target.id": detector,
        "request.suppression_filter_created": (
            not failed and name == "CreateFilter" and filter_accepted
            and request.get("action") == "ARCHIVE" and isinstance(criterion, Mapping) and bool(criterion)
        ),
        "request.suppression_filter_updated": (
            not failed and name == "UpdateFilter" and filter_accepted
            and request.get("action") == "ARCHIVE"
        ),
        "request.detector_feature_disable_requested": (
            not failed and name == "UpdateDetector" and feature_disabled
        ),
        "request.finding_frequency_six_hours_requested": (
            not failed and name == "UpdateDetector" and request.get("findingPublishingFrequency") == "SIX_HOURS"
        ),
        "request.trusted_ip_set_activation_requested": (
            not failed and name in {"CreateIPSet", "UpdateIPSet"}
            and request.get("activate") is True
            and (name != "CreateIPSet" or (isinstance(request.get("location"), str)
                and request["location"].startswith("https://")))
        ),
    }
