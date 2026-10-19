"""Wide future anomaly exclusions and deletion are separate signals."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="wide", title="Wide exclusion", level="medium", description="wide",
         technique_id="aws-cloudwatch-anomaly-detector-wide-future-exclusion", product="aws",
         selection={"event.source": "monitoring.amazonaws.com", "event.name": "PutAnomalyDetector",
                    "event.outcome": "success", "request.anomaly_detector_wide_future_exclusion": True}),
    Rule(id="delete", title="Detector deletion", level="low", description="delete",
         technique_id="aws-cloudwatch-anomaly-detector-deleted", product="aws",
         selection={"event.source": "monitoring.amazonaws.com", "event.name": "DeleteAnomalyDetector",
                    "event.outcome": "success", "request.anomaly_detector_deleted": True}),
]


def _event(name: str, request: dict) -> dict:
    return {"eventSource": "monitoring.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "eventTime": "2026-10-19T10:00:00Z", "recipientAccountId": "947247140022",
            "requestParameters": {"namespace": "Synthetic", "metricName": "Metric", "stat": "Sum", **request},
            "responseElements": None}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_multiyear_future_exclusion_and_short_range() -> None:
    event = _event("PutAnomalyDetector", {"configuration": {"excludedTimeRanges": [{
        "startTime": "2020-01-01T00:00:00Z", "endTime": "2050-01-01T00:00:00Z"}]}})
    assert _hits(event) == ["aws-cloudwatch-anomaly-detector-wide-future-exclusion"]
    for variant in ("short", "past", "error"):
        item = deepcopy(event)
        times = item["requestParameters"]["configuration"]["excludedTimeRanges"][0]
        if variant == "short": times["startTime"] = "2049-01-01T00:00:00Z"
        if variant == "past": times["endTime"] = "2025-01-01T00:00:00Z"
        if variant == "error": item["errorCode"] = "AccessDenied"
        assert _hits(item) == [], variant


def test_delete_anomaly_detector_and_failed_call() -> None:
    event = _event("DeleteAnomalyDetector", {})
    assert _hits(event) == ["aws-cloudwatch-anomaly-detector-deleted"]
    event["errorCode"] = "ResourceNotFoundException"
    assert _hits(event) == []
