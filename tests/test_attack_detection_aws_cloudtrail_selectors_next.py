"""CloudTrail selector reduction needs accepted, explicit settings."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="sources", title="Sources excluded", level="medium", description="exclude",
         technique_id="aws-cloudtrail-management-sources-excluded", product="aws",
         selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "PutEventSelectors",
                    "event.outcome": "success", "request.trail_management_sources_excluded": True}),
    Rule(id="insights", title="Insights disabled", level="medium", description="insights",
         technique_id="aws-cloudtrail-insights-disabled", product="aws",
         selection={"event.source": "cloudtrail.amazonaws.com", "event.name": "PutInsightSelectors",
                    "event.outcome": "success", "request.trail_insight_selectors_emptied": True}),
]


def _event(name: str, request: dict) -> dict:
    return {"eventSource": "cloudtrail.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "947247140022", "requestParameters": {"trailName": "synthetic", **request}}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_excluded_sources_and_normal_selector() -> None:
    event = _event("PutEventSelectors", {"eventSelectors": [{"readWriteType": "All",
                   "includeManagementEvents": True,
                   "excludeManagementEventSources": ["kms.amazonaws.com"]}]})
    assert _hits(event) == ["aws-cloudtrail-management-sources-excluded"]
    other = deepcopy(event)
    other["requestParameters"]["eventSelectors"][0]["excludeManagementEventSources"] = []
    assert _hits(other) == []
    other = deepcopy(event)
    other["errorCode"] = "InvalidParameterException"
    assert _hits(other) == []


def test_empty_insights_after_enabled_state() -> None:
    event = _event("PutInsightSelectors", {"insightSelectors": []})
    assert _hits(event) == ["aws-cloudtrail-insights-disabled"]
    event["requestParameters"]["insightSelectors"] = [{"insightType": "ApiCallRateInsight"}]
    assert _hits(event) == []
