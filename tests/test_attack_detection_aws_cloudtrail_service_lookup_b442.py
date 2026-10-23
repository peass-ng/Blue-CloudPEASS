"""Synthetic derivative of an owned restricted CloudTrail LookupEvents lab."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"
RULE = Rule(
    id="service-history", title="Service history read", level="low",
    description="synthetic", product="aws",
    technique_id="aws-cloudtrail-service-event-history-lookup",
    selection={
        "event.source": "cloudtrail.amazonaws.com", "event.name": "LookupEvents",
        "event.outcome": "success", "request.cloudtrail_service_history_lookup": True,
    },
)
CHAIN = Rule(
    id="denied-list-history", title="History fallback", level="medium",
    description="synthetic", product="aws",
    technique_id="aws-cloudtrail-denied-list-history-fallback",
    selection={
        "event.source": "cloudtrail.amazonaws.com", "event.name": "LookupEvents",
        "event.outcome": "success", "request.cloudtrail_after_denied_service_list": True,
    },
)


def event():
    return {
        "eventSource": "cloudtrail.amazonaws.com", "eventName": "LookupEvents",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT,
        "eventID": "synthetic-event", "eventTime": "2026-10-23T04:00:00Z",
        "userIdentity": {"arn": ACTOR},
        "requestParameters": {"lookupAttributes": [
            {"attributeKey": "EventSource", "attributeValue": "cloudcontrolapi.amazonaws.com"}
        ], "maxResults": 50},
        "responseElements": None,
    }


def test_filtered_history_read_and_privacy():
    hits = detect_aws_events([event()], [RULE])
    assert len(hits) == 1 and hits[0].technique_id == RULE.technique_id
    assert ACTOR not in str(hits)


def test_other_queries_and_denials_excluded():
    for edit in (
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=False),
        lambda e: e["requestParameters"]["lookupAttributes"][0].update(attributeKey="Username"),
        lambda e: e["requestParameters"]["lookupAttributes"][0].update(attributeValue="invalid"),
        lambda e: e["requestParameters"].pop("lookupAttributes"),
    ):
        record = deepcopy(event())
        edit(record)
        assert detect_aws_events([record], [RULE]) == []


def denied_list():
    return {
        "eventSource": "cloudcontrolapi.amazonaws.com",
        "eventName": "ListResourceRequests", "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": True, "errorCode": "AccessDenied",
        "recipientAccountId": ACCOUNT,
        "eventID": "synthetic-denial", "eventTime": "2026-10-23T03:59:59Z",
        "userIdentity": {"arn": ACTOR},
        "requestParameters": None, "responseElements": None,
    }


def test_denied_service_list_then_history_lookup():
    hits = detect_aws_events([event(), denied_list()], [CHAIN])
    assert len(hits) == 1 and hits[0].technique_id == CHAIN.technique_id
    both = detect_aws_events([event(), denied_list()], [RULE, CHAIN])
    assert sorted(hit.technique_id for hit in both) == sorted((RULE.technique_id, CHAIN.technique_id))
    for edit in (
        lambda r: r.update(eventSource="s3.amazonaws.com"),
        lambda r: r.update(eventTime="2026-10-23T03:40:00Z"),
        lambda r: r["userIdentity"].update(arn=f"arn:aws:iam::{ACCOUNT}:user/other"),
        lambda r: r.update(errorCode="ThrottlingException"),
    ):
        denied = denied_list()
        edit(denied)
        assert detect_aws_events([event(), denied], [CHAIN]) == []
