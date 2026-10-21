"""Synthetic derivatives of owned Metric Stream CloudTrail management records."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
NAME = "synthetic-metric-stream"
ARN = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:metric-stream/{NAME}"
FIREHOSE = f"arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/synthetic-firehose"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-metric-stream-role"
NAMESPACE_A = "PeassoSynthetic/Batch109/A"
NAMESPACE_B = "PeassoSynthetic/Batch109/B"
IDS = {
    "aws-cloudwatch-metric-stream-firehose-configured",
    "aws-cloudwatch-metric-stream-namespace-scope-expanded",
    "aws-cloudwatch-metric-stream-stopped",
    "aws-cloudwatch-metric-stream-started",
    "aws-cloudwatch-metric-stream-deleted",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 5
    return selected


def event(name, second, request, response=None, *, error=None):
    record = {
        "eventSource": "monitoring.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"99999999-9999-4999-8999-{second:012d}",
        "eventTime": f"2026-10-21T04:10:{second:02d}Z",
        "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT,
                         "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-role/session"},
        "requestParameters": request, "responseElements": response,
    }
    if error:
        record["errorCode"] = error
    return record


def put(second, namespaces):
    return event("PutMetricStream", second, {
        "name": NAME, "firehoseArn": FIREHOSE, "roleArn": ROLE,
        "outputFormat": "json",
        "includeFilters": [{"namespace": namespace} for namespace in namespaces],
    }, {"arn": ARN})


def sample():
    return [
        put(1, [NAMESPACE_A]),
        put(3, [NAMESPACE_A, NAMESPACE_B]),
        event("StopMetricStreams", 4, {"names": [NAME]}),
        event("StartMetricStreams", 5, {"names": [NAME]}),
        event("DeleteMetricStream", 6, {"name": NAME}),
    ]


def test_five_management_routes_match_synthetic_derivatives():
    hits = detect_aws_events(sample(), rules())
    assert len(hits) == 6  # Both accepted PutMetricStream requests are audit signals.
    assert {hit.technique_id for hit in hits} == IDS
    assert FIREHOSE not in str(hits) and ROLE not in str(hits)
    expanded = next(hit for hit in hits if hit.technique_id ==
                    "aws-cloudwatch-metric-stream-namespace-scope-expanded")
    assert len(expanded.evidence["correlation"]) == 1


def test_same_second_or_cross_account_update_does_not_claim_expansion():
    records = sample()
    same_second = deepcopy(records)
    same_second[1]["eventTime"] = same_second[0]["eventTime"]
    assert not any(hit.technique_id == "aws-cloudwatch-metric-stream-namespace-scope-expanded"
                   for hit in detect_aws_events(same_second, rules()))
    foreign = deepcopy(records)
    foreign[0]["recipientAccountId"] = "111111111111"
    assert not any(hit.technique_id == "aws-cloudwatch-metric-stream-namespace-scope-expanded"
                   for hit in detect_aws_events(foreign[:2], rules()))


def test_failures_malformed_targets_and_foreign_destination_are_excluded():
    records = sample()
    failed = deepcopy(records[0])
    failed["errorCode"] = "AccessDenied"
    foreign = deepcopy(records[0])
    foreign["requestParameters"]["firehoseArn"] = (
        f"arn:aws:firehose:{REGION}:111111111111:deliverystream/synthetic-foreign")
    malformed = deepcopy(records[2])
    malformed["requestParameters"]["names"] = [NAME, 42]
    bad_source = deepcopy(records[2])
    bad_source["eventName"] = ["StopMetricStreams"]
    assert detect_aws_events([failed, foreign, malformed, bad_source], rules()) == []
    assert [hit.technique_id for hit in detect_aws_events([bad_source, records[2]], rules())] == [
        "aws-cloudwatch-metric-stream-stopped"]
