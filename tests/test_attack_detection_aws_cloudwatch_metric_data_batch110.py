"""Synthetic derivatives of an owned CloudWatch metric data/stream lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
REGION = "eu-west-1"
NAMESPACE = "PeassoSynthetic/Batch110"
STREAM = "synthetic-stream"
ROLE_A = f"arn:aws:iam::{ACCOUNT}:role/synthetic-cw-a"
ROLE_B = f"arn:aws:iam::{ACCOUNT}:role/synthetic-cw-b"
FIREHOSE_A = f"arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/synthetic-a"
FIREHOSE_B = f"arn:aws:firehose:{REGION}:{ACCOUNT}:deliverystream/synthetic-b"
STREAM_ARN = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:metric-stream/{STREAM}"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-actor"
IDS = {
    "aws-cloudwatch-metric-data-published",
    "aws-cloudwatch-metric-data-write-burst",
    "aws-cloudwatch-metric-stream-metric-names-expanded",
    "aws-cloudwatch-metric-stream-destination-changed",
    "aws-cloudwatch-metric-stream-role-rebound",
    "aws-cloudwatch-metric-stream-output-format-changed",
}


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id in IDS]
    assert len(selected) == 6
    return selected


def event(name, second, request, *, data=False, response=None):
    return {
        "eventSource": "monitoring.amazonaws.com", "eventName": name,
        "eventCategory": "Data" if data else "Management",
        "eventType": "AwsApiCall", "managementEvent": not data,
        "readOnly": False, "recipientAccountId": ACCOUNT, "awsRegion": REGION,
        "eventID": f"77777777-7777-4777-8777-{second:012d}",
        "eventTime": f"2026-10-21T06:10:{second:02d}Z",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
        "requestParameters": request, "responseElements": response,
    }


def put_stream(second, *, firehose=FIREHOSE_A, role=ROLE_A,
               names=("CanaryA",), output="json"):
    return event("PutMetricStream", second, {
        "name": STREAM, "firehoseArn": firehose, "roleArn": role,
        "outputFormat": output,
        "includeFilters": [{"namespace": NAMESPACE, "metricNames": list(names)}],
    }, response={"arn": STREAM_ARN})


def publish(second, name="CanaryA"):
    return event("PutMetricData", second, {"namespace": NAMESPACE,
        "metricData": [{"metricName": name, "value": 123.0}]}, data=True)


def sample():
    return [
        put_stream(1),
        publish(3),
        put_stream(5, names=("CanaryA", "CanaryB")),
        put_stream(7, firehose=FIREHOSE_B, names=("CanaryA", "CanaryB")),
        put_stream(9, firehose=FIREHOSE_B, role=ROLE_B,
                   names=("CanaryA", "CanaryB")),
        put_stream(11, firehose=FIREHOSE_B, role=ROLE_B,
                   names=("CanaryA", "CanaryB"), output="opentelemetry0.7"),
        publish(13, "CanaryB"), publish(15, "CanaryB"),
        publish(17, "CanaryB"), publish(19, "CanaryB"),
    ]


def test_six_routes_match_owned_event_derivatives():
    hits = detect_aws_events(sample(), rules())
    assert {hit.technique_id for hit in hits} == IDS
    assert len(hits) == 10  # Five data writes, four stream changes, one burst.
    assert all(ROLE_A not in str(hit) and ROLE_B not in str(hit)
               and FIREHOSE_A not in str(hit) and FIREHOSE_B not in str(hit)
               for hit in hits)
    assert sum(bool(hit.evidence.get("correlation")) for hit in hits) == 5


def test_same_second_and_cross_account_changes_are_not_ordered():
    rows = sample()
    same_second = deepcopy(rows)
    same_second[2]["eventTime"] = same_second[0]["eventTime"]
    assert not any(hit.technique_id ==
                   "aws-cloudwatch-metric-stream-metric-names-expanded"
                   for hit in detect_aws_events(same_second, rules()))
    foreign = deepcopy(rows[:3])
    foreign[0]["recipientAccountId"] = "111111111111"
    assert not any(hit.technique_id ==
                   "aws-cloudwatch-metric-stream-metric-names-expanded"
                   for hit in detect_aws_events(foreign, rules()))
    other_namespace = deepcopy(rows[:3])
    other_namespace[0]["requestParameters"]["includeFilters"][0]["namespace"] = (
        "PeassoSynthetic/Other")
    assert not any(hit.technique_id ==
                   "aws-cloudwatch-metric-stream-metric-names-expanded"
                   for hit in detect_aws_events(other_namespace, rules()))


def test_failed_data_missing_payload_and_failed_stream_are_excluded():
    rows = sample()
    failed_data = deepcopy(rows[1])
    failed_data["errorCode"] = "AccessDenied"
    no_metric = deepcopy(rows[1])
    no_metric["requestParameters"]["metricData"] = []
    failed_update = deepcopy(rows[2])
    failed_update["errorCode"] = "AccessDenied"
    wrong_category = deepcopy(rows[1])
    wrong_category["eventCategory"] = "Management"
    assert detect_aws_events([failed_data, no_metric, wrong_category], rules()) == []
    assert not any(hit.technique_id.endswith("metric-names-expanded")
                   for hit in detect_aws_events([rows[0], failed_update], rules()))


def test_burst_requires_five_distinct_accepted_calls():
    writes = [publish(second) for second in (1, 3, 5, 7)]
    assert not any(hit.technique_id == "aws-cloudwatch-metric-data-write-burst"
                   for hit in detect_aws_events(writes + [deepcopy(writes[0])], rules()))
    assert sum(hit.technique_id == "aws-cloudwatch-metric-data-write-burst"
               for hit in detect_aws_events(writes + [publish(9)], rules())) == 1


def test_delete_between_stream_definitions_clears_prior_state():
    delete = event("DeleteMetricStream", 4, {"name": STREAM})
    hits = detect_aws_events([put_stream(1), delete,
                              put_stream(5, names=("CanaryA", "CanaryB"))], rules())
    assert not any(hit.technique_id ==
                   "aws-cloudwatch-metric-stream-metric-names-expanded" for hit in hits)
