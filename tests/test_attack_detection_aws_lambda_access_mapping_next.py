"""Lambda access and routing signals from synthetic owned-lab derivatives."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_lambda_access_mapping_lab_events.json"
IDS = {
    "0b6a8b71-17cc-4a6d-8108-6117cf2a9c4e",
    "2f795c50-2910-4c36-ac03-528b13066225",
    "a9496079-eff2-4eb6-976f-05f98406e315",
    "52104d13-2e33-4293-bc8e-1f7f1b884c8f",
    "8bda26bf-d28a-488e-84b4-4e7df92b00e2",
    "5aa8c5fc-5854-498b-877f-5b27d28c30c7",
    "06a05215-b05e-4857-9ce5-832f06922adb",
    "3ddf6ab7-d69a-44af-a963-f17f1b5c7964",
    "3997231a-cb99-4e42-a929-0ac67f462422",
}
REPOINT = "3997231a-cb99-4e42-a929-0ac67f462422"


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [rule for rule in load_rules(product="aws") if rule.id in IDS]
    assert len(rules) == 9
    return rules


def hits(records):
    return {item.rule_id for item in detect_aws_events(records, selected())}


def test_nine_lambda_signals_from_eight_management_events():
    records = events()
    detections = detect_aws_events(records, selected())
    assert len(records) == 8
    assert len(detections) == 9
    assert {item.rule_id for item in detections} == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)
    assert "SYNTHETIC_CANARY" not in repr(detections)
    assert "Location" not in repr(detections)


def test_read_events_require_success_and_read_only_management_shape():
    baseline = events()
    for index in range(5):
        records = deepcopy(baseline)
        records[index]["errorCode"] = "AccessDenied"
        assert len(hits(records)) == 8
        records = deepcopy(baseline)
        records[index]["readOnly"] = False
        assert len(hits(records)) == 8


def test_logging_signal_requires_nondefault_group_and_confirmed_response():
    baseline = events()
    missing = "5aa8c5fc-5854-498b-877f-5b27d28c30c7"
    for mutation in [
        lambda x: x["requestParameters"]["loggingConfig"].update(logGroup="/aws/lambda/synthetic-function-a"),
        lambda x: x["responseElements"]["loggingConfig"].update(logGroup="/aws/lambda/synthetic-function-a"),
        lambda x: x.update(errorCode="AccessDenied"),
    ]:
        records = deepcopy(baseline)
        mutation(records[5])
        assert missing not in hits(records)


def test_mapping_repoint_requires_same_mapping_source_and_changed_function():
    baseline = events()
    for mutation in [
        lambda x: x["requestParameters"].update(functionName="synthetic-function-a"),
        lambda x: x["responseElements"].update(functionArn="arn:aws:lambda:us-east-1:999999999999:function:synthetic-function-a"),
        lambda x: x["responseElements"].update(eventSourceArn="arn:aws:sqs:us-east-1:999999999999:other"),
        lambda x: x.update(eventTime="2026-10-20T16:00:00Z"),
    ]:
        records = deepcopy(baseline)
        mutation(records[-1])
        assert REPOINT not in hits(records)


def test_malformed_event_source_does_not_abort_valid_events():
    records = events()
    malformed = deepcopy(records[0])
    malformed["eventSource"] = ["lambda.amazonaws.com"]
    assert hits([malformed] + records) == IDS
