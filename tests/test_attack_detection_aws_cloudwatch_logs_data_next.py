"""Synthetic derivatives of an owned five-route CloudWatch Logs lab.

The real query ID, record pointer, log message, bucket and account stay in
private receipts. These tests verify detection shape and secret exclusion.
"""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-reader/session"
GROUP = "/peasso/synthetic/group"
STREAM = "synthetic-stream"
SECRET = "SYNTHETIC_MESSAGE_NEVER_EMIT"
RULE_IDS = {
    "9cafb3e1-6238-4a5d-b955-738d9eecd1e8",
    "b47c3759-bfd7-4abb-bab9-5a2b87ec82a9",
    "bd83cb3d-2b48-4fd3-a127-9ebed1e18a40",
    "fc22e136-4196-4098-9ac9-22e74bd1c492",
    "99d13eca-1038-40f7-bb9f-b8163083c0e9",
}


def rules():
    return tuple(r for r in load_rules(product="aws") if r.id in RULE_IDS)


def event(name, request, response=None):
    return {"eventSource": "logs.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": name != "CreateExportTask",
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": "synthetic-" + name, "eventTime": "2026-10-20T12:00:00Z",
            "userIdentity": {"arn": ACTOR, "accountId": ACCOUNT},
            "requestParameters": request, "responseElements": response}


def events():
    return [
        event("GetLogEvents", {"logGroupName": GROUP, "logStreamName": STREAM},
              {"events": [{"message": SECRET}]}),
        event("FilterLogEvents", {"logGroupName": GROUP, "filterPattern": ""},
              {"events": [{"message": SECRET}]}),
        event("GetQueryResults", {"queryId": "SYNTHETIC_QUERY_ID_NEVER_EMIT"},
              {"results": [[{"field": "@message", "value": SECRET}]]}),
        event("GetLogRecord", {"logRecordPointer": "SYNTHETIC_POINTER_NEVER_EMIT"},
              {"logRecord": {"@message": SECRET}}),
        event("CreateExportTask", {"logGroupName": GROUP,
              "from": 1792497500000, "to": 1792497600000,
              "destination": "synthetic-export-bucket", "destinationPrefix": "test"},
              {"taskId": "SYNTHETIC_TASK_ID_NEVER_EMIT"}),
    ]


def test_five_rules_match_synthetic_lab_derivative_without_data_leak():
    selected = rules()
    hits = detect_aws_events(events(), selected)
    assert len(selected) == len(hits) == len({x.rule_id for x in hits}) == 5
    serialized = repr(hits)
    for private in (SECRET, "SYNTHETIC_QUERY_ID_NEVER_EMIT",
                    "SYNTHETIC_POINTER_NEVER_EMIT", "SYNTHETIC_TASK_ID_NEVER_EMIT"):
        assert private not in serialized


def test_denied_malformed_and_unconfirmed_calls_do_not_match():
    selected = rules()
    for original in events():
        failed = deepcopy(original)
        failed["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([failed], selected)
        wrong_category = deepcopy(original)
        wrong_category["eventCategory"] = "Data"
        assert not detect_aws_events([wrong_category], selected)
        wrong_read_only = deepcopy(original)
        wrong_read_only["readOnly"] = not original["readOnly"]
        assert not detect_aws_events([wrong_read_only], selected)
    missing_pointer = deepcopy(events()[3])
    missing_pointer["requestParameters"]["logRecordPointer"] = ""
    assert not detect_aws_events([missing_pointer], selected)
    bad_export = deepcopy(events()[4])
    bad_export["requestParameters"]["to"] = bad_export["requestParameters"]["from"]
    assert not detect_aws_events([bad_export], selected)
    no_task = deepcopy(events()[4])
    no_task["responseElements"] = {}
    assert not detect_aws_events([no_task], selected)
