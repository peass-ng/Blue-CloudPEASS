"""Synthetic derivative of an isolated Lex test-set record read."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules

ACCOUNT = "999999999999"
TEST_SET = "SYNTHSET01"
TECHNIQUE = "aws-lex-v2-test-set-records-listed"


def rules():
    selected = [rule for rule in load_rules(product="aws") if rule.technique_id == TECHNIQUE]
    assert len(selected) == 1
    return selected


def event():
    return {
        "eventSource": "lex.amazonaws.com", "eventName": "ListTestSetRecords",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": True,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "99999999-9999-4999-8999-999999999906",
        "eventTime": "2026-10-21T12:10:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"testSetId": TEST_SET}, "responseElements": None,
    }


def test_observed_test_set_read_matches():
    findings = detect_aws_events([event()], rules())
    assert len(findings) == 1
    assert findings[0].technique_id == TECHNIQUE
    assert findings[0].target_id == TEST_SET


def test_failed_or_malformed_test_set_reads_fail_closed():
    rows = [deepcopy(event()) for _ in range(4)]
    rows[0]["errorCode"] = "AccessDeniedException"
    rows[1]["requestParameters"]["testSetId"] = "short"
    rows[2]["readOnly"] = False
    rows[3]["eventCategory"] = "Data"
    assert detect_aws_events(rows, rules()) == []


def test_no_record_content_is_emitted():
    finding = detect_aws_events([event()], rules())[0]
    assert "synthetic hello" not in str(finding)
