"""Synthetic same-actor HealthOmics read-set download sequence."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_bulk_reads_b423 import correlate
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
RULE = Rule(
    id="synthetic-omics-bulk", title="Synthetic bulk read-set retrieval",
    description="Synthetic", level="medium", technique_id="synthetic-omics-bulk",
    product="aws", selection={
        "event.source": "omics.amazonaws.com",
        "event.name": "HealthOmicsBulkReadSetRetrieval",
        "event.outcome": "success", "request.healthomics_bulk_read_sets": True,
    },
)


def _row(index, *, read_set=None, minute=None):
    return {
        "eventSource": "omics.amazonaws.com", "eventName": "GetReadSet",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": True,
        "eventID": f"synthetic-get-{index}",
        "eventTime": f"2026-10-23T00:{(index if minute is None else minute):02d}:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"sequenceStoreId": "synthetic-store",
                              "id": read_set or f"synthetic-read-set-{index}",
                              "file": "SOURCE1", "partNumber": 1},
        "responseElements": None,
    }


def test_three_distinct_read_sets_in_window_produce_one_private_target():
    rows = [_row(1), _row(2), _row(3)]
    alerts = correlate(rows)
    assert len(alerts) == 1
    assert alerts[0]["request.healthomics_distinct_read_set_count"] == 3
    assert len(detect_aws_events(rows, (RULE,))) == 1
    for raw in ("synthetic-store", "synthetic-read-set-1", "synthetic-read-set-3"):
        assert raw not in str(alerts)


def test_two_or_repeated_read_sets_do_not_trigger_bulk_rule():
    assert correlate([_row(1), _row(2)]) == []
    assert correlate([_row(1), _row(2, read_set="synthetic-read-set-1"),
                      _row(3, read_set="synthetic-read-set-1")]) == []
    assert correlate([_row(1), _row(2), _row(3, minute=20)]) == []


def test_actor_store_and_success_must_match():
    rows = [_row(1), _row(2), _row(3)]
    changed = deepcopy(rows)
    changed[2]["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/other"
    assert correlate(changed) == []
    changed = deepcopy(rows)
    changed[2]["requestParameters"]["sequenceStoreId"] = "other-store"
    assert correlate(changed) == []
    changed = deepcopy(rows)
    changed[2]["errorCode"] = "AccessDeniedException"
    assert correlate(changed) == []
