"""Synthetic derivative of a disposable HealthOmics log read."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_log_reads_b422 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
RULE = Rule(
    id="synthetic-omics-log-read", title="Synthetic HealthOmics log read",
    description="Synthetic", level="low", technique_id="synthetic-omics-log-read",
    product="aws", selection={"event.source": "logs.amazonaws.com",
                              "event.name": "GetLogEvents", "event.outcome": "success",
                              "request.healthomics_workflow_log_read": True},
)


def _row():
    return {
        "eventSource": "logs.amazonaws.com", "eventName": "GetLogEvents",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": True,
        "eventID": "synthetic-omics-log-read", "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"logGroupName": "/aws/omics/WorkflowLog",
                              "logStreamName": "manifest/run/SENTINEL-RUN/SENTINEL-UUID",
                              "limit": 10, "unmask": False},
        "responseElements": None,
    }


def test_real_log_read_shape_hits_without_stream_name():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    assert len(detect_aws_events([row], (RULE,))) == 1
    assert "SENTINEL" not in str(event)


def test_other_group_error_and_foreign_actor_do_not_hit():
    for change in (
        lambda row: row["requestParameters"].update(logGroupName="/aws/other"),
        lambda row: row.update(errorCode="AccessDeniedException"),
        lambda row: row["userIdentity"].update(accountId="000000000000"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None
