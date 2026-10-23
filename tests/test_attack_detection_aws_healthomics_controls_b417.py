"""Synthetic derivatives of isolated HealthOmics logging and limit changes."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_controls_b417 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
FIELDS = (
    "request.healthomics_access_logging_disabled",
    "request.healthomics_fallback_location_set",
    "request.healthomics_run_group_tight_limit_set",
)
RULES = tuple(Rule(
    id=f"synthetic-omics-control-{i}", title=f"Synthetic control {i}",
    description="Synthetic", level="medium", technique_id=f"synthetic-control-{i}",
    product="aws", selection={"event.source": "omics.amazonaws.com",
                              "event.outcome": "success", field: True},
) for i, field in enumerate(FIELDS))


def _row(kind: str) -> dict:
    name = "UpdateRunGroup" if kind == "limits" else "UpdateSequenceStore"
    row = {
        "eventSource": "omics.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-" + kind, "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {}, "responseElements": None,
    }
    if kind == "logs":
        row["requestParameters"] = {"sequenceStoreId": "synthetic-store",
                                    "s3AccessConfig": {"accessLogLocation": ""}}
        row["responseElements"] = {"id": "synthetic-store", "s3Access": {}}
    elif kind == "fallback":
        uri = "s3://synthetic-bucket/SENTINEL-new-location/"
        row["requestParameters"] = {"sequenceStoreId": "synthetic-store",
                                    "fallbackLocation": uri}
        row["responseElements"] = {"id": "synthetic-store", "fallbackLocation": uri}
    else:
        row["requestParameters"] = {"id": "synthetic-run-group", "maxCpus": 1,
                                    "maxRuns": 1, "maxDuration": 1}
    return row


def test_three_real_shapes_hit_and_hide_s3_path_and_ids():
    rows = [_row(kind) for kind in ("logs", "fallback", "limits")]
    hits = detect_aws_events(rows, RULES)
    assert len(hits) == 3
    events = [normalize(row) for row in rows]
    assert all(event is not None and event["target.id"].startswith("sha256:")
               for event in events)
    for hidden in ("SENTINEL", "synthetic-store", "synthetic-run-group"):
        assert hidden not in str(events)
        assert hidden not in str(hits)


def test_logging_rule_requires_explicit_blank_setting_and_response():
    row = _row("logs")
    row["requestParameters"]["s3AccessConfig"]["accessLogLocation"] = "s3://synthetic-bucket/logs/"
    assert normalize(row) is None
    row = _row("logs")
    row["responseElements"]["s3Access"]["accessLogLocation"] = "s3://synthetic-bucket/logs/"
    assert normalize(row) is None


def test_fallback_rule_requires_confirmed_same_destination():
    row = _row("fallback")
    row["responseElements"]["fallbackLocation"] = "s3://synthetic-bucket/old/"
    assert normalize(row) is None


def test_limits_rule_rejects_unconstrained_failed_and_foreign_requests():
    row = _row("limits")
    row["requestParameters"].update(maxCpus=16, maxRuns=5, maxDuration=60)
    assert normalize(row) is None
    for change in (
        lambda r: r.update(errorCode="AccessDeniedException"),
        lambda r: r["userIdentity"].update(accountId="888888888888"),
        lambda r: r.update(readOnly=True),
    ):
        row = deepcopy(_row("limits"))
        change(row)
        assert normalize(row) is None
