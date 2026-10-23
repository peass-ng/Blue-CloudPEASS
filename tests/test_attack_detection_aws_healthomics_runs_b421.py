"""Synthetic derivatives of disposable HealthOmics run events."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_runs_b421 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
RUN = "synthetic-run"
FLAGS = {
    "StartRun": "request.healthomics_run_logging_disabled",
    "GetRun": "request.healthomics_run_metadata_read",
    "CancelRun": "request.healthomics_run_cancel_accepted",
    "DeleteRun": "request.healthomics_run_delete_accepted",
}
RULES = tuple(Rule(
    id=f"synthetic-omics-{name}", title=f"Synthetic {name}",
    description="Synthetic", level="medium", technique_id=f"synthetic-omics-{name}",
    product="aws", selection={"event.source": "omics.amazonaws.com",
                              "event.name": name, "event.outcome": "success",
                              flag: True},
) for name, flag in FLAGS.items())


def _row(name):
    request = {"id": RUN}
    response = None
    if name == "StartRun":
        request = {"workflowId": "synthetic-workflow", "workflowType": "PRIVATE",
                   "roleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-run-role",
                   "outputUri": "s3://synthetic-output/SENTINEL/", "logLevel": "OFF"}
        response = {"id": RUN, "status": "PENDING",
                    "arn": f"arn:aws:omics:us-east-1:{ACCOUNT}:run/{RUN}"}
    return {
        "eventSource": "omics.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": name == "GetRun",
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": request, "responseElements": response,
    }


def test_four_live_shapes_hit_without_run_or_output_details():
    rows = [_row(name) for name in FLAGS]
    events = [normalize(row) for row in rows]
    assert all(event is not None and event["target.id"].startswith("sha256:")
               for event in events)
    assert len({event["target.id"] for event in events}) == 1
    hits = detect_aws_events(rows, RULES)
    assert len(hits) == 4
    for private in (RUN, "synthetic-output", "synthetic-workflow", "synthetic-run-role"):
        assert private not in str(events)
        assert private not in str(hits)


def test_start_run_requires_logging_disabled_and_accepted_run():
    row = _row("StartRun")
    row["requestParameters"]["logLevel"] = "ALL"
    assert normalize(row) is None
    row = _row("StartRun")
    row["responseElements"]["status"] = "FAILED"
    assert normalize(row) is None


def test_errors_and_foreign_identity_are_rejected():
    for name in FLAGS:
        for change in (
            lambda row: row.update(errorCode="AccessDeniedException"),
            lambda row: row["userIdentity"].update(accountId="000000000000"),
            lambda row: row.update(readOnly=name != "GetRun"),
        ):
            row = deepcopy(_row(name))
            change(row)
            assert normalize(row) is None
