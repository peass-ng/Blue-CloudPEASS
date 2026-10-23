"""Synthetic derivatives of a disposable private HealthOmics workflow trial."""

from copy import deepcopy

from peaso.attack_detection.aws_healthomics_workflow_b414 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
BASE = {
    "eventSource": "omics.amazonaws.com", "eventType": "AwsApiCall",
    "eventCategory": "Management", "managementEvent": True,
    "eventID": "synthetic-omics-event", "eventTime": "2026-10-23T00:00:00Z",
    "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
    "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                     "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
    "responseElements": None,
}
EXPORT_RULE = Rule(
    id="synthetic-omics-export", title="Synthetic definition export",
    description="Synthetic", level="medium",
    technique_id="aws-healthomics-private-workflow-definition-export",
    product="aws", selection={
        "event.source": "omics.amazonaws.com", "event.outcome": "success",
        "request.healthomics_definition_exported": True,
    },
)
VERSION_RULE = Rule(
    id="synthetic-omics-version", title="Synthetic version creation",
    description="Synthetic", level="medium",
    technique_id="aws-healthomics-private-workflow-version-created",
    product="aws", selection={
        "event.source": "omics.amazonaws.com", "event.name": "CreateWorkflowVersion",
        "event.outcome": "success", "request.healthomics_workflow_version_created": True,
    },
)
DELETE_RULE = Rule(
    id="synthetic-omics-delete", title="Synthetic workflow deletion",
    description="Synthetic", level="medium",
    technique_id="aws-healthomics-private-workflow-deleted", product="aws",
    selection={"event.source": "omics.amazonaws.com", "event.outcome": "success",
               "request.healthomics_workflow_deletion_accepted": True},
)


def _row(name: str) -> dict:
    row = deepcopy(BASE)
    row["eventName"] = name
    row["readOnly"] = name in {"GetWorkflow", "GetWorkflowVersion"}
    row["requestParameters"] = {"id": "synthetic-workflow-id", "type": "PRIVATE"}
    if name == "GetWorkflow":
        row["requestParameters"]["export"] = "DEFINITION,README"
        row["responseElements"] = {"definition": "https://synthetic.invalid/?secret=SENTINEL"}
    elif name == "GetWorkflowVersion":
        row["requestParameters"].update(versionName="v2-synthetic", export="DEFINITION")
    elif name == "CreateWorkflowVersion":
        row["requestParameters"].update(
            versionName="v2-synthetic", definitionZip="SENTINEL-DEFINITION-BASE64")
        row["responseElements"] = {
            "workflowId": "synthetic-workflow-id", "versionName": "v2-synthetic",
            "status": "CREATING",
            "arn": f"arn:aws:omics:us-east-2:{ACCOUNT}:workflow/synthetic-workflow-id/version/v2-synthetic",
        }
    elif name == "DeleteWorkflowVersion":
        row["requestParameters"]["versionName"] = "v2-synthetic"
    return row


def test_live_shape_three_positive_events_and_no_sensitive_output():
    rows = [_row(n) for n in ("GetWorkflow", "CreateWorkflowVersion", "GetWorkflowVersion")]
    hits = detect_aws_events(rows, (EXPORT_RULE, VERSION_RULE))
    assert len(hits) == 3
    assert all(normalize(row)["target.id"].startswith("sha256:") for row in rows)
    assert "SENTINEL" not in str(hits)
    assert "synthetic-workflow-id" not in str(hits)
    assert "SENTINEL" not in str([normalize(row) for row in rows])


def test_read_without_definition_export_is_negative():
    for name in ("GetWorkflow", "GetWorkflowVersion"):
        row = _row(name)
        del row["requestParameters"]["export"]
        assert normalize(row) is None
        row["requestParameters"]["export"] = "README"
        assert normalize(row) is None


def test_failure_foreign_identity_and_public_workflow_are_negative():
    for change in (
        lambda row: row.update(errorCode="ResourceNotFoundException"),
        lambda row: row["userIdentity"].update(accountId="888888888888"),
        lambda row: row["requestParameters"].update(type="PUBLIC"),
        lambda row: row.update(eventCategory="Data"),
    ):
        row = _row("GetWorkflow")
        change(row)
        assert normalize(row) is None


def test_version_response_must_match_request_and_account():
    for change in (
        lambda row: row["responseElements"].update(workflowId="other"),
        lambda row: row["responseElements"].update(versionName="other"),
        lambda row: row["responseElements"].update(status="FAILED"),
        lambda row: row["responseElements"].update(arn="arn:aws:omics:us-east-2:888888888888:workflow/x"),
        lambda row: row.update(readOnly=True),
    ):
        row = _row("CreateWorkflowVersion")
        change(row)
        assert normalize(row) is None


def test_accepted_deletions_hit_but_failures_do_not():
    rows = [_row("DeleteWorkflowVersion"), _row("DeleteWorkflow")]
    assert len(detect_aws_events(rows, (DELETE_RULE,))) == 2
    assert all(normalize(row)["target.id"].startswith("sha256:") for row in rows)
    for row in rows:
        row["errorCode"] = "ResourceNotFoundException"
        assert normalize(row) is None
    row = _row("DeleteWorkflowVersion")
    del row["requestParameters"]["versionName"]
    assert normalize(row) is None
