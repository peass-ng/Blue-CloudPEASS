"""Synthetic derivative of a disposable Grafana workspace update."""

from copy import deepcopy

from peaso.attack_detection.aws_grafana_workspace_role_b427 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
WORKSPACE = "g-synthetic9"
RULE = Rule(
    id="synthetic-grafana-role", title="Synthetic Grafana role update",
    description="Synthetic", level="medium", technique_id="synthetic-grafana-role",
    product="aws", selection={"event.source": "grafana.amazonaws.com",
                              "event.name": "UpdateWorkspace", "event.outcome": "success",
                              "request.grafana_workspace_role_update_submitted": True},
)


def _row():
    return {
        "eventSource": "grafana.amazonaws.com", "eventName": "UpdateWorkspace",
        "eventType": "AwsApiCall", "eventCategory": "Management", "readOnly": False,
        "eventID": "synthetic-grafana-role-event", "eventTime": "2026-10-23T01:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"workspaceId": WORKSPACE, "workspaceRoleArn": "***"},
        "responseElements": {"workspace": {"id": WORKSPACE,
                                            "permissionType": "CUSTOMER_MANAGED",
                                            "workspaceRoleArn": "***", "status": "UPDATING"}},
    }


def test_accepted_role_update_matches_without_revealing_workspace():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    assert WORKSPACE not in str(event)
    assert len(detect_aws_events([row], (RULE,))) == 1


def test_rejected_or_unrelated_workspace_update_does_not_match():
    for change in (
        lambda row: row.update(errorCode="ConflictException"),
        lambda row: row["requestParameters"].pop("workspaceRoleArn"),
        lambda row: row["responseElements"]["workspace"].update(id="g-otherwork"),
        lambda row: row["responseElements"]["workspace"].update(
            permissionType="SERVICE_MANAGED"),
        lambda row: row["userIdentity"].update(accountId="111111111111"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None
