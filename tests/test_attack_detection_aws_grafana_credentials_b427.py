"""Synthetic derivatives of disposable Managed Grafana CloudTrail events."""

from copy import deepcopy

from peaso.attack_detection.aws_grafana_credentials_b427 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
WORKSPACE = "g-synthetic9"
TOKEN = "synthetic-one-time-bearer-secret"
CASES = {
    "CreateWorkspaceApiKey": ("request.grafana_admin_api_key_created", "high"),
    "CreateWorkspaceServiceAccount": (
        "request.grafana_admin_service_account_created", "high"),
    "CreateWorkspaceServiceAccountToken": (
        "request.grafana_service_account_token_created", "medium"),
}


def _row(name):
    request = {"workspaceId": WORKSPACE}
    response = {"workspaceId": WORKSPACE}
    if name == "CreateWorkspaceApiKey":
        request.update(keyName="synthetic-key", keyRole="ADMIN", secondsToLive=600)
        response.update(keyName="synthetic-key", key=TOKEN)
    elif name == "CreateWorkspaceServiceAccount":
        request.update(name="synthetic-admin", grafanaRole="ADMIN")
        response.update(name="synthetic-admin", grafanaRole="ADMIN", id="synthetic-sa")
    else:
        request.update(serviceAccountId="synthetic-sa", name="synthetic-token",
                       secondsToLive=600)
        response.update(serviceAccountId="synthetic-sa",
                        serviceAccountToken={"id": "synthetic-token-id", "key": TOKEN})
    return {
        "eventSource": "grafana.amazonaws.com", "eventName": name,
        "eventType": "AwsApiCall", "eventCategory": "Management", "readOnly": False,
        "eventID": "synthetic-" + name, "eventTime": "2026-10-23T01:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": request, "responseElements": response,
    }


def test_credential_creation_routes_match_without_bearer_material():
    for name, (signal, level) in CASES.items():
        row = _row(name)
        event = normalize(row)
        assert event is not None and event[signal] is True
        assert TOKEN not in str(event)
        assert WORKSPACE not in str(event)
        rule = Rule(id=name, title=name, description="Synthetic", level=level,
                    technique_id=name, product="aws",
                    selection={"event.source": "grafana.amazonaws.com",
                               "event.name": name, "event.outcome": "success",
                               signal: True})
        hits = detect_aws_events([row], (rule,))
        assert len(hits) == 1
        assert TOKEN not in str(hits)


def test_failed_mismatched_or_non_admin_credential_creation_is_rejected():
    for name in CASES:
        for change in (
            lambda row: row.update(errorCode="AccessDeniedException"),
            lambda row: row["responseElements"].update(workspaceId="g-otherspace"),
            lambda row: row["userIdentity"].update(accountId="111111111111"),
            lambda row: row.update(readOnly=True),
        ):
            row = deepcopy(_row(name))
            change(row)
            assert normalize(row) is None
    row = _row("CreateWorkspaceApiKey")
    row["requestParameters"]["keyRole"] = "VIEWER"
    assert normalize(row) is None
    row = _row("CreateWorkspaceServiceAccount")
    row["requestParameters"]["grafanaRole"] = "EDITOR"
    assert normalize(row) is None
    row = _row("CreateWorkspaceServiceAccountToken")
    row["responseElements"]["serviceAccountToken"].pop("id")
    assert normalize(row) is None
