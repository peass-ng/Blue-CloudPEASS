"""Synthetic derivative of an accepted Grafana SAML configuration event."""

from copy import deepcopy

from peaso.attack_detection.aws_grafana_saml_admin_b427 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
WORKSPACE = "g-synthetic9"
URL = "https://invalid.example/synthetic-idp.xml"
RULE = Rule(
    id="synthetic-grafana-saml", title="Synthetic SAML admin mapping",
    description="Synthetic", level="high", technique_id="synthetic-grafana-saml",
    product="aws", selection={"event.source": "grafana.amazonaws.com",
                              "event.name": "UpdateWorkspaceAuthentication",
                              "event.outcome": "success",
                              "request.grafana_saml_admin_mapping_submitted": True},
)


def _row():
    return {
        "eventSource": "grafana.amazonaws.com",
        "eventName": "UpdateWorkspaceAuthentication",
        "eventType": "AwsApiCall", "eventCategory": "Management", "readOnly": False,
        "eventID": "synthetic-grafana-saml-event", "eventTime": "2026-10-23T01:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-reader"},
        "requestParameters": {"workspaceId": WORKSPACE,
                              "authenticationProviders": ["SAML"],
                              "samlConfiguration": {
                                  "idpMetadata": {"url": URL},
                                  "roleValues": {"admin": "***"}}},
        "responseElements": {"authentication": {
            "providers": ["SAML"], "saml": {"status": "CONFIGURED",
                                       "configuration": {"idpMetadata": {"url": URL},
                                                         "roleValues": {"admin": "***"}}}}},
    }


def test_saml_admin_mapping_matches_without_exporting_idp_details():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    assert URL not in str(event) and WORKSPACE not in str(event)
    assert len(detect_aws_events([row], (RULE,))) == 1


def test_failed_or_unconfirmed_mapping_is_rejected():
    for change in (
        lambda row: row.update(errorCode="ConflictException"),
        lambda row: row["requestParameters"]["samlConfiguration"]["roleValues"].pop("admin"),
        lambda row: row["responseElements"]["authentication"]["saml"].update(
            status="NOT_CONFIGURED"),
        lambda row: row["responseElements"]["authentication"]["saml"][
            "configuration"]["roleValues"].update(admin=[]),
        lambda row: row["userIdentity"].update(accountId="111111111111"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None
