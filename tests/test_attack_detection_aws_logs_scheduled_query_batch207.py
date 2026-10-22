"""Synthetic enabled Logs scheduled query CloudTrail derivative."""

from copy import deepcopy

from peaso.attack_detection.aws_logs_scheduled_query_batch207 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
ARN = f"arn:aws:logs:us-east-1:{ACCOUNT}:scheduled-query:synthetic-query"


def event():
    return {
        "eventSource": "logs.amazonaws.com", "eventName": "CreateScheduledQuery",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "eventID": "synthetic-create", "eventTime": "2026-10-22T00:00:00Z",
        "userIdentity": {"type": "IAMUser", "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-admin"},
        "requestParameters": {
            "name": "synthetic-query", "state": "ENABLED", "queryLanguage": "CWLI",
            "queryString": "fields @message | limit 1",
            "logGroupIdentifiers": [f"arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/synthetic/source"],
            "executionRoleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-exec",
            "destinationConfiguration": {"s3Configuration": {
                "destinationIdentifier": "s3://synthetic-bucket/results/",
                "roleArn": f"arn:aws:iam::{ACCOUNT}:role/synthetic-delivery",
                "ownerAccountId": ACCOUNT,
            }},
        },
        "responseElements": {"scheduledQueryArn": ARN, "state": "ENABLED"},
        "resources": [{"type": "AWS::Logs::ScheduledQuery", "ARN": ARN}],
    }


def rule():
    return Rule(
        id="20700000-0000-4000-8000-000000000001",
        title="Enabled Logs scheduled query to S3", level="medium",
        description="Accepted enabled scheduled query", technique_id="aws-logs-enabled-scheduled-query",
        product="aws", selection={
            "event.source": "logs.amazonaws.com", "event.name": "CreateScheduledQuery",
            "event.outcome": "success", "request.logs_enabled_scheduled_query": True,
        },
    )


def test_enabled_query_matches_without_exporting_query_or_destination():
    row = event()
    signal = normalize(row)
    assert signal is not None
    assert signal["target.id"].startswith("sha256:")
    assert "synthetic-bucket" not in str(signal) and "@message" not in str(signal)
    assert len(detect_aws_events([row], (rule(),))) == 1


def test_disabled_failed_or_incoherent_query_does_not_match():
    base = event()
    variants = []
    for field, value in [("errorCode", "AccessDeniedException"),
                         ("eventCategory", "Data"), ("readOnly", True),
                         ("eventSource", "other.amazonaws.com")]:
        changed = deepcopy(base);changed[field] = value;variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["state"] = "DISABLED";variants.append(changed)
    changed = deepcopy(base);changed["responseElements"]["state"] = "DISABLED";variants.append(changed)
    changed = deepcopy(base);changed["responseElements"]["scheduledQueryArn"] = ARN.replace(ACCOUNT, "888888888888")
    variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["destinationConfiguration"]["s3Configuration"]["destinationIdentifier"] = "invalid"
    variants.append(changed)
    changed = deepcopy(base);changed["requestParameters"]["executionRoleArn"] = changed["requestParameters"]["executionRoleArn"].replace(ACCOUNT, "888888888888")
    variants.append(changed)
    assert all(normalize(row) is None for row in variants)
    assert detect_aws_events(variants, (rule(),)) == []
