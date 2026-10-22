"""PCS Slurm secret reads must stay distinct from ordinary secret reads."""

import copy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REGION = "us-east-2"
NAME = "pcs!slurm-secret-cluster_aaaaaaaaaa-bbbbbb"
SECRET = f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:{NAME}"
RULE = Rule(
    id="synthetic-pcs-secret-read", title="PCS Slurm secret read",
    description="Scoped read", level="medium", technique_id="synthetic-pcs-secret-read",
    product="aws", selection={"event.name": "GetSecretValue", "event.outcome": "success",
                              "request.pcs_slurm_secret_read": True},
)
READ = {
    "eventSource": "secretsmanager.amazonaws.com", "eventName": "GetSecretValue",
    "eventType": "AwsApiCall", "eventCategory": "Management",
    "managementEvent": True, "readOnly": True,
    "recipientAccountId": ACCOUNT, "awsRegion": REGION,
    "eventID": "synthetic-pcs-read", "eventTime": "2026-10-22T16:00:00Z",
    "userIdentity": {"type": "AssumedRole", "accountId": ACCOUNT, "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/lab/synthetic"},
    "requestParameters": {"secretId": SECRET, "versionId": "synthetic-version"},
    "responseElements": None, "resources": [{"ARN": SECRET, "accountId": ACCOUNT, "type": None}],
}


def hits(event):
    return detect_aws_events([event], (RULE,))


def test_scoped_read_detects_synthetic_cloudtrail_shape():
    matches = hits(READ)
    assert len(matches) == 1
    assert matches[0].rule_id == RULE.id


def test_other_secrets_accounts_errors_and_service_reads_do_not_match():
    mutations = (
        lambda e: e["requestParameters"].update(secretId=f"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:normal-abcdef"),
        lambda e: e["requestParameters"].update(secretId=SECRET.replace(ACCOUNT, "888888888888")),
        lambda e: e.update(awsRegion="us-west-2"),
        lambda e: e["requestParameters"].update(secretId=NAME.replace("slurm", "other")),
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(eventName="DescribeSecret"),
        lambda e: e.update(eventCategory="Data"),
        lambda e: e.update(readOnly=False),
        lambda e: e["userIdentity"].update(type="AWSService"),
        lambda e: e["userIdentity"].update(accountId="888888888888"),
    )
    for change in mutations:
        event = copy.deepcopy(READ)
        change(event)
        assert not hits(event)
