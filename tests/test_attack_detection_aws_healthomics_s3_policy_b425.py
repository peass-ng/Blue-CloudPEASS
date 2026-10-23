"""Synthetic derivative of a disposable HealthOmics S3 access policy."""

import json
from copy import deepcopy
from urllib.parse import quote

from peaso.attack_detection.aws_healthomics_s3_policy_b425 import normalize
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
SERVICE = "000000000000"
STORE = "1234567890"
AP = f"arn:aws:s3:us-east-1:{SERVICE}:accesspoint/{ACCOUNT}-{STORE}"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
OBJECT = f"{AP}/object/{ACCOUNT}/sequenceStore/{STORE}/*"
RULE = Rule(
    id="synthetic-omics-policy", title="Synthetic HealthOmics S3 role grant",
    description="Synthetic", level="medium", technique_id="synthetic-omics-policy",
    product="aws", selection={
        "event.source": "omics.amazonaws.com", "event.name": "PutS3AccessPolicy",
        "event.outcome": "success",
        "request.healthomics_s3_role_read_policy_submitted": True,
    },
)


def _row(include_role=True):
    policy = {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
         "Action": ["s3:GetObject", "s3:GetObjectTagging"], "Resource": OBJECT},
    ]}
    if include_role:
        policy["Statement"].append({
            "Effect": "Allow", "Principal": {"AWS": ROLE},
            "Action": "s3:GetObject", "Resource": OBJECT,
            "Condition": {"StringEquals": {"s3:ExistingObjectTag/omics:readSetStatus": "ACTIVE"}},
        })
    return {
        "eventSource": "omics.amazonaws.com", "eventName": "PutS3AccessPolicy",
        "eventType": "AwsApiCall", "eventCategory": "Management",
        "managementEvent": True, "readOnly": False,
        "eventID": "synthetic-omics-policy", "eventTime": "2026-10-23T00:00:00Z",
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
        "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                         "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
        "requestParameters": {"s3AccessPointArn": quote(AP, safe=""),
                              "s3AccessPolicy": json.dumps(policy)},
        "responseElements": {"s3AccessPointArn": AP, "storeId": STORE,
                             "storeType": "SEQUENCE_STORE"},
    }


def test_submitted_role_grant_hits_without_policy_or_role_arn():
    row = _row()
    event = normalize(row)
    assert event is not None and event["target.id"].startswith("sha256:")
    assert len(detect_aws_events([row], (RULE,))) == 1
    for sensitive in (ROLE, AP, STORE, "synthetic-reader"):
        assert sensitive not in str(event)


def test_default_policy_restore_and_wrong_prefix_do_not_hit():
    assert normalize(_row(False)) is None
    row = _row()
    policy = json.loads(row["requestParameters"]["s3AccessPolicy"])
    policy["Statement"][1]["Resource"] = f"{AP}/object/{ACCOUNT}/otherStore/{STORE}/*"
    row["requestParameters"]["s3AccessPolicy"] = json.dumps(policy)
    assert normalize(row) is None


def test_failed_and_mismatched_responses_do_not_hit():
    for change in (
        lambda row: row.update(errorCode="ValidationException"),
        lambda row: row["responseElements"].update(storeType="REFERENCE_STORE"),
        lambda row: row["responseElements"].update(s3AccessPointArn="other"),
        lambda row: row["userIdentity"].update(accountId="000000000000"),
    ):
        row = deepcopy(_row())
        change(row)
        assert normalize(row) is None
