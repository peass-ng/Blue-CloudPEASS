"""Accepted public layer policy grants from synthetic CloudTrail derivatives."""

from copy import deepcopy
import json

from peaso.attack_detection.aws_lambda_persistence_batch112 import normalize


def event():
    account = "999999999999"
    layer = "synthetic-layer"
    version = 1
    statement = {
        "Sid": "synthetic-public", "Effect": "Allow", "Principal": "*",
        "Action": "lambda:GetLayerVersion",
        "Resource": f"arn:aws:lambda:us-east-1:{account}:layer:{layer}:{version}",
    }
    return {
        "eventSource": "lambda.amazonaws.com",
        "eventName": "AddLayerVersionPermission20181031",
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "recipientAccountId": account, "awsRegion": "us-east-1",
        "eventID": "synthetic-b174", "eventTime": "2026-10-21T23:00:00Z",
        "userIdentity": {"arn": f"arn:aws:iam::{account}:user/synthetic"},
        "requestParameters": {
            "layerName": layer, "versionNumber": version,
            "statementId": "synthetic-public", "action": "lambda:GetLayerVersion",
            "principal": "*",
        },
        "responseElements": {"revisionId": "synthetic-revision",
                             "statement": json.dumps(statement)},
        "resources": [],
    }


def test_public_layer_grant_matches_and_keeps_layer_private():
    result = normalize(event())
    assert len(result) == 1
    assert result[0]["request.lambda_public_layer_version_grant"] is True
    assert result[0]["target.id"].startswith("sha256:")
    assert "synthetic-layer" not in str(result)


def test_nonpublic_failed_or_mismatched_layer_grants_fail_closed():
    base = event()
    variants = []
    for change in (
        lambda e: e["requestParameters"].update(principal="999999999999"),
        lambda e: e["requestParameters"].update(organizationId="o-aaaaaaaaaa"),
        lambda e: e["responseElements"].update(statement=json.dumps(
            {**json.loads(e["responseElements"]["statement"]), "Principal": "999999999999"})),
        lambda e: e["responseElements"].update(statement=json.dumps(
            {**json.loads(e["responseElements"]["statement"]),
             "Resource": "arn:aws:lambda:us-east-1:111111111111:layer:synthetic-layer:1"})),
        lambda e: e.update(errorCode="AccessDeniedException"),
        lambda e: e.update(readOnly=True),
        lambda e: e["responseElements"].update(statement="not json"),
    ):
        candidate = deepcopy(base)
        change(candidate)
        variants.append(candidate)
    assert all(normalize(item) == [] for item in variants)
