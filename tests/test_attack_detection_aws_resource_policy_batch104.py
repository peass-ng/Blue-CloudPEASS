"""Synthetic derivatives of owned resource-policy validation probes."""

import json
from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
USER = f"arn:aws:iam::{ACCOUNT}:user/synthetic-existing"
MISSING = f"arn:aws:iam::{ACCOUNT}:user/synthetic-missing"
SPECS = [
    ("kinesis.amazonaws.com", "PutResourcePolicy", "policy", "resourceARN",
     f"arn:aws:kinesis:eu-west-1:{ACCOUNT}:stream/synthetic", "kinesis:DescribeStreamSummary",
     "InvalidArgumentException", "aws-kinesis-resource-policy-principal-validation"),
    ("codeartifact.amazonaws.com", "PutDomainPermissionsPolicy", "policyDocument", "domain",
     f"arn:aws:codeartifact:eu-west-1:{ACCOUNT}:domain/synthetic", "codeartifact:GetAuthorizationToken",
     "ValidationException", "aws-codeartifact-resource-policy-principal-validation"),
    ("s3tables.amazonaws.com", "PutTableBucketPolicy", "resourcePolicy", "tableBucketARN",
     f"arn:aws:s3tables:eu-west-1:{ACCOUNT}:bucket/synthetic", "s3tables:GetTableBucket",
     "BadRequestException", "aws-s3tables-resource-policy-principal-validation"),
    ("s3vectors.amazonaws.com", "PutVectorBucketPolicy", "policy", "vectorBucketArn",
     f"arn:aws:s3vectors:eu-west-1:{ACCOUNT}:bucket/synthetic", "s3vectors:GetVectorBucket",
     "ValidationException", "aws-s3vectors-resource-policy-principal-validation"),
    ("aps.amazonaws.com", "PutResourcePolicy", "policyDocument", "workspaceId",
     f"arn:aws:aps:eu-west-1:{ACCOUNT}:workspace/ws-synthetic", "aps:QueryMetrics",
     "ValidationException", "aws-amp-resource-policy-principal-validation"),
]
IDS = {x[-1] for x in SPECS} | {"aws-dynamodb-table-getitem-principal-granted"}


def policy(principal, action, resource):
    return json.dumps({"Version": "2012-10-17", "Statement": [{
        "Sid": "PrincipalValidation", "Effect": "Allow",
        "Principal": {"AWS": principal}, "Action": action, "Resource": resource,
    }]})


def event(source, name, request, response, index, error=None):
    record = {"eventSource": source, "eventName": name,
              "eventCategory": "Management", "eventType": "AwsApiCall",
              "managementEvent": True, "readOnly": False,
              "recipientAccountId": ACCOUNT, "awsRegion": "eu-west-1",
              "eventID": f"44444444-4444-4444-8444-{index:012d}",
              "eventTime": "2026-10-21T02:20:00Z",
              "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                               "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"},
              "requestParameters": request, "responseElements": response}
    if error:record["errorCode"] = error
    return record


def pair(spec, index):
    source, name, body_key, target_key, resource, action, error, _ = spec
    target = (resource.rsplit("/", 1)[-1] if target_key in ("domain", "workspaceId") else resource)
    base = {target_key: target}
    good = event(source, name, {**base, body_key: policy(USER, action, resource)},
                 {"status": "accepted"}, index)
    bad = event(source, name, {**base, body_key: policy(MISSING, action, resource)},
                None, index+1, error)
    return good, bad


def dynamodb_grant():
    table = f"arn:aws:dynamodb:eu-west-1:{ACCOUNT}:table/synthetic"
    return event("dynamodb.amazonaws.com", "PutResourcePolicy",
                 {"resourceArn": table, "policy": policy(USER, "dynamodb:GetItem", table)},
                 {"revisionId": "synthetic-revision"}, 30)


def rules():
    return [r for r in load_rules(product="aws") if r.technique_id in IDS]


def test_six_signals_match_controlled_synthetic_derivatives():
    selected = rules()
    assert len(selected) == 6
    records = [record for i, spec in enumerate(SPECS) for record in pair(spec, i*2)]
    records.append(dynamodb_grant())
    hits = detect_aws_events(records, selected)
    assert len(hits) == 6
    assert {hit.technique_id for hit in hits} == IDS
    assert "synthetic-existing" not in str(hits)
    assert "synthetic-missing" not in str(hits)


def test_failed_probe_requires_identical_policy_except_principal():
    selected = rules()
    for spec in SPECS:
        good, bad = pair(spec, 1)
        assert any(h.technique_id == spec[-1] for h in detect_aws_events([bad, good], selected))
        unrelated = deepcopy(bad)
        body = json.loads(unrelated["requestParameters"][spec[2]])
        body["Statement"][0]["Action"] = "s3:ListAllMyBuckets"
        unrelated["requestParameters"][spec[2]] = json.dumps(body)
        assert detect_aws_events([good, unrelated], selected) == []
        other_actor = deepcopy(bad)
        other_actor["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/synthetic-other"
        assert detect_aws_events([good, other_actor], selected) == []


def test_denied_grant_and_non_getitem_policy_are_excluded():
    selected = rules()
    denied = dynamodb_grant()
    denied["errorCode"] = "AccessDeniedException"
    assert detect_aws_events([denied], selected) == []
    other = dynamodb_grant()
    document = json.loads(other["requestParameters"]["policy"])
    document["Statement"][0]["Action"] = "dynamodb:DescribeTable"
    other["requestParameters"]["policy"] = json.dumps(document)
    assert detect_aws_events([other], selected) == []


def test_malformed_source_does_not_abort_following_valid_grant():
    selected = rules()
    malformed = deepcopy(dynamodb_grant())
    malformed["eventSource"] = ["dynamodb.amazonaws.com"]
    hits = detect_aws_events([malformed, dynamodb_grant()], selected)
    assert [h.technique_id for h in hits] == ["aws-dynamodb-table-getitem-principal-granted"]
