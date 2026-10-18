"""S3 bucket management writes require precise CloudTrail request evidence."""

from __future__ import annotations

from copy import deepcopy

import pytest

from peaso.attack_detection import Rule, detect_aws_events
from peaso.attack_detection.aws_s3_bucket import normalize_aws_s3_bucket


BUCKET = "peasso-disposable-example"
PAB_OFF = {key: False for key in (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}
PUBLIC_POLICY = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
    "Resource": f"arn:aws:s3:::{BUCKET}/*"}]}


def record(name: str, request: dict) -> dict:
    return {
        "eventSource": "s3.amazonaws.com", "eventName": name,
        "eventCategory": "Management", "eventType": "AwsApiCall",
        "managementEvent": True, "readOnly": False,
        "eventID": "b237dc63-9dab-495d-964f-f9b5270ba1e1",
        "eventTime": "2026-10-19T00:52:00Z", "awsRegion": "us-east-1",
        "recipientAccountId": "123456789012",
        "userIdentity": {"type": "IAMUser", "accountId": "123456789012",
                         "arn": "arn:aws:iam::123456789012:user/tester"},
        "requestParameters": {"bucketName": BUCKET, **request},
        "responseElements": None,
    }


@pytest.mark.parametrize("name,request_params,field", [
    ("PutBucketPublicAccessBlock", {"PublicAccessBlockConfiguration": PAB_OFF},
     "request.all_public_access_blocks_disabled"),
    ("PutBucketPolicy", {"bucketPolicy": PUBLIC_POLICY},
     "request.unconditional_public_object_read_policy"),
    ("PutBucketAcl", {"x-amz-acl": "public-read"}, "request.public_read_bucket_acl"),
    ("PutBucketWebsite", {"WebsiteConfiguration": {"RedirectAllRequestsTo": {
        "HostName": "example.com", "Protocol": "https"}}}, "request.website_redirect_all"),
])
def test_real_shaped_positive_records_match_exact_signal(name, request_params, field):
    event = record(name, request_params)
    rule = Rule("unit", "S3 unit", "medium", "Exact request", "unit", "aws",
                {"event.source": "s3.amazonaws.com", "event.name": name,
                 "event.outcome": "success", field: True})
    assert len(detect_aws_events([event], [rule])) == 1
    assert normalize_aws_s3_bucket(event)["target.id"] == f"arn:aws:s3:::{BUCKET}"
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDenied"
    assert detect_aws_events([denied], [rule]) == []


def test_public_access_block_requires_all_four_explicitly_false():
    request = PAB_OFF | {"BlockPublicPolicy": True}
    assert normalize_aws_s3_bucket(record("PutBucketPublicAccessBlock", {
        "PublicAccessBlockConfiguration": request})) is None
    request.pop("BlockPublicPolicy")
    assert normalize_aws_s3_bucket(record("PutBucketPublicAccessBlock", {
        "PublicAccessBlockConfiguration": request})) is None


@pytest.mark.parametrize("policy", [
    {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{BUCKET}/*",
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}}]},
    {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
                    "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{BUCKET}/*"}]},
    {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::another-bucket/*"}]},
    {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:ListBucket",
                    "Resource": f"arn:aws:s3:::{BUCKET}"}]},
])
def test_bucket_policy_excludes_conditional_nonpublic_other_bucket_and_list_only(policy):
    assert normalize_aws_s3_bucket(record("PutBucketPolicy", {"bucketPolicy": policy})) is None


def test_acl_website_cors_and_account_negatives():
    assert normalize_aws_s3_bucket(record("PutBucketAcl", {"x-amz-acl": "private"})) is None
    assert normalize_aws_s3_bucket(record("PutBucketWebsite", {"WebsiteConfiguration": {
        "IndexDocument": {"Suffix": "index.html"}}})) is None
    assert normalize_aws_s3_bucket(record("PutBucketCors", {"CORSConfiguration": {
        "CORSRule": {"AllowedOrigin": "*"}}})) is None
    mismatched = record("PutBucketAcl", {"x-amz-acl": "public-read"})
    mismatched["recipientAccountId"] = "999999999999"
    assert normalize_aws_s3_bucket(mismatched) is None
