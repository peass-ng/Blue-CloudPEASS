"""Synthetic derivatives of an owned ECR/Lightsail CloudTrail lab.

No account ID, role ARN, token, URL, image manifest or policy from the lab is
included here. The private raw events are deliberately outside this tree.
"""

from copy import deepcopy
import json

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-actor/session"
READER = f"arn:aws:iam::{ACCOUNT}:role/synthetic-reader"
REPO = "synthetic/repository"
RULE_IDS = {
    "e53cc5e4-0903-450b-a565-1ae50afd725b",
    "2a4a8e7c-0741-4e11-abde-d51548fe214c",
    "3a17a404-a6c0-4d6e-9d35-37708c0775db",
    "cece2e6c-2074-4050-bad8-9f4c616621f4",
    "c980ae77-3436-4fef-aaa0-cc6848b39975",
    "7aa97e94-9941-4a50-ba12-2bd44c5190fd",
    "51812dcc-cfd2-42d0-9980-7b442a702793",
    "97b4e504-821f-418c-956d-07457ed06850",
}


def _rules():
    return tuple(r for r in load_rules(product="aws") if r.id in RULE_IDS)


def _event(name, request=None, response=None, *, eid=None, time="2026-10-20T12:00:00Z"):
    source = "lightsail.amazonaws.com" if name == "UpdateContainerService" else "ecr.amazonaws.com"
    return {
        "eventSource": source, "eventName": name, "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True,
        "readOnly": name in {"GetAuthorizationToken", "BatchGetImage", "GetDownloadUrlForLayer"},
        "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1", "eventID": eid or name,
        "eventTime": time, "userIdentity": {"arn": ACTOR, "accountId": ACCOUNT},
        "requestParameters": request or {}, "responseElements": response,
    }


def _events():
    policy = json.dumps({"Version": "2008-10-17", "Statement": [{"Sid": "SyntheticReader",
        "Effect": "Allow", "Principal": {"AWS": READER},
        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]}]})
    lifecycle = json.dumps({"rules": [{"rulePriority": 1, "selection": {
        "tagStatus": "any", "countType": "imageCountMoreThan", "countNumber": 1},
        "action": {"type": "expire"}}]})
    digest1, digest2 = "sha256:" + "a" * 64, "sha256:" + "b" * 64
    return [
        _event("GetAuthorizationToken", response={"authorizationData": [
            {"authorizationToken": "SYNTHETIC_SECRET_NEVER_EMIT"}]}),
        _event("BatchGetImage", {"repositoryName": REPO, "imageIds": [{"imageTag": "stable"}]}),
        _event("GetDownloadUrlForLayer", {"repositoryName": REPO, "layerDigest": digest1}),
        _event("PutImage", {"repositoryName": REPO, "imageTag": "stable"},
               {"image": {"repositoryName": REPO, "imageId": {"imageDigest": digest1}}},
               eid="first-image"),
        _event("PutImage", {"repositoryName": REPO, "imageTag": "stable"},
               {"image": {"repositoryName": REPO, "imageId": {"imageDigest": digest2}}},
               eid="changed-image", time="2026-10-20T12:01:00Z"),
        _event("SetRepositoryPolicy", {"repositoryName": REPO, "policyText": policy},
               {"registryId": ACCOUNT, "repositoryName": REPO, "policyText": policy}),
        _event("PutLifecyclePolicy", {"repositoryName": REPO, "lifecyclePolicyText": lifecycle},
               {"registryId": ACCOUNT, "repositoryName": REPO, "lifecyclePolicyText": lifecycle}),
        _event("BatchDeleteImage", {"repositoryName": REPO, "imageIds": [{"imageTag": "candidate"}]},
               {"imageIds": [{"imageTag": "candidate"}], "failures": []}),
        _event("UpdateContainerService", {"serviceName": "synthetic-service", "privateRegistryAccess": {
            "ecrImagePullerRole": {"isActive": True}}}, {"containerService": {
            "containerServiceName": "synthetic-service", "privateRegistryAccess": {
                "ecrImagePullerRole": {"isActive": True}}}}),
    ]


def test_eight_rules_match_synthetic_lab_derivative():
    rules = _rules()
    hits = detect_aws_events(_events(), rules)
    assert len(rules) == 8
    assert len(hits) == 8
    assert len({hit.rule_id for hit in hits}) == 8
    assert "SYNTHETIC_SECRET_NEVER_EMIT" not in repr(hits)


def test_failed_and_incomplete_calls_do_not_match():
    rules = _rules()
    for original in _events():
        failed = deepcopy(original)
        failed["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([failed], rules), original["eventName"]
    first, changed = _events()[3:5]
    same_digest = deepcopy(changed)
    same_digest["responseElements"]["image"]["imageId"]["imageDigest"] = (
        first["responseElements"]["image"]["imageId"]["imageDigest"])
    assert not detect_aws_events([first, same_digest], rules)
