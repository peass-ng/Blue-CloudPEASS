"""Synthetic derivatives of an owned ECR private/public upload lab."""

from copy import deepcopy
import json

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-publisher/session"
GRANTEE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-grantee"
PRIVATE = "synthetic/private"
PUBLIC = "synthetic/public"
LAYER = "sha256:" + "a" * 64
IMAGE = "sha256:" + "c" * 64
MANIFEST = json.dumps({"schemaVersion": 2, "layers": [{"digest": LAYER}]})
RULE_IDS = {
    "8bdc2d55-d0fe-4f95-9d3a-c84e62c199a0",
    "740002ff-dca5-4412-82d6-0a82fb572b3f",
    "f93afe35-5394-41d3-a9da-2cca69db15f8",
    "3704fd7b-4ff8-47ef-881f-bf64c5762cd7",
    "72caf499-23fd-4ed5-9c80-20b47d9d038d",
    "16534fb7-1187-4339-bcf2-a66a90f82041",
}


def rules():
    return tuple(r for r in load_rules(product="aws") if r.id in RULE_IDS)


def event(source, name, req=None, resp=None, *, eid=None, time="2026-10-20T12:00:00Z"):
    return {"eventSource": source, "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": name == "GetAuthorizationToken",
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": eid or source + name, "eventTime": time,
            "userIdentity": {"arn": ACTOR, "accountId": ACCOUNT},
            "requestParameters": req or {}, "responseElements": resp}


def upload_pair(source, repo, prefix):
    first = event(source, "CompleteLayerUpload",
                  {"repositoryName": repo, "layerDigests": [LAYER]},
                  {"registryId": ACCOUNT, "repositoryName": repo, "layerDigest": LAYER},
                  eid=prefix + "-layer")
    second = event(source, "PutImage",
                   {"repositoryName": repo, "imageManifest": MANIFEST, "imageTag": "stable"},
                   {"image": {"registryId": ACCOUNT, "repositoryName": repo,
                              "imageId": {"imageDigest": IMAGE}}},
                   eid=prefix + "-image", time="2026-10-20T12:01:00Z")
    return first, second


def events():
    private_layer, private_image = upload_pair("ecr.amazonaws.com", PRIVATE, "private")
    public_layer, public_image = upload_pair("ecr-public.amazonaws.com", PUBLIC, "public")
    policy = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": GRANTEE}, "Action": ["ecr-public:PutImage",
        "ecr-public:InitiateLayerUpload"]}]})
    return [
        private_layer, private_image,
        event("ecr-public.amazonaws.com", "GetAuthorizationToken", resp={
            "authorizationData": {"authorizationToken": "SYNTHETIC_SECRET_NEVER_EMIT"}}),
        event("ecr-public.amazonaws.com", "SetRepositoryPolicy",
              {"repositoryName": PUBLIC, "policyText": policy},
              {"registryId": ACCOUNT, "repositoryName": PUBLIC, "policyText": policy}),
        public_layer, public_image,
        event("ecr-public.amazonaws.com", "BatchDeleteImage",
              {"repositoryName": PUBLIC, "imageIds": [{"imageTag": "stable"}]},
              {"imageIds": [{"imageTag": "stable"}], "failures": []}),
        event("ecr-public.amazonaws.com", "DeleteRepository",
              {"repositoryName": PUBLIC},
              {"repository": {"registryId": ACCOUNT, "repositoryName": PUBLIC}}),
    ]


def test_six_rules_match_synthetic_lab_derivative():
    selected = rules()
    hits = detect_aws_events(events(), selected)
    assert len(selected) == len(hits) == len({h.rule_id for h in hits}) == 6
    assert "SYNTHETIC_SECRET_NEVER_EMIT" not in repr(hits)
    assert MANIFEST not in repr(hits)
    assert GRANTEE not in repr(hits)


def test_denied_and_unrelated_sequences_do_not_match():
    selected = rules()
    for original in events():
        denied = deepcopy(original)
        denied["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([denied], selected)
    layer, image = upload_pair("ecr-public.amazonaws.com", PUBLIC, "mismatch")
    unrelated = deepcopy(image)
    unrelated["requestParameters"]["imageManifest"] = json.dumps({"layers": [
        {"digest": "sha256:" + "b" * 64}]})
    assert not detect_aws_events([layer, unrelated], selected)
    different_actor = deepcopy(image)
    different_actor["userIdentity"]["arn"] = f"arn:aws:sts::{ACCOUNT}:assumed-role/other/session"
    assert not detect_aws_events([layer, different_actor], selected)
    policy = deepcopy(events()[3])
    body = json.loads(policy["requestParameters"]["policyText"])
    body["Statement"][0]["Action"] = ["ecr-public:BatchGetImage"]
    policy["requestParameters"]["policyText"] = json.dumps(body)
    assert not detect_aws_events([policy], selected)
