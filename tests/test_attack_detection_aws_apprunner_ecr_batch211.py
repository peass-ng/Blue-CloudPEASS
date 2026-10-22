"""Private ECR tag moves only implicate an observed auto-deploy App Runner service."""

from __future__ import annotations

import copy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
REPO = "synthetic-service"
TAG = "stable"
ARN = f"arn:aws:apprunner:us-east-1:{ACCOUNT}:service/synthetic-service/abc123"
IMAGE = f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/{REPO}:{TAG}"
SOURCE = {"imageRepository": {"imageRepositoryType": "ECR", "imageIdentifier": IMAGE},
          "autoDeploymentsEnabled": True}
COMMON = {
    "eventType": "AwsApiCall", "eventCategory": "Management",
    "managementEvent": True, "readOnly": False,
    "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
    "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT,
                     "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
}
CREATE = {
    **COMMON, "eventSource": "apprunner.amazonaws.com", "eventName": "CreateService",
    "eventID": "synthetic-create", "eventTime": "2026-10-22T00:01:00Z",
    "requestParameters": {"serviceName": "synthetic-service", "sourceConfiguration": SOURCE},
    "responseElements": {"service": {"serviceName": "synthetic-service",
                                      "serviceArn": ARN, "sourceConfiguration": SOURCE}},
}


def _put(event_id, stamp, digest):
    return {
        **COMMON, "eventSource": "ecr.amazonaws.com", "eventName": "PutImage",
        "eventID": event_id, "eventTime": stamp,
        "requestParameters": {"registryId": ACCOUNT, "repositoryName": REPO, "imageTag": TAG},
        "responseElements": {"image": {"registryId": ACCOUNT, "repositoryName": REPO,
                                       "imageId": {"imageTag": TAG, "imageDigest": digest}}},
    }


FIRST = _put("synthetic-first", "2026-10-22T00:00:00Z", "sha256:" + "a" * 64)
SECOND = _put("synthetic-second", "2026-10-22T00:02:00Z", "sha256:" + "b" * 64)
RULE = Rule(id="apprunner-ecr", title="apprunner-ecr", description="apprunner-ecr",
            level="high", technique_id="apprunner-ecr", product="aws", selection={
                "event.source": "ecr.amazonaws.com", "event.name": "PutImage",
                "event.outcome": "success", "request.apprunner_auto_deploy_tag_repointed": True,
            })
TAG_RULE = Rule(id="ecr-tag", title="ecr-tag", description="ecr-tag", level="high",
                technique_id="ecr-tag", product="aws", selection={
                    "event.source": "ecr.amazonaws.com", "event.name": "PutImage",
                    "event.outcome": "success", "request.ecr_image_tag_digest_changed": True,
                })


def _hits(events):
    return detect_aws_events(events, [RULE])


def test_realistic_auto_deploy_tag_move_emits_hash_only_target():
    hits = _hits([FIRST, CREATE, SECOND])
    assert len(hits) == 1
    assert hits[0].event_id == "synthetic-second"
    assert hits[0].target_id.startswith("sha256:")
    assert "synthetic-service" not in str(hits[0])


def test_requires_matching_enabled_service_and_distinct_digests():
    for change in (
        lambda c, p: c["requestParameters"]["sourceConfiguration"].update(autoDeploymentsEnabled=False),
        lambda c, p: c["requestParameters"]["sourceConfiguration"]["imageRepository"].update(
            imageIdentifier=f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/other:stable"),
        lambda c, p: c["requestParameters"]["sourceConfiguration"]["imageRepository"].update(
            imageIdentifier=f"{ACCOUNT}.dkr.ecr.us-east-1.amazonaws.com/{REPO}@sha256:" + "a" * 64),
        lambda c, p: p["responseElements"]["image"]["imageId"].update(
            imageDigest="sha256:" + "a" * 64),
        lambda c, p: p.update(errorCode="AccessDeniedException"),
        lambda c, p: c.update(errorCode="AccessDeniedException"),
    ):
        create, second = copy.deepcopy(CREATE), copy.deepcopy(SECOND)
        change(create, second)
        assert not _hits([FIRST, create, second])


def test_deleted_service_and_wrong_account_do_not_correlate():
    deleted = {**COMMON, "eventSource": "apprunner.amazonaws.com",
               "eventName": "DeleteService", "eventID": "synthetic-delete",
               "eventTime": "2026-10-22T00:01:30Z",
               "requestParameters": {"serviceArn": ARN}}
    assert not _hits([FIRST, CREATE, deleted, SECOND])
    other = {**SECOND, "recipientAccountId": "888888888888"}
    assert not _hits([FIRST, CREATE, other])


def test_existing_ecr_tag_signal_does_not_expose_repository_name():
    hits = detect_aws_events([FIRST, SECOND], [TAG_RULE])
    assert len(hits) == 1
    assert hits[0].target_id.startswith("sha256:")
    assert REPO not in str(hits[0])
