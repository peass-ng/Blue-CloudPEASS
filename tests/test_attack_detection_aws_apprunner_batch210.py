"""App Runner configuration signals require an accepted, coherent API event."""

from __future__ import annotations

import copy

from peaso.attack_detection import Rule, detect_aws_events


ACCOUNT = "999999999999"
ARN = f"arn:aws:apprunner:us-east-1:{ACCOUNT}:service/synthetic-app/abc123"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/synthetic-app"
SOURCE = {
    "imageRepository": {
        "imageIdentifier": "public.ecr.aws/docker/library/python:3.12-slim",
        "imageRepositoryType": "ECR_PUBLIC",
        "imageConfiguration": {
            "port": "8080", "startCommand": "python -m http.server 8080",
            "runtimeEnvironmentVariables": {"PEASSO_SYNTHETIC": "value"},
        },
    },
    "autoDeploymentsEnabled": False,
}
COMMON = {
    "eventSource": "apprunner.amazonaws.com", "eventType": "AwsApiCall",
    "eventCategory": "Management", "managementEvent": True, "readOnly": False,
    "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
    "eventTime": "2026-10-22T00:00:00Z", "eventID": "synthetic-event",
    "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": f"arn:aws:iam::{ACCOUNT}:user/synthetic"},
}
CREATE = {
    **COMMON, "eventName": "CreateService",
    "requestParameters": {
        "serviceName": "synthetic-app", "sourceConfiguration": SOURCE,
        "instanceConfiguration": {"instanceRoleArn": ROLE},
    },
    "responseElements": {"service": {
        "serviceArn": ARN, "serviceName": "synthetic-app",
        "sourceConfiguration": SOURCE,
        "instanceConfiguration": {"instanceRoleArn": ROLE},
    }},
}
UPDATE = {
    **COMMON, "eventName": "UpdateService",
    "requestParameters": {"serviceArn": ARN, "sourceConfiguration": SOURCE},
    "responseElements": {"service": {"serviceArn": ARN, "sourceConfiguration": SOURCE}},
}
RULES = (
    Rule(id="create", title="create", description="create", level="medium",
         technique_id="create", product="aws", selection={
             "event.source": "apprunner.amazonaws.com", "event.name": "CreateService",
             "event.outcome": "success",
             "request.apprunner_service_created_with_instance_role": True,
         }),
    Rule(id="update", title="update", description="update", level="medium",
         technique_id="update", product="aws", selection={
             "event.source": "apprunner.amazonaws.com", "event.name": "UpdateService",
             "event.outcome": "success",
             "request.apprunner_runtime_configuration_updated": True,
         }),
)


def _hits(events):
    return {hit.technique_id for hit in detect_aws_events(events, RULES)}


def test_accepted_create_and_update_with_hash_only_target():
    hits = detect_aws_events([CREATE, UPDATE], RULES)
    assert {hit.technique_id for hit in hits} == {"create", "update"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert all("synthetic-app" not in str(hit) for hit in hits)


def test_create_requires_passed_role_and_response_agreement():
    for change in (
        lambda e: e["requestParameters"]["instanceConfiguration"].pop("instanceRoleArn"),
        lambda e: e["responseElements"]["service"]["instanceConfiguration"].update(
            instanceRoleArn=f"arn:aws:iam::{ACCOUNT}:role/other"),
        lambda e: e["requestParameters"].update(serviceName="other"),
    ):
        event = copy.deepcopy(CREATE)
        change(event)
        assert not _hits([event])


def test_update_requires_runtime_configuration():
    for change in (
        lambda e: e["requestParameters"].update(serviceArn=ARN + "-other"),
        lambda e: e["requestParameters"].update(sourceConfiguration={}),
        lambda e: e["requestParameters"]["sourceConfiguration"]["imageRepository"].update(
            imageConfiguration={"port": "8080"}),
    ):
        event = copy.deepcopy(UPDATE)
        change(event)
        assert not _hits([event])


def test_rejected_and_wrong_envelope_events():
    for original in (CREATE, UPDATE):
        for field, value in (
            ("errorCode", "AccessDeniedException"),
            ("eventCategory", "Data"), ("readOnly", True),
            ("eventSource", "iam.amazonaws.com"),
        ):
            event = {**original, field: value}
            assert not _hits([event])
        event = copy.deepcopy(original)
        event["userIdentity"]["accountId"] = "888888888888"
        assert not _hits([event])
