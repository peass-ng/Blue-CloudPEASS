"""Check secret version and policy signals against CloudTrail shaped records."""

from copy import deepcopy

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="current", title="Current version moved", level="medium", description="moved",
         technique_id="aws-secretsmanager-current-version-moved", product="aws",
         selection={"event.source": "secretsmanager.amazonaws.com",
                    "event.name": "UpdateSecretVersionStage", "event.outcome": "success",
                    "request.secretsmanager_current_version_moved": True}),
    Rule(id="policy", title="Policy deleted", level="medium", description="deleted",
         technique_id="aws-secretsmanager-resource-policy-deleted", product="aws",
         selection={"event.source": "secretsmanager.amazonaws.com",
                    "event.name": "DeleteResourcePolicy", "event.outcome": "success",
                    "request.secretsmanager_resource_policy_deleted": True}),
    Rule(id="force", title="Force deleted", level="high", description="force delete",
         technique_id="aws-secretsmanager-force-delete", product="aws",
         selection={"event.source": "secretsmanager.amazonaws.com",
                    "event.name": "DeleteSecret", "event.outcome": "success",
                    "request.secret_force_delete_accepted": True}),
    Rule(id="rotation", title="Rotation Lambda bound", level="medium", description="rotation",
         technique_id="aws-secretsmanager-rotation-lambda-bound", product="aws",
         selection={"event.source": "secretsmanager.amazonaws.com",
                    "event.name": "RotateSecret", "event.outcome": "success",
                    "request.secretsmanager_rotation_lambda_bound": True}),
    Rule(id="replica", title="Replica promoted", level="medium", description="replica",
         technique_id="aws-secretsmanager-replica-promoted", product="aws",
         selection={"event.source": "secretsmanager.amazonaws.com",
                    "event.name": "StopReplicationToReplica", "event.outcome": "success",
                    "request.secretsmanager_replica_promoted": True}),
]
ARN = "arn:aws:secretsmanager:us-east-1:222233334444:secret:synthetic-abcdef"


def _event(name: str) -> dict:
    return {"eventSource": "secretsmanager.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "222233334444", "eventID": "sample-id",
            "userIdentity": {"arn": "arn:aws:iam::222233334444:user/test"},
            "requestParameters": {"secretId": ARN, "versionStage": "AWSCURRENT",
                                  "moveToVersionId": "new", "removeFromVersionId": "old"},
            "responseElements": {"arn": ARN}}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_current_version_move_and_rejected_variants() -> None:
    event = _event("UpdateSecretVersionStage")
    assert _hits(event) == ["aws-secretsmanager-current-version-moved"]
    for change in ("pending", "missing_old", "same_version", "error", "wrong_response"):
        item = deepcopy(event)
        if change == "pending": item["requestParameters"]["versionStage"] = "AWSPENDING"
        if change == "missing_old": item["requestParameters"].pop("removeFromVersionId")
        if change == "same_version": item["requestParameters"]["removeFromVersionId"] = "new"
        if change == "error": item["errorCode"] = "AccessDeniedException"
        if change == "wrong_response": item["responseElements"]["arn"] = ARN + "-other"
        assert _hits(item) == [], change


def test_policy_deletion_and_rejected_variants() -> None:
    event = _event("DeleteResourcePolicy")
    assert _hits(event) == ["aws-secretsmanager-resource-policy-deleted"]
    for change in ("error", "wrong_response", "other_name"):
        item = deepcopy(event)
        if change == "error": item["errorCode"] = "AccessDeniedException"
        if change == "wrong_response": item["responseElements"]["arn"] = ARN + "-other"
        if change == "other_name": item["eventName"] = "GetResourcePolicy"
        assert _hits(item) == [], change


def test_force_delete_and_recoverable_delete() -> None:
    event = _event("DeleteSecret")
    event["requestParameters"]["recoveryWindowInDays"] = 7
    assert _hits(event) == []
    event["requestParameters"].pop("recoveryWindowInDays")
    event["requestParameters"]["forceDeleteWithoutRecovery"] = True
    assert _hits(event) == ["aws-secretsmanager-force-delete"]
    event["errorCode"] = "AccessDeniedException"
    assert _hits(event) == []


def test_rotation_lambda_binding_and_schedule_only_change() -> None:
    event = _event("RotateSecret")
    event["requestParameters"]["rotationLambdaARN"] = (
        "arn:aws:lambda:us-east-1:222233334444:function:synthetic-rotation")
    event["requestParameters"]["rotateImmediately"] = False
    assert _hits(event) == ["aws-secretsmanager-rotation-lambda-bound"]
    schedule_only = deepcopy(event)
    schedule_only["requestParameters"].pop("rotationLambdaARN")
    assert _hits(schedule_only) == []
    rejected = deepcopy(event)
    rejected["errorCode"] = "AccessDeniedException"
    assert _hits(rejected) == []


def test_replica_promotion_and_inconsistent_response() -> None:
    event = _event("StopReplicationToReplica")
    assert _hits(event) == ["aws-secretsmanager-replica-promoted"]
    wrong = deepcopy(event)
    wrong["responseElements"]["arn"] = ARN + "-other"
    assert _hits(wrong) == []
    denied = deepcopy(event)
    denied["errorCode"] = "AccessDeniedException"
    assert _hits(denied) == []
