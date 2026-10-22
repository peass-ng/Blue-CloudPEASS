"""Deadline queue role changes need one exact queue and a passable role."""

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, assert_unresolved, aws_snap, col, edges,
    real, reached, role, role_arn, user,
)


FARM = "farm-" + "a" * 32
QUEUE = "queue-" + "b" * 32
OTHER_QUEUE = "queue-" + "c" * 32
FARM_ARN = f"arn:aws:deadline:{REGION}:{ACCOUNT}:farm/{FARM}"
QUEUE_ARN = f"{FARM_ARN}/queue/{QUEUE}"
TID = "aws-deadline-passrole-createqueue-updatequeue"


def _snapshot(*, update=QUEUE_ARN, vend=QUEUE_ARN, pass_service="deadline.amazonaws.com",
              trust_farm=FARM_ARN, queue_role="old", inventory=True, membership=False):
    passed = allow("iam:PassRole", resource=role_arn("new"))
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": pass_service}}
    vend_grant = allow("deadline:AssumeQueueRoleForUser", resource=vend)
    if membership:
        vend_grant["Condition"] = {"StringEquals": {"deadline:QueueMembershipLevels": "MANAGER"}}
    actor = user("alice", passed, allow("deadline:UpdateQueue", resource=update), vend_grant)
    target = role("new", [{"Effect": "Allow", "Principal": {
        "Service": "credentials.deadline.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnEquals": {"aws:SourceArn": trust_farm}}}],
        allow("s3:GetObject", resource="arn:aws:s3:::private-render/*"))
    extra = [col("deadline_queue", [{"id": FARM + "/" + QUEUE, "farmId": FARM,
                                      "queueId": QUEUE, "roleArn": role_arn(queue_role),
                                      "status": "SCHEDULING", "collection_status": "collected"}])] if inventory else []
    return aws_snap([actor], [target], extra)


def test_exact_queue_update_and_role_vend():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("new"): "conditional"}
    for snap in (_snapshot(update=QUEUE_ARN.replace(QUEUE, OTHER_QUEUE)),
                 _snapshot(vend=QUEUE_ARN.replace(QUEUE, OTHER_QUEUE)),
                 _snapshot(pass_service="lambda.amazonaws.com"),
                 _snapshot(trust_farm=FARM_ARN.replace(FARM, "farm-" + "d" * 32)),
                 _snapshot(queue_role="new"), _snapshot(membership=True),
                 _snapshot(inventory=False)):
        assert edges(real(snap, TID), ALICE) == []


def test_new_queue_generation_remains_unresolved():
    snap = _snapshot(inventory=False)
    snap["collections"].append({"type": "deadline_queue", "scope": f"{ACCOUNT}/{REGION}",
                                "service": "deadline_queue", "status": "empty", "items": [], "error": None})
    actor = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        allow("iam:PassRole", resource=role_arn("new")),
        allow("deadline:CreateQueue", resource=f"{FARM_ARN}/queue/*"),
        allow("deadline:AssumeQueueRoleForUser", resource=f"{FARM_ARN}/queue/*"),
    ]
    result = real(snap, TID, include_unknown=True)
    assert role_arn("new") not in reached(result, ALICE, TID)
    assert_unresolved(result, ALICE, TID)
