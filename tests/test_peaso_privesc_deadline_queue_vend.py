"""A Deadline queue vend must join the caller's scoped grant to one attached role."""

from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached, role, role_arn, user


FARM = "farm-" + "a" * 32
QUEUE = "queue-" + "b" * 32
OTHER_QUEUE = "queue-" + "c" * 32
QUEUE_ARN = f"arn:aws:deadline:{REGION}:{ACCOUNT}:farm/{FARM}/queue/{QUEUE}"
FARM_ARN = f"arn:aws:deadline:{REGION}:{ACCOUNT}:farm/{FARM}"
TID = "aws-deadline-existing-queue-role-vend"


def _snapshot(*, permission=QUEUE_ARN, queue_role="render", trust_farm=FARM_ARN,
              condition=None, inventory=True):
    grant = allow("deadline:AssumeQueueRoleForUser", resource=permission)
    if condition:
        grant["Condition"] = condition
    actor = user("alice", grant)
    target = role("render", [{"Effect": "Allow", "Principal": {
        "Service": "credentials.deadline.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnEquals": {"aws:SourceArn": trust_farm}}}],
        allow("s3:GetObject", resource="arn:aws:s3:::private-render/*"))
    extra = []
    if inventory:
        extra.append(col("deadline_queue", [{"id": FARM + "/" + QUEUE, "farmId": FARM,
                                               "queueId": QUEUE, "roleArn": role_arn(queue_role),
                                               "status": "SCHEDULING", "collection_status": "collected"}]))
    return aws_snap([actor], [target], extra)


def test_deadline_queue_vend_requires_one_exact_queue_grant_role_and_farm_trust():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("render"): "conditional"}
    for snap in (_snapshot(permission=QUEUE_ARN.replace(QUEUE, OTHER_QUEUE)),
                 _snapshot(queue_role="other"),
                 _snapshot(trust_farm=FARM_ARN.replace(FARM, "farm-" + "d" * 32)),
                 _snapshot(inventory=False)):
        assert edges(real(snap, TID), ALICE) == []


def test_deadline_queue_vend_does_not_promote_unresolved_membership_condition():
    snap = _snapshot(condition={"StringEquals": {"deadline:QueueMembershipLevels": "CONTRIBUTOR"}})
    assert edges(real(snap, TID), ALICE) == []
