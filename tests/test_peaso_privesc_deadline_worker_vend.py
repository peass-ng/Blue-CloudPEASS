"""Fleet-role vending must bind the grant to one existing worker and its fleet role."""

from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached, role, role_arn, user


FARM = "farm-" + "a" * 32
FLEET = "fleet-" + "b" * 32
WORKER = "worker-" + "c" * 32
OTHER_WORKER = "worker-" + "d" * 32
FARM_ARN = f"arn:aws:deadline:{REGION}:{ACCOUNT}:farm/{FARM}"
WORKER_ARN = f"{FARM_ARN}/fleet/{FLEET}/worker/{WORKER}"
TID = "aws-deadline-existing-worker-role-vend"


def _snapshot(*, permission=WORKER_ARN, worker_role="fleet", trust_farm=FARM_ARN,
              condition=None, inventory=True, worker_status="RUNNING"):
    grant = allow("deadline:AssumeFleetRoleForWorker", resource=permission)
    if condition:
        grant["Condition"] = condition
    actor = user("alice", grant)
    target = role("fleet", [{"Effect": "Allow", "Principal": {
        "Service": "credentials.deadline.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnEquals": {"aws:SourceArn": trust_farm}}}],
        allow("deadline:UpdateWorker", resource=WORKER_ARN))
    extra = []
    if inventory:
        extra.append(col("deadline_worker", [{"id": FARM + "/" + FLEET + "/" + WORKER,
                                                "farmId": FARM, "fleetId": FLEET,
                                                "workerId": WORKER, "roleArn": role_arn(worker_role),
                                                "fleetStatus": "ACTIVE", "workerStatus": worker_status,
                                                "collection_status": "collected"}]))
    return aws_snap([actor], [target], extra)


def test_existing_worker_vend_requires_exact_worker_role_and_farm_trust():
    assert reached(real(_snapshot(), TID), ALICE) == {role_arn("fleet"): "conditional"}
    for snap in (_snapshot(permission=WORKER_ARN.replace(WORKER, OTHER_WORKER)),
                 _snapshot(worker_role="other"),
                 _snapshot(trust_farm=FARM_ARN.replace(FARM, "farm-" + "e" * 32)),
                 _snapshot(worker_status="STOPPED"), _snapshot(inventory=False)):
        assert edges(real(snap, TID), ALICE) == []


def test_existing_worker_vend_does_not_promote_unresolved_membership_condition():
    snap = _snapshot(condition={"StringEquals": {"deadline:FleetMembershipLevels": "MANAGER"}})
    assert edges(real(snap, TID), ALICE) == []
