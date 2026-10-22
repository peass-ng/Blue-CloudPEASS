"""Fleet-role vending must bind the grant to one existing worker and its fleet role."""

from test_peaso_privesc_aws_followups import ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, reached, role, role_arn, user
from peaso.privesc.effective_permissions.aws import _glob_covers_deadline_worker_ids


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


NEW_TID = "aws-deadline-new-worker-existing-fleet-role-vend"
FUTURE_WORKERS = f"{FARM_ARN}/fleet/{FLEET}/worker/*"


def _new_worker_snapshot(*, create=FUTURE_WORKERS, assume=FUTURE_WORKERS,
                         trust_farm=FARM_ARN, mode="customerManaged", worker_count=0,
                         max_count=2, fleet_status="ACTIVE", inventory=True,
                         managed_condition=False, list_tags=True, tag_worker=True):
    create_grant = allow("deadline:CreateWorker", resource=create)
    assume_grant = allow("deadline:AssumeFleetRoleForWorker", resource=assume)
    dependent = []
    if list_tags:
        dependent.append(allow("deadline:ListTagsForResource",
                               resource=f"{FARM_ARN}/fleet/{FLEET}"))
    if tag_worker:
        dependent.append(allow("deadline:TagResource", resource=FUTURE_WORKERS))
    if managed_condition:
        condition = {"StringEquals": {"aws:PrincipalAccount": "${aws:ResourceAccount}"}}
        create_grant["Condition"] = condition
        assume_grant["Condition"] = condition
        for grant in dependent:
            grant["Condition"] = {"StringEquals": {
                "aws:PrincipalAccount": "${aws:ResourceAccount}",
                "deadline:CalledAction": "CreateWorker"}}
    actor = user("alice", create_grant, assume_grant, *dependent)
    target = role("fleet", [{"Effect": "Allow", "Principal": {
        "Service": "credentials.deadline.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnEquals": {"aws:SourceArn": trust_farm}}}],
        allow("deadline:UpdateWorker", resource=FUTURE_WORKERS))
    extra = []
    if inventory:
        extra.append(col("deadline_fleet_role", [{"id": FARM + "/" + FLEET,
                                                    "farmId": FARM, "fleetId": FLEET,
                                                    "roleArn": role_arn("fleet"),
                                                    "fleetStatus": fleet_status, "fleetMode": mode,
                                                    "workerCount": worker_count,
                                                    "maxWorkerCount": max_count,
                                                    "collection_status": "collected"}]))
    return aws_snap([actor], [target], extra)


def test_new_worker_existing_fleet_requires_capacity_trust_and_broad_scoped_grants():
    assert reached(real(_new_worker_snapshot(), NEW_TID), ALICE) == {
        role_arn("fleet"): "conditional"}
    wrong_fleet = FUTURE_WORKERS.replace(FLEET, "fleet-" + "e" * 32)
    for snap in (_new_worker_snapshot(create=wrong_fleet),
                 _new_worker_snapshot(assume=WORKER_ARN),
                 _new_worker_snapshot(trust_farm=FARM_ARN.replace(FARM, "farm-" + "e" * 32)),
                 _new_worker_snapshot(mode="serviceManagedEc2"),
                 _new_worker_snapshot(worker_count=2, max_count=2),
                 _new_worker_snapshot(fleet_status="SUSPENDED"),
                 _new_worker_snapshot(list_tags=False),
                 _new_worker_snapshot(tag_worker=False),
                 _new_worker_snapshot(inventory=False)):
        assert edges(real(snap, NEW_TID), ALICE) == []


def test_new_worker_existing_fleet_accepts_managed_worker_host_scope():
    snap = _new_worker_snapshot(create="*", assume="*", managed_condition=True)
    assert reached(real(snap, NEW_TID), ALICE) == {role_arn("fleet"): "conditional"}


def test_future_worker_scope_requires_every_generated_id():
    prefix = f"{FARM_ARN}/fleet/{FLEET}/worker/"
    assert _glob_covers_deadline_worker_ids(prefix + "*", prefix)
    assert _glob_covers_deadline_worker_ids(prefix + "worker-*", prefix)
    assert _glob_covers_deadline_worker_ids(prefix + "worker-" + "?" * 32, prefix)
    assert not _glob_covers_deadline_worker_ids(prefix + "worker-a*", prefix)
    assert not _glob_covers_deadline_worker_ids(prefix + WORKER, prefix)
    assert not _glob_covers_deadline_worker_ids(prefix.replace(FLEET, "fleet-" + "e" * 32) + "*", prefix)
