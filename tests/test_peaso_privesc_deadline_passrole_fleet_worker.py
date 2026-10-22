"""A changed Deadline fleet role grants only a witnessed worker operation."""

from copy import deepcopy

from test_peaso_privesc_aws_followups import (
    ACCOUNT, ALICE, REGION, allow, aws_snap, col, edges, real, role, role_arn, user,
)


FARM = "farm-" + "a" * 32
FLEET = "fleet-" + "b" * 32
WORKER = "worker-" + "c" * 32
FARM_ARN = f"arn:aws:deadline:{REGION}:{ACCOUNT}:farm/{FARM}"
FLEET_ARN = f"{FARM_ARN}/fleet/{FLEET}"
WORKER_ARN = f"{FLEET_ARN}/worker/{WORKER}"
TID = "aws-deadline-passrole-fleet-createworker"
ROLE_ID = "AROADEADLINEFLEET12345"
TIME = "2026-10-22T12:00:00Z"


def _snapshot(*, operation="CreateFleet", changed=None, direct=False, duplicate=False):
    passed = allow("iam:PassRole", resource=role_arn("worker"))
    passed["Condition"] = {"StringEquals": {"iam:PassedToService": "deadline.amazonaws.com"}}
    grants = [passed, allow("deadline:" + operation, resource=FLEET_ARN),
              allow("deadline:ListTagsForResource", resource=FLEET_ARN),
              allow("deadline:CreateWorker", resource=WORKER_ARN),
              allow("deadline:AssumeFleetRoleForWorker", resource=WORKER_ARN)]
    if direct:
        grants.append(allow("deadline:UpdateWorkerSchedule", resource=WORKER_ARN))
    actor = user("alice", *grants)
    target_role = role("worker", [{"Effect": "Allow", "Principal": {
        "Service": "credentials.deadline.amazonaws.com"}, "Action": "sts:AssumeRole",
        "Condition": {"StringEquals": {"aws:SourceAccount": ACCOUNT},
                      "ArnEquals": {"aws:SourceArn": FARM_ARN}}}],
        allow("deadline:UpdateWorkerSchedule", resource=WORKER_ARN))
    target_role["RoleId"] = ROLE_ID
    proof = {
        "TechniqueId": TID, "SourceArn": ALICE, "TargetKind": "aws_verified_authority",
        "TargetId": WORKER_ARN, "TargetAccount": ACCOUNT, "Status": "verified",
        "VerifiedPreconditions": True, "EffectType": "bounded_resource_operation",
        "VerifiedConditionIds": ["exact_verified_worker_authority"],
        "FarmArn": FARM_ARN, "FleetArn": FLEET_ARN, "WorkerArn": WORKER_ARN,
        "FarmId": FARM, "FleetId": FLEET, "WorkerId": WORKER,
        "FleetRoleArn": role_arn("worker"), "FleetRoleId": ROLE_ID,
        "FleetMode": "customerManaged", "FleetOperation": operation,
        "FleetOperationSucceeded": True, "CreateWorkerSucceeded": True,
        "AssumeFleetRoleForWorkerSucceeded": True, "WorkerCredentialsUsed": True,
        "WorkerAction": "deadline:UpdateWorkerSchedule",
        "WorkerActionResourceArn": WORKER_ARN, "WorkerActionSucceeded": True,
        "SourcePreviouslyDenied": True, "WorkerTagPropagationEnabled": False,
        "FleetTagsRequested": False, "EvidenceRef": "reviewed-event-123",
        "EvidenceObservedAt": TIME, "EvidenceExpiresAt": "2026-10-22T12:05:00Z",
    }
    if changed:
        proof.update(changed)
    evidence = [proof, deepcopy(proof)] if duplicate else [proof]
    snap = aws_snap([actor], [target_role], [col("aws_privesc_challenge_evidence", evidence)])
    snap["created_at"] = "2026-10-22T12:01:00Z"
    return snap


def test_fleet_worker_new_authority_is_bounded_to_witnessed_operation():
    result = real(_snapshot(), TID, include_unknown=True)
    found = edges(result, ALICE, TID)
    assert len(found) == 1 and found[0]["confidence"] == "conditional"
    node = next(node for node in result["graph"]["nodes"] if node["id"] == found[0]["target"])
    assert node["type"] == "aws_verified_authority"
    assert node["attrs"]["arn"] == WORKER_ARN
    assert role_arn("worker") != found[0]["target"]


def test_fleet_worker_mismatches_never_become_a_concrete_edge():
    negatives = [
        _snapshot(changed={"FleetId": "fleet-" + "d" * 32}),
        _snapshot(changed={"FleetRoleId": "other"}),
        _snapshot(changed={"WorkerActionSucceeded": False}),
        _snapshot(changed={"EvidenceObservedAt": "2026-10-22T11:00:00Z"}),
        _snapshot(changed={"WorkerAction": "s3:GetObject"}),
        _snapshot(changed={"FleetRoleArn": role_arn("other")}),
        _snapshot(changed={"WorkerTagPropagationEnabled": True}),
        _snapshot(duplicate=True), _snapshot(direct=True),
    ]
    for snap in negatives:
        result = real(snap, TID, include_unknown=True)
        assert all(edge["confidence"] != "conditional" for edge in edges(result, ALICE, TID))


def test_update_fleet_branch_uses_scoped_fleet_grant():
    assert len(edges(real(_snapshot(operation="UpdateFleet"), TID), ALICE, TID)) == 1
    snap = _snapshot(operation="UpdateFleet")
    actor = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"][1]["Resource"] = FLEET_ARN + "-other"
    assert edges(real(snap, TID), ALICE, TID) == []


def test_worker_tag_propagation_requires_its_dependent_grant():
    snap = _snapshot(changed={"WorkerTagPropagationEnabled": True})
    actor = next(c for c in snap["collections"] if c["type"] == "iam_user")["items"][0]
    actor["UserPolicyList"][0]["PolicyDocument"]["Statement"].append(
        allow("deadline:TagResource", resource=WORKER_ARN))
    assert len(edges(real(snap, TID), ALICE, TID)) == 1
