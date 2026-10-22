"""A Device Farm role edge needs one usable project, pool, and upload scope."""
from __future__ import annotations

from peaso import privesc
from peaso.privesc import versioned_catalog as catalog
from tests.test_peaso_privesc_schema_ext import reached
from tests.test_peaso_privesc_v4_batch import _snapshot


ID = "aws-devicefarm-passrole-project-schedulerun"
ENTRY = next(entry for entry in privesc.load_catalog()["entries"] if entry["id"] == ID)
SOURCE = "arn:aws:iam::111111111111:user/alice"
TARGET = "arn:aws:iam::111111111111:role/victim"
SCOPE = "111111111111/us-east-1"
PROJECT = "arn:aws:devicefarm:us-east-1:111111111111:project:project-id"
POOL = "arn:aws:devicefarm:us-east-1::devicepool:pool-id"
UPLOADS = "arn:aws:devicefarm:us-east-1:111111111111:upload:project-id/*"


def _case(*, project=PROJECT, pool_project=PROJECT, pool=POOL, compatible=1,
          create_project=PROJECT, schedule_project=PROJECT, schedule_pool=POOL,
          schedule_upload=UPLOADS, passed_to="devicefarm.amazonaws.com",
          trust="devicefarm.amazonaws.com", project_status="collected", pool_status="collected"):
    snapshot = _snapshot(ENTRY)
    user = next(c for c in snapshot["collections"] if c["type"] == "iam_user")["items"][0]
    user["UserPolicyList"][0]["PolicyDocument"]["Statement"] = [
        {"Effect": "Allow", "Action": "devicefarm:CreateUpload", "Resource": create_project},
        {"Effect": "Allow", "Action": "devicefarm:ScheduleRun",
         "Resource": [schedule_project, schedule_pool, schedule_upload]},
        {"Effect": "Allow", "Action": "iam:PassRole", "Resource": TARGET,
         "Condition": {"StringEquals": {"iam:PassedToService": passed_to}}},
    ]
    role = next(c for c in snapshot["collections"] if c["type"] == "iam_role")["items"][0]
    role["AssumeRolePolicyDocument"] = {"Statement": [
        {"Effect": "Allow", "Principal": {"Service": trust}, "Action": "sts:AssumeRole"}]}
    snapshot["collections"].extend([
        {"type": "devicefarm_project", "scope": SCOPE, "service": "devicefarm",
         "status": project_status, "items": [{"arn": project}] if project_status in ("collected", "partial") else [],
         "error": None},
        {"type": "devicefarm_device_pool", "scope": SCOPE, "service": "devicefarm",
         "status": pool_status, "items": [{"arn": pool, "ProjectArn": pool_project,
                                        "CompatibleWebNodeDevices": compatible}]
         if pool_status in ("collected", "partial") else [], "error": None},
    ])
    return snapshot


def _definite(snapshot):
    return reached(privesc.analyze(snapshot, entries=[ENTRY], include_unknown=False), SOURCE, ID)


def test_exact_project_compatible_pool_and_generated_upload_scope_reach_role():
    assert _definite(_case()) == {TARGET: "conditional"}


def test_valid_project_and_pool_remain_usable_in_partial_inventory():
    assert _definite(_case(project_status="partial", pool_status="partial")) == {TARGET: "conditional"}


def test_unrelated_project_pool_or_upload_permission_does_not_reach_role():
    other = PROJECT.replace("project-id", "other-project")
    cases = [
        {"create_project": other},
        {"schedule_project": other},
        {"schedule_pool": POOL.replace("pool-id", "other-pool")},
        {"schedule_upload": UPLOADS.replace("project-id", "other-project")},
        {"schedule_upload": UPLOADS.replace("*", "one-upload")},
        {"pool_project": other},
        {"compatible": 0},
        {"passed_to": "ec2.amazonaws.com"},
        {"trust": "ec2.amazonaws.com"},
    ]
    for kwargs in cases:
        assert not _definite(_case(**kwargs)), kwargs


def test_missing_inventory_cannot_produce_definite_role_edge():
    for kwargs in ({"project_status": "access_denied"}, {"pool_status": "access_denied"},
                   {"project_status": "empty"}, {"pool_status": "empty"}):
        assert not _definite(_case(**kwargs)), kwargs


def test_prior_binding_retains_old_route_and_current_binding_is_valid():
    prior = {"schema": catalog.BINDING_SCHEMA,
             "manifest_sha256": catalog.DEVICEFARM_690_PREVIOUS_MANIFEST,
             "effective_tree_sha256": catalog.DEVICEFARM_690_PREVIOUS_TREE,
             "source_revision": catalog.V4_REVISION}
    old, status = catalog.lookup_entries([ID], prior)
    assert status == "exact_previous_current" and ID in old
    assert "preconditions" not in old[ID]
    current, status = catalog.lookup_entries([ID], catalog.current_binding())
    assert status == "exact_strict_privesc"
    assert current[ID]["preconditions"] == ["devicefarm_existing_project_new_web_test_role"]
