"""EFS privileged access signals require accepted matching API responses."""

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


RULES = [
    Rule(id="root-point", title="Root point", level="medium", description="point",
         technique_id="aws-efs-root-access-point-created", product="aws",
         selection={"event.source": "elasticfilesystem.amazonaws.com",
                    "event.name": "CreateAccessPoint", "event.outcome": "success",
                    "request.efs_root_access_point": True}),
    Rule(id="root-policy", title="Root policy", level="high", description="policy",
         technique_id="aws-efs-wildcard-client-root-policy", product="aws",
         selection={"event.source": "elasticfilesystem.amazonaws.com",
                    "event.name": "PutFileSystemPolicy", "event.outcome": "success",
                    "request.efs_wildcard_client_root_policy": True}),
    Rule(id="policy-delete", title="Policy deleted", level="medium", description="delete",
         technique_id="aws-efs-file-system-policy-deleted", product="aws",
         selection={"event.source": "elasticfilesystem.amazonaws.com",
                    "event.name": "DeleteFileSystemPolicy", "event.outcome": "success",
                    "request.efs_policy_deleted": True}),
    Rule(id="point-delete", title="Point deleted", level="medium", description="delete",
         technique_id="aws-efs-access-point-deleted", product="aws",
         selection={"event.source": "elasticfilesystem.amazonaws.com",
                    "event.name": "DeleteAccessPoint", "event.outcome": "success",
                    "request.efs_access_point_deleted": True}),
    Rule(id="fs-delete", title="File system deleted", level="high", description="delete",
         technique_id="aws-efs-file-system-deleted", product="aws",
         selection={"event.source": "elasticfilesystem.amazonaws.com",
                    "event.name": "DeleteFileSystem", "event.outcome": "success",
                    "request.efs_file_system_deleted": True}),
]


def _base(name: str, request: dict, response: dict) -> dict:
    return {"eventSource": "elasticfilesystem.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": False,
            "recipientAccountId": "222233334444", "requestParameters": request,
            "responseElements": response}


def _hits(event: dict) -> list[str]:
    return [d.technique_id for d in detect_aws_events([event], RULES)]


def test_root_access_point_and_nonroot_negative() -> None:
    fs = "fs-06793414d4e691fb4"
    point = {"posixUser": {"uid": 0, "gid": 0}, "rootDirectory": {"path": "/"}}
    event = _base("CreateAccessPoint", {"fileSystemId": fs, **point},
                  {"fileSystemId": fs, "accessPointId": "fsap-0b1f9e5329caf3644", **point})
    assert _hits(event) == ["aws-efs-root-access-point-created"]
    for variant in ("nonroot", "subdir", "failed", "wrong_fs", "data_event"):
        item = deepcopy(event)
        if variant == "nonroot": item["requestParameters"]["posixUser"]["uid"] = 1000
        if variant == "subdir": item["requestParameters"]["rootDirectory"]["path"] = "/app"
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "wrong_fs": item["responseElements"]["fileSystemId"] = "fs-11111111"
        if variant == "data_event": item["eventCategory"] = "Data"
        assert _hits(item) == [], variant


def test_wildcard_client_root_policy_and_limited_negative() -> None:
    fs = "fs-06793414d4e691fb4"
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientRootAccess"],
        "Resource": f"arn:aws:elasticfilesystem:us-east-1:222233334444:file-system/{fs}"}]}
    event = _base("PutFileSystemPolicy", {"fileSystemId": fs, "policy": json.dumps(policy)},
                  {"fileSystemId": fs, "policy": json.dumps(policy)})
    assert _hits(event) == ["aws-efs-wildcard-client-root-policy"]
    for variant in ("restricted", "no_root", "conditional", "failed", "response_limited"):
        item = deepcopy(event)
        p = deepcopy(policy)
        if variant == "restricted": p["Statement"][0]["Principal"]["AWS"] = "arn:aws:iam::222233334444:root"
        if variant == "no_root": p["Statement"][0]["Action"] = ["elasticfilesystem:ClientMount"]
        if variant == "conditional":
            p["Statement"][0]["Condition"] = {"Bool": {"elasticfilesystem:AccessedViaMountTarget": "true"}}
        if variant in {"restricted", "no_root", "conditional"}:
            item["requestParameters"]["policy"] = json.dumps(p)
            item["responseElements"]["policy"] = json.dumps(p)
        if variant == "failed": item["errorCode"] = "AccessDeniedException"
        if variant == "response_limited": item["responseElements"]["policy"] = "{}"
        assert _hits(item) == [], variant


def test_efs_deletions_require_valid_target_and_success() -> None:
    cases = (("DeleteFileSystemPolicy", "fileSystemId", "fs-06793414d4e691fb4",
              "aws-efs-file-system-policy-deleted"),
             ("DeleteAccessPoint", "accessPointId", "fsap-0b1f9e5329caf3644",
              "aws-efs-access-point-deleted"),
             ("DeleteFileSystem", "fileSystemId", "fs-06793414d4e691fb4",
              "aws-efs-file-system-deleted"))
    for name, field, target, technique in cases:
        event = _base(name, {field: target}, None)
        assert _hits(event) == [technique]
        denied = deepcopy(event)
        denied["errorCode"] = "AccessDeniedException"
        assert _hits(denied) == []
        malformed = deepcopy(event)
        malformed["requestParameters"][field] = "bad-id"
        assert _hits(malformed) == []
