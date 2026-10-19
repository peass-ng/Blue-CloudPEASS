"""Live-shaped S3, Backup, and ECR control-plane observations."""

from __future__ import annotations

from copy import deepcopy
import json

from peaso.attack_detection import Rule, detect_aws_events


SELECTIONS = {
    "s3_versioning_suspended": ("s3.amazonaws.com", "PutBucketVersioning", "request.s3_versioning_suspended"),
    "s3_broad_expiration": ("s3.amazonaws.com", "PutBucketLifecycle", "request.s3_broad_one_day_expiration"),
    "s3_bucket_deleted": ("s3.amazonaws.com", "DeleteBucket", "request.s3_bucket_deleted"),
    "s3_compliance_retention": ("s3.amazonaws.com", "PutBucketObjectLockConfiguration",
                                "request.s3_default_compliance_retention"),
    "backup_self_delete": ("backup.amazonaws.com", "PutBackupVaultAccessPolicy", "request.backup_self_delete_grant"),
    "ecr_scan_disabled": ("ecr.amazonaws.com", "PutImageScanningConfiguration", "request.ecr_scan_on_push_disabled"),
    "ecr_wildcard_read": ("ecr.amazonaws.com", "SetRepositoryPolicy", "request.ecr_wildcard_image_read_grant"),
}
RULES = [Rule(id=key, title=key, level="high", description=key, technique_id=key,
              product="aws", selection={"event.source": source, "event.name": name,
                                        "event.outcome": "success", field: True})
         for key, (source, name, field) in SELECTIONS.items()]


def _base(source: str, name: str, request: dict, response: dict | None = None) -> dict:
    return {
        "eventSource": source, "eventName": name, "eventCategory": "Management",
        "eventType": "AwsApiCall", "managementEvent": True, "readOnly": False,
        "eventID": "a7225934-7d24-4d9c-b721-ce85d6b9ab83",
        "eventTime": "2026-10-19T08:59:36Z", "awsRegion": "us-east-1",
        "recipientAccountId": "947247140022",
        "userIdentity": {"type": "IAMUser", "accountId": "947247140022",
                         "arn": "arn:aws:iam::947247140022:user/testenv"},
        "requestParameters": request, "responseElements": response,
    }


def _matches(row: dict) -> list[str]:
    return [match.technique_id for match in detect_aws_events([row], RULES)]


def test_s3_live_shaped_positive_and_benign_negatives() -> None:
    bucket = "peasso-detect-retention-947247140022-16d2fbb2b2"
    version = _base("s3.amazonaws.com", "PutBucketVersioning",
                    {"bucketName": bucket, "VersioningConfiguration": {"Status": "Suspended"}})
    assert _matches(version) == ["s3_versioning_suspended"]
    version["requestParameters"]["VersioningConfiguration"]["Status"] = "Enabled"
    assert _matches(version) == []

    lifecycle = _base("s3.amazonaws.com", "PutBucketLifecycle",
                      {"bucketName": bucket, "LifecycleConfiguration": {"Rule": {
                          "Status": "Enabled", "Filter": {"Prefix": ""},
                          "Expiration": {"Days": 1}}}})
    assert _matches(lifecycle) == ["s3_broad_expiration"]
    for change in ({"Days": 30}, {"Days": True}):
        row = deepcopy(lifecycle)
        row["requestParameters"]["LifecycleConfiguration"]["Rule"]["Expiration"] = change
        assert _matches(row) == []
    row = deepcopy(lifecycle)
    row["requestParameters"]["LifecycleConfiguration"]["Rule"]["Filter"]["Prefix"] = "scratch/"
    assert _matches(row) == []

    deleted = _base("s3.amazonaws.com", "DeleteBucket", {"bucketName": bucket})
    assert _matches(deleted) == ["s3_bucket_deleted"]
    deleted["errorCode"] = "BucketNotEmpty"
    assert _matches(deleted) == []


def test_s3_compliance_retention_and_governance_negative() -> None:
    row = _base("s3.amazonaws.com", "PutBucketObjectLockConfiguration", {
        "bucketName": "peasso-detect-lock-947247140022-68e6f745cf",
        "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", "Rule": {
            "DefaultRetention": {"Mode": "COMPLIANCE", "Days": 30}}}})
    assert _matches(row) == ["s3_compliance_retention"]
    benign = deepcopy(row)
    benign["requestParameters"]["ObjectLockConfiguration"]["Rule"]["DefaultRetention"]["Mode"] = "GOVERNANCE"
    assert _matches(benign) == []
    denied = deepcopy(row)
    denied["errorCode"] = "AccessDenied"
    assert _matches(denied) == []


def test_backup_live_shaped_self_grant_and_policy_negatives() -> None:
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
              "Principal": {"AWS": "arn:aws:iam::947247140022:user/testenv"},
              "Action": "backup:DeleteRecoveryPoint", "Resource": "*"}]}
    row = _base("backup.amazonaws.com", "PutBackupVaultAccessPolicy",
                {"backupVaultName": "peasso-detect-vault-236cab534d", "policy": json.dumps(policy)})
    assert _matches(row) == ["backup_self_delete"]
    for edit in ("different_principal", "conditional", "denied", "other_action", "bad_json"):
        item = deepcopy(row)
        p = deepcopy(policy)
        statement = p["Statement"][0]
        if edit == "different_principal": statement["Principal"]["AWS"] = "arn:aws:iam::947247140022:user/other"
        if edit == "conditional": statement["Condition"] = {"StringEquals": {"aws:PrincipalTag/team": "backup"}}
        if edit == "denied": item["errorCode"] = "AccessDeniedException"
        if edit == "other_action": statement["Action"] = "backup:DescribeRecoveryPoint"
        item["requestParameters"]["policy"] = "bad" if edit == "bad_json" else json.dumps(p)
        assert _matches(item) == [], edit


def test_ecr_live_shaped_scan_and_policy_negatives() -> None:
    repo = "peasso-detect-ecr-policy-478578e2b9"
    scan = _base("ecr.amazonaws.com", "PutImageScanningConfiguration",
                 {"repositoryName": repo, "imageScanningConfiguration": {"scanOnPush": False}},
                 {"registryId": "947247140022", "repositoryName": repo,
                  "imageScanningConfiguration": {"scanOnPush": False}})
    assert _matches(scan) == ["ecr_scan_disabled"]
    scan["requestParameters"]["imageScanningConfiguration"]["scanOnPush"] = True
    assert _matches(scan) == []
    policy = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
              "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]}]}
    grant = _base("ecr.amazonaws.com", "SetRepositoryPolicy",
                  {"repositoryName": repo, "policyText": json.dumps(policy)},
                  {"registryId": "947247140022", "repositoryName": repo,
                   "policyText": json.dumps(policy)})
    assert _matches(grant) == ["ecr_wildcard_read"]
    for edit in ("single_action", "conditional", "response_mismatch", "denied"):
        item = deepcopy(grant)
        p = deepcopy(policy)
        if edit == "single_action": p["Statement"][0]["Action"] = "ecr:BatchGetImage"
        if edit == "conditional": p["Statement"][0]["Condition"] = {"StringEquals": {"aws:PrincipalOrgID": "o-example"}}
        if edit == "response_mismatch": item["responseElements"]["registryId"] = "000000000000"
        if edit == "denied": item["errorCode"] = "AccessDeniedException"
        item["requestParameters"]["policyText"] = json.dumps(p)
        assert _matches(item) == [], edit
