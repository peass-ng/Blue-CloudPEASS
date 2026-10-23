"""Synthetic CloudTrail derivatives for a disposable Lambda/EFS canary lab."""

from copy import deepcopy

from peaso.attack_detection.aws_lambda_efs_mount_batch410 import normalize, correlate
from peaso.attack_detection.rules import Rule, detect_aws_events


ACCOUNT = "999999999999"
ARN = f"arn:aws:lambda:us-east-2:{ACCOUNT}:function:synthetic-target"
AP = f"arn:aws:elasticfilesystem:us-east-2:{ACCOUNT}:access-point/fsap-aaaaaaaaaaaaaaaaa"
ACTOR = f"arn:aws:iam::{ACCOUNT}:user/synthetic-operator"
CONFIG = {"arn": AP, "localMountPath": "/mnt/ht"}
COMMON = {
    "eventSource": "lambda.amazonaws.com", "eventType": "AwsApiCall",
    "eventCategory": "Management", "managementEvent": True, "readOnly": False,
    "recipientAccountId": ACCOUNT, "awsRegion": "us-east-2",
    "userIdentity": {"type": "IAMUser", "accountId": ACCOUNT, "arn": ACTOR},
}
ATTACH = {
    **COMMON, "eventName": "UpdateFunctionConfiguration20150331v2",
    "eventID": "synthetic-attach", "eventTime": "2026-10-22T00:00:00Z",
    "requestParameters": {"functionName": "synthetic-target", "fileSystemConfigs": [CONFIG]},
    "responseElements": {"functionArn": ARN, "fileSystemConfigs": [CONFIG]},
}
CODE = {
    **COMMON, "eventName": "UpdateFunctionCode20150331v2",
    "eventID": "synthetic-code", "eventTime": "2026-10-22T00:01:00Z",
    "requestParameters": {"functionName": ARN},
    "responseElements": {"functionArn": ARN},
}
DETACH = {
    **COMMON, "eventName": "UpdateFunctionConfiguration20150331v2",
    "eventID": "synthetic-detach", "eventTime": "2026-10-22T00:00:30Z",
    "requestParameters": {"functionName": ARN, "fileSystemConfigs": []},
    "responseElements": {"functionArn": ARN, "fileSystemConfigs": []},
}
RULES = (
    Rule(id="synthetic-efs-attach", title="Synthetic EFS attach", description="Synthetic",
         level="medium", technique_id="synthetic-efs-attach", product="aws", selection={
             "event.source": "lambda.amazonaws.com",
             "event.name": "UpdateFunctionConfiguration20150331v2",
             "event.outcome": "success", "request.lambda_efs_access_point_configured": True,
         }),
    Rule(id="synthetic-efs-code", title="Synthetic EFS code update", description="Synthetic",
         level="high", technique_id="synthetic-efs-code", product="aws", selection={
             "event.source": "lambda.amazonaws.com",
             "event.name": "UpdateFunctionCode20150331v2",
             "event.outcome": "success", "request.lambda_efs_mount_followed_by_code_update": True,
         }),
)


def test_attachment_and_code_update_correlate_without_efs_identifiers():
    assert normalize(ATTACH)["request.lambda_efs_access_point_configured"] is True
    hits = detect_aws_events([ATTACH, CODE], RULES)
    assert {hit.technique_id for hit in hits} == {"synthetic-efs-attach", "synthetic-efs-code"}
    assert all(hit.target_id.startswith("sha256:") for hit in hits)
    assert AP not in str(hits) and "synthetic-target" not in str(hits)
    nested = deepcopy(ATTACH)
    nested["requestParameters"]["fileSystemConfigs"][0]["localMountPath"] = "/mnt/data/ht"
    nested["responseElements"]["fileSystemConfigs"][0]["localMountPath"] = "/mnt/data/ht"
    assert normalize(nested) is not None


def test_rejects_failed_foreign_or_unconfirmed_attachment():
    mutations = (
        lambda x: x.update(errorCode="AccessDeniedException"),
        lambda x: x.update(readOnly=True),
        lambda x: x["userIdentity"].update(accountId="888888888888"),
        lambda x: x["requestParameters"]["fileSystemConfigs"][0].update(
            arn=AP.replace(ACCOUNT, "888888888888")),
        lambda x: x["requestParameters"]["fileSystemConfigs"][0].update(
            localMountPath="/tmp/ht"),
        lambda x: x["responseElements"].update(fileSystemConfigs=[]),
    )
    for change in mutations:
        row = deepcopy(ATTACH)
        change(row)
        assert normalize(row) is None
        assert correlate([row, CODE]) == []


def test_detach_actor_and_time_limit_break_the_code_update_chain():
    assert normalize(DETACH) is None
    assert correlate([ATTACH, DETACH, CODE]) == []
    early = deepcopy(CODE)
    early["eventTime"] = "2026-10-21T23:59:00Z"
    assert correlate([early, ATTACH]) == []
    other_actor = deepcopy(CODE)
    other_actor["userIdentity"]["arn"] = f"arn:aws:iam::{ACCOUNT}:user/synthetic-other"
    assert correlate([ATTACH, other_actor]) == []
    late = deepcopy(CODE)
    late["eventTime"] = "2026-10-22T00:16:00Z"
    assert correlate([ATTACH, late]) == []
    dry_run = deepcopy(CODE)
    dry_run["requestParameters"]["dryRun"] = True
    assert correlate([ATTACH, dry_run]) == []
