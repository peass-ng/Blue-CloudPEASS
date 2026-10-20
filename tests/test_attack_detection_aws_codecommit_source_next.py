"""Synthetic derivatives of an owned CodeCommit read, clone and push lab."""

from copy import deepcopy

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


ACCOUNT = "999999999999"
ACTOR = f"arn:aws:sts::{ACCOUNT}:assumed-role/synthetic-code-reader/session"
REPO = "synthetic-repository"
PATH = "synthetic-private-path-never-emit.txt"
BLOB = "a" * 40
COMMIT = "b" * 40
SECRET = "SYNTHETIC_SOURCE_BYTES_NEVER_EMIT"
RULE_IDS = {
    "e9b1ef76-d35b-46d1-8704-34cdfb2d1831",
    "6a0b22fc-a23f-4d60-b781-cff5620e1adb",
    "7bb81135-f1e1-4083-9442-34b4e1508206",
    "251290c3-4874-4570-913e-917ffd5f38cf",
    "61ac2c63-e049-4c2c-b90e-ca3359f4083c",
}


def rules():
    return tuple(x for x in load_rules(product="aws") if x.id in RULE_IDS)


def event(name, request=None, response=None, extra=None):
    return {"eventSource": "codecommit.amazonaws.com", "eventName": name,
            "eventCategory": "Management", "eventType": "AwsApiCall",
            "managementEvent": True, "readOnly": name != "GitPush",
            "recipientAccountId": ACCOUNT, "awsRegion": "us-east-1",
            "eventID": "synthetic-" + name, "eventTime": "2026-10-20T13:00:00Z",
            "userIdentity": {"arn": ACTOR, "accountId": ACCOUNT},
            "requestParameters": request, "responseElements": response,
            "additionalEventData": extra}


def events():
    return [
        event("GetFile", {"repositoryName": REPO, "filePath": PATH},
              {"fileContent": SECRET}),
        event("GetBlob", {"repositoryName": REPO, "blobId": BLOB},
              {"content": SECRET}),
        event("GetCommit", {"repositoryName": REPO, "commitId": COMMIT},
              {"commit": {"message": SECRET}}),
        event("GitPull", extra={"repositoryName": REPO,
              "dataTransferred": True, "protocol": "HTTP"}),
        event("GitPush", extra={"repositoryName": REPO,
              "dataTransferred": True, "protocol": "HTTP"}),
    ]


def test_five_real_shape_signals_without_source_data_leak():
    selected = rules()
    hits = detect_aws_events(events(), selected)
    assert len(selected) == len(hits) == len({x.rule_id for x in hits}) == 5
    serialized = repr(hits)
    for sensitive in (SECRET, PATH, BLOB, COMMIT):
        assert sensitive not in serialized


def test_denied_metadata_only_and_mismatched_calls_do_not_match():
    selected = rules()
    for original in events():
        denied = deepcopy(original)
        denied["errorCode"] = "AccessDeniedException"
        assert not detect_aws_events([denied], selected)
        read_only = deepcopy(original)
        read_only["readOnly"] = not original["readOnly"]
        assert not detect_aws_events([read_only], selected)
    for original in events()[3:]:
        no_transfer = deepcopy(original)
        no_transfer["additionalEventData"]["dataTransferred"] = False
        assert not detect_aws_events([no_transfer], selected)
        no_repository = deepcopy(original)
        no_repository["additionalEventData"]["repositoryName"] = ""
        assert not detect_aws_events([no_repository], selected)
    wrong_blob = deepcopy(events()[1])
    wrong_blob["requestParameters"]["blobId"] = "not-a-blob"
    assert not detect_aws_events([wrong_blob], selected)
