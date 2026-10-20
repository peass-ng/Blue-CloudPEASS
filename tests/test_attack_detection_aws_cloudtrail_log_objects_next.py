"""Synthetic derivatives of versioned CloudTrail log-object data events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_cloudtrail_historical_object_lab_events.json"
IDS = {
    "72e55ff0-db91-46d2-9f61-69470fc6a357",  # re-encrypted copy
    "a5650b8d-5e1a-4a98-96c7-92c7167d60a2",  # linked CMK disable
    "889ad220-51d4-45c4-a8aa-c7ca39b95c61",  # delete marker
    "d074406e-55df-4d0c-b042-b9d19a56c9fb",  # exact version delete
    "cfd6c186-b698-45ee-b846-f37a6431f412",  # live log bucket deletion
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 5
    return rules


def hits(records):
    return {x.rule_id for x in detect_aws_events(records, selected())}


def test_five_real_shaped_version_and_bucket_signals():
    records = events()
    assert len(records) == 9
    assert hits(records) == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)


def test_copy_requires_same_log_object_confirmed_customer_key_and_trail():
    baseline = events()
    assert hits([x for x in baseline if x["eventName"] != "CreateTrail"]) == set()
    copy_ids = {"72e55ff0-db91-46d2-9f61-69470fc6a357",
                "a5650b8d-5e1a-4a98-96c7-92c7167d60a2"}
    for field, value in [
        ("x-amz-copy-source", "unrelated/object?versionId=synthetic-version-1"),
        ("x-amz-server-side-encryption", "AES256"),
    ]:
        changed = deepcopy(baseline)
        next(x for x in changed if x["eventName"] == "CopyObject")[
            "requestParameters"][field] = value
        assert hits(changed) == IDS - copy_ids
    wrong_response = deepcopy(baseline)
    next(x for x in wrong_response if x["eventName"] == "CopyObject")[
        "responseElements"]["x-amz-copy-source-version-id"] = "different-version"
    assert hits(wrong_response) == IDS - copy_ids
    missing_resource = deepcopy(baseline)
    next(x for x in missing_resource if x["eventName"] == "CopyObject")["resources"] = []
    assert hits(missing_resource) == IDS - copy_ids


def test_delete_marker_and_version_are_separate_accepted_actions():
    baseline = events()
    marker_id = "889ad220-51d4-45c4-a8aa-c7ca39b95c61"
    version_id = "d074406e-55df-4d0c-b042-b9d19a56c9fb"
    deletes = [x for x in baseline if x["eventName"] == "DeleteObject"]
    marker = next(x for x in deletes if "versionId" not in x["requestParameters"])
    marker["responseElements"]["x-amz-delete-marker"] = "false"
    assert hits(baseline) == IDS - {marker_id}
    other = events()
    version = next(x for x in other if x["eventName"] == "DeleteObject"
                   and "versionId" in x["requestParameters"])
    version["responseElements"]["x-amz-version-id"] = "different-version"
    assert hits(other) == IDS - {version_id}
    denied = events()
    next(x for x in denied if x["eventName"] == "DeleteObject"
         and "versionId" in x["requestParameters"])["errorCode"] = "AccessDenied"
    assert hits(denied) == IDS - {version_id}


def test_bucket_delete_requires_active_trail_and_disable_needs_same_key():
    baseline = events()
    bucket_id = "cfd6c186-b698-45ee-b846-f37a6431f412"
    disable_id = "a5650b8d-5e1a-4a98-96c7-92c7167d60a2"
    stopped = deepcopy(baseline)
    next(x for x in stopped if x["eventName"] == "StopLogging")[
        "eventTime"] = "2026-01-02T03:06:30Z"
    assert hits(stopped) == IDS - {bucket_id}
    no_start = [x for x in baseline if x["eventName"] != "StartLogging"]
    assert hits(no_start) == IDS - {bucket_id}
    wrong_key = deepcopy(baseline)
    disable = next(x for x in wrong_key if x["eventName"] == "DisableKey")
    disable["requestParameters"]["keyId"] = "arn:aws:kms:us-east-1:999999999999:key/11111111-2222-4333-8444-555555555555"
    disable["responseElements"]["keyId"] = disable["requestParameters"]["keyId"]
    assert hits(wrong_key) == IDS - {disable_id}
