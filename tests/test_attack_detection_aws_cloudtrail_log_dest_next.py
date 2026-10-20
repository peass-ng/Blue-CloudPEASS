"""Synthetic derivatives of accepted owned CloudTrail/S3/KMS management events."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_cloudtrail_log_destination_lab_events.json"
IDS = {
    "2ecb40d5-0b55-4980-9cf2-5e660388fe32",  # short expiration
    "82fe12b1-46a5-4acf-9439-ce74ae6c6227",  # delivery deny
    "983a36dd-773b-4ceb-a80d-258e4485b704",  # bucket CMK
    "27d18225-625a-4dcc-8a35-641c08b21601",  # trail CMK
    "b3bc2894-3803-428f-90d5-54a362f4f611",  # linked disable
    "eb33ce82-9636-4d0b-856b-aad83c4bfcfe",  # linked deletion
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 6
    return rules


def hits(records):
    return {h.rule_id for h in detect_aws_events(records, selected())}


def test_six_real_event_shaped_route_signals():
    records = events()
    assert len(records) == 7
    assert hits(records) == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)


def test_log_bucket_controls_require_matching_trail_and_actual_hazard():
    baseline = events()
    without_trail = [x for x in baseline if x["eventName"] not in {"CreateTrail", "UpdateTrail"}]
    assert hits(without_trail) == set()
    for name, edit, missing in [
        ("PutBucketLifecycle", lambda x: x["requestParameters"]["LifecycleConfiguration"]
            ["Rule"]["Expiration"].update(Days=30), "2ecb40d5-0b55-4980-9cf2-5e660388fe32"),
        ("PutBucketLifecycle", lambda x: x["requestParameters"]["LifecycleConfiguration"]
            ["Rule"]["Filter"].update(Prefix="unrelated/"), "2ecb40d5-0b55-4980-9cf2-5e660388fe32"),
        ("PutBucketPolicy", lambda x: x["requestParameters"]["bucketPolicy"]
            ["Statement"][-1].update(Effect="Allow"), "82fe12b1-46a5-4acf-9439-ce74ae6c6227"),
        ("PutBucketEncryption", lambda x: x["requestParameters"]
            ["ServerSideEncryptionConfiguration"]["Rule"]
            ["ApplyServerSideEncryptionByDefault"].update(SSEAlgorithm="AES256"),
            "983a36dd-773b-4ceb-a80d-258e4485b704"),
    ]:
        changed = deepcopy(baseline)
        edit(next(x for x in changed if x["eventName"] == name))
        assert hits(changed) == IDS - {missing}
    wrong_bucket = deepcopy(baseline)
    next(x for x in wrong_bucket if x["eventName"] == "PutBucketPolicy")[
        "requestParameters"]["bucketName"] = "unrelated-bucket"
    assert "82fe12b1-46a5-4acf-9439-ce74ae6c6227" not in hits(wrong_bucket)


def test_key_links_require_matching_key_and_accepted_state_change():
    baseline = events()
    for name, missing in [
        ("DisableKey", "b3bc2894-3803-428f-90d5-54a362f4f611"),
        ("ScheduleKeyDeletion", "eb33ce82-9636-4d0b-856b-aad83c4bfcfe"),
    ]:
        denied = deepcopy(baseline)
        next(x for x in denied if x["eventName"] == name)["errorCode"] = "AccessDeniedException"
        assert hits(denied) == IDS - {missing}
        wrong = deepcopy(baseline)
        event = next(x for x in wrong if x["eventName"] == name)
        event["requestParameters"]["keyId"] = "arn:aws:kms:us-east-1:999999999999:key/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        event["responseElements"]["keyId"] = event["requestParameters"]["keyId"]
        assert hits(wrong) == IDS - {missing}
    pending = deepcopy(baseline)
    next(x for x in pending if x["eventName"] == "ScheduleKeyDeletion")[
        "responseElements"]["keyState"] = "Enabled"
    assert hits(pending) == IDS - {"eb33ce82-9636-4d0b-856b-aad83c4bfcfe"}


def test_trail_key_observation_needs_confirmed_response():
    records = events()
    update = next(x for x in records if x["eventName"] == "UpdateTrail")
    update["responseElements"].pop("kmsKeyId")
    assert "27d18225-625a-4dcc-8a35-641c08b21601" not in hits(records)
