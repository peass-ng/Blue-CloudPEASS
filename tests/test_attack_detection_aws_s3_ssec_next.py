"""SSE-C route signals from synthetic derivatives of an owned S3 lab."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_s3_ssec_ransomware_lab_events.json"
IDS = {
    "43ea9adf-5651-4776-8b38-382c24285fed",  # SSE-C enabled
    "95050eab-4c20-4d8a-9705-3f912d0e3954",  # current expiry
    "4314f490-468e-4b2a-9fc6-4ca564515d33",  # noncurrent expiry
    "81f53a15-eb12-4aa2-9f6c-e75b7c4a0825",  # versioned SSE-C put
    "0f4b346b-590e-49c6-826e-b7da6ac0ab58",  # in-place SSE-C copy
    "d6475655-1693-4629-9e37-b95eb4b59803",  # existing versioning rule
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 6
    return rules


def hits(records):
    return {x.rule_id for x in detect_aws_events(records, selected())}


def test_six_real_shaped_ssec_and_retention_signals():
    records = events()
    assert len(records) == 6
    found = detect_aws_events(records, selected())
    assert len(found) == 6
    assert {x.rule_id for x in found} == IDS
    assert {x["recipientAccountId"] for x in records} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in records)
    assert "SSECustomerKey" not in repr(found)


def test_ssec_unblock_lifecycle_and_versioning_require_explicit_values():
    baseline = events()
    cases = [
        ("PutBucketEncryption", lambda x: x["requestParameters"]
            ["ServerSideEncryptionConfiguration"]["Rule"]["BlockedEncryptionTypes"]
            .update(EncryptionType="SSE-C"), "43ea9adf-5651-4776-8b38-382c24285fed"),
        ("PutBucketLifecycle", lambda x: x["requestParameters"]
            ["LifecycleConfiguration"]["Rule"]["Expiration"].update(Days=30),
            "95050eab-4c20-4d8a-9705-3f912d0e3954"),
        ("PutBucketLifecycle", lambda x: x["requestParameters"]
            ["LifecycleConfiguration"]["Rule"]["NoncurrentVersionExpiration"]
            .update(NoncurrentDays=30), "4314f490-468e-4b2a-9fc6-4ca564515d33"),
        ("PutBucketVersioning", lambda x: x["requestParameters"]
            ["VersioningConfiguration"].update(Status="Enabled"),
            "d6475655-1693-4629-9e37-b95eb4b59803"),
    ]
    for name, change, missing in cases:
        copy = deepcopy(baseline)
        change(next(x for x in copy if x["eventName"] == name))
        assert hits(copy) == IDS - {missing}


def test_inplace_copy_requires_same_object_and_confirmed_ssec():
    baseline = events()
    copy_id = "0f4b346b-590e-49c6-826e-b7da6ac0ab58"
    for change in [
        lambda x: x["requestParameters"].update(**{"x-amz-copy-source": "unrelated/obj"}),
        lambda x: x["requestParameters"].update(**{
            "x-amz-server-side-encryption-customer-algorithm": "AES128"}),
        lambda x: x["responseElements"].update(**{
            "x-amz-copy-source-version-id": "different-version"}),
        lambda x: x.update(resources=[]),
        lambda x: x.update(errorCode="AccessDenied"),
    ]:
        records = deepcopy(baseline)
        change(next(x for x in records if x["eventName"] == "CopyObject"))
        assert hits(records) == IDS - {copy_id}


def test_versioned_put_requires_success_matching_mode_and_version():
    baseline = events()
    put_id = "81f53a15-eb12-4aa2-9f6c-e75b7c4a0825"
    for change in [
        lambda x: x["requestParameters"].pop("x-amz-server-side-encryption-customer-algorithm"),
        lambda x: x["responseElements"].update(**{"x-amz-version-id": "null"}),
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x.update(resources=[]),
    ]:
        records = deepcopy(baseline)
        change(next(x for x in records if x["eventName"] == "PutObject"))
        assert hits(records) == IDS - {put_id}
