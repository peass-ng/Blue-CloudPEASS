"""S3 ACL, CORS and Access Grants signals from synthetic CloudTrail derivatives."""

from copy import deepcopy
import json
from pathlib import Path

from peaso.attack_detection import detect_aws_events
from peaso.attack_detection.rules import load_rules


FIXTURE = Path(__file__).parent / "fixtures/aws_s3_acl_grants_batch62_events.json"
IDS = {
    "2df27f6f-7aab-45e7-8bc5-1dedcd877fc7",
    "2e130659-4d41-4b32-966e-711fca2d5d51",
    "5c1d4266-6a23-4cc8-a240-12b0355f3d80",
    "a11d0fcf-50b4-4907-ba56-2815f2b7078c",
    "4b256613-9fed-447d-818d-db7253fab78a",
    "1f2ee01d-3ac1-4770-abfa-0dbb6632ed61",
}


def events():
    return deepcopy(json.loads(FIXTURE.read_text())["events"])


def selected():
    rules = [r for r in load_rules(product="aws") if r.id in IDS]
    assert len(rules) == 6
    return rules


def hits(records):
    return {h.rule_id for h in detect_aws_events(records, selected())}


def test_six_real_shaped_s3_signals():
    rows = events()
    found = detect_aws_events(rows, selected())
    assert len(rows) == len(found) == 6
    assert {h.rule_id for h in found} == IDS
    assert {x["recipientAccountId"] for x in rows} == {"999999999999"}
    assert all(x["eventID"].startswith("synthetic-") for x in rows)
    assert "SecretAccessKey" not in repr(found)


def test_object_acl_requires_public_canned_acl_and_matching_data_resource():
    for mutate in (
        lambda x: x["requestParameters"].update(**{"x-amz-acl": "private"}),
        lambda x: x.update(resources=[]),
        lambda x: x["requestParameters"].update(bucketName="different-bucket"),
        lambda x: x.update(errorCode="AccessDenied"),
        lambda x: x.update(eventCategory="Management"),
    ):
        rows = events()
        mutate(rows[0])
        assert "2df27f6f-7aab-45e7-8bc5-1dedcd877fc7" not in hits(rows)
    rows = events()
    rows[1]["requestParameters"]["versionId"] = "null"
    assert "2e130659-4d41-4b32-966e-711fca2d5d51" not in hits(rows)


def test_wildcard_cors_requires_read_or_write_method_and_matching_bucket():
    for mutate in (
        lambda x: x["requestParameters"]["CORSConfiguration"]["CORSRule"].update(
            AllowedOrigin="https://approved.example"),
        lambda x: x["requestParameters"]["CORSConfiguration"]["CORSRule"].update(
            AllowedMethod=["OPTIONS"]),
        lambda x: x.update(resources=[]),
        lambda x: x.update(errorCode="AccessDenied"),
    ):
        rows = events()
        mutate(rows[2])
        assert "5c1d4266-6a23-4cc8-a240-12b0355f3d80" not in hits(rows)


def test_access_grants_requires_regional_instance_scoped_role_and_broad_grant():
    cases = (
        (3, lambda x: x.update(resources=[]), "a11d0fcf-50b4-4907-ba56-2815f2b7078c"),
        (3, lambda x: x["requestParameters"]["CreateAccessGrantsLocationRequest"].update(
            IAMRoleArn="arn:aws:iam::888888888888:role/foreign"),
            "a11d0fcf-50b4-4907-ba56-2815f2b7078c"),
        (4, lambda x: x["requestParameters"]["CreateAccessGrantRequest"]
            ["AccessGrantsLocationConfiguration"].update(S3SubPrefix="approved/*"),
            "4b256613-9fed-447d-818d-db7253fab78a"),
        (4, lambda x: x["requestParameters"]["CreateAccessGrantRequest"].update(Permission="WRITE"),
            "4b256613-9fed-447d-818d-db7253fab78a"),
        (5, lambda x: x.update(readOnly=False), "1f2ee01d-3ac1-4770-abfa-0dbb6632ed61"),
        (5, lambda x: x.update(resources=[]), "1f2ee01d-3ac1-4770-abfa-0dbb6632ed61"),
    )
    for index, mutate, missing in cases:
        rows = events()
        mutate(rows[index])
        assert missing not in hits(rows)
