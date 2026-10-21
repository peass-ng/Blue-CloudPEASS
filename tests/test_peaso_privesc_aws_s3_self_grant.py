"""An S3 policy write is an escalation only with a reviewed self-permission gain."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import ACCOUNT, ALICE, allow, aws_snap, reached, user


ENTRY = next(e for e in yaml.safe_load((Path(__file__).parents[1] / "peaso/privesc/catalog/aws/s3.yaml").read_text())
             if e["id"] == "aws-s3-putbucketpolicy-self-grant")
BUCKET = "arn:aws:s3:::reviewed-bucket"
TARGET = f"aws_verified_authority:s3-policy:{BUCKET}/private/:{ALICE}"


def proof():
    return {"TechniqueId": ENTRY["id"], "Status": "verified", "SourceArn": ALICE,
            "BucketOwnerAccount": ACCOUNT, "BucketArn": BUCKET, "ObjectPrefix": "private/",
            "PolicyPrincipalArn": ALICE, "GrantedAction": "s3:GetObject",
            "PolicyResourceArn": BUCKET + "/private/*", "PriorAccessDenied": True,
            "PolicyAccepted": True, "EffectiveAccessAfterAllowed": True, "GuardrailsReviewed": True,
            "EvidenceRef": "reviewed-s3-policy-differential-1"}


def case(records=None, *, writer=True, status="collected"):
    alice = user("alice", allow("s3:PutBucketPolicy", BUCKET) if writer else allow("s3:GetBucketPolicy", BUCKET))
    snap = aws_snap([alice])
    snap["collections"].append({"type": "aws_s3_policy_self_grant_evidence", "scope": ACCOUNT + "/us-east-1",
                                "service": "s3", "status": status, "items": [proof()] if records is None else records,
                                "error": None})
    return snap


def test_reviewed_s3_policy_self_grant_has_only_bounded_permission_target():
    assert validate_entry(ENTRY)[0] == []
    snap = case()
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRY])
    assert reached(result, ALICE, ENTRY["id"]) == {TARGET: "conditional"}
    assert result["graph"]["edges"][0]["technique_details"][0]["grants"] == ENTRY["target"]["grants"]
    assert snap == before


@pytest.mark.parametrize("field,value", [
    ("SourceArn", "arn:aws:iam::111111111111:user/bob"),
    ("BucketOwnerAccount", "222222222222"),
    ("BucketArn", "arn:aws-cn:s3:::reviewed-bucket"),
    ("PolicyPrincipalArn", "arn:aws:iam::111111111111:user/bob"),
    ("PolicyResourceArn", BUCKET + "/public/*"),
    ("GrantedAction", "s3:PutObject"),
    ("PriorAccessDenied", False),
    ("PolicyAccepted", False),
    ("EffectiveAccessAfterAllowed", False),
    ("GuardrailsReviewed", False),
    ("EvidenceRef", ""),
    ("Status", "unreviewed"),
])
def test_false_or_mismatched_s3_policy_review_has_no_path(field, value):
    record = proof()
    record[field] = value
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), ALICE, ENTRY["id"]) == {}


@pytest.mark.parametrize("field", sorted(proof()))
def test_every_s3_review_field_is_required(field):
    record = proof()
    record.pop(field)
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), ALICE, ENTRY["id"]) == {}


def test_missing_duplicate_partial_or_nonwriter_has_no_path():
    for snap in (case([]), case([proof(), proof()]), case(status="partial"), case(status="empty"),
                 case(writer=False)):
        assert reached(privesc.analyze(snap, entries=[ENTRY]), ALICE, ENTRY["id"]) == {}
