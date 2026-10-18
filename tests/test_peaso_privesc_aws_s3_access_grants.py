"""S3 Access Grants vends a new bounded S3 session only with an exact reviewed join."""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from peaso import privesc
from peaso.privesc.schema import validate_entry
from tests.test_peaso_privesc_schema_ext import ACCOUNT, ALICE, allow, aws_snap, reached, user


ENTRY = next(e for e in yaml.safe_load((Path(__file__).parents[1] / "peaso/privesc/catalog/aws/s3.yaml").read_text())
             if e["id"] == "aws-s3-accessgrants-self-grant")
INSTANCE = f"arn:aws:s3:us-east-1:{ACCOUNT}:access-grants/default"
LOCATION = f"arn:aws:s3:us-east-1:{ACCOUNT}:access-grants/location/loc-1"
ROLE = f"arn:aws:iam::{ACCOUNT}:role/s3-location"
BUCKET = "arn:aws:s3:::reviewed-bucket"
TARGET = f"aws_verified_authority:s3-access-grants:{BUCKET}/private/:{ALICE}"


def proof():
    return {"TechniqueId": ENTRY["id"], "Status": "verified", "SourceArn": ALICE,
            "AccessGrantsInstanceArn": INSTANCE, "LocationArn": LOCATION, "LocationRoleArn": ROLE,
            "BucketArn": BUCKET, "ObjectPrefix": "private/", "GrantGranteeArn": ALICE,
            "GrantPermission": "READ", "GrantScope": "s3://reviewed-bucket/private/*",
            "GrantArn": INSTANCE + "/grant-grant-1", "RoleTrustsAccessGrants": True,
            "LocationRoleAllowsGetObject": True, "PriorAccessDenied": True,
            "LocationRegistered": True, "GrantCreated": True, "GetDataAccessSucceeded": True,
            "SessionSubjectRoleArn": ROLE, "SessionScope": "s3://reviewed-bucket/private/*",
            "CredentialUsable": True, "EffectiveAccessAfterAllowed": True,
            "EvidenceRef": "reviewed-access-grants-session-1"}


def case(records=None, *, grant_writer=True, status="collected"):
    permissions = [allow("s3:CreateAccessGrantsLocation", INSTANCE), allow("iam:PassRole", ROLE),
                   allow("s3:CreateAccessGrant", LOCATION) if grant_writer else allow("s3:GetAccessGrant", LOCATION),
                   allow("s3:GetDataAccess", INSTANCE)]
    snap = aws_snap([user("alice", *permissions)])
    snap["collections"].append({"type": "aws_s3_access_grants_self_grant_evidence", "scope": ACCOUNT + "/us-east-1",
                                "service": "s3", "status": status, "items": [proof()] if records is None else records,
                                "error": None})
    return snap


def test_reviewed_access_grants_path_is_bounded_to_prefix():
    assert validate_entry(ENTRY)[0] == []
    snap = case()
    before = copy.deepcopy(snap)
    result = privesc.analyze(snap, entries=[ENTRY])
    assert reached(result, ALICE, ENTRY["id"]) == {TARGET: "conditional"}
    assert result["graph"]["edges"][0]["technique_details"][0]["outcome"] == "permission_grant"
    assert snap == before


@pytest.mark.parametrize("field,value", [
    ("SourceArn", "arn:aws:iam::111111111111:user/bob"),
    ("GrantGranteeArn", "arn:aws:iam::111111111111:user/bob"),
    ("LocationRoleArn", "arn:aws:iam::222222222222:role/other"),
    ("GrantScope", "s3://reviewed-bucket/public/*"),
    ("SessionScope", "s3://reviewed-bucket/public/*"),
    ("SessionSubjectRoleArn", "arn:aws:iam::111111111111:role/other"),
    ("GrantPermission", "WRITE"),
    ("RoleTrustsAccessGrants", False),
    ("LocationRoleAllowsGetObject", False),
    ("PriorAccessDenied", False),
    ("GetDataAccessSucceeded", False),
    ("CredentialUsable", False),
    ("EffectiveAccessAfterAllowed", False),
    ("EvidenceRef", ""),
    ("Status", "unreviewed"),
])
def test_mismatched_access_grants_review_has_no_path(field, value):
    record = proof()
    record[field] = value
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), ALICE, ENTRY["id"]) == {}


@pytest.mark.parametrize("field", sorted(proof()))
def test_every_access_grants_review_field_is_required(field):
    record = proof()
    record.pop(field)
    assert reached(privesc.analyze(case([record]), entries=[ENTRY]), ALICE, ENTRY["id"]) == {}


def test_missing_duplicate_partial_or_unpermitted_source_has_no_path():
    for snap in (case([]), case([proof(), proof()]), case(status="partial"), case(grant_writer=False)):
        assert reached(privesc.analyze(snap, entries=[ENTRY]), ALICE, ENTRY["id"]) == {}
