"""Stored public read and Prowler account mitigation remain independent of unreadable bucket BPA."""
from copy import deepcopy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from peaso.checks.claude_aws_a_s3 import B, ABSENT, ALL_USERS, OWNER_GRANT, ACCT_OPEN, BLOCKS

SCOPE = "123456789012/us-east-1"
READ = "aws.claude_a.s3.restrict_public_read"
PUBLIC = "aws.claude_a.s3.prowler_public_access"

def bucket(public=False, unknown_acl=False):
    item = deepcopy(B)
    item["PublicAccessBlock"] = deepcopy(ABSENT)
    item["PublicAccessBlock"]["_coverage"] = {"collection_status": {"status": "denied"}}
    item["Acl"]["Grants"] = [deepcopy(OWNER_GRANT)]
    if public:
        item["Acl"]["Grants"].append({"Grantee": {"Type": "Group", "URI": ALL_USERS}, "Permission": "READ"})
    if unknown_acl:
        row = {"Grantee": {"Type": "Group", "URI": ALL_USERS}, "Permission": "READ"}
        row["Grantee"]["_coverage"] = {"URI": {"status": "denied"}}
        item["Acl"]["Grants"].append(row)
    return item

def verdict(cid, item, account=None):
    snap = make_snapshot("aws", [SCOPE], [
        {"type": "bucket", "scope": SCOPE, "status": "collected", "items": [deepcopy(item)]},
        {"type": "s3_account_public_access_block", "scope": SCOPE, "status": "collected", "items": [deepcopy(ACCT_OPEN if account is None else account)]},
    ], created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snap)
    rows = [f for f in evaluate_snapshot(snap, checks=[cid])["findings"] if f["check_id"] == cid]
    assert snap == before and len(rows) == 1
    return rows[0]

@pytest.mark.parametrize("public,unknown_acl,expected", [(True, False, "FAIL"), (False, False, "PASS"), (False, True, "UNKNOWN")])
def test_stored_public_read_ignores_unreadable_mitigation(public, unknown_acl, expected):
    finding = verdict(READ, bucket(public, unknown_acl))
    assert finding["status"] == expected
    if expected != "UNKNOWN":
        evidence = finding.get("evidence") or {}
        assert evidence.get("runtime_acl_ignored") is not True

@pytest.mark.parametrize("safe,public,expected", [(True, True, "PASS"), (False, True, "UNKNOWN"), (False, False, "PASS")])
def test_prowler_account_or_absent_finding_with_unreadable_bucket(safe, public, expected):
    account = {"PublicAccessBlockConfiguration": {key: safe for key in BLOCKS}}
    assert verdict(PUBLIC, bucket(public), account)["status"] == expected


def test_stored_public_policy_ignores_unreadable_mitigation():
    item = bucket()
    item["Policy"] = {"collection_status": "collected", "Policy": {"Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b1/*"}
    ]}}
    assert verdict(READ, item)["status"] == "FAIL"
