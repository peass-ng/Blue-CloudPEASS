"""Account PAB facts require an authoritative account identity in registered snapshots."""
from copy import deepcopy
import pytest

from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
from tests.test_peaso_aws_bucket_field_authority import PAB, SCOPE, bucket, flags


def verdict(account_rows, *, bucket_all_true=False):
    bucket_flags = flags() if bucket_all_true else flags(BlockPublicAcls=False)
    collections = [
        {"type": "bucket", "scope": SCOPE, "status": "collected", "items": [
            bucket({"PublicAccessBlockConfiguration": bucket_flags})]},
        {"type": "s3_account_public_access_block", "scope": "123456789012/global",
         "status": "collected", "global": True, "account_id": "123456789012",
         "items": account_rows},
    ]
    snapshot = make_snapshot("aws", [SCOPE], collections, created_at="2026-10-17T00:00:00Z")
    before = deepcopy(snapshot)
    rows = [row for row in evaluate_snapshot(snapshot, checks=[PAB])["findings"]
            if row["check_id"] == PAB and row["scope"] == SCOPE]
    assert snapshot == before and len(rows) == 1
    return rows[0]["status"]


def account(account_id="123456789012", *, coverage=None):
    item = {"AccountId": account_id, "PublicAccessBlockConfiguration": flags()}
    if coverage is not None:
        item["_coverage"] = {"AccountId": {"status": coverage}}
    return item


def test_unreadable_account_identity_cannot_prove_effective_pab():
    assert verdict([account(coverage="denied")]) == "UNKNOWN"


def test_bucket_complete_flags_are_independent_of_account_identity():
    assert verdict([account(coverage="denied")], bucket_all_true=True) == "PASS"


@pytest.mark.parametrize("rows,expected", [
    ([account()], "PASS"),
    ([account("999999999999")], "UNKNOWN"),
    ([{"PublicAccessBlockConfiguration": flags()}], "UNKNOWN"),
    ([account(), account()], "UNKNOWN"),
])
def test_global_account_identity_join_is_exact_and_unique(rows, expected):
    assert verdict(rows) == expected
