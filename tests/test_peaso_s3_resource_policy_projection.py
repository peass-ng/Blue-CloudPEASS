"""S3 resource-policy projection through registered native snapshot evaluation."""
import copy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CROSS = "aws.claude_a.s3.policy_no_cross_account_permission_changes"
READ = "aws.claude_a.s3.restrict_public_read"
SCOPE = s3.ACCOUNT + "/us-east-1"

def verdict(cid, *statements, public=False):
    policy = {"collection_status": "collected", "Policy": {"Version": "2012-10-17",
        "Statement": copy.deepcopy(list(statements))}}
    item = s3.w(s3.B, Policy=policy, PolicyStatus__PolicyStatus__IsPublic=public)
    snapshot = make_snapshot("aws", [SCOPE], [{"type": "bucket", "scope": SCOPE,
        "status": "collected", "items": [item]}], created_at="2026-10-17T00:00:00Z")
    rows = [r for r in evaluate_snapshot(snapshot, checks=[cid])["findings"] if r["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]

def change(principal, action="s3:PutBucketPolicy", effect="Allow"):
    return {"Effect": effect, "Principal": principal, "Action": action, "Resource": "arn:aws:s3:::b1"}

def denied(row, field):
    row.setdefault("_coverage", {})[field] = {"status": "denied"}
    return row

def test_selected_aws_principal_restores_cross_account_failure():
    assert verdict(CROSS, change({"AWS": "arn:aws:iam::999999999999:root"})) == "FAIL"
    assert verdict(CROSS, change({"AWS": "arn:aws:iam::" + s3.ACCOUNT + ":root"})) == "PASS"

def test_public_read_selected_wildcard_principal_fails():
    row = change("*", action="s3:GetObject")
    assert verdict(READ, row, public=True) == "FAIL"

@pytest.mark.parametrize("field", ["Principal", "Action", "Resource"])
def test_unavailable_relevant_field_cannot_prove_safe_cross_account(field):
    row = change({"AWS": "arn:aws:iam::999999999999:root"})
    assert verdict(CROSS, denied(row, field)) == "UNKNOWN"

@pytest.mark.parametrize("principal", [42, None, [], {}, {"AWS": None}])
def test_malformed_selected_principal_cannot_prove_safe_cross_account(principal):
    assert verdict(CROSS, change(principal)) == "UNKNOWN"

def test_irrelevant_action_and_deny_skip_unused_principal():
    row = denied(change({"AWS": "arn:aws:iam::999999999999:root"}, action="s3:*"), "Principal")
    assert verdict(CROSS, row) == "PASS"
    row = denied(change({"AWS": "arn:aws:iam::999999999999:root"}, effect="Deny"), "Principal")
    assert verdict(CROSS, row) == "PASS"

def test_irrelevant_read_action_skips_unused_principal():
    row = denied(change("*", action="s3:PutObject"), "Principal")
    assert verdict(READ, row, public=False) == "PASS"


@pytest.mark.parametrize("reverse", [False, True])
def test_known_cross_account_change_survives_unresolved_peer(reverse):
    rows = [denied(change({"AWS": "arn:aws:iam::999999999999:root"}), "Principal"),
            change({"AWS": "arn:aws:iam::999999999999:root"})]
    if reverse:
        rows.reverse()
    assert verdict(CROSS, *rows) == "FAIL"

@pytest.mark.parametrize("reverse", [False, True])
def test_known_public_read_survives_unresolved_peer(reverse):
    rows = [denied(change("*", action="s3:GetObject"), "Principal"),
            change("*", action="s3:GetObject")]
    if reverse:
        rows.reverse()
    assert verdict(READ, *rows, public=True) == "FAIL"


@pytest.mark.parametrize("field", ["Principal", "Action", "Resource"])
def test_unavailable_relevant_public_read_field_is_unknown(field):
    assert verdict(READ, denied(change("*", action="s3:GetObject"), field), public=False) == "UNKNOWN"

def test_nonmatching_action_does_not_consume_resource_or_principal():
    row = denied(denied(change(42, action="s3:*"), "Resource"), "Principal")
    assert verdict(CROSS, row) == "PASS"
