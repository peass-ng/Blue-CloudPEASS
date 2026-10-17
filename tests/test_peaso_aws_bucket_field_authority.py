"""Bucket and account configuration field authority in registered AWS snapshots."""
import copy
import pytest
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

SCOPE = "123456789012/us-east-1"
PAB = "aws.s3.public_access_block"
ENC = "aws.s3.default_encryption"
NAMES = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")

def flags(**changes):
    return {**{key: True for key in NAMES}, **changes}

def bucket(config=None, encryption=None):
    return {"Name": "b1", "PublicAccessBlock": copy.deepcopy(config if config is not None else
            {"PublicAccessBlockConfiguration": flags()}),
            "Encryption": copy.deepcopy(encryption if encryption is not None else
            {"ServerSideEncryptionConfiguration": {"Rules": [
                {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}})}

def verdict(cid, item, accounts=None, *, account_status="collected"):
    collections = [{"type": "bucket", "scope": SCOPE, "status": "collected", "items": [copy.deepcopy(item)]}]
    if accounts is not None:
        collections.append({"type": "s3_account_public_access_block", "scope": SCOPE,
            "status": account_status, "items": copy.deepcopy(accounts)})
    snapshot = make_snapshot("aws", [SCOPE], collections, created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snapshot, checks=[cid])["findings"] if row["check_id"] == cid]
    assert len(rows) == 1
    return rows[0]["status"]

def denied(row, key):
    row.setdefault("_coverage", {})[key] = {"status": "denied"}
    return row

def test_complete_bucket_all_true_proves_pass_without_account_inventory():
    assert verdict(PAB, bucket()) == "PASS"
    assert verdict(PAB, bucket(), accounts=[], account_status="denied") == "PASS"

def test_unreadable_selected_bucket_configuration_is_not_pass():
    config = denied({"PublicAccessBlockConfiguration": flags()}, "PublicAccessBlockConfiguration")
    assert verdict(PAB, bucket(config)) == "UNKNOWN"

def test_unreadable_selected_bucket_flag_is_not_pass():
    config = {"PublicAccessBlockConfiguration": denied(flags(), "BlockPublicAcls")}
    assert verdict(PAB, bucket(config)) == "UNKNOWN"

def test_account_all_true_proves_pass_when_bucket_fact_unreadable():
    item = denied(bucket(), "PublicAccessBlock")
    assert verdict(PAB, item, accounts=[{"PublicAccessBlockConfiguration": flags()}]) == "PASS"

def test_account_selected_flag_denial_cannot_prove_pass():
    config = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False)}
    account = {"PublicAccessBlockConfiguration": denied(flags(), "BlockPublicAcls")}
    assert verdict(PAB, bucket(config), accounts=[account]) == "UNKNOWN"

def test_account_flag_string_cannot_prove_pass():
    config = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False)}
    account = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls="true")}
    assert verdict(PAB, bucket(config), accounts=[account]) == "UNKNOWN"

def test_independent_known_missing_effective_flag_still_fails():
    config = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False, IgnorePublicAcls=False)}
    account_flags = denied(flags(BlockPublicAcls=False), "IgnorePublicAcls")
    assert verdict(PAB, bucket(config), accounts=[{"PublicAccessBlockConfiguration": account_flags}]) == "FAIL"

def test_duplicate_account_rows_cannot_choose_last_configuration():
    config = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False)}
    rows = [{"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False)},
            {"PublicAccessBlockConfiguration": flags()}]
    assert verdict(PAB, bucket(config), accounts=rows) == "UNKNOWN"

@pytest.mark.parametrize("field", ["ServerSideEncryptionConfiguration", "Rules"])
def test_encryption_selected_parent_denial_is_unknown(field):
    encryption = {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}}
    if field == "Rules":
        denied(encryption["ServerSideEncryptionConfiguration"], "Rules")
    else:
        denied(encryption, field)
    assert verdict(ENC, bucket(encryption=encryption)) == "UNKNOWN"

def test_encryption_selected_algorithm_denial_is_unknown():
    encryption = {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": denied({"SSEAlgorithm": "AES256"}, "SSEAlgorithm")} ]}}
    assert verdict(ENC, bucket(encryption=encryption)) == "UNKNOWN"

def test_valid_encryption_algorithm_stays_pass():
    assert verdict(ENC, bucket()) == "PASS"


def test_native_account_global_row_can_prove_missing_bucket_flag():
    config = {"PublicAccessBlockConfiguration": flags(BlockPublicAcls=False)}
    item = bucket(config)
    account_item = {"AccountId": "123456789012", "PublicAccessBlockConfiguration": flags()}
    collections = [
        {"type": "bucket", "scope": SCOPE, "status": "collected", "items": [item]},
        {"type": "s3_account_public_access_block", "scope": "123456789012/global",
         "status": "collected", "global": True, "account_id": "123456789012", "items": [account_item]},
    ]
    snapshot = make_snapshot("aws", [SCOPE], collections, created_at="2026-10-17T00:00:00Z")
    rows = [row for row in evaluate_snapshot(snapshot, checks=[PAB])["findings"]
            if row["check_id"] == PAB and row["scope"] == SCOPE]
    assert len(rows) == 1
    assert rows[0]["status"] == "PASS"
