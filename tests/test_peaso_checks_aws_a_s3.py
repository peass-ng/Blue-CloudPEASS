"""Presence/MFA and each bucket OR account setting, with honest joins."""
import copy
import pytest
from peaso.checks import CHECKS, aws_a_s3 as rules, evaluate_check
from peaso.checks.fixtures import CASES
from peaso.checks.aws_a_facts import scope_fixture

REGISTRY = {c.id: c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", rules.NATIVE_IDS)
def test_s3_real_states_and_input_purity(cid):
    cases = CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item, index = copy.deepcopy(cases[state]), copy.deepcopy(cases.get(state + "_index", cases.get("index", {})))
        before = copy.deepcopy((item, index))
        assert REGISTRY[cid].evaluate(item, index)[0] == expected
        assert (item, index) == before
    assert REGISTRY[cid].evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_versioning_enabled_does_not_imply_mfa_delete():
    check = REGISTRY["aws.a.s3.mfa_delete_enabled"]
    assert check.evaluate({"Versioning": {"collection_status": "collected", "Status": "Enabled"}}, {})[0] == "FAIL"
    assert check.evaluate({"Versioning": {"Status": "Enabled"}}, {})[0] == "UNKNOWN"


BLOCKS = ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls", "RestrictPublicBuckets")
OLD_ID = "aws.a.s3.bucket_account_public_blocks"
NEW_ID = "aws.s3.public_access_block"
ACCOUNT_BAD = {"PublicAccessBlockConfiguration": {field: False for field in BLOCKS}}
CONTEXT = {"scope": "123456789012/us-east-1"}


@pytest.mark.parametrize("field", BLOCKS)
def test_one_missing_preventive_control_is_not_satisfied_by_other_controls(field):
    bucket = {key: key != field for key in BLOCKS}
    item = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": bucket}}
    idx = {**scope_fixture("s3_account_public_access_block", [copy.deepcopy(ACCOUNT_BAD)]), "context": CONTEXT}
    assert evaluate_check(OLD_ID, item, idx)[0] == "FAIL"
    idx["collections"]["s3_account_public_access_block"][0]["items"][0]["PublicAccessBlockConfiguration"][field] = True
    assert evaluate_check(OLD_ID, item, idx)[0] == "PASS"
    assert evaluate_check(OLD_ID, item, idx)[0] == evaluate_check(NEW_ID, item, idx)[0]


def test_unverified_or_malformed_account_cannot_supply_bucket_controls():
    item = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {field: False for field in BLOCKS}}}
    idx = {**scope_fixture("s3_account_public_access_block", [{"PublicAccessBlockConfiguration": {field: True for field in BLOCKS}}]), "context": CONTEXT}
    idx["collections"]["s3_account_public_access_block"][0]["account_id"] = "210987654321"
    assert evaluate_check(OLD_ID, item, idx)[0] == "UNKNOWN"
    idx = {**scope_fixture("s3_account_public_access_block", [{"PublicAccessBlockConfiguration": {field: True for field in BLOCKS}}]), "context": CONTEXT}
    idx["collections"]["s3_account_public_access_block"][0]["items"][0]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = "true"
    assert evaluate_check(OLD_ID, item, idx)[0] == "UNKNOWN"
    assert evaluate_check(OLD_ID, {**item, "AccountId": "210987654321"}, idx)[0] == "UNKNOWN"


def test_all_bucket_controls_prove_or_result_without_unavailable_account():
    item = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {field: True for field in BLOCKS}}}
    assert evaluate_check(OLD_ID, item, {})[0] == "PASS"
