"""Presence/MFA and each bucket OR account setting, with honest joins."""
import copy
import pytest
from peaso.checks import CHECKS, aws_a_s3 as rules
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


@pytest.mark.parametrize("field", rules.BLOCKS)
def test_one_missing_preventive_control_is_not_satisfied_by_other_controls(field):
    check = REGISTRY["aws.a.s3.bucket_account_public_blocks"]
    bucket = {key: key != field for key in rules.BLOCKS}
    item = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": bucket}}
    idx = {**scope_fixture("s3_account_public_access_block", [copy.deepcopy(rules.ACCOUNT_BAD)]), "context": rules.CONTEXT}
    assert check.evaluate(item, idx)[0] == "FAIL"
    idx["collections"]["s3_account_public_access_block"][0]["items"][0]["PublicAccessBlockConfiguration"][field] = True
    assert check.evaluate(item, idx)[0] == "PASS"


def test_unverified_or_malformed_account_cannot_supply_bucket_controls():
    check = REGISTRY["aws.a.s3.bucket_account_public_blocks"]
    item = copy.deepcopy(CASES[check.id]["pass"])
    idx = copy.deepcopy(CASES[check.id]["index"])
    idx["collections"]["s3_account_public_access_block"][0]["account_id"] = "210987654321"
    assert check.evaluate(item, idx)[0] == "UNKNOWN"
    idx = copy.deepcopy(CASES[check.id]["index"])
    idx["collections"]["s3_account_public_access_block"][0]["items"][0]["PublicAccessBlockConfiguration"]["BlockPublicPolicy"] = "true"
    assert check.evaluate(item, idx)[0] == "UNKNOWN"


def test_all_bucket_controls_prove_or_result_without_unavailable_account():
    item = {"PublicAccessBlock": {"PublicAccessBlockConfiguration": {field: True for field in rules.BLOCKS}}}
    assert REGISTRY["aws.a.s3.bucket_account_public_blocks"].evaluate(item, {})[0] == "PASS"
