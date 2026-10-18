"""An FMS policy cannot pass against a contradictory scoped ACL universe."""
import pytest

from peaso.checks import evaluate_check


def add_other_policy(index):
    other = {"PolicyId": "p-other", "SecurityServiceType": "WAFV2"}
    index["collections"]["fms_policy"][0]["items"].append(other)
    index["fms_policy"].append({"type": "fms_policy", "scope": index["context"]["scope"], "data": other})

from tests.test_peaso_fms_multi_acl_priority import case, CONTROL


@pytest.mark.parametrize("mode", ["same_acl_claimed_by_other_policy", "foreign_account_other_policy", "foreign_region_other_policy", "wrong_type_other_policy"])
def test_other_policy_row_must_not_poison_scoped_association_inventory(mode):
    policy, rows, index = case()
    add_other_policy(index)
    rows[1]["PolicyId"] = "p-other"
    if mode == "same_acl_claimed_by_other_policy":
        rows[1]["WebACLArn"] = rows[0]["WebACLArn"]
    elif mode == "foreign_account_other_policy":
        rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("123456789012", "999999999999")
    elif mode == "foreign_region_other_policy":
        rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("us-east-1", "us-west-2")
    else:
        rows[1]["WebACLArn"] = rows[1]["WebACLArn"].replace("/webacl/", "/ipset/")
    assert evaluate_check(CONTROL, policy, index)[0] == "UNKNOWN"


def test_distinct_scoped_acl_of_another_policy_does_not_change_verdict():
    policy, rows, index = case()
    add_other_policy(index)
    rows[1]["PolicyId"] = "p-other"
    assert evaluate_check(CONTROL, policy, index)[0] == "PASS"


@pytest.mark.parametrize("mode", ["missing_direct_policy", "unlisted_policy"])
def test_tags_or_unlisted_policy_do_not_establish_acl_association(mode):
    policy, rows, index = case()
    rows[1]["Tags"] = [{"Key": "PolicyId", "Value": policy["PolicyId"]}]
    if mode == "missing_direct_policy":
        rows[1].pop("PolicyId")
    else:
        rows[1]["PolicyId"] = "p-unlisted"
    assert evaluate_check(CONTROL, policy, index)[0] == "UNKNOWN"
