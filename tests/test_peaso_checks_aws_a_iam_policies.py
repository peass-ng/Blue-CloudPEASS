"""Direct declared policy variants and source wildcard/info applicability."""
import copy
import pytest
from peaso.checks import CHECKS, aws_a_iam_policies as rules
from peaso.checks.fixtures import CASES

REGISTRY = {c.id: c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid", rules.NATIVE_IDS)
def test_policy_variant_real_states_and_purity(cid):
    cases = CASES[cid]
    for state, expected in (("pass", "PASS"), ("fail", "FAIL"), ("missing", "UNKNOWN"), ("malformed", "UNKNOWN")):
        item = copy.deepcopy(cases[state]);before = copy.deepcopy(item)
        assert REGISTRY[cid].evaluate(item, {})[0] == expected
        assert item == before
    assert REGISTRY[cid].evaluate({"collection_status": "denied"}, {})[0] == "UNKNOWN"


def test_aws_managed_wildcard_is_outside_customer_scope_and_unattached_policy_skips():
    check = REGISTRY["aws.a.iam.attached_policy_no_star_star"]
    assert check.evaluate(CASES[check.id]["aws_managed_not_applicable"], {})[0] == "NOT_APPLICABLE"
    assert check.evaluate({"AttachmentCount": 0}, {})[0] == "NOT_APPLICABLE"


@pytest.mark.parametrize("action", ["*", "*:*"])
def test_conditioned_and_both_source_fullaction_spellings_alarm(action):
    item = copy.deepcopy(rules.BAD)
    item["PolicyVersionList"][0]["Document"]["Statement"][0].update(Action=action, Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}})
    assert REGISTRY["aws.a.iam.attached_policy_no_star_star"].evaluate(item, {})[0] == "FAIL"


def test_only_default_version_and_exact_declared_allow_literal_count():
    item = copy.deepcopy(rules.POLICY)
    item["PolicyVersionList"].append({"IsDefaultVersion": False, "Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}})
    assert REGISTRY["aws.a.iam.attached_policy_no_star_star"].evaluate(item, {})[0] == "PASS"
    item["PolicyVersionList"][0]["Document"]["Statement"][0] = {"Effect": "Deny", "Action": "*", "Resource": "*"}
    assert REGISTRY["aws.a.iam.attached_policy_no_star_star"].evaluate(item, {})[0] == "PASS"


def test_cloudshell_exact_managed_arn_does_not_include_inline_or_customer_namesake():
    for cid in rules.NATIVE_IDS[:3]:
        item = {"AttachedManagedPolicies": [{"PolicyArn": "arn:aws:iam::123456789012:policy/AWSCloudShellFullAccess"}], "UserPolicyList": [{"PolicyName": "AWSCloudShellFullAccess"}]}
        assert REGISTRY[cid].evaluate(item, {})[0] == "PASS"
        item["AttachedManagedPolicies"][0]["PolicyArn"] = rules.SHELL
        assert REGISTRY[cid].evaluate(item, {})[0] == "FAIL"
