"""Source INFO/PASS semantics, explicit trust parameters and condition literals."""
import copy
import pytest
from peaso.checks import CHECKS,aws_a_sharing as rules
from peaso.checks.fixtures import CASES

REGISTRY={c.id:c for c in CHECKS if c.id in rules.NATIVE_IDS}


@pytest.mark.parametrize("cid",rules.NATIVE_IDS)
def test_sharing_real_applicable_states_without_fake_failure(cid):
    cases=CASES[cid]
    for state,expected in (("pass","PASS"),("fail","FAIL"),("manual","MANUAL"),("missing","UNKNOWN"),("malformed","UNKNOWN")):
        if state not in cases:continue
        item,index=copy.deepcopy(cases[state]),copy.deepcopy(cases.get(state+"_index",cases.get("index",{})));before=copy.deepcopy((item,index))
        assert REGISTRY[cid].evaluate(item,index)[0]==expected
        assert (item,index)==before
    assert REGISTRY[cid].evaluate({"collection_status":"denied"},cases.get("index",{}))[0]=="UNKNOWN"


def test_source_trust_parameter_is_explicit_binding_not_implicit_own_account():
    check=REGISTRY["aws.a.config.aggregate_authorization_review"]
    assert check.evaluate({"AuthorizedAccountId":"123456789012"},{"context":{"metadata":{"trusted_scope_ids":[]}}})[0]=="MANUAL"
    assert check.evaluate({"AuthorizedAccountId":rules.TRUSTED},{})[0]=="UNKNOWN"
    assert check.evaluate({"AuthorizedAccountId":None},{})[0]=="PASS"


def test_dlm_disables_skips_and_all_four_schedules_are_reviewed():
    item=copy.deepcopy(rules.DLM);policy=item["Details"]["Policy"]
    policy["State"]="DISABLED"
    assert REGISTRY["aws.a.dlm.snapshot_sharing_review"].evaluate(item,{})[0]=="NOT_APPLICABLE"
    policy["State"]="ENABLED";policy["PolicyDetails"]["Schedules"]=[{}, {}, {}, {"ShareRules":[{"TargetAccounts":["210987654321"]}]}]
    assert REGISTRY["aws.a.dlm.snapshot_sharing_review"].evaluate(item,rules.TRUST_INDEX)[0]=="MANUAL"
    policy["PolicyDetails"]["Schedules"]=[{}]
    assert REGISTRY["aws.a.dlm.snapshot_sharing_review"].evaluate(item,rules.TRUST_INDEX)[0]=="PASS"
    item["Details"]["collection_status"]="denied"
    assert REGISTRY["aws.a.dlm.snapshot_sharing_review"].evaluate(item,rules.TRUST_INDEX)[0]=="UNKNOWN"


def test_cloudwatch_role_existence_alone_is_not_statement_crossjoin():
    from peaso.checks.aws_a_facts import scope_fixture
    check=REGISTRY["aws.a.cloudwatch.cross_account_sharing_review"]
    index=scope_fixture("iam_role",[{"RoleName":"CloudWatch-CrossAccountSharingRole","AssumeRolePolicyDocument":{"Statement":[]}}])
    assert check.evaluate({"scope":"123456789012/us-east-1"},index)[0]=="PASS"


def test_public_policy_exact_arn_equals_wildcard_and_numeric_condition_variants():
    check=REGISTRY["aws.a.cloudwatch.resource_policy_declared_public"]
    for condition,expected in (({"ArnEquals":{"aws:SourceArn":"*"}},"FAIL"),({"ArnEquals":{"aws:SourceArn":"arn:aws:logs:us-east-1:123456789012:log-group:inert"}},"PASS"),({"NumericEquals":{"aws:PrincipalAccount":rules.TRUSTED}},"FAIL")):
        item=copy.deepcopy(rules.LOG_BAD);item["policyDocument"]["Statement"][0]["Condition"]=condition
        assert check.evaluate(item,{})[0]==expected
