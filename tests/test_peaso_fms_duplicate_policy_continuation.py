"""Conflicting complete policy inventory cannot authenticate ACL association."""
from peaso.checks import evaluate_check
from tests.test_peaso_fms_multi_acl_priority import CONTROL,case
from tests.test_peaso_fms_association_continuation import add_other_policy

def test_duplicate_unrelated_policy_identity_is_unknown():
    policy,rows,index=case()
    add_other_policy(index)
    add_other_policy(index)
    rows[1]['PolicyId']='p-other'
    assert evaluate_check(CONTROL,policy,index)[0]=='UNKNOWN'
