"""Selected IAM statement facts through the public normalized snapshot evaluator."""
import copy
from peaso.checks import aws_gap_ec2 as ec2
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot

CID="aws.gap.ec2.instance_no_iam_role_with_management_level_access"
ALLOW={"Effect":"Allow","Action":"iam:CreatePolicy","Resource":"*"}
DENY={**ALLOW,"Effect":"Deny"}

def denied(statement,field,coverage=None):
    value=copy.deepcopy(statement)
    value["_coverage"]={field:coverage if coverage is not None else {"status":"denied"}}
    return value

def observed(*statements):
    role=copy.deepcopy(ec2.APP)
    role["RolePolicyList"]=[{"PolicyName":"audit","PolicyDocument":{"Version":"2012-10-17","Statement":list(statements)}}]
    collections=[{"type":kind,"scope":"*","status":"collected" if rows else "empty","items":rows}
                 for kind,rows in (("instance",[copy.deepcopy(ec2.INST)]),("iam_role",[role]),("iam_policy",[]))]
    snapshot=make_snapshot("aws",["*"],collections,created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[CID])["findings"] if f["check_id"]==CID]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_unreadable_deny_resource_cannot_prove_role_safe():
    assert observed(ALLOW,denied(DENY,"Resource"))=="UNKNOWN"

def test_each_consumed_grant_field_requires_authority():
    variants=[(ALLOW,f) for f in ("Effect","Action","Resource","Condition","NotAction","NotResource")]
    variants += [({"Effect":"Allow","NotAction":"ec2:*","Resource":"*"},"NotAction"),
                 ({"Effect":"Allow","Action":"iam:CreatePolicy","NotResource":"arn:aws:iam::123456789012:policy/one"},"NotResource")]
    for statement,field in variants:
        assert observed(denied(statement,field))=="UNKNOWN"

def test_malformed_selected_coverage_is_not_authority():
    for field in ("Effect","Action","Resource","Condition"):
        assert observed(denied(ALLOW,field,"collected"))=="UNKNOWN"

def test_independent_authoritative_deny_survives_unreadable_peers():
    for peer in (denied(ALLOW,"Resource"),denied(DENY,"Action"),denied(DENY,"Effect")):
        assert observed(peer,DENY)=="PASS"
        assert observed(DENY,peer)=="PASS"

def test_independent_authoritative_allow_survives_unreadable_allow_peer():
    peer=denied(ALLOW,"Resource")
    assert observed(peer,ALLOW)=="FAIL"
    assert observed(ALLOW,peer)=="FAIL"

def test_unreadable_possible_deny_keeps_grant_unresolved():
    for field in ("Effect","Action","Resource","Condition"):
        assert observed(ALLOW,denied(DENY,field))=="UNKNOWN"

def test_known_nonmatching_action_does_not_consume_irrelevant_scope():
    assert observed(denied({**ALLOW,"Action":"ec2:DescribeInstances"},"Resource"))=="PASS"

def test_contextual_grants_and_scoped_denies_remain_unknown():
    scoped={**ALLOW,"Resource":"arn:aws:iam::123456789012:policy/one"}
    conditional={**ALLOW,"Condition":{"StringEquals":{"aws:PrincipalTag/team":"app"}}}
    assert observed(scoped)=="UNKNOWN"
    assert observed(conditional)=="UNKNOWN"
    assert observed(ALLOW,{**scoped,"Effect":"Deny"})=="UNKNOWN"

def test_authoritative_empty_policy_allow_and_deny_keep_original_verdicts():
    assert observed()=="PASS"
    assert observed(ALLOW)=="FAIL"
    assert observed(ALLOW,DENY)=="PASS"
