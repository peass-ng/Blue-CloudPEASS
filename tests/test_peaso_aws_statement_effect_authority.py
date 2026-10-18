"""Required Allow/Deny statement Effect through admitted public snapshots."""
import copy
import pytest
from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
IDS=("aws.claude_a.iam.role_trust_not_public","aws.claude_a.iam.role_readonly_not_cross_account", "aws.claude_a.iam.prowler_role_readonly_not_cross_account")
PUBLIC={"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"arn:aws:iam::999999999999:root"}}
# Trust perimeter requires the literal wildcard for a public-principal violation.
PUBLIC["Principal"]={"AWS":"*"}

def observed(cid,statements):
    role=copy.deepcopy(iam.HUMAN_ROLE);role=iam.attach("iam_role",iam.READONLY,role)
    role["AssumeRolePolicyDocument"]=iam.doc(*copy.deepcopy(statements))
    snap=make_snapshot("aws",[iam.ACCOUNT],[{"type":"iam_role","scope":iam.ACCOUNT,"status":"collected","items":[role]}],created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snap)
    findings=[f for f in evaluate_snapshot(snap,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snap==before and len(findings)==1
    return findings[0]["status"]

@pytest.mark.parametrize("value",["missing",None,42,"allow","Unexpected",""],ids=["missing","null","numeric","wrongcase","unknown","empty"])
def test_required_allow_deny_effect_cannot_be_missing_or_invalid(value):
    row=copy.deepcopy(PUBLIC)
    if value=="missing":row.pop("Effect")
    else:row["Effect"]=value
    for cid in IDS:assert observed(cid,[row])=="UNKNOWN"

def test_explicitly_denied_effect_cannot_support_verdict():
    row={**PUBLIC,"_coverage":{"Effect":{"status":"denied"}}}
    for cid in IDS:assert observed(cid,[row])=="UNKNOWN"

def test_valid_deny_keeps_unused_principal_condition_isolation():
    row={"Effect":"Deny","_coverage":{"Principal":{"status":"denied"},"Condition":{"status":"denied"}}}
    for cid in IDS:assert observed(cid,[row])=="PASS"

def test_independent_valid_public_allow_survives_unknown_effect_peer():
    row={**PUBLIC,"Effect":"Unexpected"}
    for cid in IDS:
        assert observed(cid,[row,PUBLIC])=="FAIL"
        assert observed(cid,[PUBLIC,row])=="FAIL"

def test_empty_statement_array_preserves_existing_applicability():
    for cid in IDS:
        assert observed(cid,[])==("NOT_APPLICABLE" if cid==IDS[2] else "PASS")
