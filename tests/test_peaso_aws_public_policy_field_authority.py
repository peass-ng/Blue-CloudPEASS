"""Public resource/trust-policy field authority through registered snapshots."""
import copy
from peaso.checks.fixtures import CASES
from peaso.checks.claude_aws_a_common import SCOPE
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
TRUST="aws.claude_a.iam.role_trust_not_public"
WRITE="aws.claude_a.s3.prowler_policy_public_write"
PUBLIC={"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:PutObject","Resource":"*"}
RESTRICTED={**PUBLIC,"Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}

def denied(row,field):
    row=copy.deepcopy(row);row.setdefault("_coverage",{})[field]={"status":"denied"};return row

def observed(statements,cid=TRUST):
    case=CASES[cid];item=copy.deepcopy(case["fail"])
    doc={"Version":"2012-10-17","Statement":copy.deepcopy(statements)}
    kind="iam_role" if cid==TRUST else "bucket"
    if kind=="iam_role":item["AssumeRolePolicyDocument"]=doc
    else:item["Policy"]={"Policy":doc}
    index=copy.deepcopy(case.get("fail_index",case.get("index",{})))
    collections=[{"type":kind,"scope":SCOPE,"status":"collected","items":[item]}]
    for dep,envelopes in index.get("collections",{}).items():
        if dep!=kind:collections+=envelopes
    snapshot=make_snapshot("aws",[SCOPE],collections,created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_denied_restrictive_condition_cannot_prove_policy_private():
    assert observed([denied(RESTRICTED,"Condition")])=="UNKNOWN"

def test_denied_public_principal_cannot_prove_public_violation():
    assert observed([denied(PUBLIC,"Principal")])=="UNKNOWN"

def test_nested_principal_authority_is_required():
    for cid in (TRUST,WRITE):
        row=copy.deepcopy(PUBLIC);row["Principal"]=denied(row["Principal"],"AWS")
        assert observed([row],cid)=="UNKNOWN"

def test_condition_operator_and_key_authority_are_required():
    for cid in (TRUST,WRITE):
        for level in ("operator","key"):
            row=copy.deepcopy(RESTRICTED)
            if level=="operator":row["Condition"]=denied(row["Condition"],"StringEquals")
            else:row["Condition"]["StringEquals"]=denied(row["Condition"]["StringEquals"],"aws:SourceAccount")
            assert observed([row],cid)=="UNKNOWN"

def test_denied_effect_cannot_prove_private_or_public():
    for cid in (TRUST,WRITE):assert observed([denied(PUBLIC,"Effect")],cid)=="UNKNOWN"

def test_independent_authoritative_public_statement_survives_unknown_peer():
    for cid in (TRUST,WRITE):
        uncertain=denied(RESTRICTED,"Condition")
        assert observed([uncertain,PUBLIC],cid)=="FAIL"
        assert observed([PUBLIC,uncertain],cid)=="FAIL"

def test_known_deny_does_not_consume_unavailable_principal_or_condition():
    row=denied(denied({**PUBLIC,"Effect":"Deny"},"Principal"),"Condition")
    for cid in (TRUST,WRITE):assert observed([row],cid)=="PASS"

def test_prowler_action_authority_and_nonmatching_action_isolation():
    assert observed([denied(PUBLIC,"Action")],WRITE)=="UNKNOWN"
    unrelated=denied(denied({**PUBLIC,"Action":"s3:GetObject"},"Principal"),"Condition")
    assert observed([unrelated],WRITE)=="PASS"

def test_available_public_and_restrictive_conditions_keep_verdicts():
    for cid in (TRUST,WRITE):
        assert observed([PUBLIC],cid)=="FAIL"
        assert observed([RESTRICTED],cid)=="PASS"


def test_malformed_consumed_fields_cannot_prove_policy_private_or_public():
    variants=[{**PUBLIC,"Effect":1},{**PUBLIC,"Principal":{"AWS":42}},
              {**PUBLIC,"Condition":{"StringEquals":[]}},
              {**PUBLIC,"Condition":{"StringEquals":{"aws:SourceAccount":42}}}]
    for cid in (TRUST,WRITE):
        for statement in variants:assert observed([statement],cid)=="UNKNOWN"
