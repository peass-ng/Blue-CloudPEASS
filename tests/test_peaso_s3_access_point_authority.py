"""Access-point public-block evidence through registered inert snapshots."""
from copy import deepcopy
import pytest
from peaso.checks import claude_aws_a_s3 as s3
from peaso.snapshot import make_snapshot
from peaso.engine import evaluate_snapshot

CASES=[("aws.claude_a.s3.access_point_public_access_block","s3_access_point",s3.AP,"PublicAccessBlockConfiguration"),
       ("aws.claude_a.s3.multi_region_access_point_public_access_block","s3_multi_region_access_point",s3.MRAP,"PublicAccessBlock")]

def verdict(case,item):
    cid,kind,_,_=case
    scope=s3.ACCOUNT+"/us-east-1"
    snapshot=make_snapshot("aws",[scope],[{"type":kind,"scope":scope,"status":"collected","items":[item]}],created_at="2026-10-17T00:00:00Z")
    before=deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

@pytest.mark.parametrize("case",CASES,ids=["access-point","multi-region"])
@pytest.mark.parametrize("field",s3.BLOCKS)
def test_unavailable_retained_true_does_not_prove_protection(case,field):
    item=deepcopy(case[2]);item[case[3]]["_coverage"]={field:{"status":"denied"}}
    assert verdict(case,item)=="UNKNOWN"

@pytest.mark.parametrize("case",CASES,ids=["access-point","multi-region"])
@pytest.mark.parametrize("value",[None,1,"true"])
def test_malformed_flag_does_not_prove_violation(case,value):
    item=deepcopy(case[2]);item[case[3]]["BlockPublicAcls"]=value
    assert verdict(case,item)=="UNKNOWN"

@pytest.mark.parametrize("case",CASES,ids=["access-point","multi-region"])
def test_omitted_flag_requires_evidence(case):
    item=deepcopy(case[2]);del item[case[3]]["BlockPublicAcls"]
    assert verdict(case,item)=="UNKNOWN"

@pytest.mark.parametrize("case",CASES,ids=["access-point","multi-region"])
def test_known_disabled_flag_survives_unavailable_peer(case):
    item=deepcopy(case[2]);config=item[case[3]]
    config["BlockPublicPolicy"]=False;config["_coverage"]={"BlockPublicAcls":{"status":"denied"}}
    assert verdict(case,item)=="FAIL"

@pytest.mark.parametrize("case",CASES,ids=["access-point","multi-region"])
def test_available_native_configurations_preserve_outcomes(case):
    item=deepcopy(case[2]);assert verdict(case,item)=="PASS"
    item[case[3]]["BlockPublicAcls"]=False;assert verdict(case,item)=="FAIL"
