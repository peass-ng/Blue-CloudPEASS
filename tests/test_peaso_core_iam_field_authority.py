"""Core IAM declarations do not infer policy facts from explicitly unavailable fields."""
from copy import deepcopy
import pytest
from peaso.engine import collect_snapshot,evaluate_snapshot
from peaso.snapshot import make_snapshot

ADMIN="aws.iam.no_full_admin"
TRUST="aws.iam.restrict_public_trust"
SCOPE="123456789012/global"


def assessed(cid,item):
    kind="iam_policy" if cid==ADMIN else "iam_role"
    snapshot=make_snapshot("aws",[SCOPE],[{"type":kind,"scope":SCOPE,"status":"collected","items":[item]}])
    before=deepcopy(snapshot)
    imported=collect_snapshot({"connector":{"provider":"aws","scopes":[SCOPE],"options":{"snapshot":snapshot}},"checks":[cid]})
    rows=[r for r in evaluate_snapshot(imported,checks=[cid])["findings"] if r["check_id"]==cid]
    assert len(rows)==1 and before==snapshot and imported==before
    return rows[0]["status"]


def admin():
    return {"PolicyDocument":{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}}


def trust():
    return {"AssumeRolePolicyDocument":{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Principal":{"AWS":"*"}}]}}


@pytest.mark.parametrize("field",["Effect","Action","Resource","Condition"])
def test_core_admin_selected_denied_field_is_unknown(field):
    item=admin();row=item["PolicyDocument"]["Statement"][0]
    row["_coverage"]={field:{"status":"denied"}}
    assert assessed(ADMIN,item)=="UNKNOWN"


@pytest.mark.parametrize("field",["Effect","Action","Principal","Condition"])
def test_core_trust_selected_denied_field_is_unknown(field):
    item=trust();row=item["AssumeRolePolicyDocument"]["Statement"][0]
    row["_coverage"]={field:{"status":"denied"}}
    assert assessed(TRUST,item)=="UNKNOWN"


def test_unreadable_nested_principal_is_unknown():
    item=trust();item["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["_coverage"]={"AWS":{"status":"denied"}}
    assert assessed(TRUST,item)=="UNKNOWN"


def test_unreadable_trust_document_cannot_prove_broad_trust():
    item=trust();item["_coverage"]={"AssumeRolePolicyDocument":{"status":"denied"}}
    assert assessed(TRUST,item)=="UNKNOWN"


def test_unreadable_default_version_selector_cannot_supply_admin_document():
    item={"PolicyVersionList":[{"IsDefaultVersion":True,"Document":admin()["PolicyDocument"],"_coverage":{"IsDefaultVersion":{"status":"denied"}}}]}
    assert assessed(ADMIN,item)=="UNKNOWN"


def test_unreadable_inline_inventory_cannot_prove_no_admin():
    item={"RolePolicyList":[],"PolicyDocument":{"Statement":[]},"_coverage":{"RolePolicyList":{"status":"denied"}}}
    assert assessed(ADMIN,item)=="UNKNOWN"


@pytest.mark.parametrize("cid,builder,key",[(ADMIN,admin,"PolicyDocument"),(TRUST,trust,"AssumeRolePolicyDocument")])
@pytest.mark.parametrize("first",[False,True])
def test_known_declaration_survives_unreadable_peer(cid,builder,key,first):
    item=builder();bad=item[key]["Statement"][0]
    peer=deepcopy(bad);peer["_coverage"]={"Effect":{"status":"denied"}}
    item[key]["Statement"]=[bad,peer] if first else [peer,bad]
    assert assessed(cid,item)=="FAIL"


@pytest.mark.parametrize("cid,builder,key",[(ADMIN,admin,"PolicyDocument"),(TRUST,trust,"AssumeRolePolicyDocument")])
def test_known_conditional_declaration_remains_manual(cid,builder,key):
    item=builder();item[key]["Statement"][0]["Condition"]={"StringEquals":{"aws:PrincipalOrgID":"o-example"}}
    assert assessed(cid,item)=="MANUAL"


def test_omitted_denied_principal_member_cannot_prove_restricted_trust():
    item=trust();item["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]={"_coverage":{"AWS":{"status":"denied"}}}
    assert assessed(TRUST,item)=="UNKNOWN"


def test_known_public_principal_survives_unreadable_other_principal_member():
    item=trust();principal=item["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]
    principal["Service"]="ec2.amazonaws.com";principal["_coverage"]={"Service":{"status":"denied"}}
    assert assessed(TRUST,item)=="FAIL"
