"""Existential identity-policy violations survive unrelated unavailable statements."""
import copy
from peaso.checks.fixtures import CASES
from peaso.checks import claude_aws_a_iam as iam
from peaso.engine import evaluate_snapshot
from peaso.snapshot import make_snapshot
BASE="aws.claude_a.iam."
MANAGED=[BASE+s for s in ("custom_policy_no_star_star","custom_attached_policy_no_star_star","custom_unattached_policy_no_star_star","attached_policy_no_star_star","custom_policy_no_service_wildcard","custom_policy_no_cloudtrail_star","custom_policy_no_kms_star","custom_policy_no_blocked_kms_actions","custom_policy_kms_decrypt_restricted")]
INLINE=[BASE+kind+suffix for kind in ("user","group","role") for suffix in ("_inline_no_admin","_inline_no_blocked_kms_actions","_inline_kms_decrypt_restricted")]
UNCERTAIN={"Effect":"Allow","Action":"s3:GetObject","Resource":"*","_coverage":{"Action":{"status":"denied"}}}

def observed(cid,edit):
    item=copy.deepcopy(CASES[cid]["fail"])
    if cid in MANAGED:
        kind="iam_policy";document=item["PolicyVersionList"][0]["Document"]
    else:
        kind=next(k for k,(_,field,_) in iam.PRINCIPALS.items() if field in item)
        document=item[iam.PRINCIPALS[kind][1]][0]["PolicyDocument"]
    edit(item,document,kind)
    snapshot=make_snapshot("aws",[iam.ACCOUNT],[{"type":kind,"scope":iam.ACCOUNT,"status":"collected","items":[item]}],created_at="2026-10-17T00:00:00Z")
    before=copy.deepcopy(snapshot)
    rows=[f for f in evaluate_snapshot(snapshot,checks=[cid])["findings"] if f["check_id"]==cid]
    assert snapshot==before and len(rows)==1
    return rows[0]["status"]

def test_managed_definite_violation_survives_unavailable_peer_in_either_order():
    for cid in MANAGED:
        for first in (False,True):
            def edit(item,document,kind):document["Statement"].insert(0 if first else len(document["Statement"]),copy.deepcopy(UNCERTAIN))
            assert observed(cid,edit)=="FAIL"

def test_inline_definite_violation_survives_unavailable_peer_in_either_order():
    for cid in INLINE:
        for first in (False,True):
            def edit(item,document,kind):document["Statement"].insert(0 if first else len(document["Statement"]),copy.deepcopy(UNCERTAIN))
            assert observed(cid,edit)=="FAIL"

def test_no_known_violation_cannot_hide_uncertainty_as_pass():
    for cid in MANAGED+INLINE:
        def edit(item,document,kind):document["Statement"]=[copy.deepcopy(UNCERTAIN),iam.allow("s3:GetObject","arn:aws:s3:::bucket/object")]
        assert observed(cid,edit)=="UNKNOWN"

def test_empty_statement_inventory_preserves_safe_classification():
    for cid in MANAGED+INLINE:
        def edit(item,document,kind):document["Statement"]=[]
        assert observed(cid,edit)=="PASS"

def test_known_deny_does_not_consume_unused_action_resource():
    for cid in MANAGED+INLINE:
        def edit(item,document,kind):document["Statement"]=[{"Effect":"Deny","_coverage":{"Action":{"status":"denied"},"Resource":{"status":"denied"}}}]
        assert observed(cid,edit)=="PASS"

def test_independent_inline_document_can_prove_violation_when_other_document_unavailable():
    for cid in INLINE:
        def edit(item,document,kind):item[iam.PRINCIPALS[kind][1]].insert(0,{"PolicyName":"unavailable","_coverage":{"PolicyDocument":{"status":"denied"}}})
        assert observed(cid,edit)=="FAIL"

def test_unavailable_default_document_cannot_expose_retained_stale_grants():
    for cid in MANAGED:
        def edit(item,document,kind):item["PolicyVersionList"][0]["_coverage"]={"Document":{"status":"denied"}}
        assert observed(cid,edit)=="UNKNOWN"
