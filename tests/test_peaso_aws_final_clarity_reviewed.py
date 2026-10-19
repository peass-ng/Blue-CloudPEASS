from tests.observed_evidence_successors import assert_original_evidence_preserved
"""Replay collected source tests and preserve each final AWS presentation contract."""
from copy import deepcopy
import gzip
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.catalog import _base_description_for
from peaso.checks.aws_final_clarity_reviewed import ROWS,_digest,description,remediation,evidence_summary
ROOT=Path(__file__).resolve().parents[1]
BY_ID={c.id:c for c in CHECKS}
CASES=json.loads(gzip.decompress((ROOT/'tests/fixtures/aws_final_clarity_reviewed.json.gz').read_bytes()))

@pytest.fixture(scope='module')
def originals():
    out={cid:None for cid,r in ROWS.items() if r['remediation_base_sha256']==_digest(None)}
    for p in (ROOT/'peaso/rulepacks').glob('remediation*.json'):
        v=json.loads(p.read_text())
        if not isinstance(v,dict):continue
        for cid,r in v.items():
            if cid in ROWS and _digest(r)==ROWS[cid]['remediation_base_sha256']:out[cid]=r
    assert set(out)==set(ROWS)
    return out

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_specific_copy_preserves_criteria_and_approved_commands(cid,originals):
    old=_base_description_for(cid);saved=deepcopy(old);new=description(cid,old)
    assert old==saved and 5<=len(new['description'].split())<=40
    assert {k:v for k,v in new.items() if k!='description'}=={k:v for k,v in old.items() if k!='description'}
    old=originals[cid];saved=deepcopy(old);new=remediation(cid,old)
    assert old==saved and new['steps']==[new['summary']]
    assert len(new['summary'].split())<=40
    changed=ROWS[cid]['remediation_fields']
    assert {k:v for k,v in new.items() if k not in changed}=={k:v for k,v in (old or {}).items() if k not in changed}
    if old and old.get('review_status')=='approved':
        assert new.get('cli')==old.get('cli') and new.get('iac')==old.get('iac')
    else:assert new['review_status']=='approved' and new['cli']==[] and not new.get('iac')
    assert new['references']

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_stale_bases_fail_closed(cid,originals):
    for old,fn in [(_base_description_for(cid),description),(originals[cid],remediation)]:
        changed=deepcopy(old) or {};changed['unreviewed']=True
        with pytest.raises(ValueError,match='Reviewed final AWS clarity base changed'):fn(cid,changed)

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_reviewed_predicate_and_delegate_sources_remain_exact(cid):
    row=ROWS[cid];c=BY_ID[cid];fn=inspect.unwrap(c.evaluate);bind=row['reviewed_binding']
    assert bind['kind']==c.kind and row['reviewed_source_severity']==c.severity
    assert bind['predicate_source_sha256']==hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    capture=inspect.getclosurevars(fn).nonlocals
    assert bind['delegate_sources']=={k:hashlib.sha256(inspect.getsource(v).encode()).hexdigest() for k,v in capture.items() if callable(v)}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_actual_registered_callback_fixture_verdicts_and_raw_evidence_unchanged(cid):
    assert {'PASS','FAIL'}<=CASES[cid].keys()
    c=BY_ID[cid]
    for expected,case in CASES[cid].items():
        item,index=deepcopy(case['item']),deepcopy(case['index'])
        status,evidence=c.evaluate(item,index)
        assert status==expected
        assert_original_evidence_preserved(cid, json.loads(json.dumps(evidence)), case['evidence'])
        finding={'provider':'aws','check_id':cid,'status':status,'evidence':evidence};before=deepcopy(finding)
        text=evidence_summary(finding)
        assert finding==before
        if status != 'FAIL':assert text is None
        elif cid in LEGACY_OR_INSUFFICIENT_EVIDENCE:assert text is None
        else:assert isinstance(text,str) and text.strip()
        if text:assert len(text.split())<=35


LEGACY_OR_INSUFFICIENT_EVIDENCE = {
    "aws.pci.vpc.peering_dns_resolution",
    "aws_shield_automatic_application_layer_response",
    "aws_g6_elbv2_only_https_tls_listeners",
}

@pytest.mark.parametrize("cid", sorted(ROWS))
@pytest.mark.parametrize("evidence", [{}, {"unrelated": True}, {"public":"true", "external_accounts":"999999999999"}, {"matching_rules":True}, {"rule_count":False}])
def test_absent_unrelated_and_malformed_fields_never_invent_observation(cid,evidence):
    assert evidence_summary({"provider":"aws","status":"FAIL","check_id":cid,"evidence":evidence}) is None


def test_trust_observations_distinguish_public_declarations_from_named_outsiders():
    base={"provider":"aws","status":"FAIL","check_id":"aws.htbp.ecr.registry_policy_trust_boundary"}
    assert evidence_summary({**base,"evidence":{"public":True,"external_accounts":[]}})=="ECR registry policy declares an unrestricted public principal."
    assert evidence_summary({**base,"evidence":{"public":False,"organization_inventory":True,"external_accounts":["999999999999"]}})=="The declaration names accounts outside the collected organization: 999999999999."
    assert evidence_summary({**base,"evidence":{"public":False,"organization_inventory":False,"external_accounts":["999999999999"]}}) is None
    assert evidence_summary({**base,"status":"UNKNOWN","evidence":{"public":True}}) is None
    assert evidence_summary({**base,"provider":"azure","evidence":{"public":True}}) is None


def test_cloudfront_mixed_validity_does_not_claim_all_groups_are_invalid():
    base={"provider":"aws","status":"FAIL","check_id":"aws_cloudfront_origin_failover_configured"}
    assert evidence_summary({**base,"evidence":{"origin_group_count":0}})=="No CloudFront origin failover group is configured."
    assert evidence_summary({**base,"evidence":{"origin_group_count":2,"invalid_origin_groups":["bad-secondary"]}})=="Origin groups failing the declared member or failover-code checks: bad-secondary."
    assert evidence_summary({**base,"evidence":{"origin_group_count":2,"invalid_origin_groups":[]}}) is None


def test_config_copy_and_observation_follow_actual_flag_scope():
    base={"provider":"aws","status":"FAIL","check_id":"aws_config_continuous_inventory"}
    assert evidence_summary({**base,"evidence":{"recording":True,"all_supported":True,"frequency":"DAILY"}})=="The Config recorder declares DAILY default recording."
    assert "does not resolve recording strategies" in ROWS[base['check_id']]['description_fields']['description']
    assert "public" not in ROWS['aws_cis_elbv2_only_tls_listeners']['description_fields']['description'].lower()
    assert "public" not in ROWS['aws_cis_elbv2_only_tls_listeners']['static_observed_sentence'].lower()
