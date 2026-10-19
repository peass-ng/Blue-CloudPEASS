"""Actual database predicate outputs and guarded concise finding presentation."""
from copy import deepcopy
import hashlib
import inspect
import json
from pathlib import Path
import pytest
from peaso.checks import CHECKS
from peaso.checks.fixtures import CASES
from peaso.checks.catalog import _base_description_for, description_for
from peaso.checks.aws_database_clarity_reviewed import ROWS, _digest, description, remediation, evidence_summary

CHECK_BY_ID = {c.id:c for c in CHECKS}
PACK = Path(__file__).resolve().parents[1]/'peaso/rulepacks'

@pytest.fixture(scope='module')
def originals():
    out={}
    for path in PACK.glob('remediation*.json'):
        value=json.loads(path.read_text())
        if not isinstance(value,dict):continue
        for cid,entry in value.items():
            if cid in ROWS and _digest(entry)==ROWS[cid]['remediation_base_sha256']:out[cid]=entry
    assert set(out)==set(ROWS)
    return out

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_copy_changes_only_reviewed_fields_and_preserves_originals(cid, originals):
    original=_base_description_for(cid);saved=deepcopy(original);actual=description(cid,original)
    assert original==saved
    assert actual['description']==ROWS[cid]['description_fields']['description']
    assert 5<=len(actual['description'].split())<=35
    assert {k:v for k,v in actual.items() if k!='description'}=={k:v for k,v in original.items() if k!='description'}
    assert description_for(cid)==actual
    original=originals[cid];saved=deepcopy(original);actual=remediation(cid,original)
    assert original==saved
    assert len(actual['steps'])==1 and actual['steps'][0]==actual['summary']
    assert len(actual['summary'].split())<=40
    changed=ROWS[cid]['remediation_fields']
    assert {k:v for k,v in actual.items() if k not in changed}=={k:v for k,v in original.items() if k not in changed}
    if original.get('review_status')=='approved':
        assert actual.get('cli')==original.get('cli')
        assert actual.get('iac')==original.get('iac')
        assert actual.get('references')==original.get('references')

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_source_and_severity_decisions_bind_actual_predicates(cid):
    row=ROWS[cid];check=CHECK_BY_ID[cid];fn=inspect.unwrap(check.evaluate)
    assert row['reviewed_binding']['kind']==check.kind
    assert row['reviewed_binding']['predicate_qualname']==fn.__qualname__
    assert row['reviewed_binding']['predicate_source_sha256']==hashlib.sha256(inspect.getsource(fn).encode()).hexdigest()
    assert row['reviewed_source_severity']==check.severity
    assert row['reviewed_severity'] in {'critical','high','medium','low','info'}

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_stale_catalog_and_guidance_fail_closed(cid,originals):
    for original,apply in [(_base_description_for(cid),description),(originals[cid],remediation)]:
        original=deepcopy(original);original['unexpected_drift']=True
        with pytest.raises(ValueError,match='Reviewed database clarity base changed'):apply(cid,original)

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_summaries_use_real_failure_cases_and_preserve_raw_evidence(cid):
    check=CHECK_BY_ID[cid];cases=CASES[cid];seen=set()
    for branch in ['pass','fail','unknown','missing','malformed','not_applicable','manual']:
        if branch not in cases:continue
        item=deepcopy(cases[branch])
        status,evidence=check.evaluate(item,cases.get(branch+'_index',cases.get('index',{})))
        finding={'provider':'aws','status':status,'check_id':cid,'evidence':evidence}
        before=deepcopy(finding);summary=evidence_summary(finding)
        assert finding==before
        if status=='FAIL' and cid not in {'aws.cb.rds.instance_snapshot_not_public_prowler','aws.cb.rds.cluster_snapshot_not_public_prowler'}:
            assert summary==ROWS[cid]['static_observed_sentence']
            assert len(summary.split())<=30
        else:assert summary is None
        seen.add(status)
    # These two historical manual trust profiles intentionally have no FAIL.
    if not cid.endswith('_snapshot_shared_accounts_review'):assert {'PASS','FAIL'}<=seen


def test_unowned_and_uncertain_findings_never_get_a_failing_summary():
    for f in [None,{}, {'provider':'gcp','status':'FAIL','evidence':{}},
              {'provider':'aws','status':'UNKNOWN','check_id':next(iter(ROWS)),'evidence':{}},
              {'provider':'aws','status':'FAIL','check_id':'unowned','evidence':{}}]:
        assert evidence_summary(f) is None


@pytest.mark.parametrize('cid',sorted(ROWS))
def test_fail_label_without_decisive_evidence_never_produces_database_facts(cid):
    for evidence in [{}, {'irrelevant':'FAIL'}, {'public':False}, {'enabled':True}]:
        assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_real_passing_evidence_cannot_be_relabelled_as_failing_observation(cid):
    cases=CASES[cid]
    status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(cases['pass']),deepcopy(cases.get('pass_index',cases.get('index',{}))))
    assert status=='PASS'
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None

@pytest.mark.parametrize('cid',sorted(ROWS))
def test_wrong_evidence_value_shapes_never_become_database_observations(cid):
    cases=CASES[cid]
    if 'fail' not in cases:return
    status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(cases['fail']),deepcopy(cases.get('fail_index',cases.get('index',{}))))
    assert status=='FAIL'
    # Malformed means a type the real native output cannot carry. Empty
    # string lists and booleans can be legitimate failure witnesses, so they
    # are not mislabeled as malformed merely to force a null summary.
    def wrong(value,variant):
        if type(value) is bool:return [0,1,'false',[],{}][variant]
        if isinstance(value,list):return ['not-a-list',{},[None],[1],[{}]][variant]
        if isinstance(value,str):return [False,1,[],{},3.14][variant]
        if type(value) is int:return [True,False,{},[],3.14][variant]
        if type(value) is float:return [True,'invalid',[],{},None][variant]
        return [True,0,[],{},3.14][variant]
    for variant in range(5):
        changed={key:wrong(value,variant) for key,value in evidence.items()}
        assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':changed}) is None


@pytest.mark.parametrize('cid',['aws.cb.rds.instance_snapshot_not_public_prowler','aws.cb.rds.cluster_snapshot_not_public_prowler'])
def test_snapshot_attribute_names_are_not_public_attribute_values(cid):
    cases=CASES[cid]
    outcomes=[]
    for branch in ['pass','fail']:
        status,evidence=CHECK_BY_ID[cid].evaluate(deepcopy(cases[branch]),deepcopy(cases.get(branch+'_index',cases.get('index',{}))))
        outcomes.append(evidence)
        assert evidence=={'attributes':['restore'], 'public_attribute': branch=='fail'}
        assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':{'attributes':['restore']}}) is None
    assert outcomes[0] != outcomes[1]
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':{'attributes':['restore'],'public_attribute_value_detected':True}})

@pytest.mark.parametrize('cid',['aws.cb.rds.instance_default_master_username','aws.cb.rds.instance_multi_az_or_cluster'])
def test_missing_cluster_join_reason_does_not_invent_username_or_zone_facts(cid):
    evidence={'reason':'member cluster not found in the complete cluster inventory'}
    assert evidence_summary({'provider':'aws','status':'FAIL','check_id':cid,'evidence':evidence}) is None


def test_parameter_name_and_value_must_match_the_claim():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.rds.postgres_force_ssl_parameter','evidence':{'parameter':'rds.force_ssl','value':'0'}}
    assert evidence_summary(finding)
    for evidence in [{'parameter':'other','value':'0'},{'parameter':'rds.force_ssl','value':'1'},
                     {'parameter':'rds.force_ssl','value':0},{'parameter':'rds.force_ssl','value':None}]:
        assert evidence_summary(dict(finding,evidence=evidence)) is None


def test_required_log_exports_are_checked_against_the_observed_list():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.rds.postgres_log_exports','evidence':{'exports':['postgresql'],'required':['postgresql','upgrade']}}
    assert evidence_summary(finding)
    assert evidence_summary(dict(finding,evidence={'exports':['postgresql','upgrade']})) is None
    assert evidence_summary(dict(finding,evidence={'exports':'postgresql'})) is None


def test_backup_match_requires_explicit_boolean_and_a_resource_reference():
    finding={'provider':'aws','status':'FAIL','check_id':'aws.cb.rds.cluster_in_backup_plan_selection','evidence':{'backup_selection_match':False,'resource_arn':'arn:aws:rds:us-east-1:111111111111:cluster:c1'}}
    assert evidence_summary(finding)
    for evidence in [{'backup_selection_match':False},{'backup_selection_match':'false','resource_arn':finding['evidence']['resource_arn']},
                     {'backup_selection_match':True,'resource_arn':finding['evidence']['resource_arn']},
                     {'backup_selection_match':False,'resource_arn':'arn:invalid:rds:bad'}]:
        assert evidence_summary(dict(finding,evidence=evidence)) is None
