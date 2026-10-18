"""Registered source lifecycle with unchanged supplied provider-auditor records."""
import copy,json
from pathlib import Path
from peaso.snapshot import make_snapshot
from tests.archived_check_contract import evaluate_snapshot
CID='azure_c5_dev_09_01b'
NAME='provider_source_lifecycle'
FIXTURE=Path(__file__).parent/'fixtures/bulk_pending_behavior.json'

def fixture():
    idx=copy.deepcopy(json.loads(FIXTURE.read_text())[CID]['pass_index'])
    return idx['collections'],idx['context']
def normal(ctx):
    metadata=ctx['metadata'];metadata['compliance_policy']={'sw22':metadata.pop('sw22')}
    return metadata['compliance_policy']['sw22'][NAME]
def dual(ctx):
    legacy=ctx['metadata']['sw22'][NAME]
    ctx['metadata']['compliance_policy']={'sw22':{NAME:copy.deepcopy(legacy)}}
    return legacy,ctx['metadata']['compliance_policy']['sw22'][NAME]
def status(c,ctx):
    envelopes=[dict(e) for batches in c.values() for e in batches]
    snapshot=make_snapshot('azure',[ctx['scope']],envelopes,metadata=ctx['metadata'],created_at=ctx['created_at'])
    findings=[f for f in evaluate_snapshot(snapshot,checks=[CID],include_not_applicable=True)['findings'] if f['check_id']==CID]
    assert len(findings)==1
    status.last=findings
    return findings[0]['status']

def test_standard_connector_policy_namespace_resolves_actual_lifecycle_records():
    c,ctx=fixture();normal(ctx)
    assert status(c,ctx)=='PASS',status.last

def test_equal_normal_and_legacy_copies_are_unambiguous():
    c,ctx=fixture();dual(ctx)
    assert status(c,ctx)=='PASS',status.last

def test_conflicting_same_name_copies_never_select_a_winner():
    for which in (0,1):
        for field,value in [('organization_id','another-provider'),('provider_owned',False),('max_age_seconds',1)]:
            c,ctx=fixture();dual(ctx)[which][field]=value
            assert status(c,ctx)=='UNKNOWN',status.last
    c,ctx=fixture();a,b=dual(ctx);a['extra_typed_annotation']=True;b['extra_typed_annotation']=1
    assert status(c,ctx)=='UNKNOWN',status.last

def test_denied_same_name_leaf_cannot_be_masked_by_other_copy():
    for root in ('legacy','normal'):
        for present in (True,False):
            c,ctx=fixture();dual(ctx)
            parent=ctx['metadata']['sw22'] if root=='legacy' else ctx['metadata']['compliance_policy']['sw22']
            parent['_coverage']={NAME:{'status':'denied'}}
            if not present:parent.pop(NAME)
            assert status(c,ctx)=='UNKNOWN',status.last

def test_malformed_declared_parent_cannot_be_masked():
    for field in ('legacy','normal_root','normal_sw22','normal_leaf'):
        for value in (None,[],17,'malformed'):
            c,ctx=fixture();dual(ctx);metadata=ctx['metadata']
            if field=='legacy':metadata['sw22']=value
            elif field=='normal_root':metadata['compliance_policy']=value
            elif field=='normal_sw22':metadata['compliance_policy']['sw22']=value
            else:metadata['compliance_policy']['sw22'][NAME]=value
            assert status(c,ctx)=='UNKNOWN',status.last

def test_every_declared_copy_requires_original_status_scope_and_reference():
    for field,value in [('status','partial'),('scope','/subscriptions/foreign'),('evidence_ref','')]:
        for which in (0,1):
            c,ctx=fixture();dual(ctx)[which][field]=value
            assert status(c,ctx)=='UNKNOWN',status.last

def test_covered_unavailable_root_or_missing_declared_name_is_unknown():
    for mode in ('metadata','compliance_root','sw22_root','covered_missing'):
        c,ctx=fixture();dual(ctx);m=ctx['metadata']
        if mode=='metadata':m['_coverage']={'compliance_policy':{'status':'denied'}}
        elif mode=='compliance_root':m['compliance_policy']['_coverage']={'sw22':{'status':'partial'}}
        elif mode=='sw22_root':m['compliance_policy']['sw22']['collection_status']='denied'
        else:m['compliance_policy']['sw22'].pop(NAME);m['compliance_policy']['sw22']['_coverage']={NAME:{'status':'collected'}}
        assert status(c,ctx)=='UNKNOWN',status.last

def test_unrelated_name_differences_do_not_create_selected_policy_conflicts():
    c,ctx=fixture();dual(ctx)
    ctx['metadata']['sw22']['unrelated_policy']={'different':'legacy'}
    ctx['metadata']['compliance_policy']['sw22']['unrelated_policy']={'different':'normal'}
    assert status(c,ctx)=='PASS',status.last

def test_measured_lifecycle_violation_remains_fail_with_standard_policy():
    c,ctx=fixture();normal(ctx)
    c['source_control_evidence'][0]['items'][0]['outcome']='missing'
    assert status(c,ctx)=='FAIL',status.last

def test_standard_policy_does_not_create_provider_records_or_source_authority():
    for mode in ('no_policy','no_records','stale','customer'):
        c,ctx=fixture();normal(ctx)
        if mode=='no_policy':ctx['metadata']['compliance_policy']['sw22'].pop(NAME)
        elif mode=='no_records':c['source_control_evidence'][0]['items']=[];c['source_control_evidence'][0]['status']='empty'
        elif mode=='stale':c['source_control_evidence'][0]['items'][0]['observed_at']='2020-01-01T00:00:00Z'
        else:c['source_control_evidence'][0]['items'][0]['source_authority']='customer'
        assert status(c,ctx)=='UNKNOWN',status.last
