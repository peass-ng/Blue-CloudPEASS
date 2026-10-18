"""Missing approval remains conclusive only outside unresolved resource joins."""
import pytest
from peaso.checks import evaluate_check
from tests.test_peaso_azure_change_approval_aggregate_failure import CID,facts,event,approval,BASE

def grade(events,approvals):
    return evaluate_check(CID,{},facts(events,approvals))

@pytest.mark.parametrize('reverse',[False,True])
def test_missing_approval_survives_other_resource_unjoinable_record(reverse):
    a,b=event('missing'),event('unresolved')
    b['correlationId']=''
    p=approval('unresolved',status='Approved');p['correlationId']=''
    records=[a,b]
    if reverse:records.reverse()
    outcome,evidence=grade(records,[p])
    assert outcome=='FAIL',evidence
    assert a['id'] in evidence['changes_without_predating_approval']
    assert b['id'] in evidence['unresolved_changes']

def test_blank_approval_for_other_resource_does_not_mask_missing_approval():
    p=approval('unrelated',status='Approved');p['correlationId']=''
    outcome,evidence=grade([event('missing')],[p])
    assert outcome=='FAIL',evidence

def test_unjoinable_record_for_same_resource_is_not_proven_absence():
    p=approval('unresolved',status='Approved');p['correlationId']=''
    assert grade([event('unresolved')],[p])[0]=='UNKNOWN'

def test_empty_event_and_approval_correlation_never_authenticates_join():
    e=event('unresolved');e['correlationId']=''
    p=approval('unresolved',status='Approved');p['correlationId']=''
    assert grade([e],[p])[0]=='UNKNOWN'

def test_foreign_unjoinable_approval_keeps_global_scope_guard():
    p=approval('foreign',status='Approved');p['correlationId']='';p['resourceId']=BASE.replace('11111111','22222222')+'/foreign'
    assert grade([event('missing')],[p])[0]=='UNKNOWN'
