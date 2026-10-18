# Historical fixture contracts; current native admission is tested separately.
"""Explicit TLS criteria never substitute for native endpoint observations."""
import copy
from datetime import timedelta
from types import SimpleNamespace
import pytest
from fastapi import HTTPException
from peaso import azure_tls_owner_policy as policy
from peaso.collectors import azure
from tests.archived_check_contract import evaluate_snapshot
from peaso.server.validation import validate_connector
from tests.compliance_draft_isolation import staged_registry

# Import the fixture library under its existing registrar sandbox; collect no old tests.
with staged_registry(["compliance_new_sw20"]):
    from tests import test_peaso_compliance_new_sw20 as fixtures

SCOPE, FOREIGN = fixtures.SCOPE, fixtures.FOREIGN

def owner():
    return {'status':'collected','scope':SCOPE,'observed_at':fixtures.STAMP,'max_age_seconds':86400,
            'parameters':{'approvedTlsServiceInventory':['applicationGateway','appService'],'tlsObservationMaxAgeSeconds':3600}}

def options(raw=None):
    return {'compliance_parameters':{policy.NAMESPACE:owner() if raw is None else raw}}

@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_valid_intake_preserves_approval_and_deepcopy(auth_mode):
    supplied=options();before=copy.deepcopy(supplied)
    validate_connector('azure',{'method':'token','arm_token':'INERT_FIXTURE'},supplied,SimpleNamespace(auth_mode=auth_mode))
    normalized=policy.normalize(supplied)
    assert normalized==owner() and normalized is not supplied['compliance_parameters'][policy.NAMESPACE]
    normalized['parameters']['approvedTlsServiceInventory'].append('anotherService')
    assert supplied==before and policy.normalize(supplied)['observed_at']==fixtures.STAMP

@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('mode',['null','list','missing_status','wrong_status','bad_scope','null_time','naive_time','bad_time','boolean_review_age','zero_review_age','huge_review_age','observations','payload','snapshot','null_parameters','missing_services','extra_parameter','null_services','string_services','empty_services','duplicate_aliases','malformed_service','null_service','too_many_services','boolean_observation_age','zero_observation_age','float_observation_age'])
def test_invalid_criteria_rejected_in_both_intakes(auth_mode,mode):
    raw=owner()
    if mode=='null':raw=None
    elif mode=='list':raw=[]
    elif mode=='missing_status':raw.pop('status')
    elif mode=='wrong_status':raw['status']='approved'
    elif mode=='bad_scope':raw['scope']='https://evil.invalid/subscription'
    elif mode=='null_time':raw['observed_at']=None
    elif mode=='naive_time':raw['observed_at']='2026-10-12T12:00:00'
    elif mode=='bad_time':raw['observed_at']='not-a-time'
    elif mode=='boolean_review_age':raw['max_age_seconds']=True
    elif mode=='zero_review_age':raw['max_age_seconds']=0
    elif mode=='huge_review_age':raw['max_age_seconds']=policy.MAX_AGE+1
    elif mode=='observations':raw['observations']=[{'enabled':True}]
    elif mode=='payload':raw['vault_certificate']={'thumbprint':'fake'}
    elif mode=='snapshot':raw['collections']=[]
    elif mode=='null_parameters':raw['parameters']=None
    elif mode=='missing_services':raw['parameters'].pop('approvedTlsServiceInventory')
    elif mode=='extra_parameter':raw['parameters']['native_evidence']={'status':'complete'}
    elif mode=='null_services':raw['parameters']['approvedTlsServiceInventory']=None
    elif mode=='string_services':raw['parameters']['approvedTlsServiceInventory']='appService'
    elif mode=='empty_services':raw['parameters']['approvedTlsServiceInventory']=[]
    elif mode=='duplicate_aliases':raw['parameters']['approvedTlsServiceInventory']=['appService','APPSERVICE']
    elif mode=='malformed_service':raw['parameters']['approvedTlsServiceInventory']=['Microsoft.Web/sites']
    elif mode=='null_service':raw['parameters']['approvedTlsServiceInventory']=[None]
    elif mode=='too_many_services':raw['parameters']['approvedTlsServiceInventory']=['Service'+str(n)for n in range(65)]
    elif mode=='boolean_observation_age':raw['parameters']['tlsObservationMaxAgeSeconds']=False
    elif mode=='zero_observation_age':raw['parameters']['tlsObservationMaxAgeSeconds']=0
    elif mode=='float_observation_age':raw['parameters']['tlsObservationMaxAgeSeconds']=1.5
    supplied={'compliance_parameters':{policy.NAMESPACE:raw}}
    with pytest.raises(ValueError):policy.normalize(supplied)
    with pytest.raises(HTTPException)as caught:validate_connector('azure',{},supplied,SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code==422

@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('provider',['aws','gcp','k8s'])
def test_namespace_is_azure_only(auth_mode,provider):
    with pytest.raises(HTTPException)as caught:validate_connector(provider,{},options(),SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code==422

@pytest.mark.parametrize('auth_mode',['local','cognito'])
def test_parent_null_rejected_and_absence_never_synthesized(auth_mode):
    assert policy.normalize({})is None and policy.normalize({'compliance_parameters':{'unrelated':{}}})is None
    with pytest.raises(HTTPException)as caught:validate_connector('azure',{}, {'compliance_parameters':None},SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code==422
    metadata={'other':{'value':1}};policy.merge_metadata(metadata,None);assert metadata=={'other':{'value':1}}

@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('arm_scope',[SCOPE,FOREIGN])
def test_legacy_arm_ssl_cannot_share_explicit_tls_authority(auth_mode,arm_scope):
    supplied=options();supplied['compliance_parameters']['azure_arm_metadata']={'status':'collected','scope':arm_scope,'approvedPredefinedSslPolicyName':'AppGwSslPolicy20220101S'}
    with pytest.raises(ValueError):policy.normalize(supplied)
    with pytest.raises(HTTPException)as caught:validate_connector('azure',{},supplied,SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code==422

def test_other_arm_fields_do_not_attach_ssl_approval():
    supplied=options();supplied['compliance_parameters']['azure_arm_metadata']={'scope':SCOPE,'unrelated':'kept'}
    assert policy.normalize(supplied)==owner()

def test_same_authority_preserves_other_parameters_namespaces_and_deepcopy():
    raw=owner();metadata={'other_metadata':{'value':1},'compliance_policy':{**{k:raw[k]for k in policy.AUTHORITY},'parameters':{'unrelated':['retain']},'sw33':{'status':'collected'}}}
    policy.merge_metadata(metadata,raw)
    assert metadata['compliance_policy']['parameters']=={'unrelated':['retain'],**raw['parameters']}
    assert metadata['compliance_policy']['sw33']=={'status':'collected'} and metadata['other_metadata']=={'value':1}
    raw['parameters']['approvedTlsServiceInventory'].append('later')
    assert 'later'not in metadata['compliance_policy']['parameters']['approvedTlsServiceInventory']
    metadata['compliance_policy']['parameters']['tlsObservationMaxAgeSeconds']=2
    assert raw['parameters']['tlsObservationMaxAgeSeconds']==3600

@pytest.mark.parametrize('conflict',['scope','observed_at','max_age_seconds','status','parameters','prior_shape','parameter_shape'])
def test_merge_conflicts_never_rebind_or_mutate(conflict):
    metadata={'compliance_policy':owner()};prior=metadata['compliance_policy']
    if conflict=='scope':prior['scope']=FOREIGN
    elif conflict=='observed_at':prior['observed_at']=(fixtures.NOW-timedelta(seconds=1)).isoformat()
    elif conflict=='max_age_seconds':prior['max_age_seconds']=1
    elif conflict=='status':prior['status']='unknown'
    elif conflict=='parameters':prior['parameters']['tlsObservationMaxAgeSeconds']=1
    elif conflict=='prior_shape':metadata['compliance_policy']=[]
    elif conflict=='parameter_shape':prior['parameters']=[]
    before=copy.deepcopy(metadata)
    with pytest.raises(ValueError):policy.merge_metadata(metadata,owner())
    assert metadata==before

def test_selected_scope_mismatch_before_transport_construction(monkeypatch):
    constructions=[]
    def forbidden(auth):constructions.append(auth);raise AssertionError('No credential access')
    monkeypatch.setattr(azure,'AzureTransport',forbidden)
    with pytest.raises(ValueError,match='outside selected subscriptions'):azure.collect({'auth':{},'scopes':[FOREIGN],'options':options()},requirements=[])
    assert constructions==[]

def test_real_collect_empty_requirements_exact_criteria_zero_requests():
    class Inert:
        tenant=verified_tenant='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        def __init__(self):self.calls=[]
        def request(self,*args,**kwargs):self.calls.append((args,kwargs));raise AssertionError('No API expected')
    inert=Inert();supplied=options()
    snapshot=azure.collect({'auth':{},'scopes':[SCOPE],'options':supplied},requirements=[],transport=inert)
    assert inert.calls==[] and snapshot['metadata']['calls']==0
    assert snapshot['metadata']['compliance_policy']==owner() and supplied==options()
    assert not {'vault_certificate','certificate_issuance'}&{c['type']for c in snapshot['collections']}
    ids=[fixtures.sw.ROTATE90,fixtures.sw.ROTATE180];report=evaluate_snapshot(snapshot,checks=ids)
    assert {f['check_id']:f['status']for f in report['findings']if f['check_id']in ids}==dict.fromkeys(ids,'UNKNOWN')

@pytest.mark.parametrize('check_id',[fixtures.sw.ROTATE90,fixtures.sw.ROTATE180])
@pytest.mark.parametrize('bad,expected',[(False,'PASS'),(True,'FAIL')])
def test_complete_signed_endpoint_fixture_verdict_preserved(check_id,bad,expected):
    index=fixtures.build(check_id,bad=bad);metadata=index['context']['metadata'];before=copy.deepcopy(metadata)
    policy.merge_metadata(metadata,policy.normalize(options()))
    assert metadata==before and fixtures.evaluate(check_id,index)[0]==expected

@pytest.mark.parametrize('check_id',[fixtures.sw.ROTATE90,fixtures.sw.ROTATE180])
@pytest.mark.parametrize('when',['stale','future'])
def test_supplied_approval_time_never_refreshed_unknown(check_id,when):
    raw=owner();raw['observed_at']=(fixtures.NOW+timedelta(seconds=1)if when=='future'else fixtures.NOW-timedelta(seconds=raw['max_age_seconds']+1)).isoformat()
    normalized=policy.normalize(options(raw));assert normalized['observed_at']==raw['observed_at']
    index=fixtures.build(check_id);index['context']['metadata'].pop('compliance_policy');policy.merge_metadata(index['context']['metadata'],normalized)
    assert index['context']['metadata']['compliance_policy']['observed_at']==raw['observed_at']
    assert fixtures.evaluate(check_id,index)[0]=='UNKNOWN'

@pytest.mark.parametrize('auth_mode',['local','cognito'])
@pytest.mark.parametrize('field',['scope','status','observed_at','max_age_seconds','parameters'])
def test_raw_flat_competing_policy_rejected_in_both_intakes(auth_mode,field):
    supplied=options();supplied['compliance_policy']={field:copy.deepcopy(owner()[field])}
    # Reject even equal values: bulk evidence must not attach another flat review.
    with pytest.raises(ValueError):policy.normalize(supplied)
    with pytest.raises(HTTPException)as caught:validate_connector('azure',{},supplied,SimpleNamespace(auth_mode=auth_mode))
    assert caught.value.status_code==422

@pytest.mark.parametrize('field',['scope','status','observed_at','max_age_seconds','parameters'])
def test_raw_flat_competing_policy_rejected_before_transport(field,monkeypatch):
    supplied=options();supplied['compliance_policy']={field:copy.deepcopy(owner()[field])}
    constructions=[]
    def forbidden(auth):constructions.append(auth);raise AssertionError('No credential access')
    monkeypatch.setattr(azure,'AzureTransport',forbidden)
    with pytest.raises(ValueError,match='owner criteria'):azure.collect({'auth':{},'scopes':[SCOPE],'options':supplied},requirements=[])
    assert constructions==[]


def test_namespace_only_reviews_preserve_sw03_sw33_and_explicit_authority():
    raw={'sw03':{'status':'collected','scope':SCOPE,'legacyAgentBaseline':{'required':False}},
         'sw33':{'status':'collected','scope':SCOPE,'databricksAccount':{'accountId':'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'}}}
    supplied=options();supplied['compliance_policy']=copy.deepcopy(raw)
    assert policy.normalize(supplied)==owner()
    metadata={'compliance_policy':copy.deepcopy(raw)};policy.merge_metadata(metadata,owner())
    assert metadata['compliance_policy']=={**raw,**owner()}
    class Inert:
        tenant=verified_tenant='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        def request(self,*args,**kwargs):raise AssertionError('No API expected')
    snapshot=azure.collect({'auth':{},'scopes':[SCOPE],'options':supplied},requirements=[],transport=Inert())
    assert snapshot['metadata']['calls']==0
    assert snapshot['metadata']['compliance_policy']=={**raw,**owner()}
    assert supplied['compliance_policy']==raw
