import copy
from pathlib import Path
import pytest
import sys
import peaso.checks
m=sys.modules['peaso.checks._bulk_pending_compliance_new_sw13']
from peaso.collectors import azure
from peaso.engine import _index
from peaso.snapshot import resources
from tests.test_peaso_azure_bulk_native import Transport,SUB

native=m.native_universal_mfa
TENANT='/tenants/'+Transport.tenant

def fixture(cid=m.USERS, mode='complete'):
 rule={'id':'ca-1','state':'enabled','conditions':{'users':{'includeUsers':['All'],'excludeUsers':[],
  'includeGroups':[],'excludeGroups':[],'includeRoles':[],'excludeRoles':[]},
  'applications':{'includeApplications':['All'],'excludeApplications':[]},'clientAppTypes':['all'],
  'locations':None,'platforms':None,'devices':None,'signInRiskLevels':[],'userRiskLevels':[],'authenticationFlows':None},
  'grantControls':{'operator':'AND','builtInControls':['mfa'],'authenticationStrength':None,
    'customAuthenticationFactors':[],'termsOfUse':[]}}
 if mode=='disabled':rule['state']='disabled'
 if mode=='reportonly':rule['state']='enabledForReportingButNotEnforced'
 if mode=='device':rule['conditions']['devices']={'deviceFilter':{'mode':'exclude','rule':'device.isCompliant -eq True'}}
 if mode=='risk':rule['conditions']['signInRiskLevels']=['high']
 if mode=='exclude':rule['conditions']['users']['excludeUsers']=['user-1']
 if mode=='group':rule['conditions']['users']['includeUsers']=[];rule['conditions']['users']['includeGroups']=['group-1']
 if mode=='app':rule['conditions']['applications']['includeApplications']=['Office365']
 if mode=='client':rule['conditions']['clientAppTypes']=['browser']
 if mode=='or':rule['grantControls'].update(operator='OR',builtInControls=['mfa','compliantDevice'])
 if mode=='block':rule['grantControls']['builtInControls']=['block']
 if mode=='unknowncontrol':rule['grantControls']['builtInControls']=['newControl']
 if mode=='terms':rule['grantControls']['termsOfUse']=['terms']
 routes={'/v1.0/identity/conditionalAccess/policies':{'value':[rule]},
 '/v1.0/users':{'value':[{'id':'user-1','accountEnabled':True,'userType':'Member','isMfaRegistered':True}]},
 '/v1.0/policies/identitySecurityDefaultsEnforcementPolicy':{'id':'defaults','isEnabled':mode=='defaults'}}
 if mode=='denied':routes['/v1.0/identity/conditionalAccess/policies']=azure.AzureReadError('forbidden',403)
 api=Transport(routes)
 snap=azure.collect({'scopes':[SUB],'options':{'retries':0}},['conditional_access_policy','directory_user','directory_security_defaults'],transport=api)
 idx=_index(snap,resources(snap));idx['context']={'provider':'azure','scope':TENANT,'created_at':snap['created_at'],
  'metadata':{'compliance_policy':{'sw13':{'status':'collected','scope':TENANT,'authorized_by':'security-owner','document_id':'policy',
   'observed_at':'2026-10-01T00:00:00Z','expires_at':'2026-11-01T00:00:00Z','checks':{cid.replace('.','|'):{
    'userScope':'administrative' if cid==m.ADMIN else 'all','designatedGroups':['group'],'designatedRoles':[],
    'requiredApplications':['app-1'],'requiredClientAppTypes':['browser']}}}}}}
 idx=copy.deepcopy(idx)
 rows=idx.get('conditional_access_policy',[])
 item=rows[0]['data'] if rows else {'id':'missing','_provenance':{'endpoint':'/v1.0/identity/conditionalAccess/policies','tenant_verified':True,'read_only':True}}
 return item,idx

@pytest.mark.parametrize('cid',[m.USERS,m.ADMIN,m.RISK])
def test_actual_graph_native_all_users_mfa(cid):
 item,idx=fixture(cid);assert native(item,idx,cid)[0]=='PASS'

@pytest.mark.parametrize('mode',['device','risk','exclude','group','app','client','or','block','unknowncontrol','terms','defaults'])
def test_no_unsupported_condition_becomes_an_enforced_mfa_proof(mode):
 item,idx=fixture(mode=mode);assert native(item,idx,m.USERS) is None

@pytest.mark.parametrize('mode',['disabled','reportonly'])
def test_no_enabled_policy_is_a_real_negative(mode):
 item,idx=fixture(mode=mode);assert native(item,idx,m.USERS)[0]=='FAIL'

def test_denied_native_roster_never_becomes_a_gap():
 item,idx=fixture(mode='denied')
 with pytest.raises(m.Unavailable):native(item,idx,m.USERS)

def test_foreign_or_unverified_native_authority_rejected():
 item,idx=fixture();item['_provenance']['tenant_id']='foreign'
 with pytest.raises(m.Unavailable):native(item,idx,m.USERS)
 item,idx=fixture();item['_provenance']['tenant_verified']=False
 assert native(item,idx,m.USERS) is None

from peaso.collectors import azure_conditional_access_native as adapter
STRENGTH='00000000-0000-0000-0000-000000000004'

@pytest.mark.parametrize('mode,expected',[('complete','collected'),('empty','empty'),('denied','denied'),
 ('partial','partial'),('duplicate','malformed'),('malformed','malformed'),('unverified','unknown')])
def test_native_strength_metadata_authority_pagination_and_privacy(mode,expected):
 row={'id':STRENGTH,'requirementsSatisfied':'mfa','allowedCombinations':['fido2'],
  'description':'private-marker','displayName':'private-marker'}
 if mode=='malformed':row['allowedCombinations']=[]
 def response(query):
  if mode=='denied' or mode=='partial' and '$skiptoken' in query:raise azure.AzureReadError('forbidden',403)
  value={'value':[] if mode=='empty' else [row,row] if mode=='duplicate' else [row]}
  if mode=='partial':value['@odata.nextLink']=azure.GRAPH+'/v1.0/policies/authenticationStrengthPolicies?$skiptoken=next'
  return value
 api=Transport({'/v1.0/policies/authenticationStrengthPolicies':response})
 if mode=='unverified':api.verified_tenant=None
 reader=azure._Reader({'retries':0});adapter.collect(reader,api.request,{'authentication_strength'},api)
 result=reader.collections[0];assert result['status']==expected
 import json
 assert 'private-marker' not in json.dumps(result)
 if mode=='complete':assert result['items'][0]['_provenance']['tenant_verified'] is True

@pytest.mark.parametrize('methods,requirements,expected',[(['fido2'],'mfa','PASS'),
 (['password'],'none',None),(['futureMethod'],'mfa',None),(['password'],'mfa',None)])
def test_independent_native_strength_join_requires_actual_mfa_methods(methods,requirements,expected):
 item,idx=fixture();controls=item['grantControls'];controls.update(builtInControls=[],authenticationStrength={'id':STRENGTH})
 controls['authenticationStrength@odata.context']='https://graph.microsoft.com/v1.0/$metadata#strength'
 idx['collections']['conditional_access_policy'][0]['items']=[copy.deepcopy(item)]
 api=Transport({'/v1.0/policies/authenticationStrengthPolicies':{'value':[{'id':STRENGTH,
  'requirementsSatisfied':requirements,'allowedCombinations':methods}]}})
 reader=azure._Reader({'retries':0});adapter.collect(reader,api.request,{'authentication_strength'},api)
 env=reader.collections[0];idx['collections']['authentication_strength']=[env]
 idx['authentication_strength']=[{'scope':TENANT,'type':'authentication_strength','data':r} for r in env['items']]
 result=native(item,idx,m.USERS);assert (result[0] if result is not None else None)==expected

@pytest.mark.parametrize('kind',['conditional_access_policy','directory_user','directory_security_defaults'])
def test_partial_native_inputs_never_prove_universal_mfa(kind):
 item,idx=fixture();idx['collections'][kind][0]['status']='partial'
 with pytest.raises(m.Unavailable):native(item,idx,m.USERS)

@pytest.mark.parametrize('change',['expired','foreignscope','missingauthor'])
def test_authorized_scope_obligation_still_required(change):
 item,idx=fixture();owner=idx['context']['metadata']['compliance_policy']['sw13']
 if change=='expired':owner['expires_at']='2020-01-01T00:00:00Z'
 if change=='foreignscope':owner['scope']='/tenants/foreign'
 if change=='missingauthor':owner.pop('authorized_by')
 with pytest.raises(m.Unavailable):native(item,idx,m.USERS)
