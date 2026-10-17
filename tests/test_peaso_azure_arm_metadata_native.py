from datetime import datetime,timezone,timedelta
import copy,json
import pytest
from peaso.collectors import azure
from tests.test_peaso_azure_bulk_native import Transport,parent,routes,collect,verdict,SCOPE,BASE,STORAGE
NODE_CHECK='azure_vm_1_2_8_10_1bd35d0'
SSL_CHECK='azure_application_gateway_app_ensure_http_is_redirected_to_https_e598c17'
FILES_CHECK='azure_storage_file_share_10_3_3_15_f2d7075'
ACCOUNT=BASE+'Microsoft.Automation/automationAccounts/account'
NODE=ACCOUNT+'/nodes/node'
GATEWAY=BASE+'Microsoft.Network/applicationGateways/gateway'
SHARE=STORAGE+'/fileServices/default/shares/share'
VAULT=BASE+'Microsoft.RecoveryServices/vaults/vault'
ITEM=VAULT+'/backupFabrics/Azure/protectionContainers/storagecontainer;storage;rg;account/protectedItems/azurefileshare;share'
def policy(**kw):return {'compliance_parameters':{'azure_arm_metadata':{'scope':SCOPE,'status':'collected',**kw}}}
def node_case(mode):
 m=routes('automation_account',ACCOUNT,{})
 p={'nodeId':'native-node-id','lastSeen':datetime.now(timezone.utc).isoformat(),'status':'Compliant','nodeConfiguration':{'name':'baseline'},'ip':'private-marker'}
 if mode=='bad':p['status']='NotCompliant'
 if mode=='unassigned':p['nodeConfiguration']=None
 if mode=='missing':p.pop('lastSeen')
 if mode=='stale':p['lastSeen']=(datetime.now(timezone.utc)-timedelta(days=10)).isoformat()
 r=parent(NODE,'Microsoft.Automation/automationAccounts/nodes',p)
 m[ACCOUNT+'/nodes']={'value':[r]}
 if mode=='foreign':r['id']=NODE.replace('/automationAccounts/account/','/automationAccounts/foreign/')
 if mode=='denied':m[ACCOUNT+'/nodes']=azure.AzureReadError('forbidden',403)
 if mode=='empty':m[ACCOUNT+'/nodes']={'value':[]}
 if mode=='partial':m[ACCOUNT+'/nodes']=lambda q:azure.AzureReadError('forbidden',403) if 'page' in q else {'value':[r],'nextLink':azure.ARM+ACCOUNT+'/nodes?page=2'}
 return m
@pytest.mark.parametrize('mode,expected',[('good','PASS'),('bad','FAIL'),('unassigned','FAIL'),('missing','UNKNOWN'),('stale','UNKNOWN'),('foreign','UNKNOWN'),('denied','DENIED'),('partial','UNKNOWN'),('empty','UNKNOWN')])
def test_native_dsc(mode,expected):
 s=collect(['automation_node'],Transport(node_case(mode)),**policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24}))
 assert verdict(s,NODE_CHECK)==expected
 assert 'private-marker' not in json.dumps(s)
def gateway_case(mode):
 p={'httpListeners':[{'id':GATEWAY+'/httpListeners/https','properties':{'protocol':'Https'}}],'sslProfiles':[],'sslPolicy':{'policyType':'Predefined','policyName':'AppGwSslPolicy20220101'}}
 if mode=='bad':p['sslPolicy']['policyType']='Custom'
 if mode=='missing':p.pop('sslPolicy')
 if mode=='foreignlistener':p['httpListeners'][0]['id']=GATEWAY.replace('/gateway','/other')+'/httpListeners/https'
 if mode=='profile':
  profile=GATEWAY+'/sslProfiles/profile'
  p['httpListeners'][0]['properties']['sslProfile']={'id':profile}
  p['sslProfiles']=[{'id':profile,'properties':{'sslPolicy':p.pop('sslPolicy')}}]
 m=routes('application_gateway',GATEWAY,p)
 m[SCOPE+'/providers/Microsoft.Network/frontDoors']={'value':[]}
 if mode=='denied':m[SCOPE+'/providers/Microsoft.Network/frontDoors']=azure.AzureReadError('forbidden',403)
 if mode=='partial':m[SCOPE+'/providers/Microsoft.Network/frontDoors']=lambda q:azure.AzureReadError('forbidden',403) if 'page' in q else {'value':[],'nextLink':azure.ARM+SCOPE+'/providers/Microsoft.Network/frontDoors?page=2'}
 return m
@pytest.mark.parametrize('mode,expected',[('good','PASS'),('profile','PASS'),('bad','FAIL'),('missing','UNKNOWN'),('foreignlistener','UNKNOWN'),('denied','UNKNOWN'),('partial','UNKNOWN')])
def test_native_gateway(mode,expected):
 assert verdict(collect(['application_gateway_and_frontdoor'],Transport(gateway_case(mode)),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101')),SSL_CHECK)==expected
def files_case(mode):
 m=routes('storage_account',STORAGE,{})
 m[STORAGE+'/fileServices/default/shares']={'value':[parent(SHARE,'Microsoft.Storage/storageAccounts/fileServices/shares',{})]}
 m.update(routes('recovery_vault',VAULT,{}))
 p={'protectedItemType':'AzureFileShareProtectedItem','sourceResourceId':STORAGE,'friendlyName':'share','protectionState':'Protected','policyId':VAULT+'/backupPolicies/policy'}
 if mode=='bad':p['protectionState']='ProtectionStopped'
 if mode=='missingstate':p.pop('protectionState')
 if mode=='foreignsource':p['sourceResourceId']=STORAGE.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
 m[VAULT+'/backupProtectedItems']={'value':[parent(ITEM,'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems',p)]}
 if mode=='empty':m[VAULT+'/backupProtectedItems']={'value':[]}
 if mode=='denied':m[VAULT+'/backupProtectedItems']=azure.AzureReadError('forbidden',403)
 if mode=='novault':m[SCOPE+'/providers/Microsoft.RecoveryServices/vaults']={'value':[]}
 return m
@pytest.mark.parametrize('mode,expected',[('good','PASS'),('bad','FAIL'),('empty','FAIL'),('novault','FAIL'),('missingstate','UNKNOWN'),('foreignsource','UNKNOWN'),('denied','DENIED')])
def test_native_files(mode,expected):assert verdict(collect(['storage_file_share_and_backup_item'],Transport(files_case(mode))),FILES_CHECK)==expected
@pytest.mark.parametrize('check,kind,mapping,options',[(NODE_CHECK,'automation_node',node_case('good'),policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24})),(SSL_CHECK,'application_gateway_and_frontdoor',gateway_case('good'),policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))])
@pytest.mark.parametrize('mutation',['missing','foreign','observations'])
def test_policy_rejection(check,kind,mapping,options,mutation):
 options=copy.deepcopy(options)
 if mutation=='missing':options={}
 elif mutation=='foreign':options['compliance_parameters']['azure_arm_metadata']['scope']='/subscriptions/foreign'
 else:options['compliance_parameters']['azure_arm_metadata']['observations']={'passed':True}
 assert verdict(collect([kind],Transport(mapping),**options),check)=='UNKNOWN'

@pytest.mark.parametrize('mode',['foreign','getdenied','wrongget'])
def test_gateway_identity_and_get_integrity(mode):
 m=gateway_case('good')
 if mode=='duplicate':m[SCOPE+'/providers/Microsoft.Network/applicationGateways']['value']*=2
 if mode=='foreign':m[SCOPE+'/providers/Microsoft.Network/applicationGateways']['value'][0]['id']=GATEWAY.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
 if mode=='getdenied':m[GATEWAY]=azure.AzureReadError('forbidden',403)
 if mode=='wrongget':m[GATEWAY]['id']=GATEWAY+'/foreign/child'
 status=verdict(collect(['application_gateway_and_frontdoor'],Transport(m),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101')),SSL_CHECK)
 assert status in ('UNKNOWN','DENIED')

def test_gateway_projection_never_preserves_unneeded_customer_values():
 m=gateway_case('good')
 m[GATEWAY]['properties']['httpListeners'][0]['properties']['customErrorConfigurations']=[{'customErrorPageUrl':'private-marker'}]
 m[GATEWAY]['properties']['sslCertificates']=[{'properties':{'data':'private-marker','password':'private-marker'}}]
 s=collect(['application_gateway_and_frontdoor'],Transport(m),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))
 c=next(c for c in s['collections'] if c['type']=='application_gateway_and_frontdoor')
 assert 'private-marker' not in json.dumps(c)
 assert verdict(s,SSL_CHECK)=='PASS'

def test_full_classic_frontdoor_does_not_become_gateway_predefined_policy():
 m=gateway_case('good')
 rid=BASE+'Microsoft.Network/frontDoors/frontdoor'
 endpoint=rid+'/frontendEndpoints/endpoint'
 props={'frontendEndpoints':[{'id':endpoint,'properties':{'customHttpsProvisioningState':'Enabled'}}],
        'routingRules':[{'id':rid+'/routingRules/route','properties':{'acceptedProtocols':['Https'],'frontendEndpoints':[{'id':endpoint}]}}]}
 m[SCOPE+'/providers/Microsoft.Network/frontDoors']={'value':[parent(rid,'Microsoft.Network/frontDoors',props)]}
 m[rid]=parent(rid,'Microsoft.Network/frontDoors',props)
 assert verdict(collect(['application_gateway_and_frontdoor'],Transport(m),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101')),SSL_CHECK)=='UNKNOWN'

@pytest.mark.parametrize('mode',['deniedshare','partialbackup','foreignvault','duplicatebackup'])
def test_backup_coverage_or_join_failure_cannot_prove_protection(mode):
 m=files_case('good')
 if mode=='deniedshare':m[STORAGE+'/fileServices/default/shares']=azure.AzureReadError('forbidden',403)
 if mode=='partialbackup':
  rows=m[VAULT+'/backupProtectedItems']['value']
  m[VAULT+'/backupProtectedItems']=lambda q:azure.AzureReadError('forbidden',403) if 'page' in q else {'value':rows,'nextLink':azure.ARM+VAULT+'/backupProtectedItems?page=2'}
 if mode=='foreignvault':m[SCOPE+'/providers/Microsoft.RecoveryServices/vaults']['value'][0]['id']=VAULT.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')
 if mode=='duplicatebackup':
  other=copy.deepcopy(m[VAULT+'/backupProtectedItems']['value'][0]);other['id']=ITEM+'other'
  m[VAULT+'/backupProtectedItems']['value'].append(other)
 assert verdict(collect(['storage_file_share_and_backup_item'],Transport(m)),FILES_CHECK) in ('UNKNOWN','DENIED')


def test_identical_parent_list_duplicates_do_not_replace_authoritative_get():
 m=gateway_case('good')
 m[SCOPE+'/providers/Microsoft.Network/applicationGateways']['value']*=2
 assert verdict(collect(['application_gateway_and_frontdoor'],Transport(m),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101')),SSL_CHECK)=='PASS'

@pytest.mark.parametrize('kind,check,mapping,options',[
 ('automation_node',NODE_CHECK,node_case('good'),policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24})),
 ('application_gateway_and_frontdoor',SSL_CHECK,gateway_case('good'),policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101')),
 ('storage_file_share_and_backup_item',FILES_CHECK,files_case('good'),{})])
def test_shared_call_budget_and_no_secret_or_mutating_endpoints(kind,check,mapping,options):
 api=Transport(mapping)
 s=collect([kind],api,max_calls=1,**options)
 assert verdict(s,check) in ('UNKNOWN','DENIED')
 assert len(api.calls)<=1
 assert not any(any(fragment.casefold() in url.casefold() for fragment in ('listKeys','listSecrets','appsettings','publish','invoke')) for url in api.calls)

@pytest.mark.parametrize('value',[{'requiredNodeIds':['node','node'],'maxHeartbeatAgeHours':24},
 {'requiredNodeIds':[{'passed':True}],'maxHeartbeatAgeHours':24},
 {'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':True},
 {'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24,'observations':{'passed':True}}])
def test_untrusted_dsc_policy_does_not_become_approval(value):
 assert verdict(collect(['automation_node'],Transport(node_case('good')),**policy(dscNodes=value)),NODE_CHECK)=='UNKNOWN'

@pytest.mark.parametrize('suffix',['..','%2e%2e','bad%2Fname','bad\\name','bad\x00name'])
def test_parent_identity_cannot_escape_selected_arm_path(suffix):
 m=node_case('good')
 m[SCOPE+'/providers/Microsoft.Automation/automationAccounts']['value'][0]['id']=ACCOUNT.rsplit('/',1)[0]+'/'+suffix
 api=Transport(m)
 assert verdict(collect(['automation_node'],api,**policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24})),NODE_CHECK) in ('UNKNOWN','DENIED')
 assert not any('/'+suffix+'/nodes' in url for url in api.calls)

def test_new_ssl_approval_preserves_existing_policy_namespaces_and_parameters(monkeypatch):
 from peaso.collectors import azure_swc
 monkeypatch.setattr(azure_swc,'owner_metadata',lambda *_:{'compliance_policy':{'status':'collected','scope':SCOPE,'observed_at':datetime.now(timezone.utc).isoformat(),'max_age_seconds':3600,'parameters':{'existingSqlPolicyParameter':123},'sw13':{'status':'collected','untouched':'baseline'}}})
 s=collect(['application_gateway_and_frontdoor'],Transport(gateway_case('good')),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))
 p=s['metadata']['compliance_policy']
 assert p['parameters']=={'existingSqlPolicyParameter':123,'approvedPredefinedSslPolicyName':'AppGwSslPolicy20220101'}
 assert p['sw13']=={'status':'collected','untouched':'baseline'}
 assert verdict(s,SSL_CHECK)=='PASS'


@pytest.mark.parametrize('scope',[None,1,[],{},True])
@pytest.mark.parametrize('check,kind,mapping,options',[(NODE_CHECK,'automation_node',node_case('good'),policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24})),(SSL_CHECK,'application_gateway_and_frontdoor',gateway_case('good'),policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))])
def test_malformed_scope_cannot_crash_collection(scope,check,kind,mapping,options):
 options=copy.deepcopy(options)
 options['compliance_parameters']['azure_arm_metadata']['scope']=scope
 assert verdict(collect([kind],Transport(mapping),**options),check)=='UNKNOWN'

@pytest.mark.parametrize('policy_id',['garbage',VAULT+'/backupPolicies/..',VAULT.replace('/vaults/vault','/vaults/other')+'/backupPolicies/policy',VAULT.replace(SCOPE,'/subscriptions/33333333-3333-3333-3333-333333333333')+'/backupPolicies/policy'])
def test_malformed_or_foreign_backup_policy_cannot_prove_protection(policy_id):
 m=files_case('good')
 m[VAULT+'/backupProtectedItems']['value'][0]['properties']['policyId']=policy_id
 assert verdict(collect(['storage_file_share_and_backup_item'],Transport(m)),FILES_CHECK)=='UNKNOWN'


@pytest.mark.parametrize('mode',['foreign','stale','denied','missing'])
def test_ssl_cannot_reauthorize_unrelated_existing_flat_policy(monkeypatch,mode):
 from peaso.collectors import azure_swc
 existing={'status':'collected','scope':SCOPE,'observed_at':datetime.now(timezone.utc).isoformat(),'max_age_seconds':3600,'parameters':{'unrelatedApproval':'keep'}}
 if mode=='foreign':existing['scope']='/subscriptions/33333333-3333-3333-3333-333333333333'
 if mode=='stale':existing['observed_at']=(datetime.now(timezone.utc)-timedelta(days=10)).isoformat()
 if mode=='denied':existing['status']='denied'
 if mode=='missing':existing={"parameters":existing['parameters']}
 monkeypatch.setattr(azure_swc,'owner_metadata',lambda *_:{'compliance_policy':copy.deepcopy(existing)})
 s=collect(['application_gateway_and_frontdoor'],Transport(gateway_case('good')),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))
 p=s['metadata']['compliance_policy']
 for key in ('status','scope','observed_at','max_age_seconds'):
  assert p.get(key)==existing.get(key)
 assert p['parameters']['unrelatedApproval']=='keep'
 assert verdict(s,SSL_CHECK)=='UNKNOWN'

@pytest.mark.parametrize('status',['collected','denied'])
def test_dsc_policy_merge_preserves_namespace_and_authority(monkeypatch,status):
 from peaso.collectors import azure_swc
 monkeypatch.setattr(azure_swc,'owner_metadata',lambda *_:{'compliance_policy':{'sw27':{'status':status,'unrelatedBaseline':{'keep':True}}}})
 s=collect(['automation_node'],Transport(node_case('good')),**policy(dscNodes={'requiredNodeIds':['native-node-id'],'maxHeartbeatAgeHours':24}))
 assert s['metadata']['compliance_policy']['sw27']['unrelatedBaseline']=={'keep':True}
 assert s['metadata']['compliance_policy']['sw27']['status']==status
 assert verdict(s,NODE_CHECK)==('PASS'if status=='collected'else'UNKNOWN')


@pytest.mark.parametrize('conflict',[False,True])
def test_paged_same_backup_id_preserves_conflict_instead_of_false_protected(conflict):
 m=files_case('good');first=m[VAULT+'/backupProtectedItems']['value'][0]
 second=copy.deepcopy(first)
 if conflict:second['properties']['protectionState']='ProtectionStopped'
 m[VAULT+'/backupProtectedItems']=lambda q:{'value':[second]}if 'page'in q else {'value':[first],'nextLink':azure.ARM+VAULT+'/backupProtectedItems?page=2'}
 assert verdict(collect(['storage_file_share_and_backup_item'],Transport(m)),FILES_CHECK)==('UNKNOWN'if conflict else'PASS')


@pytest.mark.parametrize('status',['denied','collected'])
def test_status_only_existing_policy_is_not_given_scope_or_freshness(monkeypatch,status):
 from peaso.collectors import azure_swc
 monkeypatch.setattr(azure_swc,'owner_metadata',lambda *_:{'compliance_policy':{'status':status}})
 s=collect(['application_gateway_and_frontdoor'],Transport(gateway_case('good')),**policy(approvedPredefinedSslPolicyName='AppGwSslPolicy20220101'))
 p=s['metadata']['compliance_policy']
 assert p['status']==status
 assert all(key not in p for key in ('scope','observed_at','max_age_seconds'))
 assert verdict(s,SSL_CHECK)=='UNKNOWN'
