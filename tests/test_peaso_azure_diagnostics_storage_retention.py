# Historical fixture contracts; current native admission is tested separately.
"""Two frozen diagnostics contracts over actual ARM service/table response shapes."""
import copy,json
import pytest
from peaso.collectors import azure,collect_live
from peaso.collectors.azure_resource_logging_policy import normalize,CHECK
from peaso.collectors.azure_resource_diagnostics_native import CHECK as ROUTES,STORAGE_SERVICES
from tests.archived_check_contract import evaluate_snapshot, plan_collection
from tests.test_peaso_azure_bulk_native import Transport,SUB,SCOPE,BASE,parent
KV=BASE+'Microsoft.KeyVault/vaults/vault'
ACCOUNT=BASE+'Microsoft.Storage/storageAccounts/account'
WORKSPACE=BASE+'Microsoft.OperationalInsights/workspaces/workspace'
LIST=SCOPE+'/resources'

def fixture(mode='good',service=None):
 rid=ACCOUNT+'/'+service+'/default'if service else KV
 r={LIST:{'value':[parent(ACCOUNT if service else KV,'Microsoft.Storage/storageAccounts'if service else'Microsoft.KeyVault/vaults',{})]},WORKSPACE:parent(WORKSPACE,'Microsoft.OperationalInsights/workspaces',{})}
 category='StorageRead'if service else'AuditEvent';table=STORAGE_SERVICES[service]if service else'AzureDiagnostics'
 cpath=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories';spath=rid+'/providers/Microsoft.Insights/diagnosticSettings';tid=WORKSPACE+'/tables/'+table
 cat={'id':cpath+'/'+category,'name':category,'properties':{'categoryType':'Logs','categoryGroups':['allLogs','audit']}}
 props={'logs':[{'category':category,'enabled':True}],'workspaceId':WORKSPACE}
 if service:props['logAnalyticsDestinationType']='Dedicated'
 setting=parent(spath+'/route','Microsoft.Insights/diagnosticSettings',props)
 r.update({cpath:{'value':[cat]},spath:{'value':[setting]},setting['id']:copy.deepcopy(setting),tid:{'id':tid,'name':table,'properties':{'provisioningState':'Succeeded','plan':'Analytics','retentionInDays':30,'totalRetentionInDays':90,'archiveRetentionInDays':60,'retentionInDaysAsDefault':True}}})
 if service:
  account=parent(ACCOUNT,'Microsoft.Storage/storageAccounts',{});account['kind']='StorageV2';r[ACCOUNT]=account
  r[ACCOUNT+'/providers/Microsoft.Insights/diagnosticSettingsCategories']={'value':[]}
  for segment in STORAGE_SERVICES:r[ACCOUNT+'/'+segment]={'value':[parent(rid,'Microsoft.Storage/storageAccounts/'+segment,{})]if segment==service else[]}
 if mode=='group':props['logs']=[{'categoryGroup':'allLogs','enabled':True}]
 if mode=='disabled':props['logs'][0]['enabled']=False
 if mode=='no_settings':r[spath]={'value':[]}
 if mode=='short':r[tid]['properties'].update(totalRetentionInDays=30,archiveRetentionInDays=0)
 if mode=='missing_total':r[tid]['properties'].pop('totalRetentionInDays')
 if mode=='inherit_marker':r[tid]['properties']['retentionInDays']=-1
 if mode=='zero_total':r[tid]['properties']['totalRetentionInDays']=0
 if mode=='bool_total':r[tid]['properties']['totalRetentionInDays']=True
 if mode=='archive_bool':r[tid]['properties'].update(totalRetentionInDays=30,archiveRetentionInDays=False)
 if mode=='archive_conflict':r[tid]['properties']['archiveRetentionInDays']=1
 if mode=='table_updating':r[tid]['properties']['provisioningState']='Updating'
 if mode=='foreign_table':r[tid]['id']=tid+'foreign'
 if mode=='foreign_table_name':r[tid]['name']='unrelated'
 if mode=='table_denied':r[tid]=azure.AzureReadError('forbidden',403)
 if mode=='table_missing':r[tid]=azure.AzureReadError('ResourceNotFound',404)
 if mode=='dedicated_unmapped':props['logAnalyticsDestinationType']='Dedicated';cat['name']='FutureCategory';cat['id']=cpath+'/FutureCategory';props['logs'][0]['category']='FutureCategory';category='FutureCategory'
 if mode=='wrong_service_mode':props['logAnalyticsDestinationType']='future'
 if mode=='get_denied':r[setting['id']]=azure.AzureReadError('forbidden',403)
 if mode=='get_foreign':r[setting['id']]['id']=setting['id']+'foreign'
 if mode=='get_changed':r[setting['id']]['properties']['logs'][0]['enabled']=False
 if mode=='service_denied':r[ACCOUNT+'/'+service]=azure.AzureReadError('forbidden',403)
 if mode=='service_foreign':r[ACCOUNT+'/'+service]['value'][0]['id']=rid.replace('/account/','/foreign/')
 if mode=='service_duplicate':r[ACCOUNT+'/'+service]['value']*=2
 if mode=='account_foreign':r[ACCOUNT]['id']=ACCOUNT+'foreign'
 if mode=='account_kind_unknown':r[ACCOUNT]['kind']='FutureStorage'
 if mode in('service_second_page','service_partial','service_page_limit'):
  rows=copy.deepcopy(r[ACCOUNT+'/'+service]['value']);path=ACCOUNT+'/'+service
  r[path]=lambda q:({'value':rows}if mode!='service_partial'else azure.AzureReadError('forbidden',403))if'page'in q else{'value':[],'nextLink':azure.ARM+path+'?page=2'}
 # LIST and GET are independent API observations; reproduce the exact native
 # representation unless this case deliberately introduces drift/denial.
 if mode not in ('get_denied','get_foreign','get_changed'):r[setting['id']]=copy.deepcopy(setting)
 policy={'scope':SCOPE,'status':'collected','resources':[{'resourceId':rid,'requiredCategories':[category],'requiredCategoryGroups':[],'approvedSinkIds':[WORKSPACE],'minRetentionDays':60}]}
 if mode=='group_policy':policy['resources'][0].update(requiredCategories=[],requiredCategoryGroups=['audit'])
 if mode=='foreign_policy_resource':policy['resources'][0]['resourceId']=KV+'foreign'
 if mode=='foreign_approved_sink':policy['resources'][0]['approvedSinkIds']=[WORKSPACE+'foreign']
 return r,policy,rid

class API(Transport):
 def request(self,url,*,body=None,audience=azure.ARM):
  assert body is None and audience==azure.ARM
  return super().request(url,body=body,audience=audience)

def capture(mode='good',service=None,which=(CHECK,ROUTES)):
 r,policy,rid=fixture(mode,service);api=API(r)
 options={'retries':0,'max_pages':1 if mode=='service_page_limit'else 5}
 if mode!='no_policy':options['compliance_parameters']={'azure_resource_logging':policy}
 connector={'provider':'azure','scopes':[SUB],'options':options}
 kinds=plan_collection({'connector':connector,'checks':list(which)})
 snapshot=azure.collect(connector,kinds,transport=api)
 findings=evaluate_snapshot(snapshot,checks=list(which),include_not_applicable=True)['findings']
 return {x['check_id']:x['status']for x in findings},snapshot,api

@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('group','PASS'),('group_policy','PASS'),('short','FAIL'),('disabled','FAIL'),('no_settings','FAIL'),
 ('missing_total','UNKNOWN'),('inherit_marker','UNKNOWN'),('zero_total','UNKNOWN'),('bool_total','UNKNOWN'),('archive_conflict','UNKNOWN'),('archive_bool','UNKNOWN'),('table_updating','UNKNOWN'),('foreign_table','UNKNOWN'),('foreign_table_name','UNKNOWN'),('table_denied','UNKNOWN'),('table_missing','UNKNOWN'),('dedicated_unmapped','UNKNOWN'),('wrong_service_mode','UNKNOWN'),('get_denied','UNKNOWN'),('get_foreign','UNKNOWN'),('get_changed','UNKNOWN'),('no_policy','UNKNOWN'),('foreign_policy_resource','UNKNOWN'),('foreign_approved_sink','FAIL')])
def test_keyvault_routes_and_actual_total_table_retention(mode,expected):
 statuses,snapshot,api=capture(mode)
 assert statuses[CHECK]==expected,statuses
 assert statuses[ROUTES]==('FAIL'if mode in ('disabled','no_settings')else'PASS'),statuses
 assert not any('query'in url.lower()or'listkeys'in url.lower()for url in api.calls)

@pytest.mark.parametrize('service',list(STORAGE_SERVICES))
@pytest.mark.parametrize('mode,expected',[
 ('good','PASS'),('group','PASS'),('short','FAIL'),('service_second_page','PASS'),('service_partial','DENIED'),('service_page_limit','UNKNOWN'),('service_denied','DENIED'),('service_foreign','UNKNOWN'),('service_duplicate','UNKNOWN'),('account_foreign','UNKNOWN'),('account_kind_unknown','UNKNOWN'),('table_denied','UNKNOWN')])
def test_four_storage_services_native_list_category_and_dedicated_table(service,mode,expected):
 statuses,snapshot,api=capture(mode,service)
 assert statuses[CHECK]==expected,statuses
 assert statuses[ROUTES]==('PASS'if mode in ('good','group','short','service_second_page','table_denied')else expected),statuses
 assert all(any('/'+segment+'?'in url for url in api.calls)for segment in STORAGE_SERVICES)if mode in ('good','group','short','table_denied')else True

@pytest.mark.parametrize('mutation',['null','observation','foreign_scope','bad_minimum','duplicate','unknown_field','foreign_sink_scope','resource_control','resource_traversal'])
def test_only_normative_owner_inputs_allowed(mutation):
 _,policy,_=fixture();options={'compliance_parameters':{'azure_resource_logging':policy}}
 if mutation=='null':options['compliance_parameters']['azure_resource_logging']=None
 if mutation=='observation':policy['resources'][0]['retentionEvidence']=[]
 if mutation=='foreign_scope':policy['scope']='foreign'
 if mutation=='bad_minimum':policy['resources'][0]['minRetentionDays']=True
 if mutation=='duplicate':policy['resources']*=2
 if mutation=='unknown_field':policy['native_verified']=True
 if mutation=='resource_control':policy['resources'][0]['resourceId']=KV+'\x00'
 if mutation=='resource_traversal':policy['resources'][0]['resourceId']=KV+'/../vault'
 if mutation=='foreign_sink_scope':policy['resources'][0]['approvedSinkIds']=[WORKSPACE.replace(SUB,'99999999-9999-9999-9999-999999999999')]
 with pytest.raises(ValueError):normalize(options)

def test_unrequested_retention_does_not_issue_table_or_setting_gets():
 statuses,snapshot,api=capture(which=(ROUTES,))
 assert statuses=={ROUTES:'PASS'}
 assert not any('/tables/'in url or '/diagnosticSettings/route?'in url for url in api.calls)


def test_policy_normalizer_copy_scope_and_existing_namespace_authority():
 r,policy,_=fixture()
 options={'retries':0,'compliance_parameters':{'azure_resource_logging':policy},'compliance_policy':{'sw16':{'status':'denied','scope':SCOPE,'unrelated_control':{'approved':False}}}}
 from peaso.collectors.azure_resource_logging_policy import owner_policy
 normalized=normalize(options);normalized['resources'][0]['minRetentionDays']=1
 assert policy['resources'][0]['minRetentionDays']==60
 with pytest.raises(ValueError):owner_policy(options,['/subscriptions/99999999-9999-9999-9999-999999999999'])
 snapshot=azure.collect({'provider':'azure','scopes':[SUB],'options':options},['azure_diagnostic_eligible_resource'],transport=API(r))
 sw16=snapshot['metadata']['compliance_policy']['sw16']
 assert sw16['status']=='denied' and sw16['scope']==SCOPE and sw16['unrelated_control']=={'approved':False}
 assert sw16[CHECK]==policy


def test_no_secret_or_log_payload_projected():
 r,policy,_=fixture();marker='DO_NOT_RETAIN_DIAGNOSTIC_PAYLOAD'
 r[WORKSPACE+'/tables/AzureDiagnostics']['properties']['searchResults']={'query':marker}
 r[KV+'/providers/Microsoft.Insights/diagnosticSettings/route']['properties']['arbitrary']=marker
 snapshot=azure.collect({'provider':'azure','scopes':[SUB],'options':{'retries':0,'compliance_parameters':{'azure_resource_logging':policy}}},['azure_diagnostic_eligible_resource'],transport=API(r))
 assert marker not in json.dumps(snapshot)


def test_empty_complete_universe_is_not_applicable_without_owner_policy():
 api=API({LIST:{'value':[]}})
 snapshot=azure.collect({'provider':'azure','scopes':[SUB],'options':{'retries':0}},['azure_diagnostic_eligible_resource'],transport=api)
 assert evaluate_snapshot(snapshot,checks=[CHECK],include_not_applicable=True)['findings'][0]['status']=='NOT_APPLICABLE'
