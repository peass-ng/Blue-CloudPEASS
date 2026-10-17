"""Monitor source metadata keeps literal categories and named-container applicability."""
from . import register,result
from .facts import get,list_of_objects,optional,Unavailable
from .fixtures import CASES
from .azure_ports_defender import _scope_rows,_non_subscription,_fixture

CHECK_IDS=[]
SOURCE_QUERIES={}


def port(query,kind,title,target='resource',deps=None):
    cid='azure.port.'+query
    CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    return register(cid,'azure','hardening',kind,title,'medium','AU-12','Review the declared logging/storage metadata; no logs, keys, blob contents or delivery probes are read.',target=target,dependencies=deps or [kind])


for _query,_kind in [('monitor_application_insights_configured','application_insights'),('monitor_diagnostic_settings_exists_for_subscription','subscription_diagnostic_setting')]:
    def _presence(query,kind):
        @port(query,kind,'Selected subscription has at least one '+kind+' declaration','scope',[kind])
        def evaluate(item,index):
            if _non_subscription(item):return 'NOT_APPLICABLE',{'reason':'Required sourcepresence is subscription-scoped'}
            rows=_scope_rows(item,index,kind)
            return result(not rows,declared_count=len(rows),semantics='Presence only; enabledtelemetry/logdelivery/actualexportcategories remainseparate')
        rid='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Insights/components/app' if kind=='application_insights' else '/subscriptions/sub/providers/Microsoft.Insights/diagnosticSettings/log'
        CASES[SOURCE_QUERIES[query]]={'pass':{'scope':'/subscriptions/sub'},'fail':{'scope':'/subscriptions/sub'},'pass_index':_fixture(kind,[{'id':rid}]),'fail_index':_fixture(kind,[],'empty')}
    _presence(_query,_kind)


@port('monitor_diagnostic_settings_captures_proper_categories','subscription_diagnostic_setting','Subscription diagnosticsetting explicitly enables four required literal categories')
def categories(item,index):
    logs=list_of_objects(get(item,'properties.logs',list));wanted={'Administrative','Security','Alert','Policy'};found=[]
    for log in logs:
        enabled=get(log,'enabled',bool);category=optional(log,'category',None)
        if category is not None and not isinstance(category,str):raise Unavailable('Malformed activity-log category')
        if enabled and category in wanted:found.append(category)
    if len(found)!=len(set(found)):raise Unavailable('Duplicate category metadata cannot establish distinct required categories')
    return result(len(found)!=4,categories=sorted(found),semantics='Exact pinnedliteral count after uniqueprovidercategory validation; categoryGroup-only differs')
CASES[SOURCE_QUERIES['monitor_diagnostic_settings_captures_proper_categories']]={'pass':{'properties':{'logs':[{'category':x,'enabled':True} for x in ('Administrative','Security','Alert','Policy')]}},'fail':{'properties':{'logs':[{'category':'Administrative','enabled':True}]}}}


for _prefix,_name in [('activity','insights-activity-logs'),('operational','insights-operational-logs')]:
    def _named_container(prefix,name):
        query='monitor_logs_storage_container_insights_'+prefix+'_logs_not_public_accessible'
        @port(query,'storage_container','Named '+name+' container declares publicaccessNone')
        def evaluate(item,index):
            if get(item,'name',str)!=name:return 'NOT_APPLICABLE',{'reason':'Pinnednamed-containerselector excludes this container'}
            access=get(item,'properties.publicAccess',str)
            if access not in ('None','Blob','Container'):raise Unavailable('Unrecognized blobcontainer publicaccess')
            return result(access!='None',public_access=access,semantics='Container accessleveldeclaration only; parentaccount/publicnetwork/authorization separate')
        CASES[SOURCE_QUERIES[query]]={'pass':{'name':name,'properties':{'publicAccess':'None'}},'fail':{'name':name,'properties':{'publicAccess':'Container'}}}
    _named_container(_prefix,_name)


for _prefix,_name in [('activity','insights-activity-logs'),('operational','insights-operational-logs')]:
    def _named_cmk(prefix,name):
        query='monitor_logs_storage_container_insights_'+prefix+'_logs_encrypted_with_byok'
        @port(query,'storage_account','Account with '+name+' container selects KeyVault keysource')
        def evaluate(item,index):
            rows=list_of_objects(get(item,'blobContainers',list))
            matches=[row for row in rows if get(row,'name',str)==name]
            if not matches:return 'NOT_APPLICABLE',{'reason':'Knowncomplete namedcontainerabsence excluded bysourceWHERE'}
            rid=get(item,'id',str)
            for row in matches:
                if not get(row,'id',str).casefold().startswith((rid+'/blobServices/default/containers/').casefold()):raise Unavailable('Foreign namedcontainer metadata')
            source=get(item,'properties.encryption.keySource',str)
            if source not in ('Microsoft.Storage','Microsoft.Keyvault','Microsoft.KeyVault'):raise Unavailable('Unrecognized storagekeysource')
            return result(source!='Microsoft.Keyvault',key_source=source,semantics='Exact sourcecaseKeyvault declaration; unknownprovidercase variants not broadlymerged; no keyvalue/telemetrydelivery claim')
        account='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Storage/storageAccounts/account';container={'id':account+'/blobServices/default/containers/'+name,'name':name}
        CASES[SOURCE_QUERIES[query]]={'pass':{'id':account,'blobContainers':[container],'properties':{'encryption':{'keySource':'Microsoft.Keyvault'}}},'fail':{'id':account,'blobContainers':[container],'properties':{'encryption':{'keySource':'Microsoft.Storage'}}}}
    _named_cmk(_prefix,_name)
