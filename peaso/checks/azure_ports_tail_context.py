"""Context-sensitive tail checks require explicit captured metadata, never safe defaults."""
import ipaddress,re
from datetime import datetime,timedelta
from . import register,result
from .facts import get,optional,list_of_objects,complete_items,Unavailable
from .fixtures import CASES,nest
from .azure_ports_app_variants import applicable
from .azure_ports_directory import _tenant
from .azure_ports_defender import _scope_rows,_non_subscription,_fixture
from .azure_ports_sql import SERVER,_children,_server
CHECK_IDS=[];SOURCE_QUERIES={}


def port(query,kind,title,target='resource',deps=None):
    cid='azure.port.'+query;CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    return register(cid,'azure','hardening',kind,title,'medium','CM-6','Review captured metadata and explicit provider context; no secrets, app settings, workload requests, configurations or grants are fetched or changed.',target=target,dependencies=deps or [kind])


for _query,_selector in [('appservice_api_app_uses_managed_identity','api'),('appservice_function_app_uses_managed_identity','function_prefix'),('appservice_web_app_uses_managed_identity','app')]:
    def _legacy_identity(query,selector):
        @port(query,'app_service','Source-selected site declares at least one legacy managed identity ID field')
        def evaluate(item,index):
            if not applicable(item,selector):return 'NOT_APPLICABLE',{'reason':'Outside exact source table/kind selector'}
            config=get(item,'configuration.properties',dict);ids=[get(config,key) for key in ('xManagedServiceIdentityId','managedServiceIdentityId')]
            if any(value is not None and type(value) is not int for value in ids):raise Unavailable('Malformed legacy identity ID')
            return result(all(value is None for value in ids),legacy_id_declared=any(value is not None for value in ids),semantics='Literal non-null integer configuration ID declaration; current identity.type/principal grants and actual authentication are separate')
        kind='api' if selector=='api' else 'functionapp' if selector=='function_prefix' else 'app'
        def fixture(value):return {'kind':kind,'configuration':{'properties':{'managedServiceIdentityId':value,'xManagedServiceIdentityId':None}}}
        CASES[SOURCE_QUERIES[query]]={'pass':fixture(1),'fail':fixture(None)}
    _legacy_identity(_query,_selector)


@port('appservice_web_app_worker_more_than_one','app_service','Plan-associated App Service declares more than one worker',deps=['app_service','app_service_plan'])
def workers(item,index):
    plan=get(item,'properties.serverFarmId',str)
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Web/serverfarms/[^/]+',plan,re.I):raise Unavailable('Malformed App Service plan identity')
    matches=[row for row in complete_items(index,'app_service_plan') if get(row,'id',str).casefold()==plan.casefold()]
    if len(matches)!=1:raise Unavailable('Plan association missing or ambiguous')
    count=get(item,'configuration.properties.numberOfWorkers',int)
    if count<0:raise Unavailable('Malformed worker count')
    return result(count<=1,worker_count=count,plan_id=plan,semantics='Source app row associated with exact plan; per-app configured workers, not available capacity or plan SKU capacity')
_PLAN='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Web/serverfarms/plan'
_idx={'app_service_plan':[{'data':{'id':_PLAN}}],'collections':{'app_service_plan':[{'status':'collected','scope':'/subscriptions/sub'}]}}
CASES[SOURCE_QUERIES['appservice_web_app_worker_more_than_one']]={'pass':{'properties':{'serverFarmId':_PLAN},**nest('configuration.properties.numberOfWorkers',2)},'fail':{'properties':{'serverFarmId':_PLAN},**nest('configuration.properties.numberOfWorkers',1)},'pass_index':_idx,'fail_index':_idx}


@port('appservice_web_app_use_virtual_service_endpoint','app_service','Selected web site declares the configured VNet connection resource ID')
def web_vnet(item,index):
    if not applicable(item,'web'):return 'NOT_APPLICABLE',{'reason':'Outside source web table'}
    name=get(item,'configuration.properties.vnetName')
    if name is None or name=='':return result(True,configured_vnet=False,semantics='Known unconfigured VNet name, no inferred connection')
    if not isinstance(name,str):raise Unavailable('Malformed configured VNet name')
    matches=[row for row in list_of_objects(get(item,'vnetConnections',list)) if get(row,'name',str)==name]
    if len(matches)!=1:raise Unavailable('Configured VNet connection missing or ambiguous')
    vnet=get(matches[0],'properties.vnetResourceId')
    if vnet is None:return result(True,configured_vnet=False)
    if not isinstance(vnet,str) or not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+',vnet,re.I):raise Unavailable('Malformed VNet connection ARM ID')
    return result(False,declared_vnet_id=vnet,semantics='Legacy connection declaration; subnet service endpoints and effective outbound route enforcement are separate')
_VNET='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Network/virtualNetworks/vnet'
CASES[SOURCE_QUERIES['appservice_web_app_use_virtual_service_endpoint']]={'pass':{'kind':'app',**nest('configuration.properties.vnetName','vnet'),'vnetConnections':[{'name':'vnet','properties':{'vnetResourceId':_VNET}}]},'fail':{'kind':'app',**nest('configuration.properties.vnetName',None)}}


@port('ad_disabled_user_no_role_assignments','directory_user','Disabled directory user has no declared ARM role assignment in captured scopes',deps=['directory_user','role_assignment'])
def disabled_user(item,index):
    tenant=_tenant(item,index)
    if get(item,'accountEnabled',bool):return 'NOT_APPLICABLE',{'reason':'Source skips enabled users'}
    uid=get(item,'id',str);matches=[]
    for assignment in complete_items(index,'role_assignment'):
        if _tenant(assignment,{'context':{'metadata':{'tenant_id':tenant}}})!=tenant:raise Unavailable('Foreign tenant ARM role metadata')
        if get(assignment,'properties.principalId',str)==uid:matches.append(get(assignment,'id',str))
    return result(bool(matches),assignment_ids=matches,tenant_id=tenant,semantics='Declared assignments within captured complete scopes only; no claim about inaccessible scopes, conditions, group membership or effective permissions')
_UID='user';_ASSIGN={'id':'/subscriptions/sub/providers/Microsoft.Authorization/roleAssignments/assignment','properties':{'principalId':_UID},'_provenance':{'tenant_id':'tenant'}}
CASES[SOURCE_QUERIES['ad_disabled_user_no_role_assignments']]={'pass':{'id':_UID,'accountEnabled':False,'_provenance':{'tenant_id':'tenant'}},'fail':{'id':_UID,'accountEnabled':False,'_provenance':{'tenant_id':'tenant'}},'pass_index':_fixture('role_assignment',[],'empty'),'fail_index':_fixture('role_assignment',[_ASSIGN])}


for _query,_field in [('sql_server_va_setting_periodic_scan_enabled','isEnabled'),('sql_server_va_setting_reports_notify_admins','emailSubscriptionAdmins'),('sql_server_va_setting_scan_reports_configured','emails')]:
    def _classic_va(query,field):
        @port(query,'sql_server','Legacy SQL VA conditional baseline: '+field)
        def evaluate(item,index):
            policies=_children(item,'securityAlertPolicies','securityAlertPolicies');rid=_server(item)
            if not policies:raise Unavailable('Required security-alert configuration empty')
            va=get(item,'vulnerabilityAssessment',dict)
            if get(va,'id',str).casefold()!=(rid+'/vulnerabilityAssessments/default').casefold():raise Unavailable('Foreign SQL VA metadata')
            path=get(va,'properties.storageContainerPath')
            if path is not None and not isinstance(path,str):raise Unavailable('Malformed legacy storage path')
            bad=[]
            for policy in policies:
                state=get(policy,'properties.state',str)
                if state not in ('Enabled','Disabled'):raise Unavailable('Unknown security-alert state')
                if state=='Disabled':bad.append(policy['id']);continue
                if path is None:
                    # Null legacy storage is safe only with actual known express
                    # mode; otherwise required enabled VA context is unavailable.
                    if get(item,'expressVulnerabilityAssessment.properties.state',str)!='Enabled':raise Unavailable('VA applicability/context not established')
                    continue
                value=get(va,'properties.recurringScans.'+field,list if field=='emails' else bool)
                if field=='emails' and any(not isinstance(v,str) for v in value):raise Unavailable('Malformed VA recipients')
                if not value:bad.append(policy['id'])
            return result(bool(bad),matching_policy_ids=bad,semantics='Exact legacy conditional flag/list baseline after known VA mode; express mode never fabricates legacy email/periodic flags or scalar-empty success')
        props={'storageContainerPath':'https://storage.invalid/container','recurringScans':{'isEnabled':True,'emailSubscriptionAdmins':True,'emails':['security@example.invalid']}}
        good={'id':SERVER,'securityAlertPolicies':[{'id':SERVER+'/securityAlertPolicies/Default','properties':{'state':'Enabled'}}],'vulnerabilityAssessment':{'id':SERVER+'/vulnerabilityAssessments/default','properties':props}}
        import copy
        bad=copy.deepcopy(good);bad['vulnerabilityAssessment']['properties']['recurringScans'][field]=[] if field=='emails' else False
        CASES[SOURCE_QUERIES[query]]={'pass':good,'fail':bad}
    _classic_va(_query,_field)


for _language,_baseline in [('java','17'),('php','8.2'),('python','3.12')]:
    def _runtime(language,baseline):
        query='app_ensure_'+language+'_version_is_latest'
        @port(query,'app_service','App-prefixed site meets pinned '+language+' runtime literal baseline '+baseline)
        def evaluate(item,index):
            if not get(item,'kind',str).startswith('app'):return 'NOT_APPLICABLE',{'reason':'Pinned Prowler app-prefix scope'}
            config=get(item,'configuration.properties',dict);fx=get(config,'linuxFxVersion',str);version=get(config,language+'Version')
            if version is not None and not isinstance(version,str):raise Unavailable('Malformed runtime version')
            if language not in fx.lower() and not version:return 'NOT_APPLICABLE',{'reason':'Known source language not in use'}
            wanted=(index.get('context',{}).get('metadata',{}).get('audit_config',{}) or {}).get(language+'_latest_version',baseline)
            if not isinstance(wanted,str) or not re.fullmatch(r'\d+(?:\.\d+)*',wanted):raise Unavailable('Malformed captured runtime baseline')
            good=(('java'+wanted) in fx if language=='java' else wanted in fx) or wanted==version
            return result(not good,pinned_baseline=wanted,semantics='Literal source substring/exact-version baseline; not current latest or supported-lifecycle guarantee')
        def fixture(version):return {'kind':'app','configuration':{'properties':{'linuxFxVersion':language.upper()+'|'+version+('-java'+version if language=='java' else ''),language+'Version':None}}}
        CASES[SOURCE_QUERIES[query]]={'pass':fixture(baseline),'fail':fixture('0.0')}
    _runtime(_language,_baseline)


@port('app_function_application_insights_enabled','app_service','Function has captured presence evidence for an Application Insights setting')
def instrumentation(item,index):
    if not get(item,'kind',str).startswith('functionapp'):return 'NOT_APPLICABLE',{'reason':'Pinned function-prefix selector'}
    metadata=get(item,'appSettingsMetadata',dict)
    flags=[get(metadata,key,bool) for key in ('APPINSIGHTS_INSTRUMENTATIONKEY_nonempty','APPLICATIONINSIGHTS_CONNECTION_STRING_nonempty')]
    return result(not any(flags),telemetry_setting_present=any(flags),semantics='Captured nonempty-presence booleans only; collector never requests secret-bearing application settings and delivery is not tested')
CASES[SOURCE_QUERIES['app_function_application_insights_enabled']]={'pass':{'kind':'functionapp','appSettingsMetadata':{'APPINSIGHTS_INSTRUMENTATIONKEY_nonempty':True,'APPLICATIONINSIGHTS_CONNECTION_STRING_nonempty':False}},'fail':{'kind':'functionapp','appSettingsMetadata':{'APPINSIGHTS_INSTRUMENTATIONKEY_nonempty':False,'APPLICATIONINSIGHTS_CONNECTION_STRING_nonempty':False}}}


@port('app_function_latest_runtime_version','app_service','Function captured nonsecret extension version metadata equals ~4')
def extension_version(item,index):
    if not get(item,'kind',str).startswith('functionapp'):return 'NOT_APPLICABLE',{'reason':'Pinned function-prefix selector'}
    version=get(item,'appSettingsMetadata.FUNCTIONS_EXTENSION_VERSION',str)
    return result(version!='~4',extension_version=version,semantics='Captured nonsecret field only; native collector never requests appsettings/list and absence is UNKNOWN')
CASES[SOURCE_QUERIES['app_function_latest_runtime_version']]={'pass':{'kind':'functionapp',**nest('appSettingsMetadata.FUNCTIONS_EXTENSION_VERSION','~4')},'fail':{'kind':'functionapp',**nest('appSettingsMetadata.FUNCTIONS_EXTENSION_VERSION','~3')}}


@port('security_center_attack_path_alerts_enabled','security_setting','AttackPath setting and selected subscription legacy alert notifications are enabled',target='scope',deps=['security_setting','security_contact'])
def attack_path(item,index):
    if _non_subscription(item):return 'NOT_APPLICABLE',{'reason':'Required setting is subscription-scoped'}
    scope=get(item,'scope',str)
    matches=[row for row in _scope_rows(item,index,'security_setting') if get(row,'name',str)=='AttackPath']
    if len(matches)!=1:raise Unavailable('Required legacy AttackPath setting missing/ambiguous; current native API applicability unproven')
    enabled=get(matches[0],'properties.enabled',bool)
    notifications=[]
    for contact in _scope_rows(item,index,'security_contact'):
        state=get(contact,'properties.alertNotifications.state',str)
        if state not in ('On','Off'):raise Unavailable('Legacy notification state unavailable/unknown')
        notifications.append(state)
    return result(not(enabled and 'On' in notifications),setting_enabled=enabled,scope=scope,setting_id=matches[0]['id'],semantics='Exact legacy setting/contact conjunction on known applicable configuration; current notification-source risk thresholds remain separate and required setting absence is UNKNOWN')
_SETTING='/subscriptions/sub/providers/Microsoft.Security/settings/AttackPath';_CONTACT='/subscriptions/sub/providers/Microsoft.Security/securityContacts/default'
def _attack(enabled):
    setting=_fixture('security_setting',[{'id':_SETTING,'name':'AttackPath','properties':{'enabled':enabled}}])
    contacts=_fixture('security_contact',[{'id':_CONTACT,'properties':{'alertNotifications':{'state':'On'}}}])
    return {'security_setting':setting['security_setting'],'security_contact':contacts['security_contact'],'collections':{**setting['collections'],**contacts['collections']}}
CASES[SOURCE_QUERIES['security_center_attack_path_alerts_enabled']]={'pass':{'scope':'/subscriptions/sub'},'fail':{'scope':'/subscriptions/sub'},'pass_index':_attack(True),'fail_index':_attack(False)}
