"""Reviewed tail predicates: authoritative joins and explicit metadata-only fact needs."""
import re
from . import register,result
from .facts import get,optional,list_of_objects,complete_items,Unavailable
from .fixtures import CASES,nest
from .azure_ports_defender import _scope_rows,_non_subscription,_fixture
from .azure_ports_app_variants import applicable
from .azure_ports_directory import _tenant
CHECK_IDS=[];SOURCE_QUERIES={'aisearch_service_not_publicly_accessible':'azure.port.search_service_public_network_access_disabled','appinsights_ensure_is_configured':'azure.port.monitor_application_insights_configured'}


def port(query,kind,title,target='resource',deps=None):
    cid='azure.port.'+query;CHECK_IDS.append(cid);SOURCE_QUERIES[query]=cid
    return register(cid,'azure','hardening',kind,title,'medium','CM-6','Review captured declarations, native constraints and completeness; no workload execution, probes, changes, values or remediation are performed.',target=target,dependencies=deps or [kind])


@port('automation_account_variable_encryption_enabled','automation_variable','Automation variable declares encrypted storage')
def variable(item,index):return result(not get(item,'properties.isEncrypted',bool),semantics='Encryption flag only; variable value is excluded at collection')
CASES[SOURCE_QUERIES['automation_account_variable_encryption_enabled']]={'pass':nest('properties.isEncrypted',True),'fail':nest('properties.isEncrypted',False)}


@port('app_service_environment_internal_encryption_enabled','app_service_environment','App Service Environment declares InternalEncryption=true')
def ase(item,index):
    matches=[get(s,'value',str) for s in list_of_objects(get(item,'properties.clusterSettings',list)) if get(s,'name',str)=='InternalEncryption']
    if len(matches)>1:raise Unavailable('Ambiguous InternalEncryption declaration')
    return result('true' not in matches,semantics='Exact named cluster flag; implicit platform encryption/version guarantees are separate')
CASES[SOURCE_QUERIES['app_service_environment_internal_encryption_enabled']]={'pass':nest('properties.clusterSettings',[{'name':'InternalEncryption','value':'true'}]),'fail':nest('properties.clusterSettings',[])}


@port('databricks_workspace_cmk_configured','databricks_workspace','Databricks declares reviewed customerManagedKeyId parameter')
def databricks_cmk(item,index):
    params=get(item,'properties.parameters',dict)
    value=optional(params,'customerManagedKeyId',None)
    if 'customerManagedKeyId' in params and not isinstance(value,dict):raise Unavailable('Malformed legacy CMK parameter')
    return result(value is None,semantics='Pinned parameter-object presence; current managed-services/disk encryption properties and key access are separate')
CASES[SOURCE_QUERIES['databricks_workspace_cmk_configured']]={'pass':nest('properties.parameters.customerManagedKeyId',{'value':'key'}),'fail':nest('properties.parameters',{})}


@port('databricks_workspace_subnet_with_nsg_configured','databricks_workspace','Reviewed Databricks custom subnets declare NSG association',deps=['databricks_workspace','subnet'])
def databricks_subnets(item,index):
    params=get(item,'properties.parameters',dict)
    if 'customVirtualNetworkId' not in params:return 'NOT_APPLICABLE',{'reason':'Source excludes absent custom VNet parameter'}
    vnet=get(params,'customVirtualNetworkId.value',str)
    if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+',vnet,re.I):raise Unavailable('Malformed Databricks VNet identity')
    names=[]
    for field in ('customPrivateSubnetName','customPublicSubnetName'):
        if field not in params:continue
        name=get(params,field+'.value')
        if name is None:continue
        if not isinstance(name,str) or not name or '/' in name:raise Unavailable('Malformed Databricks subnet name')
        names.append(name)
    # SQL has no subnet rows for these absent/null parameters. Expose declaration
    # semantics; this is not proof that both required deployment subnets exist.
    rows=complete_items(index,'subnet');bad=[]
    for name in names:
        rid=vnet+'/subnets/'+name;matches=[r for r in rows if get(r,'id',str).casefold()==rid.casefold()]
        if len(matches)!=1:raise Unavailable('Databricks subnet missing or ambiguous')
        props=get(matches[0],'properties',dict);nsg=optional(props,'networkSecurityGroup',None)
        if nsg is None:bad.append(rid)
        elif not isinstance(nsg,dict) or not isinstance(nsg.get('id'),str):raise Unavailable('Malformed NSG association')
    return result(bool(bad),subnets_without_nsg=bad,semantics='Exact source-selected declared subnets and full ARM joins; no network enforcement assertion')
_VNET='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Network/virtualNetworks/vnet'
def _subnets(nsg):return {'subnet':[{'data':{'id':_VNET+'/subnets/private','properties':{'networkSecurityGroup':nsg}}}],'collections':{'subnet':[{'status':'collected','scope':'/subscriptions/sub'}]}}
CASES[SOURCE_QUERIES['databricks_workspace_subnet_with_nsg_configured']]={'pass':nest('properties.parameters',{'customVirtualNetworkId':{'value':_VNET},'customPrivateSubnetName':{'value':'private'}}),'fail':nest('properties.parameters',{'customVirtualNetworkId':{'value':_VNET},'customPrivateSubnetName':{'value':'private'}}),'pass_index':_subnets({'id':'/nsg'}),'fail_index':_subnets(None)}


@port('databricks_workspace_diagnostic_log_delivery_configured','databricks_workspace','Premium Databricks diagnostics explicitly declare all six source categories')
def databricks_logs(item,index):
    sku=get(item,'sku.name',str)
    if sku in ('standard','trial'):return 'NOT_APPLICABLE',{'reason':'Exact source SKU exclusion'}
    if sku!='premium':raise Unavailable('Unknown Databricks SKU')
    wanted={'clusters','accounts','jobs','notebook','workspace','sqlPermissions'};found=set();rid=get(item,'id',str)
    for setting in list_of_objects(get(item,'diagnosticSettings',list)):
        if not get(setting,'id',str).casefold().startswith((rid+'/providers/Microsoft.Insights/diagnosticSettings/').casefold()):raise Unavailable('Foreign Databricks diagnostic')
        for log in list_of_objects(get(setting,'properties.logs',list)):
            category=optional(log,'category',None)
            if category is not None and not isinstance(category,str):raise Unavailable('Malformed diagnostic category')
            if get(log,'enabled',bool) and category in wanted:found.add(category)
    return result(not wanted<=found,enabled_categories=sorted(found),semantics='Literal six categories across settings, not delivery, categoryGroup or sink validation')
_DB='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Databricks/workspaces/workspace'
CASES[SOURCE_QUERIES['databricks_workspace_diagnostic_log_delivery_configured']]={'pass':{'id':_DB,'sku':{'name':'premium'},'diagnosticSettings':[{'id':_DB+'/providers/Microsoft.Insights/diagnosticSettings/log','properties':{'logs':[{'category':c,'enabled':True} for c in ('clusters','accounts','jobs','notebook','workspace','sqlPermissions')]}}]},'fail':{'id':_DB,'sku':{'name':'premium'},'diagnosticSettings':[]}}


@port('network_virtual_network_gateway_aad_only','virtual_network_gateway','VPN authentication type list declares only AAD')
def vpn(item,index):
    types=get(item,'properties.vpnClientConfiguration.vpnAuthenticationTypes',list)
    if any(t not in ('AAD','Certificate','Radius') for t in types):raise Unavailable('Malformed or unknown VPN auth type')
    if not types:return 'NOT_APPLICABLE',{'reason':'Explicit empty point-to-site auth configuration is excluded by source'}
    return result(types!=['AAD'],authentication_types=types,semantics='Exact one-element array; gateway routes and actual auth enforcement are separate')
CASES[SOURCE_QUERIES['network_virtual_network_gateway_aad_only']]={'pass':nest('properties.vpnClientConfiguration.vpnAuthenticationTypes',['AAD']),'fail':nest('properties.vpnClientConfiguration.vpnAuthenticationTypes',['AAD','Certificate'])}


@port('network_interface_ip_forwarding_disabled','vm','Every source-selected VM NIC declares IP forwarding disabled',deps=['vm','nic'])
def nic_forwarding(item,index):
    interfaces=list_of_objects(get(item,'properties.networkProfile.networkInterfaces',list))
    if not interfaces:return 'NOT_APPLICABLE',{'reason':'Source VM NIC expansion is empty'}
    rows=complete_items(index,'nic');bad=[]
    for interface in interfaces:
        rid=get(interface,'id',str)
        if not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/networkInterfaces/[^/]+',rid,re.I):raise Unavailable('Malformed NIC identity')
        matches=[r for r in rows if get(r,'id',str).casefold()==rid.casefold()]
        if len(matches)!=1:raise Unavailable('VM NIC missing or ambiguous')
        if get(matches[0],'properties.enableIPForwarding',bool):bad.append(rid)
    return result(bool(bad),forwarding_nics=bad,semantics='Per-attached-NIC declaration; aggregation fails if any selected source row fails, no packet probe')
_NIC='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Network/networkInterfaces/nic'
def _nic(value):return {'nic':[{'data':{'id':_NIC,'properties':{'enableIPForwarding':value}}}],'collections':{'nic':[{'scope':'/subscriptions/sub','status':'collected'}]}}
CASES[SOURCE_QUERIES['network_interface_ip_forwarding_disabled']]={'pass':nest('properties.networkProfile.networkInterfaces',[{'id':_NIC}]),'fail':nest('properties.networkProfile.networkInterfaces',[{'id':_NIC}]),'pass_index':_nic(False),'fail_index':_nic(True)}


@port('monitor_log_alert_service_health','activity_log_alert','Subscription declares enabled global ServiceHealth OR ResourceHealth alert','scope',['activity_log_alert'])
def service_health(item,index):
    if _non_subscription(item):return 'NOT_APPLICABLE',{'reason':'Source subscription scope'}
    scope=get(item,'scope',str);matches=[]
    for alert in _scope_rows(item,index,'activity_log_alert'):
        enabled=get(alert,'properties.enabled',bool);location=get(alert,'location',str);scopes=get(alert,'properties.scopes',list)
        if any(not isinstance(s,str) for s in scopes):raise Unavailable('Malformed alert scopes')
        if not enabled or location.lower()!='global' or scope not in scopes:continue
        for leaf in list_of_objects(get(alert,'properties.condition.allOf',list)):
            if 'anyOf' in leaf:continue
            field=get(leaf,'field',str);value=optional(leaf,'equals',None)
            if value is not None and not isinstance(value,str):raise Unavailable('Malformed alert equality')
            if field=='category' and value in ('ServiceHealth','ResourceHealth'):matches.append(alert['id'])
    return result(not matches,matching_alerts=sorted(set(matches)),semantics='Exact source category OR; ResourceHealth is deliberately not renamed ServiceHealth and no event delivery is asserted')
_ALERT={'id':'/subscriptions/sub/resourceGroups/g/providers/Microsoft.Insights/activityLogAlerts/log','location':'global','properties':{'enabled':True,'scopes':['/subscriptions/sub'],'condition':{'allOf':[{'field':'category','equals':'ServiceHealth'}]}}}
CASES[SOURCE_QUERIES['monitor_log_alert_service_health']]={'pass':{'scope':'/subscriptions/sub'},'fail':{'scope':'/subscriptions/sub'},'pass_index':_fixture('activity_log_alert',[_ALERT]),'fail_index':_fixture('activity_log_alert',[],'empty')}


@port('aks_cluster_azure_monitor_enabled','aks_cluster','AKS declares managed Prometheus metrics enabled')
def aks_metrics(item,index):
    get(item,'properties.kubernetesVersion',str)
    return result(not get(item,'properties.azureMonitorProfile.metrics.enabled',bool),semantics='Managed Prometheus flag, separate from OMS/ContainerInsights/log delivery')
CASES[SOURCE_QUERIES['aks_cluster_azure_monitor_enabled']]={'pass':{'properties':{'kubernetesVersion':'1.31','azureMonitorProfile':{'metrics':{'enabled':True}}}},'fail':{'properties':{'kubernetesVersion':'1.31','azureMonitorProfile':{'metrics':{'enabled':False}}}}}


@port('aks_clusters_created_with_private_nodes','aks_cluster','All AKS agent pools declare node public IP disabled')
def aks_nodes(item,index):
    get(item,'properties.kubernetesVersion',str);pools=list_of_objects(get(item,'properties.agentPoolProfiles',list))
    if not pools:raise Unavailable('Required agent-pool metadata empty; enabled cluster configuration not certified')
    flags=[get(p,'enableNodePublicIP',bool) for p in pools]
    return result(any(flags),public_node_ip_flags=flags,semantics='All pools, not existential any-private-pool and not private API endpoint')
CASES[SOURCE_QUERIES['aks_clusters_created_with_private_nodes']]={'pass':{'properties':{'kubernetesVersion':'1.31','agentPoolProfiles':[{'enableNodePublicIP':False}]}},'fail':{'properties':{'kubernetesVersion':'1.31','agentPoolProfiles':[{'enableNodePublicIP':False},{'enableNodePublicIP':True}]}}}


@port('aks_network_policy_enabled','aks_cluster','AKS declares a recognized network policy provider')
def aks_policy(item,index):
    get(item,'properties.kubernetesVersion',str);policy=get(item,'properties.networkProfile.networkPolicy')
    if policy is not None and not isinstance(policy,str):raise Unavailable('Malformed network policy provider')
    if policy not in (None,'','azure','calico','cilium'):raise Unavailable('Unknown network policy provider')
    return result(not bool(policy),network_policy=policy,semantics='Configured provider only; CNI enforcement, node agents and actual policy isolation remain unverified')
CASES[SOURCE_QUERIES['aks_network_policy_enabled']]={'pass':{'properties':{'kubernetesVersion':'1.31','networkProfile':{'networkPolicy':'azure'}}},'fail':{'properties':{'kubernetesVersion':'1.31','networkProfile':{'networkPolicy':None}}}}


for _query,_path,_good,_bad in [('app_function_ensure_http_is_redirected_to_https','properties.httpsOnly',True,False),('app_function_ftps_deployment_disabled','configuration.properties.ftpsState','Disabled','FtpsOnly'),('app_function_not_publicly_accessible','properties.publicNetworkAccess','Disabled','Enabled')]:
    def _function(query,path,good,bad):
        @port(query,'app_service','Function app declared baseline: '+query.removeprefix('app_function_').replace('_',' '))
        def evaluate(item,index):
            if not get(item,'kind',str).startswith('functionapp'):return 'NOT_APPLICABLE',{'reason':'Pinned Prowler function-prefix selector'}
            value=get(item,path,type(good))
            if path.endswith('ftpsState') and value not in ('AllAllowed','FtpsOnly','Disabled'):raise Unavailable('Unknown FTP mode')
            if path.endswith('publicNetworkAccess') and value not in ('Enabled','Disabled'):raise Unavailable('Unknown public network mode')
            return result(value!=good,configured=value,semantics='Exact Prowler function scope and declared flag, not token-substring function table or effective network reachability')
        CASES[SOURCE_QUERIES[query]]={'pass':{'kind':'functionapp,linux',**nest(path,good)},'fail':{'kind':'functionapp,linux',**nest(path,bad)}}
    _function(_query,_path,_good,_bad)


@port('app_function_vnet_integration_enabled','app_service','Function declares nonempty VNet integration subnet ARM ID')
def function_vnet(item,index):
    if not get(item,'kind',str).startswith('functionapp'):return 'NOT_APPLICABLE',{'reason':'Pinned Prowler function-prefix selector'}
    subnet=get(item,'properties.virtualNetworkSubnetId')
    if subnet is not None and not isinstance(subnet,str):raise Unavailable('Malformed VNet subnet')
    if subnet and not re.fullmatch(r'/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Network/virtualNetworks/[^/]+/subnets/[^/]+',subnet,re.I):raise Unavailable('Malformed VNet subnet ARM identity')
    return result(not bool(subnet),subnet_id=subnet,semantics='Declared outbound integration, not inbound private access or effective route enforcement')
CASES[SOURCE_QUERIES['app_function_vnet_integration_enabled']]={'pass':{'kind':'functionapp',**nest('properties.virtualNetworkSubnetId',_VNET+'/subnets/subnet')},'fail':{'kind':'functionapp',**nest('properties.virtualNetworkSubnetId',None)}}


@port('app_http_logs_enabled','app_service','App-prefixed nonfunction site diagnostics declare HTTPLogs OR allLogs')
def http_logs(item,index):
    kind=get(item,'kind',str)
    if not kind.startswith('app') or 'functionapp' in kind:return 'NOT_APPLICABLE',{'reason':'Exact Prowler app-prefix/nonfunction selector'}
    rid=get(item,'id',str);matches=[]
    for setting in list_of_objects(get(item,'diagnosticSettings',list)):
        if not get(setting,'id',str).casefold().startswith((rid+'/providers/Microsoft.Insights/diagnosticSettings/').casefold()):raise Unavailable('Foreign diagnostic')
        for log in list_of_objects(get(setting,'properties.logs',list)):
            category=optional(log,'category',None);group=optional(log,'categoryGroup',None)
            if any(v is not None and not isinstance(v,str) for v in (category,group)):raise Unavailable('Malformed log category/group')
            if get(log,'enabled',bool) and (category=='AppServiceHTTPLogs' or group=='allLogs'):matches.append(setting['id'])
    return result(not matches,matching_settings=matches,semantics='Explicit source HTTP category OR allLogs group; exact-category-only Steampipe predicate differs')
_APP='/subscriptions/sub/resourceGroups/g/providers/Microsoft.Web/sites/app'
CASES[SOURCE_QUERIES['app_http_logs_enabled']]={'pass':{'id':_APP,'kind':'app','diagnosticSettings':[{'id':_APP+'/providers/Microsoft.Insights/diagnosticSettings/log','properties':{'logs':[{'categoryGroup':'allLogs','enabled':True}]}}]},'fail':{'id':_APP,'kind':'app','diagnosticSettings':[]}}
