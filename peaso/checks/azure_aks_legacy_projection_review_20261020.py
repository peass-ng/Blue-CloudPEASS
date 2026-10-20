"""Explicit unregistered AKS successors; signed SW30 sources remain unchanged."""
from copy import deepcopy
from dataclasses import replace
import hashlib,inspect,re
from urllib.parse import urlsplit
from .facts import Unavailable
from . import unknown,result
from peaso.collectors import azure_aks_legacy_projection_review_20261020 as native

PRIV='azure_aks_cluster_7_2_1_6_93c4fab'
NONROOT='azure_aks_cluster_aks_cluster_rbac_enabled_db12524'
DIAGNOSTIC='azure.logging.aks_supported_log_categories_destination_declared'
FROZEN={PRIV:'ef7b992d7276bf5ba86ff0e337b9cb92f1fc938187ac89796a1fa2979f603719',NONROOT:'145cd00154f8a701c093147ffa74fd90b8198bb44d5718906c0af28f1ae4bb22'}
_ORIGINALS={}
DECLARATIONS=[{'id':DIAGNOSTIC,'provider':'azure','kind':'aks_cluster','category':'hardening','finding_type':'logging','severity':'medium','ui_group':'Logging','requirements':[],
 'dependencies':['aks_cluster',native.DIAGNOSTIC_KIND],
 'title':'AKS declares supported log categories to diagnostic destinations',
 'remediation':'Enable each supported control-plane log category with the intended diagnostic destination. Verify destination permissions and log delivery separately.'}]
UUID=r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}'


def bound(item,index,kind):
    ctx=index.get('context',{});scope=ctx.get('scope');meta=ctx.get('metadata',{});rid=item.get('id')
    if ctx.get('provider')!='azure' or not isinstance(scope,str) or re.fullmatch('/subscriptions/'+UUID,scope,re.I) is None:
        raise Unavailable('Azure selected subscription absent')
    if (not isinstance(rid,str) or re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/\s?#%\\]+/providers/Microsoft\.ContainerService/managedClusters/[^/\s?#%\\]+',rid,re.I) is None
            or str(item.get('type','')).casefold()!='microsoft.containerservice/managedclusters'):
        raise Unavailable('native selected AKS identity unavailable')
    parents=index.get('collections',{}).get('aks_cluster',[])
    if (len(parents)!=1 or parents[0].get('scope','').casefold()!=scope.casefold() or parents[0].get('status')!='collected'
            or sum(isinstance(p,dict) and str(p.get('id','')).casefold()==rid.casefold() for p in parents[0].get('items',[]))!=1):
        raise Unavailable('complete unique parent inventory absent')
    collections=index.get('collections',{}).get(kind,[])
    if len(collections)!=1 or collections[0].get('status')!='collected' or str(collections[0].get('scope','')).casefold()!=scope.casefold():
        raise Unavailable('complete native projection missing')
    envelope=collections[0];rows=envelope.get('items');seen=set();matches=[]
    if not isinstance(rows,list):raise Unavailable('native projection rows malformed')
    for row in rows:
        identity=row.get('id') if isinstance(row,dict) else None
        if (not isinstance(identity,str) or not identity.casefold().startswith(scope.casefold()+'/') or identity.casefold() in seen):
            raise Unavailable('foreign or duplicate native projection')
        seen.add(identity.casefold())
        if identity.casefold()==rid.casefold():matches.append(row)
    if len(matches)!=1:raise Unavailable('native cluster projection absent')
    row=matches[0]
    for obj in (item,parents[0],envelope,row):
        proof=obj.get('_provenance',{})
        for key in ('credential_context_id','customer_context_id'):
            value=meta.get(key)
            if not isinstance(value,str) or not value or proof.get(key)!=value:raise Unavailable('native capture context differs')
    if row.get('parent_id','').casefold()!=rid.casefold() or row.get('_provenance',{}).get('read_only') is not True:
        raise Unavailable('native cluster projection binding differs')
    return row


def legacy_item(item,index):
    row=bound(item,index,native.KIND);p=row.get('_provenance',{});rid=item['id']
    if (p.get('source_operation')!='AKS_NamespaceList_PodList' or p.get('api_version')!='v1' or p.get('ARM_api_version')!='2024-05-01'
            or str(p.get('cluster_id','')).casefold()!=rid.casefold()
            or p.get('representation')!='native full JSON read; retained only identity and complete deciding security fields'):
        raise Unavailable('native source operation/representation unavailable')
    ctx=index['context']['metadata']
    if ctx.get('tenant_verified') is not True or not isinstance(ctx.get('subscription_tenants'),dict) or ctx['subscription_tenants'].get(index['context']['scope'])!=ctx.get('tenant_id'):
        raise Unavailable('authenticated ARM subscription tenant unavailable')
    arm=row.get('ARM_get');props=arm.get('properties') if isinstance(arm,dict) else None
    if (not isinstance(props,dict) or str(arm.get('id','')).casefold()!=rid.casefold()
            or str(arm.get('type','')).casefold()!='microsoft.containerservice/managedclusters'
            or str(arm.get('name','')).casefold()!=rid.rsplit('/',1)[-1].casefold() or props.get('provisioningState')!='Succeeded'):
        raise Unavailable('native ARM GET identity unavailable')
    server=row.get('server');ca=row.get('ca_sha256')
    if (not isinstance(server,str) or not re.fullmatch(r'https://[a-z0-9.-]+',server) or urlsplit(server).hostname not in {props.get('fqdn'),props.get('privateFQDN')}
            or not isinstance(ca,str) or re.fullmatch('[0-9a-f]{64}',ca) is None):raise Unavailable('native TLS endpoint binding unavailable')
    proof={'_provenance':{**p,'server':server,'ca_sha256':ca,'native_list_pages':row.get('native_list_pages')},
        'native_namespace_uids':row.get('namespace_uids'),'native_ARM_get':arm}
    recomputed=native.project(row['id'],row.get('pods'),proof)
    if any(row.get(key)!=value for key,value in recomputed.items() if key!='_provenance'):
        raise Unavailable('native projection/count/version contradiction')
    if row.get('cluster_uid')!=p.get('cluster_uid_before') or p.get('cluster_uid_before')!=p.get('cluster_uid_after'):
        raise Unavailable('native cluster UID changed')
    copy=deepcopy(item)
    copy['podInventory']={'status':'collected','pagesComplete':True,'namespacesComplete':True,'clusterId':rid,
        'resourceVersion':row['list_resource_versions']['/api/v1/pods'],'consistent':True,'fullPodRepresentation':True,'items':deepcopy(row['pods'])}
    return copy


def _evaluate(check_id,item,index):
    try:
        prepared=legacy_item(item,index)
        function=_ORIGINALS.get(check_id)
        if function is None:raise Unavailable('explicit native successor not installed')
        return function(prepared,index)
    except (Unavailable,ValueError,TypeError,KeyError,AttributeError):
        return unknown('authenticated complete AKS native Pod/Namespace capture unavailable')


def privileged(item,index):return _evaluate(PRIV,item,index)

def nonroot(item,index):return _evaluate(NONROOT,item,index)


def install_successors():
    """Coordinator-approved exact callback/dependency replacement, no source repin."""
    from . import CHECKS
    for number,c in enumerate(CHECKS):
        if c.id not in FROZEN:continue
        callback={PRIV:privileged,NONROOT:nonroot}[c.id]
        if c.evaluate is callback:continue
        function=inspect.unwrap(c.evaluate)
        if hashlib.sha256(inspect.getsource(function).encode()).hexdigest()!=FROZEN[c.id]:raise ValueError('frozen SW30 predicate changed before explicit native successor')
        _ORIGINALS[c.id]=function
        CHECKS[number]=replace(c,evaluate=callback,declared_dependencies=tuple(dict.fromkeys((*c.dependencies,native.KIND))))


def destination_refs(props):
    patterns={'storageAccountId':r'Microsoft\.Storage/storageAccounts/[a-z0-9]{3,24}',
        'workspaceId':r'Microsoft\.OperationalInsights/workspaces/[^/\s?#%\\]{4,63}',
        'eventHubAuthorizationRuleId':r'Microsoft\.EventHub/namespaces/[^/\s?#%\\]+/authorizationRules/[^/\s?#%\\]+'}
    result=[]
    for field,tail in patterns.items():
        value=props.get(field)
        if value in (None,''):continue
        if (not isinstance(value,str) or re.fullmatch(r'/subscriptions/'+UUID+r'/resourceGroups/[^/\s?#%\\]+/providers/'+tail,value,re.I) is None
                or any(part in ('.','..') for part in value.split('/'))):raise Unavailable('native diagnostic destination reference malformed')
        result.append((field,value))
    return result


def diagnostic_declaration(item,index):
    try:
        row=bound(item,index,native.DIAGNOSTIC_KIND);rid=item['id'];p=row['_provenance']
        if (p.get('source_operation')!='DiagnosticSettingsCategories_List_and_DiagnosticSettings_List' or p.get('api_version')!=native.VERSION
                or p.get('scope')!=index['context']['scope'] or p.get('request_path')!=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories'
                or p.get('settings_request_path')!=rid+'/providers/Microsoft.Insights/diagnosticSettings'):
            raise Unavailable('native diagnostic source differs')
        categories=row.get('categories');settings=row.get('diagnostic_settings');supported=set();groups={};seen=set();enabled=set();unresolved=False;destinations=[]
        if not isinstance(categories,list) or not isinstance(settings,list):raise Unavailable('native diagnostic list absent')
        for c in categories:
            name=c['name'];props=c['properties']
            if (not isinstance(name,str) or name in seen or c['id'].casefold()!=(p['request_path']+'/'+name).casefold()
                    or c['type'].casefold()!='microsoft.insights/diagnosticsettingscategories' or props.get('categoryType') not in ('Logs','Metrics')):raise Unavailable('native category identity/type unavailable')
            seen.add(name)
            if props['categoryType']=='Logs':
                supported.add(name);values=props.get('categoryGroups',[])
                if not isinstance(values,list) or any(not isinstance(v,str) or not v for v in values):raise Unavailable('native category groups malformed')
                for g in values:groups.setdefault(g,set()).add(name)
        if not supported:raise Unavailable('supported native log categories unavailable')
        seen=set()
        for setting in settings:
            sid=setting['id'];props=setting['properties']
            if (not isinstance(sid,str) or re.fullmatch(re.escape(rid)+r'/providers/Microsoft\.Insights/diagnosticSettings/[^/\s?#%\\]+',sid,re.I) is None
                    or sid.casefold() in seen or setting['type'].casefold()!='microsoft.insights/diagnosticsettings'):
                raise Unavailable('native diagnostic setting identity differs')
            seen.add(sid.casefold());refs=destination_refs(props);logs=props.get('logs')
            if not isinstance(logs,list):raise Unavailable('native logs absent')
            for log in logs:
                if not isinstance(log,dict) or type(log.get('enabled')) is not bool:raise Unavailable('native log flag unavailable')
                category,group=log.get('category'),log.get('categoryGroup')
                if (category is None)==(group is None):raise Unavailable('native log selector absent or ambiguous')
                if not log['enabled']:continue
                selected=supported if group=='allLogs' else groups.get(group) if group is not None else {category} if category in supported else None
                if selected is None:unresolved=True
                elif refs:enabled.update(selected);destinations.extend(refs)
                elif any(props.get(k) for k in ('marketplacePartnerId','serviceBusRuleId')):unresolved=True
        if unresolved:return unknown('native category or destination form unsupported')
        return result(bool(supported-enabled),missing_categories=sorted(supported-enabled),destination_references=sorted(set(destinations)),
            observed=('AKS declares supported log categories with native diagnostic destination references. Destination access and log delivery were not tested.' if supported<=enabled else 'Some supported AKS log categories lack an enabled native destination declaration. Log delivery was not tested.'))
    except (Unavailable,ValueError,TypeError,KeyError,AttributeError):return unknown('native AKS diagnostic declaration incomplete, malformed or unbound')


def install_diagnostic(registrar):
    d=DECLARATIONS[0]
    return registrar(DIAGNOSTIC,'azure','hardening','aks_cluster',d['title'],'medium','security_configuration',d['remediation'],dependencies=d['dependencies'])(diagnostic_declaration)
