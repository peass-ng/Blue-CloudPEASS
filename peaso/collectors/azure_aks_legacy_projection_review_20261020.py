"""Source-bound AKS security projections; no caller supplied observation flags."""
from copy import deepcopy
import hashlib,json,re
from urllib.parse import parse_qs,urlsplit

KIND='aks_legacy_pod_inventory'
DIAGNOSTIC_KIND='aks_diagnostic_declaration'
HSM_KIND='hsm_audit_destination_declaration'
NATIVE_TYPES=(DIAGNOSTIC_KIND,HSM_KIND)
PATHS=('/api/v1/namespaces','/api/v1/pods')
MAX_PAGES=100;MAX_PODS=10000;MAX_NAMESPACES=4096;MAX_BYTES=8*1024*1024
VERSION='2021-05-01-preview'
ARM='https://management.azure.com'


def required_types(wanted):
    return ({'aks_cluster'} if DIAGNOSTIC_KIND in wanted else set())|({'managed_hsm'} if HSM_KIND in wanted else set())


def record_page(receipts,path,params,payload):
    """Record only actual native page metadata; raw bodies remain ephemeral."""
    if path not in PATHS:return
    pages=receipts.setdefault(path,[])
    received=len(json.dumps(payload,allow_nan=False).encode())
    total=sum(p['bytes'] for values in receipts.values() for p in values)
    if len(pages)>=MAX_PAGES or received+total>MAX_BYTES:
        raise ValueError('AKS native page budget exceeded')
    meta=payload['metadata'];items=payload['items'];maximum=MAX_PODS if path==PATHS[1] else MAX_NAMESPACES
    if sum(p['items'] for p in pages)+len(items)>maximum:raise ValueError('AKS native object budget exceeded')
    pages.append({'request_path':path,'request_limit':params['limit'],'request_continue':params.get('continue',''),
        'resourceVersion':meta['resourceVersion'],'continue':meta.get('continue',''),'items':len(items),'bytes':received})


def validate_pages(pages,path,count):
    if not isinstance(pages,list) or not 0<len(pages)<=MAX_PAGES:raise ValueError('native list pages absent')
    continuation='';version=None;total=0;seen=set()
    for p in pages:
        if not isinstance(p,dict) or set(p)!={'request_path','request_limit','request_continue','resourceVersion','continue','items','bytes'}:
            raise ValueError('native list receipt malformed')
        if (p['request_path']!=path or type(p['request_limit']) is not int or not 1<=p['request_limit']<=1000
                or p['request_continue']!=continuation or not isinstance(p['continue'],str)
                or not isinstance(p['resourceVersion'],str) or not p['resourceVersion']
                or type(p['items']) is not int or p['items']<0 or type(p['bytes']) is not int or not 0<p['bytes']<=MAX_BYTES):raise ValueError('native list receipt contradicts request')
        if version is not None and version!=p['resourceVersion']:raise ValueError('native list version changed')
        version=p['resourceVersion'];continuation=p['continue'];total+=p['items']
        if continuation in seen:raise ValueError('native list repeated continuation')
        if continuation:seen.add(continuation)
    if continuation or total!=count:raise ValueError('native list incomplete or count differs')
    return version


def security_pods(pods):
    if not isinstance(pods,list) or len(pods)>MAX_PODS:raise ValueError('native Pod collection malformed')
    result=[];uids=set();names=set()
    for pod in pods:
        if not isinstance(pod,dict) or pod.get('apiVersion')!='v1' or pod.get('kind')!='Pod':raise ValueError('native Pod type invalid')
        meta=pod.get('metadata');spec=pod.get('spec')
        if (not isinstance(meta,dict) or not isinstance(spec,dict)
                or any(not isinstance(meta.get(k),str) or not meta[k] for k in ('name','namespace','uid','resourceVersion'))):
            raise ValueError('native Pod identity/spec unavailable')
        identity=(meta['namespace'],meta['name'])
        if meta['uid'] in uids or identity in names:raise ValueError('duplicate native Pod identity')
        uids.add(meta['uid']);names.add(identity)
        projected={};seen=set()
        if 'os' in spec:projected['os']=deepcopy(spec['os'])
        if 'securityContext' in spec:
            context=spec['securityContext']
            projected['securityContext']={k:deepcopy(context[k]) for k in ('runAsUser',) if k in context} if isinstance(context,dict) else deepcopy(context)
        for field in ('containers','initContainers','ephemeralContainers'):
            if field not in spec:
                if field=='containers':raise ValueError('native regular containers omitted')
                continue
            values=spec[field]
            if not isinstance(values,list) or field=='containers' and not values:raise ValueError('native container list unavailable')
            output=[]
            for container in values:
                if not isinstance(container,dict) or not isinstance(container.get('name'),str) or not container['name'] or container['name'] in seen:
                    raise ValueError('native container identity absent or duplicate')
                seen.add(container['name']);row={'name':container['name']}
                if 'securityContext' in container:
                    ctx=container['securityContext'];row['securityContext']={k:deepcopy(ctx[k]) for k in ('privileged','runAsUser') if k in ctx} if isinstance(ctx,dict) else deepcopy(ctx)
                output.append(row)
            projected[field]=output
        result.append({'apiVersion':'v1','kind':'Pod','metadata':{k:meta[k] for k in ('name','namespace','uid','resourceVersion')},'spec':projected})
    return result


def project(rid,pods,proof):
    """Called only after authenticated full Lists and stable UID postcheck."""
    provenance=proof['_provenance'];namespaces=proof['native_namespace_uids'];receipts=provenance['native_list_pages']
    if not isinstance(receipts,dict) or set(receipts)!=set(PATHS) or sum(p['bytes'] for values in receipts.values() for p in values)>MAX_BYTES:
        raise ValueError('native total received byte budget exceeded')
    if (not isinstance(namespaces,dict) or not namespaces or len(namespaces)>MAX_NAMESPACES
            or len(set(namespaces.values()))!=len(namespaces) or any(not isinstance(k,str) or not k or not isinstance(v,str) or not v for k,v in namespaces.items())
            or namespaces.get('kube-system')!=provenance['cluster_uid_before'] or provenance['cluster_uid_before']!=provenance['cluster_uid_after']):
        raise ValueError('native Namespace/cluster UID coverage differs')
    projected=security_pods(pods)
    if any(p['metadata']['namespace'] not in namespaces for p in projected):raise ValueError('native Pod outside namespace capture')
    versions={path:validate_pages(receipts[path],path,len(namespaces) if path==PATHS[0] else len(projected)) for path in PATHS}
    value={'id':rid,'parent_id':rid,'cluster_uid':provenance['cluster_uid_before'],'namespace_uids':deepcopy(namespaces),'pods':projected,
        'native_list_pages':deepcopy(receipts),'list_resource_versions':versions,'server':provenance['server'],'ca_sha256':provenance['ca_sha256'],'ARM_get':deepcopy(proof['native_ARM_get']),
        '_provenance':{'source_operation':'AKS_NamespaceList_PodList','read_only':True,'api_version':'v1','ARM_api_version':'2024-05-01','cluster_id':rid,
            'cluster_uid_before':provenance['cluster_uid_before'],'cluster_uid_after':provenance['cluster_uid_after'],
            'representation':'native full JSON read; retained only identity and complete deciding security fields'}}
    if len(json.dumps(value,allow_nan=False).encode())>MAX_BYTES:raise ValueError('native projected byte budget exceeded')
    return value


def native_pages(reader,request,url):
    expected=urlsplit(url);calls=0
    def source(candidate,*,body=None,audience=ARM):
        nonlocal calls
        parsed=urlsplit(candidate);query=parse_qs(parsed.query);calls+=1
        if (calls>MAX_PAGES or body is not None or audience!=ARM or parsed.scheme!='https' or parsed.netloc!='management.azure.com'
                or parsed.path!=expected.path or parsed.fragment or query.get('api-version')!=[VERSION]):
            raise ValueError('native AKS diagnostic continuation changed source')
        return request(candidate,body=body,audience=audience)
    return reader.pages(source,url)


def collect_diagnostics(reader,request,scopes,wanted):
    """Unregistered declaration proposal; never asserts sink usability."""
    if DIAGNOSTIC_KIND not in wanted:return
    from .azure import AzureReadError,_child_rows
    for scope in scopes:
        def fetch(scope=scope):
            parents=[c for c in reader.collections if c['type']=='aks_cluster' and c['scope'].casefold()==scope.casefold()]
            if len(parents)!=1 or parents[0]['status'] not in ('collected','empty'):raise AzureReadError('aks_parent_inventory_incomplete')
            for parent in parents[0]['items']:
                rid=parent['id'];path=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories';url=ARM+path+'?api-version='+VERSION
                rows=[];seen=set()
                for page in native_pages(reader,request,url):
                    for cat in page:
                        name=cat.get('name');identity=cat.get('id');typ=cat.get('type');props=cat.get('properties')
                        if (not isinstance(name,str) or not name or '/' in name or name.casefold() in seen
                                or not isinstance(identity,str) or identity.casefold()!=(path+'/'+name).casefold()
                                or str(typ).casefold()!='microsoft.insights/diagnosticsettingscategories' or not isinstance(props,dict)):
                            raise ValueError('native AKS diagnostic category identity invalid')
                        seen.add(name.casefold());rows.append({'id':identity,'name':name,'type':typ,'properties':{k:deepcopy(props[k]) for k in ('categoryType','categoryGroups') if k in props}})
                raw=[]
                settings_path=rid+'/providers/Microsoft.Insights/diagnosticSettings'
                for page in native_pages(reader,request,ARM+settings_path+'?api-version='+VERSION):
                    raw.extend(page)
                    if len(raw)>100:raise ValueError('native AKS diagnostic setting budget exceeded')
                settings=_child_rows(raw,rid,'diagnosticSettings')
                yield [{'id':rid,'parent_id':rid,'categories':rows,'diagnostic_settings':settings,'_provenance':{'source_operation':'DiagnosticSettingsCategories_List_and_DiagnosticSettings_List','read_only':True,'api_version':VERSION,
                    'request_path':path,'scope':scope,'settings_request_path':rid+'/providers/Microsoft.Insights/diagnosticSettings'}}]
        reader.run([(DIAGNOSTIC_KIND,scope,'Microsoft.Insights',fetch)])


def collect_hsm_categories(reader,request,scopes,wanted):
    """Resolve only group-dependent audit declarations; no destination reads."""
    if HSM_KIND not in wanted:return
    from .azure import AzureReadError,_safe_error
    for scope in scopes:
        def fetch(scope=scope):
            parents=[c for c in reader.collections if c['type']=='managed_hsm' and c['scope'].casefold()==scope.casefold()]
            if len(parents)!=1 or parents[0]['status'] not in ('collected','empty'):raise AzureReadError('hsm_parent_inventory_incomplete')
            for parent in parents[0]['items']:
                rid=parent['id'];path=rid+'/providers/Microsoft.Insights/diagnosticSettingsCategories'
                if (re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/\s?#%\\]+/providers/Microsoft\.KeyVault/managedHSMs/[A-Za-z0-9-]{3,24}',rid,re.I) is None
                        or str(parent.get('type','')).casefold()!='microsoft.keyvault/managedhsms'):
                    raise ValueError('selected native HSM parent identity unavailable')
                settings=parent.get('diagnosticSettings',[])
                logs=[(s.get('properties',{}),log) for s in settings if isinstance(s,dict) and isinstance(s.get('properties'),dict) and isinstance(s['properties'].get('logs'),list) for log in s['properties']['logs'] if isinstance(log,dict)]
                explicit=any(log.get('enabled') is True and log.get('category')=='AuditEvent' and any(props.get(k) for k in ('storageAccountId','workspaceId')) for props,log in logs)
                groups=any(log.get('enabled') is True and log.get('categoryGroup') is not None for props,log in logs)
                inventory={'status':'not_collected','items':[],'reason':'explicit category is decisive or no enabled category group'}
                if groups and not explicit:
                    try:
                        rows=[];seen=set()
                        for page in native_pages(reader,request,ARM+path+'?api-version='+VERSION):
                            for cat in page:
                                name=cat.get('name');props=cat.get('properties')
                                if (not isinstance(name,str) or not name or '/' in name or name.casefold() in seen
                                        or str(cat.get('id','')).casefold()!=(path+'/'+name).casefold()
                                        or str(cat.get('type','')).casefold()!='microsoft.insights/diagnosticsettingscategories'
                                        or not isinstance(props,dict)):
                                    raise ValueError('native HSM category identity unavailable')
                                seen.add(name.casefold());rows.append({'id':cat['id'],'name':name,'type':cat['type'],'properties':{k:deepcopy(props[k]) for k in ('categoryType','categoryGroups') if k in props}})
                                if len(rows)>100:raise ValueError('native HSM category bound exceeded')
                        inventory={'status':'collected','items':rows,'_provenance':{'source_operation':'DiagnosticSettingsCategories_List','read_only':True,'api_version':VERSION,'request_path':path,'scope':rid}}
                    except Exception as exc:
                        status,error=_safe_error(exc);inventory={'status':status,'items':[],'error':error}
                yield [{'id':rid,'parent_id':rid,'category_inventory':inventory,'_provenance':{'source_operation':'HSM_AuditDestinationMetadata','read_only':True,'api_version':VERSION,'scope':scope,'request_path':path}}]
        reader.run([(HSM_KIND,scope,'Microsoft.Insights',fetch)])
