"""Exact native declaration reads; no Key Vault or Log Analytics data access."""
from copy import deepcopy
import re
from urllib.parse import parse_qs,urlsplit

ARM='https://management.azure.com'
MARKER='_automation_aci_declaration_native'
CONTRACTS={
 'automation_cmk_declaration':('automation_account','Microsoft.Automation/automationAccounts','2023-11-01','AutomationAccount_Get'),
 'aci_log_analytics_declaration':('container_group','Microsoft.ContainerInstance/containerGroups','2023-05-01','ContainerGroups_Get'),
}
NATIVE_TYPES=tuple(CONTRACTS)
GUID=r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'


def resource_id(value,scope,typ):
    if (not isinstance(scope,str) or not re.fullmatch('/subscriptions/'+GUID,scope,re.I)
            or not isinstance(value,str) or not re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/?#%\s\\]+/providers/'+re.escape(typ)+r'/[^/?#%\s\\]+',value,re.I)
            or any(ord(c)<33 or ord(c)==127 for c in value) or any(p in ('.','..') for p in value.split('/'))):
        raise ValueError('native resource outside selected subscription')
    return value


def required_types(wanted):
    return {contract[0] for kind,contract in CONTRACTS.items() if kind in wanted}


def aci_metadata_route(url,scopes):
    """Only selected native group List/Get routes, not logs/exec/Graph/ARG."""
    parsed=urlsplit(url);query=parse_qs(parsed.query)
    if (parsed.scheme!='https' or parsed.netloc.casefold()!='management.azure.com' or parsed.fragment
            or query.get('api-version')!=['2023-05-01']):return False
    for scope in scopes:
        if (isinstance(scope,str) and re.fullmatch('/subscriptions/'+GUID,scope,re.I)
                and re.fullmatch(re.escape(scope)+r'/(?:providers/Microsoft\.ContainerInstance/containerGroups|resourceGroups/[^/?#%\s\\]+/providers/Microsoft\.ContainerInstance/containerGroups(?:/[^/?#%\s\\]+)?)',parsed.path,re.I)
                and not any(ord(c)<33 or ord(c)==127 for c in parsed.path)
                and not any(p in ('.','..') for p in parsed.path.split('/'))):return True
    return False


def project(raw,rid,scope,kind):
    parent,typ,version,operation=CONTRACTS[kind]
    resource_id(rid,scope,typ)
    if (not isinstance(raw,dict) or resource_id(raw.get('id'),scope,typ).casefold()!=rid.casefold()
            or str(raw.get('type','')).casefold()!=typ.casefold()
            or not isinstance(raw.get('name'),str) or raw['name'].casefold()!=rid.rsplit('/',1)[-1].casefold()
            or not isinstance(raw.get('properties'),dict)):
        raise ValueError('native GET identity or representation unavailable')
    props=raw['properties'];out={}
    if parent=='automation_account':
        for key in ('state','encryption'):
            if key in props:out[key]=deepcopy(props[key])
    else:
        if 'provisioningState' in props:out['provisioningState']=deepcopy(props['provisioningState'])
        if 'diagnostics' in props:
            diagnostics=props['diagnostics']
            if diagnostics is not None and not isinstance(diagnostics,dict):raise ValueError('native diagnostics malformed')
            out['diagnostics']=None if diagnostics is None else {}
            if isinstance(diagnostics,dict) and 'logAnalytics' in diagnostics:
                log=diagnostics['logAnalytics']
                if log is not None and not isinstance(log,dict):raise ValueError('native log analytics malformed')
                # Do not access, copy, export or scan workspaceKey.
                out['diagnostics']['logAnalytics']=None if log is None else {k:deepcopy(log[k]) for k in ('workspaceId','logType') if k in log}
    item={'id':raw['id'],'parent_id':rid,'type':raw['type'],'properties':out,
          MARKER:{'kind':kind,'scope':scope,'resource_id':rid,'method':'GET','api_version':version,
                  'request_uri':ARM+rid+'?api-version='+version,'complete':True},
          '_provenance':{'scope':scope,'source_operation':operation,'read_only':True,'api_version':version}}
    if parent=='automation_account' and 'identity' in raw:item['identity']=deepcopy(raw['identity'])
    return item


def collect(reader,request,scopes,wanted):
    for kind in sorted(set(CONTRACTS)&set(wanted)):
        parent,typ,version,operation=CONTRACTS[kind]
        for scope in scopes:
            def fetch(kind=kind,parent=parent,typ=typ,version=version,scope=scope):
                sources=[c for c in reader.collections if c['type']==parent and c['scope'].casefold()==scope.casefold()]
                if len(sources)!=1 or sources[0]['status'] not in ('collected','empty'):
                    raise ValueError('complete parent inventory unavailable')
                source=sources[0]
                if not isinstance(source['items'],list) or (source['status']=='empty')!=(not source['items']):
                    raise ValueError('parent inventory contradictory')
                selected=[]
                for item in source['items']:
                    rid=resource_id(item.get('id'),scope,typ)
                    if str(item.get('type','')).casefold()!=typ.casefold() or rid.casefold() in {v.casefold() for v in selected}:
                        raise ValueError('foreign or duplicate native parent')
                    selected.append(rid)
                for rid in selected:
                    raw=reader.call(request,ARM+rid+'?api-version='+version)
                    yield [project(raw,rid,scope,kind)]
            reader.collections.append(reader._read((kind,scope,typ.split('/')[0],fetch)))
