"""Configuration-only alternatives to stronger unproduced access/delivery facts."""
from copy import deepcopy
from functools import wraps
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from peaso.collectors.azure_automation_aci_metadata_native_20261020 import ARM,CONTRACTS,GUID,MARKER,resource_id
from .facts import Unavailable

AUTOMATION='azure.encryption.automation_cmk_declared'
ACI='azure.logging.aci_log_analytics_declared'
DECLARATIONS=[
 dict(id=AUTOMATION,provider='azure',category='hardening',kind='automation_account',finding_type='encryption',severity='medium',ui_group='Encryption',
      title='Automation declares a customer-managed key reference and attached system identity',
      remediation='Configure a complete Key Vault key reference and attach the Automation system-assigned identity. Review key authorization, connectivity and key use separately.',
      dependencies=['automation_account','automation_cmk_declaration'],requirements=[]),
 dict(id=ACI,provider='azure',category='hardening',kind='container_group',finding_type='logging',severity='medium',ui_group='Logging',
      title='Container groups declare a Log Analytics customer UUID and supported log type',
      remediation='Configure diagnostics.logAnalytics with the workspace customer UUID and a supported logType. Verify workspace access and log delivery separately.',
      dependencies=['container_group','aci_log_analytics_declaration'],requirements=[]),
]


def bound(item,index,kind):
    parent,typ,version,operation=CONTRACTS[kind];ctx=index.get('context',{});scope=ctx.get('scope')
    if ctx.get('provider')!='azure':raise Unavailable('Azure context unavailable')
    rid=resource_id(item.get('id'),scope,typ)
    if str(item.get('type','')).casefold()!=typ.casefold():raise Unavailable('native parent type unavailable')
    sources=[c for c in index.get('collections',{}).get(kind,[]) if c.get('scope','').casefold()==scope.casefold()]
    if len(sources)!=1 or sources[0].get('status')!='collected':raise Unavailable('complete declaration inventory unavailable')
    own=sources[0];rows=own.get('items')
    if not isinstance(rows,list):raise Unavailable('declaration inventory malformed')
    seen=set();matches=[]
    for row in rows:
        ident=resource_id(row.get('id'),scope,typ)
        if ident.casefold() in seen:raise Unavailable('duplicate declaration identity')
        seen.add(ident.casefold())
        if ident.casefold()==rid.casefold():matches.append(row)
    if len(matches)!=1:raise Unavailable('selected declaration absent')
    row=matches[0];selected=row.get('parent_id');proof=row.get('_provenance',{});meta=ctx.get('metadata',{})
    for obj in (item,own,row):
        for key in ('credential_context_id','customer_context_id'):
            value=meta.get(key)
            if not isinstance(value,str) or not value or obj.get('_provenance',{}).get(key)!=value:
                raise Unavailable('declaration capture context unavailable')
    expected={'kind':kind,'scope':scope,'resource_id':selected,'method':'GET','api_version':version,
              'request_uri':ARM+str(selected)+'?api-version='+version,'complete':True}
    if (not isinstance(selected,str) or selected.casefold()!=rid.casefold() or str(row.get('type','')).casefold()!=typ.casefold()
            or row.get(MARKER)!=expected or row.get(MARKER,{}).get('complete') is not True
            or proof.get('scope')!=scope or proof.get('source_operation')!=operation
            or proof.get('read_only') is not True or proof.get('api_version')!=version or not isinstance(row.get('properties'),dict)):
        raise Unavailable('native GET provenance unavailable')
    return row


def uuid(value):
    return isinstance(value,str) and re.fullmatch(GUID,value,re.I) is not None and value.replace('-','')!='0'*32


def automation(item,index):
    row=bound(item,index,'automation_cmk_declaration');props=row['properties']
    if props.get('state')!='Ok':raise Unavailable('Automation account state unavailable')
    encryption=props.get('encryption')
    if not isinstance(encryption,dict):raise Unavailable('native encryption declaration unavailable')
    source=encryption.get('keySource')
    if source=='Microsoft.Automation':
        return 'FAIL',{'key_source':source,'observed':'Automation declares a platform-managed key. This check does not assess cryptographic key use.'}
    if source!='Microsoft.Keyvault':raise Unavailable('native key source unsupported')
    vault=encryption.get('keyVaultProperties')
    if not isinstance(vault,dict):raise Unavailable('native Key Vault reference unavailable')
    name,uri,version=vault.get('keyName'),vault.get('keyvaultUri'),vault.get('keyVersion')
    if any(v=='' or v is None for v in (name,uri,version)):
        if all(k in vault for k in ('keyName','keyvaultUri','keyVersion')):
            return 'FAIL',{'key_source':source,'observed':'Automation returns an incomplete customer-managed key reference. Key authorization and key use were not tested.'}
        raise Unavailable('key reference fields were omitted')
    if (not isinstance(name,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,127}',name)
            or not isinstance(version,str) or not re.fullmatch(r'[A-Za-z0-9-]{1,128}',version) or not isinstance(uri,str)):
        raise Unavailable('key reference malformed')
    parsed=urlsplit(uri)
    if (parsed.scheme!='https' or not re.fullmatch(r'[a-z0-9][a-z0-9-]{1,22}[a-z0-9]\.vault\.azure\.net',parsed.netloc,re.I)
            or parsed.path not in ('','/') or parsed.query or parsed.fragment):
        raise Unavailable('public Azure Key Vault reference unsupported')
    identity=row.get('identity')
    if identity is None:
        return 'FAIL',{'observed':'Automation has no attached system-assigned identity declaration. Key authorization and key use were not tested.'}
    if not isinstance(identity,dict) or identity.get('type') not in ('SystemAssigned','SystemAssigned, UserAssigned','UserAssigned','None'):
        raise Unavailable('attached identity form unsupported')
    if identity['type']=='None':return 'FAIL',{'observed':'Automation declares no attached identity. Key authorization and key use were not tested.'}
    if identity['type']=='UserAssigned':raise Unavailable('user-only Automation CMK selection is not covered by documented system-identity contract')
    if not uuid(identity.get('principalId')) or not uuid(identity.get('tenantId')):
        raise Unavailable('attached system identity principal unavailable')
    selected=encryption.get('identity')
    if selected not in (None,{}) and (not isinstance(selected,dict) or any(k not in ('type','principalId','tenantId') for k in selected)
            or any(selected.get(k)!=identity.get(k) for k in selected)):
        raise Unavailable('explicit encryption identity unsupported or contradictory')
    return 'PASS',{'key_source':source,'vault_hostname':parsed.hostname,'key_name':name,'key_version':version,'identity_type':identity['type'],
                   'observed':'Automation declares a complete customer-managed key reference and an attached system identity. Key existence, authorization, connectivity and cryptographic use were not tested.'}


def aci(item,index):
    row=bound(item,index,'aci_log_analytics_declaration');props=row['properties']
    if props.get('provisioningState')!='Succeeded':raise Unavailable('container group configuration not settled')
    diagnostics=props.get('diagnostics')
    if diagnostics is None or isinstance(diagnostics,dict) and diagnostics.get('logAnalytics') is None:
        return 'FAIL',{'observed':'The full container group configuration has no Log Analytics declaration. Workspace access and log delivery were not tested.'}
    if not isinstance(diagnostics,dict) or not isinstance(diagnostics.get('logAnalytics'),dict):
        raise Unavailable('native diagnostics representation unavailable')
    log=diagnostics['logAnalytics'];workspace=log.get('workspaceId');mode=log.get('logType')
    if workspace=='':return 'FAIL',{'observed':'The container group returns an empty Log Analytics workspace UUID. Workspace access and log delivery were not tested.'}
    if not uuid(workspace) or mode not in ('ContainerInsights','ContainerInstanceLogs'):
        raise Unavailable('native workspace customer UUID or log type unavailable')
    return 'PASS',{'workspace_customer_id':workspace,'log_type':mode,
                   'observed':'The container group declares a Log Analytics workspace customer UUID and supported log type. Workspace existence, access and log ingestion or delivery were not tested.'}


def install():
    from . import CHECKS,register
    from .fixtures import CASES
    path=Path(__file__).with_name('azure_automation_aci_metadata_review_20261020_fixtures.json')
    fixtures=json.loads(path.read_text())
    if set(fixtures)!={d['id'] for d in DECLARATIONS} or any(not isinstance(row,dict) or
            not {'pass','fail','unknown','pass_index','fail_index','unknown_index'}<=set(row)
            for row in fixtures.values()):
        raise RuntimeError('Reviewed native declaration fixtures are missing or incomplete')
    for d,fn in zip(DECLARATIONS,(automation,aci)):
        if any(c.id==d['id'] for c in CHECKS):continue
        def declaration(function,ident):
            @wraps(function)
            def evaluate(item,index):
                status,evidence=function(item,index)
                if status in ('PASS','FAIL'):
                    evidence={**evidence,'criterion':ident,'configured':status=='PASS','effective_access':'not_tested'}
                return status,evidence
            return evaluate
        register(d['id'],'azure','hardening',d['kind'],d['title'],'medium','security_configuration',d['remediation'],dependencies=d['dependencies'])(declaration(fn,d['id']))
        CASES[d['id']]=deepcopy(fixtures[d['id']])
