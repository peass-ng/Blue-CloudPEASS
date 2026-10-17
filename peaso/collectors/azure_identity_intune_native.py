"""Actual read-only directory membership, SQL MI administrators and Intune routes."""
from __future__ import annotations
import re
ARM='https://management.azure.com'
GRAPH='https://graph.microsoft.com'
TYPES=frozenset({'directory_user_group_membership','sql_managed_instance_administrator','intune_diagnostic_setting'})
GUID=re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}',re.I)

def required_types(wanted):
    return ({'subscription'} if set(wanted)&{'directory_user_group_membership','intune_diagnostic_setting'} else set()) | ({'directory_user'} if 'directory_user_group_membership' in wanted else set()) | ({'mssql_managed_instance'} if 'sql_managed_instance_administrator' in wanted else set())

def _guid(value):
    if not isinstance(value,str) or not GUID.fullmatch(value):raise ValueError('malformed directory identity')
    return value

def _proof(operation,tenant=None):
    return {'read_only':True,'representation':'full','source_operation':operation,**({'tenant_id':tenant,'tenant_verified':True}if tenant else {})}

def _source(reader,kind,scope):
    from .azure import AzureReadError
    sources=[c for c in reader.collections if c['type']==kind and c['scope'].casefold()==scope.casefold()]
    if len(sources)!=1 or sources[0]['status'] not in ('collected','empty'):raise AzureReadError('native_parent_inventory_incomplete')
    if sources[0]['status']=='empty' and sources[0]['items']:raise ValueError('conflicting native parent empty')
    return sources[0]['items']

def _rows(reader,request,url,*,graph=False):
    rows=[];seen=set()
    for page in reader.pages(request,url,**({'audience':GRAPH,'next_key':'@odata.nextLink'}if graph else {})):
        for row in page:
            rid=row.get('id')if isinstance(row,dict)else None
            if not isinstance(rid,str) or not rid or rid.casefold()in seen:raise ValueError('malformed duplicate native child')
            seen.add(rid.casefold());rows.append(row)
    return rows

def collect(reader,request,scopes,wanted,transport):
    from .azure import AzureReadError
    jobs=[]
    tenant=getattr(transport,'verified_tenant',None)
    verified=isinstance(tenant,str)and GUID.fullmatch(tenant)
    tenant_scope='/tenants/'+tenant if verified else '/tenants/unverified'
    if 'directory_user_group_membership'in wanted:
        def memberships():
            if not verified:raise AzureReadError('native_membership_tenant_unverified')
            users=_source(reader,'directory_user',tenant_scope)
            seen=set()
            for user in users:
                uid=_guid(user.get('id'))
                if uid.casefold()in seen:raise ValueError('duplicate native user')
                seen.add(uid.casefold())
                # Uncast transitiveMemberOf needs no advanced-query eventual-consistency mode.
                children=_rows(reader,request,GRAPH+'/v1.0/users/'+uid+'/transitiveMemberOf',graph=True)
                groups=[]
                for child in children:
                    _guid(child['id']);kind=child.get('@odata.type')
                    if kind not in ('#microsoft.graph.group','#microsoft.graph.directoryRole','#microsoft.graph.administrativeUnit'):
                        raise ValueError('directory membership type unavailable')
                    if kind=='#microsoft.graph.group':groups.append({'id':child['id']})
                yield [{'id':uid,'userId':uid,'groups':groups,'_coverage':{'groups':{'status':'collected'if groups else'empty'}},'_provenance':_proof('users/transitiveMemberOf',tenant)}]
        jobs.append(('directory_user_group_membership',tenant_scope,'Microsoft.Graph',memberships))
    if 'sql_managed_instance_administrator'in wanted:
        for scope in scopes:
            def admins(scope=scope):
                parents=_source(reader,'mssql_managed_instance',scope)
                seen=set()
                for parent in parents:
                    rid=parent.get('id')
                    if not isinstance(rid,str)or not re.fullmatch(re.escape(scope)+r'/resourceGroups/[^/?#]+/providers/Microsoft.Sql/managedInstances/[^/?#]+',rid,re.I)or rid.casefold()in seen:raise ValueError('foreign duplicate native managed instance')
                    seen.add(rid.casefold())
                    children=_rows(reader,request,ARM+rid+'/administrators?api-version=2023-08-01')
                    safe=[]
                    for child in children:
                        if not re.fullmatch(re.escape(rid)+r'/administrators/[^/?#]+',child['id'],re.I):raise ValueError('foreign managed instance administrator')
                        props=child.get('properties')
                        if not isinstance(props,dict):raise ValueError('malformed managed instance administrator')
                        if props.get('administratorType')=='ActiveDirectory':_guid(props.get('sid'));_guid(props.get('tenantId'))
                        if props.get('tenantId')and(not verified or props['tenantId'].casefold()!=tenant.casefold()):raise ValueError('foreign administrator tenant')
                        safe.append({'id':child['id'],'properties':{k:v for k,v in props.items()if k in ('administratorType','sid','tenantId')}})
                    yield [{'id':rid,'administrators':safe,'_coverage':{'administrators':{'status':'collected'if safe else'empty'}},'_provenance':_proof('ManagedInstanceAdministrators_ListByInstance')}]
            jobs.append(('sql_managed_instance_administrator',scope,'Microsoft.Sql',admins))
    if 'intune_diagnostic_setting'in wanted:
        def intune():
            if not verified:raise AzureReadError('native_intune_tenant_unverified')
            parent='/providers/microsoft.intune';version='2017-04-01-preview'
            categories=_rows(reader,request,ARM+parent+'/diagnosticSettingsCategories?api-version='+version)
            safe_categories=[]
            for row in categories:
                if not re.fullmatch(re.escape(parent)+r'/diagnosticSettingsCategories/[^/?#]+',row['id'],re.I):raise ValueError('foreign Intune category')
                props=row.get('properties')
                if not isinstance(props,dict):raise ValueError('malformed Intune category')
                safe_categories.append({'id':row['id'],'name':row.get('name'),'parent_id':parent,'properties':{k:v for k,v in props.items()if k in ('categoryType','categoryGroups')},'_provenance':_proof('IntuneDiagnosticSettingsCategories_List',tenant)})
            settings=_rows(reader,request,ARM+parent+'/diagnosticSettings?api-version='+version)
            safe_settings=[]
            for row in settings:
                if not re.fullmatch(re.escape(parent)+r'/diagnosticSettings/[^/?#]+',row['id'],re.I):raise ValueError('foreign Intune diagnostic setting')
                full=reader.call(request,ARM+row['id']+'?api-version='+version)
                if not isinstance(full,dict)or str(full.get('id','')).casefold()!=row['id'].casefold()or not isinstance(full.get('properties'),dict):raise ValueError('foreign Intune setting GET')
                props=full['properties'];workspace=props.get('workspaceId')
                if workspace:
                    if not isinstance(workspace,str)or not any(re.fullmatch(re.escape(s)+r'/resourceGroups/[^/?#]+/providers/Microsoft.OperationalInsights/workspaces/[^/?#]+',workspace,re.I)for s in scopes):raise ValueError('untrusted Intune workspace scope')
                    sink=reader.call(request,ARM+workspace+'?api-version=2022-10-01')
                    if not isinstance(sink,dict)or str(sink.get('id','')).casefold()!=workspace.casefold():raise ValueError('foreign Intune workspace GET')
                safe_settings.append({'id':full['id'],'parent_id':parent,'properties':{k:v for k,v in props.items()if k in ('workspaceId','storageAccountId','eventHubAuthorizationRuleId','logs')},'_provenance':_proof('IntuneDiagnosticSettings_Get',tenant)})
            yield [{'id':parent,'scope_id':tenant_scope,'categories':safe_categories,'diagnosticSettings':safe_settings,
                    '_coverage':{'categories':{'status':'collected'if categories else'empty'},'diagnosticSettings':{'status':'collected'if settings else'empty'}},'_provenance':_proof('IntuneDiagnosticSettings_List',tenant)}]
        jobs.append(('intune_diagnostic_setting',tenant_scope,'Microsoft.Intune',intune))
    start=len(reader.collections);reader.run(jobs)
    for collection in reader.collections[start:]:
        if collection['type']in('directory_user_group_membership','intune_diagnostic_setting'):
            collection.setdefault('_provenance',{}).update(_proof(collection['type'],tenant if verified else None))
