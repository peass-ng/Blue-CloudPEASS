"""Read-only ARM custom-role consumers over all authorized assignable scopes."""
from datetime import datetime,timezone
from concurrent.futures import ThreadPoolExecutor
from peaso.azure_unused_arm_role_contract import ARM,KIND,META,SCHEMA,REPORTS,MAX_ROWS,MG,scope,subscription,path,project,validate_read,guid


def collect(reader,request,scopes,wanted,transport,credential_context_id,customer_context_id):
    if KIND not in wanted:return
    from .azure import _safe_error,AzureReadError
    targets=[c for c in reader.collections if c['type']=='role_definition']
    try:
        tenant=guid(getattr(transport,'verified_tenant',None))
        if guid(getattr(transport,'tenant',None))!=tenant:raise ValueError('ARM authentication tenant is unresolved')
    except ValueError as exc:
        for c in targets:reader.unavailable(KIND,c['scope'],'Microsoft.Authorization',exc)
        return
    proof={'schema':SCHEMA,'endpoint':'native-unused-arm-role-projection','read_only':True,'tenant_verified':True,'tenant_id':tenant,
        'credential_context_id':credential_context_id,'customer_context_id':customer_context_id,'observed_at':datetime.now(timezone.utc).isoformat()}
    selected={scope(s) for s in scopes};assignable=set();need=False
    for c in targets:
        for row in c['items']:
            props=row.get('properties',{})
            if props.get('type')!='CustomRole':continue
            need=True
            values=props.get('assignableScopes')
            if not isinstance(values,list):continue
            for value in values:
                try:assignable.add(scope(value))
                except ValueError:continue  # Evaluator retains the malformed role as UNKNOWN.
    def one_binding(sc):
        version='2020-05-01' if sc.startswith(MG) else '2022-12-01'
        result={'scope':sc,'path':sc,'api_version':version,'method':'GET','body':None,'audience':ARM,'status':'not_collected'}
        try:
            value=reader.call(request,ARM+sc+'?api-version='+version,audience=ARM,body=None)
            if not isinstance(value,dict) or scope(value.get('id'))!=sc:raise ValueError('ARM owning-scope identity disagrees')
            actual=value.get('properties',{}).get('tenantId') if sc.startswith(MG) else value.get('tenantId')
            if guid(actual)!=tenant:raise ValueError('ARM owning scope belongs to another tenant')
            if not sc.startswith(MG) and guid(value.get('subscriptionId'))!=sc.rsplit('/',1)[-1]:raise ValueError('subscription ID disagrees')
            result.update(status='collected',tenant_id=tenant)
        except Exception as exc:
            status,error=_safe_error(exc);result.update(status=status,error={**error,'cause_status':status})
        return result
    binding_scopes=sorted(selected|{s for s in assignable if s.startswith(MG)}) if need else []
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:bindings={r['scope']:r for r in pool.map(one_binding,binding_scopes)}
    hierarchies={}
    for sc in sorted(s for s in assignable if s.startswith(MG)):
        source={'scope':sc,'path':sc+'/descendants','api_version':'2020-05-01','audience':ARM,'method':'GET','body':None,'filter':None,'status':'not_collected','items':[],'integrity_error':False}
        if bindings.get(sc,{}).get('status')=='collected':
            try:
                def read(url,*,audience=ARM,body=None):
                    validate_read(url,source['path'],'2020-05-01',audience=audience,body=body)
                    return request(url,audience=audience,body=body)
                seen=set()
                for page in reader.pages(read,ARM+source['path']+'?api-version=2020-05-01'):
                    for row in page:
                        sid=scope(row.get('id'));parent=scope(row.get('properties',{}).get('parent',{}).get('id'))
                        typ='microsoft.management/managementgroups/subscriptions' if subscription(sid) else 'microsoft.management/managementgroups'
                        if str(row.get('type','')).casefold()!=typ or sid==sc or sid in seen:raise ValueError('management-group descendant identity is inconsistent')
                        if len(source['items'])>=MAX_ROWS:raise AzureReadError('resource_limit')
                        seen.add(sid);source['items'].append({'id':sid,'parent':parent})
                source['status']='collected' if source['items'] else 'empty'
            except Exception as exc:
                status,error=_safe_error(exc);source.update(status='partial' if source['items'] else status,error={**error,'cause_status':status},integrity_error=isinstance(exc,ValueError))
        else:source.update(status=bindings.get(sc,{}).get('status','unknown'),error=bindings.get(sc,{}).get('error',{}))
        hierarchies[sc]=source
    authorized=set(selected if need else ())
    unresolved=[]
    for sc in sorted(assignable):
        parent=subscription(sc)
        if parent in selected and bindings.get(parent,{}).get('status')=='collected':authorized.add(sc)
        elif sc.startswith(MG):
            tree=hierarchies[sc]
            children={r['id']:r['parent'] for r in tree['items']}
            complete=tree['status'] in ('collected','empty') and not tree['integrity_error']
            for sid in children:
                seen=set();current=sid
                while current!=sc:
                    if current in seen or current not in children:complete=False;break
                    seen.add(current);current=children[current]
            subs={s for s in children if subscription(s)}
            if complete and subs<=selected and all(bindings.get(s,{}).get('status')=='collected' for s in subs):
                authorized.add(sc)
                # At-scope native Lists plus selected subscription Lists cover all
                # descendant management groups and subscriptions independently.
                authorized.update(s for s in children if s.startswith(MG))
            else:unresolved.append(sc)
        else:unresolved.append(sc)
    # Failed subscription bindings cannot authorize even a same-name scoped read.
    authorized={s for s in authorized if (subscription(s) is None or bindings.get(subscription(s),{}).get('status')=='collected')}
    def one_source(job):
        sc,name=job;p,version=path(sc,name)
        result={'scope':sc,'name':name,'path':p,'api_version':version,'audience':ARM,'method':'GET','body':None,'filter':None,
            'status':'not_collected','items':[],'integrity_error':False}
        seen=set()
        try:
            def read(url,*,audience=ARM,body=None):
                validate_read(url,p,version,audience=audience,body=body)
                return request(url,audience=audience,body=body)
            for page in reader.pages(read,ARM+p+'?api-version='+version):
                for raw in page:
                    row=project(name,raw,sc);identity=row['id'].casefold()
                    if identity in seen:raise ValueError('ARM consumer identity is duplicated')
                    if len(result['items'])>=MAX_ROWS or reader.budget.max_items is not None and len(result['items'])>=reader.budget.max_items:raise AzureReadError('resource_limit')
                    seen.add(identity);result['items'].append(row)
            result['status']='collected' if result['items'] else 'empty'
        except Exception as exc:
            status,error=_safe_error(exc);result.update(status='partial' if result['items'] else status,error={**error,'cause_status':status},integrity_error=isinstance(exc,ValueError))
        return result
    jobs=[(sc,name) for sc in sorted(authorized) for name in REPORTS]
    with ThreadPoolExecutor(max_workers=reader.workers) as pool:reports=list(pool.map(one_source,jobs))
    record={'schema':SCHEMA,'selected_subscriptions':sorted(selected),'bindings':bindings,'hierarchies':hierarchies,'sources':reports,
        'unresolved_assignable_scopes':unresolved,'_provenance':proof}
    reader.unused_arm_role_metadata={META:record}
    # References keep the large shared source frame once in snapshot metadata,
    # while the normal per-scope dependency inventory stays independently typed.
    for c in targets:
        sc=c['scope'];item={'id':sc.rstrip('/')+'/unusedArmRoleEvidence','schema':SCHEMA,'metadata_key':META,'_provenance':dict(proof)}
        reader.collections.append({'type':KIND,'scope':sc,'service':'Microsoft.Authorization','status':'collected','items':[item],'_provenance':dict(proof)})
