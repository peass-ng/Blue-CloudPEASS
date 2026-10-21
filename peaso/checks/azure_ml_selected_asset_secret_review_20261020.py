"""Two pure unregistered source-limited ML optional controls; no inherited mappings."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION
from peaso.collectors import azure_ml_selected_asset_secret_indicators as source

DECLARATIONS=[dict(id=p['check'],provider='azure',category='exposure',kind=p['kind'],finding_type='secrets',severity='high',
    requirements=[],dependencies=[p['kind']],allow_incomplete_failure=True,ui_group='Secrets',title=p['title'],
    remediation='Remove credential literals from the selected source and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
    scope='Returned inline Conda text or one explicitly selected Dockerfile bound to an environment build context, datastore and blob; no full context or image inspection.'if name=='environment'else'Exactly selected file bound to a native code asset URI and datastore plus explicit storage parent; no original/executed/version-creation bytes or complete code-folder assertion.')for name,p in source.PROFILES.items()]


def _evaluate(profile,item,index):
    try:
        p=source.PROFILES[profile];kind=p['kind'];ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure'or not source.SCOPE.fullmatch(scope)or meta[kind+'_authorized']is not True
                or meta['context_binding']!='scan_local'or meta.get('tenant_verified')is not True
                or not isinstance(meta.get('tenant_id'),str)or not re.fullmatch(source.GUID,meta['tenant_id'],re.I)):raise ValueError()
        capture=meta[kind+'_capture'];selected=meta[kind+'_selection'][scope]
        if not re.fullmatch('ml-asset-capture:[0-9a-f]{32}',capture)or not isinstance(selected,list)or not 1<=len(selected)<=source.MAX_TARGETS or len(set(selected))!=len(selected)or any(not isinstance(x,str)or not re.fullmatch(kind+':[0-9a-f]{64}',x)for x in selected):raise ValueError()
        own,=[c for c in index['collections'][kind]if c.get('scope')==scope]
        ids=[r['id']for r in own['items']]
        if own['status']not in('collected','partial')or own['service']!=source.SERVICE or len(set(ids))!=len(ids)or any(x not in selected for x in ids)or sum(o==item for o in own['items'])!=1:raise ValueError()
        for obj in(item,own):
            if any(not isinstance(meta.get(k),str)or not meta[k]or obj['_provenance'].get(k)!=meta[k]for k in('credential_context_id','customer_context_id')):raise ValueError()
        ident=item['id'];m=item[source.MARKER]
        job_bound=profile=='code'and 'job_binding'in m
        expected={'schema','identity','scope','capture','profile','complete','native_complete','workspace_binding','association_binding','object_binding','storage_service','immutable_source_proven','parts','leaks','source_requests','verification'}
        if (set(m)!=expected|({'job_binding'}if job_bound else set())
                or ident not in selected or m['schema']!=source.SCHEMA or m['identity']!=ident or m['scope']!=scope or m['capture']!=capture or m['profile']!=profile
                or type(m['complete'])is not bool or m['native_complete']is not True or m['immutable_source_proven']is not False or m['verification']!='not_attempted'
                or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or any(not isinstance(m[k],str)or not re.fullmatch('[0-9a-f]{64}',m[k])for k in('workspace_binding','association_binding'))):raise ValueError()
        if job_bound and (not isinstance(m['job_binding'],str)or not re.fullmatch('[0-9a-f]{64}',m['job_binding'])):raise ValueError()
        build=profile=='environment'and m['storage_service']=='blob'
        if profile=='code'or build:
            if not isinstance(m['object_binding'],str)or not re.fullmatch('[0-9a-f]{64}',m['object_binding'])or m['storage_service']not in(('blob',)if build else('blob','file')):raise ValueError()
        elif m['object_binding']is not None or m['storage_service']is not None:raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts'];operations=source.operations(profile,build,job_bound)
        allowed_lengths=(len(operations)-1,len(operations))if job_bound else(len(operations),)
        if (not isinstance(refs,list)or len(refs)not in allowed_lengths
                or len(set(refs))!=len(refs)or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list)or not len(refs)<=len(ledger)<=source.MAX_CALLS or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        principals=set()
        job_stable=not job_bound
        for ref,operation in zip(refs,operations):
            r,=[r for r in ledger if r.get('id')==ref]
            data=operation in('properties_before','content','properties_after');stored=data or operation=='account'
            version='2022-12-01'if operation=='subscription'else source.WORKSPACE_API if operation.startswith('workspace_')else '2024-04-01'if operation.startswith('job_')else source.storage.DATA_VERSION if data else source.storage.ARM_VERSION if operation=='account'else source.API
            trailing=operation=='job_after' and bool(m['leaks'])
            if (set(r)!={'id','identity','scope','capture','operation','method','origin','request','version','tenant','principal','bound','status','bytes','native_request'}
                    or not re.fullmatch(('storage-source-read:'if stored else'ml-asset-read:')+'[0-9a-f]{32}',ref)
                    or r['identity']!=ident or r['scope'].casefold()!=scope.casefold()or r['capture']!=capture or r['operation']!=operation
                    or r['method']!=('HEAD'if operation.startswith('properties_')else'GET')or r['version']!=version
                    or (r['origin']!=m['storage_service']if data else r['origin']!='arm')
                    or (r['bound'] is not True or r['status']!='collected') and not trailing
                    or r['status']not in('collected','unavailable')
                    or (not isinstance(r['tenant'],str)or r['tenant'].casefold()!=meta['tenant_id'].casefold()) and not trailing
                    or (not isinstance(r['principal'],str)or not re.fullmatch('storage-source-principal:[0-9a-f]{64}',r['principal'])) and not trailing
                    or not isinstance(r['request'],str)or not re.fullmatch('[0-9a-f]{64}',r['request'])
                    or r['native_request'] is not None and not re.fullmatch('[0-9a-f]{64}',r['native_request'])
                    or r['status']=='collected' and not isinstance(r['native_request'],str)
                    or type(r['bytes'])is not int or (r['bytes']!=0 if operation.startswith('properties_')else not 1<=r['bytes']<=(source.MAX_CONTENT if data else source.MAX_ARM)) and not trailing):raise ValueError()
            if r['principal'] is not None:principals.add(r['principal'])
            if operation=='job_after':job_stable=r['bound'] is True and r['status']=='collected'
        if len(principals)!=1:raise ValueError()
        part,=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if set(part)!={'bytes','complete','engines'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(l['locations'])for l in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',l['fingerprint'])or not l['detectors']or not l['locations']or any(d['engine']not in trusted for d in l['detectors'])or any(loc['path']!=ident+'.'+profile for loc in l['locations'])for l in leaks)):raise ValueError()
        complete=bool(m['complete']and job_stable and part['complete']and own['status']=='collected'and set(ids)==set(selected)and all(o.get(source.MARKER,{}).get('complete')is True for o in own['items']))
        if not leaks and not complete:raise ValueError()
        label='Dockerfile'if build else'inline Conda text'if profile=='environment'else'code source file referenced by the selected Command job'if job_bound else'associated code source file'
        if leaks:
            observed='The selected '+label+' contains a likely secret literal.\nIts hidden value was not validated but may allow access to data or services.\nPeople or their data could be exposed if it is valid.'
        else:
            observed='The selected '+label+' contains no recorded secret indicator.\nIts captured text may be less likely to expose a credential.\nOther '+('environment'if profile=='environment'else'code asset')+' content could still expose people or their data.'
        if not complete:observed='The selected '+label+' contains a likely secret literal.\nIts hidden value was not validated but may allow access to data or services.\nThe selected text or detector output is incomplete, so further risk remains unclear.'
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,'coverage':'selected_captured_ml_asset_text_only'if complete else'incomplete_selected_ml_asset_text','immutable_source_proven':False,'credential_validation':'not_attempted','parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):return'UNKNOWN',{'complete':False,'observed':'The selected ML asset text or its storage binding was unavailable.\nThe exact source bytes therefore remain unclear.\nA secret in the selected source may expose data if that source is used.'}


def environment(item,index):return _evaluate('environment',item,index)


def code(item,index):return _evaluate('code',item,index)
