"""Pure unregistered selected Command-job declaration check; not referenced source."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_ml_selected_job_secret_indicators as source

DECLARATION = dict(id=source.CHECK,provider='azure',category='exposure',kind=source.KIND,finding_type='secrets',severity='high',
    requirements=[],dependencies=[source.KIND],allow_incomplete_failure=True,ui_group='Secrets',
    title='Selected Machine Learning Command-job literals have no detected secrets',
    remediation='Remove credential literals from job declarations and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
    scope='Returned command text and explicit literal environment variables of selected native Command jobs only. No source download, expanded reference, image, execution or effective deployment claim.')


def _evaluate(item,index):
    try:
        kind=source.KIND;ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure'or not source.SCOPE.fullmatch(scope)or meta[kind+'_authorized']is not True
                or meta['context_binding']!='scan_local'or meta.get('tenant_verified')is not True
                or not isinstance(meta.get('tenant_id'),str)or not re.fullmatch(source.GUID,meta['tenant_id'],re.I)):raise ValueError()
        capture=meta[kind+'_capture'];selected=meta[kind+'_selection'][scope]
        if (not re.fullmatch(r'ml-command-job-capture:[0-9a-f]{32}',capture)or not isinstance(selected,list)
                or not 1<=len(selected)<=source.MAX_TARGETS or len(set(selected))!=len(selected)
                or any(not isinstance(x,str)or not re.fullmatch(kind+':[0-9a-f]{64}',x)for x in selected)):raise ValueError()
        own,=[c for c in index['collections'][kind]if c.get('scope')==scope]
        if own['status']not in('collected','partial')or own['service']!=source.SERVICE:raise ValueError()
        ids=[o['id']for o in own['items']]
        if len(set(ids))!=len(ids)or any(x not in selected for x in ids)or sum(o==item for o in own['items'])!=1:raise ValueError()
        for obj in(own,item):
            p=obj['_provenance']
            if any(not isinstance(meta.get(k),str)or not meta[k]or p.get(k)!=meta[k]for k in('credential_context_id','customer_context_id')):raise ValueError()
        ident=item['id'];m=item[source.MARKER]
        if (set(m)!={'schema','identity','scope','capture','complete','projection_complete','job_type','workspace_binding','declared_references','parts','leaks','source_requests','verification'}
                or m['schema']!=source.SCHEMA or m['identity']!=ident or m['scope']!=scope or m['capture']!=capture
                or m['job_type']!='Command'or type(m['complete'])is not bool or type(m['projection_complete'])is not bool
                or m['verification']!='not_attempted'or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or not isinstance(m['workspace_binding'],str)or not re.fullmatch('[0-9a-f]{64}',m['workspace_binding'])
                or not isinstance(m['declared_references'],dict)or not set(m['declared_references'])<={'codeId','environmentId'}
                or any(not isinstance(v,str)or not re.fullmatch('[0-9a-f]{64}',v)for v in m['declared_references'].values())):raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts']
        if (not isinstance(refs,list)or len(refs)!=3 or len(set(refs))!=3 or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list)or not 1<=len(ledger)<=source.MAX_CALLS or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        for ref,operation in zip(refs,('subscription','workspace','job')):
            receipt,=[r for r in ledger if r.get('id')==ref]
            if (set(receipt)!={'id','identity','scope','operation','method','host_class','host_binding','audience','request_digest','capture','status','bytes','tenant_id','identity_bound','etag_binding'}
                    or not re.fullmatch(r'declaration-read-[1-9][0-9]*',ref)or receipt['identity']!=ident or receipt['scope']!=scope
                    or receipt['operation']!=operation or receipt['method']!='GET'or receipt['host_class']!='arm'
                    or not re.fullmatch('[0-9a-f]{64}',receipt['host_binding'])or receipt['audience']!=source.ARM
                    or not re.fullmatch('[0-9a-f]{64}',receipt['request_digest'])or receipt['capture']!=capture
                    or receipt['status']!='collected'or receipt['identity_bound']is not True or receipt['etag_binding']is not None
                    or str(receipt['tenant_id']).casefold()!=meta['tenant_id'].casefold()or type(receipt['bytes'])is not int or not 1<=receipt['bytes']<=source.MAX_WIRE):raise ValueError()
        part,=m['parts']
        if set(part)!={'bytes','engines','complete'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION};engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(l['locations'])for l in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',l['fingerprint'])or not l['detectors']or not l['locations']
                    or any(d['engine']not in trusted for d in l['detectors'])or any(loc['path']!=ident+'.command_environment_literals'for loc in l['locations'])for l in leaks)):raise ValueError()
        complete=bool(m['complete']and m['projection_complete']and part['complete']and own['status']=='collected'and set(ids)==set(selected)
            and all(o.get(source.MARKER,{}).get('complete')is True for o in own['items']))
        if not leaks and not complete:raise ValueError()
        observed=('A likely secret was detected in selected Command-job literals. Its value is hidden and was not validated.'if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected command text and literal environment variables. Referenced code and images were not inspected.')
        if not complete:observed+=' Inspection is incomplete.'
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,
            'coverage':'selected_command_environment_declarations_only'if complete else'incomplete_selected_declarations',
            'referenced_sources_inspected':False,'credential_validation':'not_attempted','parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):
        return'UNKNOWN',{'complete':False,'coverage':'incomplete_selected_declarations','referenced_sources_inspected':False,
            'observed':'Selected Command-job literals were unavailable, unbound or incompletely inspected. A clean declaration result cannot be established.'}


def evaluate(item,index):return _evaluate(item,index)
