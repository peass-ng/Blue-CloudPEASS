"""Pure unregistered selected notebook SOURCE check; no immutable revision or execution assertion."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_databricks_notebook_secret_indicators as source

DECLARATION = dict(id=source.CHECK,provider='azure',category='exposure',kind=source.KIND,finding_type='secrets',severity='high',
    requirements=[],dependencies=[source.KIND],allow_incomplete_failure=True,ui_group='Secrets',
    title='Selected Databricks notebook source has no detected secrets',
    remediation='Remove credential literals from notebook source and rotate confirmed exposed credentials. Use managed identities or supported secret references.',
    scope='Captured SOURCE bytes from exact selected notebook paths only. No immutable cell revision, execution, output, whole-workspace or deployment assertion.')


def _evaluate(item,index):
    try:
        kind=source.KIND;ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure'or not source.SCOPE.fullmatch(scope)or meta[kind+'_authorized']is not True
                or meta['context_binding']!='scan_local'or meta.get('tenant_verified')is not True
                or not isinstance(meta.get('tenant_id'),str)or not re.fullmatch(source.GUID,meta['tenant_id'],re.I)):raise ValueError()
        capture=meta[kind+'_capture'];selected=meta[kind+'_selection'][scope]
        if (not re.fullmatch(r'notebook-capture:[0-9a-f]{32}',capture)or not isinstance(selected,list)
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
        if (set(m)!={'schema','identity','scope','capture','complete','format','consistency','workspace_binding','object_binding','language','parts','leaks','source_requests','verification'}
                or m['schema']!=source.SCHEMA or m['identity']!=ident or m['scope']!=scope or m['capture']!=capture
                or type(m['complete'])is not bool or m['format']!='SOURCE'or m['consistency']!='point_in_time_export_only'
                or m['language']not in source.LANGUAGES or m['verification']!='not_attempted'
                or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or any(not isinstance(m[k],str)or not re.fullmatch('[0-9a-f]{64}',m[k])for k in('workspace_binding','object_binding'))):raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts']
        if (not isinstance(refs,list)or len(refs)!=5 or len(set(refs))!=5 or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list)or not 1<=len(ledger)<=source.MAX_CALLS or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        receipts=[]
        for ref,operation in zip(refs,('subscription','workspace','status_before','export','status_after')):
            receipt,=[r for r in ledger if r.get('id')==ref];native=operation in('status_before','export','status_after')
            if (set(receipt)!={'id','identity','scope','capture','operation','method','host_class','host_binding','audience','request_digest','status','bytes','tenant_id','principal_binding','identity_bound','object_binding'}
                    or not re.fullmatch(r'notebook-read-[1-9][0-9]*',ref)or receipt['identity']!=ident or receipt['scope']!=scope
                    or receipt['operation']!=operation or receipt['method']!='GET'or receipt['host_class']!=('databricks'if native else'arm')
                    or receipt['audience']!=(source.DATABRICKS if native else source.ARM)
                    or any(not isinstance(receipt[k],str)or not re.fullmatch('[0-9a-f]{64}',receipt[k])for k in('host_binding','request_digest','principal_binding'))
                    or receipt['capture']!=capture or receipt['status']!='collected'or receipt['identity_bound']is not True
                    or receipt['object_binding']!=(m['object_binding']if native else None)
                    or str(receipt['tenant_id']).casefold()!=meta['tenant_id'].casefold()or type(receipt['bytes'])is not int or not 1<=receipt['bytes']<=source.MAX_WIRE):raise ValueError()
            receipts.append(receipt)
        if (len({r['principal_binding']for r in receipts})!=1 or receipts[0]['host_binding']!=receipts[1]['host_binding']
                or len({r['host_binding']for r in receipts[2:]})!=1 or receipts[1]['host_binding']==receipts[2]['host_binding']
                or receipts[2]['request_digest']!=receipts[4]['request_digest']or receipts[3]['request_digest']==receipts[2]['request_digest']):raise ValueError()
        part,=m['parts']
        if set(part)!={'bytes','engines','complete'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION};engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(l['locations'])for l in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',l['fingerprint'])or not l['detectors']or not l['locations']
                    or any(d['engine']not in trusted for d in l['detectors'])or any(loc['path']!=ident+'.notebook_source'for loc in l['locations'])for l in leaks)):raise ValueError()
        complete=bool(m['complete']and part['complete']and own['status']=='collected'and set(ids)==set(selected)
            and all(o.get(source.MARKER,{}).get('complete')is True for o in own['items']))
        if not leaks and not complete:raise ValueError()
        observed=('A likely secret was detected in the captured notebook source. Its value is hidden and was not validated.'if leaks else
            'Both offline detectors completed without detecting a supported secret in the captured notebook SOURCE bytes. This is a point-in-time export, not proof of an immutable revision or execution.')
        if not complete:observed+=' Inspection is incomplete.'
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,
            'coverage':'selected_notebook_export_only'if complete else'incomplete_selected_notebook_export',
            'immutable_revision_proven':False,'credential_validation':'not_attempted','parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):
        return'UNKNOWN',{'complete':False,'coverage':'incomplete_selected_notebook_export','immutable_revision_proven':False,
            'observed':'Selected notebook source was unavailable, unbound or incompletely inspected. A clean export result cannot be established.'}


def evaluate(item,index):return _evaluate(item,index)
