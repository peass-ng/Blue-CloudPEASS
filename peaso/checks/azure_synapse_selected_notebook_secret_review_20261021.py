"""Pure selected published Synapse notebook source control."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_synapse_selected_notebook_secret_indicators as source

DECLARATION=dict(id=source.CHECK,provider='azure',category='exposure',kind=source.KIND,finding_type='secrets',severity='high',
    requirements=[],dependencies=[source.KIND],allow_incomplete_failure=True,ui_group='Secrets',
    title='Selected Synapse notebook source has no detected secrets',
    remediation='Remove credential literals from the selected notebook source and rotate confirmed exposed credentials.',
    scope='Published source cells from one exact selected notebook; no outputs, attachments, Git branch, execution or workspace-wide claim.')

def evaluate(item,index):
    try:
        ctx=index['context'];meta=ctx['metadata'];scope=ctx['scope'];kind=source.KIND
        if (ctx['provider']!='azure'or not source.SCOPE.fullmatch(scope)or meta[kind+'_authorized']is not True
                or meta.get('context_binding')!='scan_local'or meta.get('tenant_verified')is not True
                or not isinstance(meta.get('tenant_id'),str)or not re.fullmatch(source.GUID,meta['tenant_id'],re.I)):raise ValueError()
        capture=meta[kind+'_capture'];selected=meta[kind+'_selection'][scope]
        if (not re.fullmatch('synapse-notebook-capture:[0-9a-f]{32}',capture)or not isinstance(selected,list)or not 1<=len(selected)<=source.MAX_TARGETS
                or len(set(selected))!=len(selected)or any(not isinstance(x,str)or not re.fullmatch(kind+':[0-9a-f]{64}',x)for x in selected)):raise ValueError()
        own,=[c for c in index['collections'][kind]if c.get('scope')==scope]
        if own['status']not in('collected','partial')or own['service']!=source.SERVICE:raise ValueError()
        ids=[o['id']for o in own['items']]
        if len(set(ids))!=len(ids)or any(x not in selected for x in ids)or sum(o==item for o in own['items'])!=1:raise ValueError()
        for obj in(own,item):
            p=obj['_provenance']
            if any(not isinstance(meta.get(k),str)or not meta[k]or p.get(k)!=meta[k]for k in('credential_context_id','customer_context_id')):raise ValueError()
        ident=item['id'];m=item[source.MARKER]
        if (set(m)!={'schema','identity','scope','capture','complete','native_complete','workspace_binding','notebook_binding','parts','leaks','source_requests','verification'}
                or m['schema']!=source.SCHEMA or m['identity']!=ident or m['scope']!=scope or m['capture']!=capture
                or type(m['complete'])is not bool or m['native_complete']is not True or m['verification']!='not_attempted'
                or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or any(not isinstance(m[k],str)or not re.fullmatch('[0-9a-f]{64}',m[k])for k in('workspace_binding','notebook_binding'))):raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts'];operations=('subscription','workspace_before','notebook_before','notebook_after','workspace_after')
        if (not isinstance(refs,list)or len(refs)!=len(operations)or len(set(refs))!=len(refs)
                or item['_provenance']['source_requests']!=refs or not isinstance(ledger,list)or not len(refs)<=len(ledger)<=source.MAX_CALLS
                or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        receipts=[]
        for ref,op in zip(refs,operations):
            r,=[r for r in ledger if r.get('id')==ref];native=op.startswith('notebook_')
            if (set(r)!={'id','identity','scope','capture','operation','method','host_class','host_binding','audience','request_digest','status','bytes','tenant_id','principal_binding','identity_bound','object_binding'}
                    or not re.fullmatch('synapse-notebook-read-[1-9][0-9]*',ref)or r['identity']!=ident or r['scope']!=scope or r['capture']!=capture
                    or r['operation']!=op or r['method']!='GET'or r['host_class']!=('synapse'if native else'arm')
                    or r['audience']!=(source.SYNAPSE if native else source.ARM)or r['status']!='collected'or r['identity_bound']is not True
                    or r['object_binding']!=(m['notebook_binding']if native else None)
                    or str(r['tenant_id']).casefold()!=meta['tenant_id'].casefold()or type(r['bytes'])is not int or not 1<=r['bytes']<=source.MAX_WIRE
                    or any(not isinstance(r[k],str)or not re.fullmatch('[0-9a-f]{64}',r[k])for k in('host_binding','request_digest','principal_binding'))):raise ValueError()
            receipts.append(r)
        if (len({r['principal_binding']for r in receipts})!=1 or len({r['host_binding']for r in(receipts[0],receipts[1],receipts[4])})!=1
                or receipts[2]['host_binding']!=receipts[3]['host_binding']or receipts[2]['host_binding']==receipts[1]['host_binding']
                or receipts[2]['request_digest']!=receipts[3]['request_digest']or receipts[1]['request_digest']!=receipts[4]['request_digest']):raise ValueError()
        part,=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if set(part)!={'bytes','engines','complete'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(x['locations'])for x in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',x['fingerprint'])or not x['detectors']or not x['locations']
                    or any(d['engine']not in trusted for d in x['detectors'])or any(loc['path']!=ident+'.notebook_source'for loc in x['locations'])for x in leaks)):raise ValueError()
        complete=bool(m['complete']and part['complete']and own['status']=='collected'and set(ids)==set(selected)
            and all(o.get(source.MARKER,{}).get('complete')is True for o in own['items']))
        if not leaks and not complete:raise ValueError()
        if leaks:
            observed='The selected Synapse notebook source contains a likely secret literal.\nIts hidden value was not validated but may allow access to data or services.\nPeople or their data could be exposed if it is valid.'
            if not complete:observed='The selected Synapse notebook source contains a likely secret literal.\nIts hidden value was not validated but may allow access to data or services.\nSource or detector coverage is incomplete, so further risk remains unclear.'
        else:
            observed='The selected Synapse notebook source cells contain no recorded secret indicator.\nThese captured cells may be less likely to expose a credential.\nOther notebook content could still expose people or their data.'
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,
            'coverage':'selected_published_notebook_source_only'if complete else'incomplete_selected_notebook_source','credential_validation':'not_attempted','parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):
        return'UNKNOWN',{'complete':False,'coverage':'incomplete_selected_notebook_source',
            'observed':'The selected Synapse notebook source or its workspace binding was unavailable.\nThe exact source bytes therefore remain unclear.\nA secret in those cells may expose data if the notebook is used.'}

def install():
    from . import register
    from .fixtures import CASES
    from pathlib import Path
    import json
    cases = json.loads(Path(__file__).with_name('azure_synapse_selected_notebook_secret_review_20261021_cases.json').read_text())
    if set(cases) != {source.CHECK} or source.CHECK in CASES:
        raise RuntimeError('Synapse notebook native fixture collision or absence')
    CASES[source.CHECK] = cases[source.CHECK]
    register(source.CHECK,'azure','exposure',source.KIND,DECLARATION['title'],'high','security_configuration',DECLARATION['remediation'],
        dependencies=[source.KIND],allow_incomplete_failure=True)(evaluate)
