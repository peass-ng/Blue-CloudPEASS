"""Selected Databricks SOURCE, FILE, or task-run output bytes."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks, KINGFISHER_VERSION, TRUFFLEHOG_VERSION
from peaso.collectors import azure_databricks_notebook_secret_indicators as source

DECLARATION = dict(id=source.CHECK,provider='azure',category='exposure',kind=source.KIND,finding_type='secrets',severity='high',
    requirements=[],dependencies=[source.KIND],allow_incomplete_failure=True,ui_group='Secrets',
    title='Selected Databricks workspace content has no detected secrets',
    remediation='Remove confirmed credential literals from selected content and rotate exposed credentials. Use supported secret references.',
    scope='Captured bytes from exact selected notebook SOURCE, workspace FILE, or terminal task-run output only. No whole-workspace, repository, execution or history assertion.')


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
                or type(m['complete'])is not bool or m['format']not in('SOURCE','RAW','NOTEBOOK_RESULT','TASK_LOGS')
                or m['consistency']!=('status_bound_file_export_only'if m['format']=='RAW'else
                    'selected_terminal_task_output_only'if m['format']in('NOTEBOOK_RESULT','TASK_LOGS')else'point_in_time_export_only')
                or m['language'] not in ({'TEXT'} if m['format']!='SOURCE' else source.LANGUAGES) or m['verification']!='not_attempted'
                or item['_provenance']['scope']!=scope or item['_provenance']['capture']!=capture
                or any(not isinstance(m[k],str)or not re.fullmatch('[0-9a-f]{64}',m[k])for k in('workspace_binding','object_binding'))):raise ValueError()
        refs=m['source_requests'];ledger=meta[kind+'_receipts']
        is_run=m['format']in('NOTEBOOK_RESULT','TASK_LOGS')
        operations=(('subscription','workspace_before','parent_before','task_before','output','task_after','parent_after','workspace_after') if is_run
            else ('subscription','workspace','status_before','export','status_after'))
        if (not isinstance(refs,list)or len(refs)!=len(operations) or len(set(refs))!=len(operations) or item['_provenance']['source_requests']!=refs
                or not isinstance(ledger,list)or not 1<=len(ledger)<=source.MAX_CALLS or len({r['id']for r in ledger})!=len(ledger)):raise ValueError()
        receipts=[]
        for ref,operation in zip(refs,operations):
            receipt,=[r for r in ledger if r.get('id')==ref];native=operation not in('subscription','workspace','workspace_before','workspace_after')
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
                or len({r['host_binding']for r in (receipts[2:-1] if is_run else receipts[2:])})!=1
                or receipts[1]['host_binding']==receipts[2]['host_binding']):raise ValueError()
        if is_run:
            if (receipts[1]['host_binding']!=receipts[-1]['host_binding']
                    or receipts[1]['request_digest']!=receipts[-1]['request_digest']
                    or receipts[2]['request_digest']!=receipts[6]['request_digest']
                    or receipts[3]['request_digest']!=receipts[5]['request_digest']
                    or receipts[4]['request_digest']in(receipts[2]['request_digest'],receipts[3]['request_digest'])):raise ValueError()
        elif receipts[2]['request_digest']!=receipts[4]['request_digest']or receipts[3]['request_digest']==receipts[2]['request_digest']:raise ValueError()
        part,=m['parts']
        if set(part)!={'bytes','engines','complete'}or type(part['bytes'])is not int or not 1<=part['bytes']<=source.MAX_CONTENT or type(part['complete'])is not bool:raise ValueError()
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION};engines=part['engines']
        if (not isinstance(engines,list)or len(engines)!=2 or {e['engine']for e in engines}!=set(versions)
                or any(set(e)!={'engine','version','status'}or e['version']!=versions[e['engine']]or e['status']not in('complete','unavailable')for e in engines)
                or part['complete']!=all(e['status']=='complete'for e in engines)):raise ValueError()
        leaks=m['leaks'];trusted={e['engine']for e in engines if e['status']=='complete'}
        if (not isinstance(leaks,list)or merge_leaks(leaks)!=leaks or len(leaks)>source.MAX_LEAKS or sum(len(l['locations'])for l in leaks)>source.MAX_LOCATIONS
                or any(not re.fullmatch('[0-9a-f]{64}',l['fingerprint'])or not l['detectors']or not l['locations']
                    or any(d['engine']not in trusted for d in l['detectors'])or any(loc['path']!=ident+('.task_output'if is_run else'.workspace_file'if m['format']=='RAW'else'.notebook_source')for loc in l['locations'])for l in leaks)):raise ValueError()
        complete=bool(m['complete']and part['complete']and own['status']=='collected'and set(ids)==set(selected)
            and all(o.get(source.MARKER,{}).get('complete')is True for o in own['items']))
        if not leaks and not complete:raise ValueError()
        content=('notebook result' if m['format']=='NOTEBOOK_RESULT' else 'task logs' if m['format']=='TASK_LOGS' else
            'workspace file' if m['format']=='RAW' else 'notebook SOURCE')
        observed=(f'The selected {content} contained a likely secret whose value is hidden.\n'
            'The value may allow someone with access to it to use the linked account or service.\n'
            'That could expose people or their data if the credential is active.' if leaks else
            f'The selected {content} contained no recorded secret indicator.\n'+
            ('Its captured bytes may be less likely to expose a credential.\n'
             'Other task output could still expose people or their data.' if is_run else
             'The content may change after this capture.\n'
             'A later exposed credential could put people or their data at risk.'))
        if not complete:observed=(f'The selected {content} contained a likely secret whose value is hidden.\n'
            'Other selected content or a detector was incomplete.\n'
            'The value may expose people or their data if it is usable.')
        return('FAIL'if leaks else'PASS'),{'observed':observed,'secret_leaks':deepcopy(leaks),'complete':complete,
            'coverage':('selected_task_output_only'if is_run else'selected_workspace_content_export_only')if complete else'incomplete_selected_content',
            'immutable_revision_proven':False,'credential_validation':'not_attempted','parts':deepcopy(m['parts'])}
    except(KeyError,TypeError,ValueError,AttributeError,IndexError):
        return'UNKNOWN',{'complete':False,'coverage':'incomplete_selected_content','immutable_revision_proven':False,
            'observed':'The selected Databricks content had no complete, bound bytes recorded.\nIts exact source, file, or task output remains unknown.\nA credential in those bytes could expose people or their data.'}


def evaluate(item,index):return _evaluate(item,index)
