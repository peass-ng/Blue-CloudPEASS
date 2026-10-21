"""Pure configured Flex deployment-container archive consumer; no active package claim."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION
from peaso.collectors import azure_flex_deployment_archives_20261021 as source
from peaso.collectors import azure_selected_storage_secret_indicators as storage

DECLARATIONS=[{'id':source.CHECK,'provider':'azure','category':'exposure','kind':source.KIND,
    'finding_type':'secrets','ui_group':'Secrets','severity':'high','requirements':[],
    'dependencies':[source.KIND],'allow_incomplete_failure':True,
    'title':'Configured Flex deployment-container archives have no detected secrets',
    'remediation':'Remove confirmed exposed values from configured deployment archives and rotate the credentials.',
    'scope':'Selected Flex Function configured deployment container and bounded current ZIP archives; no active-package or running-code claim.'}]

def evaluate(item,index):
    try:
        context=index['context'];scope=context['scope'];meta=context['metadata'];m=item[source.MARKER]
        if (context['provider']!='azure' or not storage.SCOPE.fullmatch(scope)
                or meta[source.KIND+'_authorized'] is not True
                or item['id'] not in meta[source.KIND+'_selection'][scope]
                or m['schema']!=source.SCHEMA or m['identity']!=item['id'] or m['scope'].casefold()!=scope.casefold()
                or item['_provenance']!={'scope':m['scope'],'capture':m['capture']}
                or not re.fullmatch('flex-archives:[0-9a-f]{32}',m['capture'])
                or m['configured_container'] is not True
                or not isinstance(m['tenant'],str) or not re.fullmatch(storage.GUID,m['tenant'],re.I)
                or str(meta.get('tenant_id','')).casefold()!=m['tenant'].casefold()
                or meta.get('tenant_verified') is not True
                or not isinstance(m['principal'],str) or not re.fullmatch('storage-source-principal:[0-9a-f]{64}',m['principal'])
                or not isinstance(m['listing_locator'],str) or not re.fullmatch('flex-list:[0-9a-f]{64}',m['listing_locator'])
                or type(m['archive_count']) is not int or not 1<=m['archive_count']<=source.MAX_ARCHIVES
                or not isinstance(m['archives'],list) or len(m['archives'])>m['archive_count']
                or not isinstance(m['receipts'],list) or len(m['receipts'])>source.MAX_ARCHIVES*5+3):raise ValueError()
        collection,=[c for c in index['collections'][source.KIND] if c.get('scope')==scope]
        if (collection['status'] not in ('collected','partial') or collection['service']!='Microsoft.Web'
                or sum(row==item for row in collection['items'])!=1):raise ValueError()
        ids=[r['id'] for r in collection['items']]
        if len(ids)!=len(set(ids)) or set(ids)!=set(meta[source.KIND+'_selection'][scope]):raise ValueError()
        ledger=m['receipts'];by_ref={r['id']:r for r in ledger}
        if len(by_ref)!=len(ledger):raise ValueError()
        leaks=[];clean=True;seen=set()
        for child in m['archives']:
            ident=child['id'];b=child[storage.MARKER]
            if (ident in seen or b['schema']!=storage.SCHEMA or b['identity']!=ident or b['capture']!=m['capture']
                    or b['scope'].casefold()!=scope.casefold() or b['service']!='blob' or b['format']!='zip'
                    or b['selection_mode']!='current' or child['_provenance']['source_requests']!=b['source_requests']):raise ValueError()
            seen.add(ident)
            if b['native_complete'] is not True:
                if b['leaks'] or b['parts']:raise ValueError()
                clean=False
                continue
            if (b['tenant']!=m['tenant'] or b['principal']!=m['principal']
                    or len(b['source_requests'])!=5 or len(set(b['source_requests']))!=5):raise ValueError()
            operations=('subscription','account','properties_before','content','properties_after')
            for ref,op in zip(b['source_requests'],operations):
                r=by_ref.get(ref)
                if (not isinstance(r,dict) or not re.fullmatch('storage-source-read:[0-9a-f]{32}',ref)
                        or r.get('identity')!=ident or r.get('operation')!=op
                        or r.get('method')!=('HEAD' if op.startswith('properties_') else 'GET')
                        or r.get('status')!='collected' or r.get('bound') is not True
                        or r.get('http_status')!=200 or r.get('tenant')!=m['tenant']
                        or r.get('principal')!=m['principal']):raise ValueError()
            if (b['native_complete'] is not True or not isinstance(b['etag_locator'],str)
                    or not re.fullmatch('storage-source-etag:[0-9a-f]{64}',b['etag_locator'])):raise ValueError()
            parts=b['parts']
            if not isinstance(parts,list) or not 1<=len(parts)<=storage.MAX_MEMBERS:raise ValueError()
            for number,part in enumerate(parts,1):
                if (part.get('path')!=ident+'.file-'+str(number) or type(part.get('complete')) is not bool
                        or type(part.get('bytes')) is not int or not 1<=part['bytes']<=storage.MAX_MEMBER
                        or not isinstance(part.get('engines'),list) or len(part['engines'])!=2
                        or {e.get('engine') for e in part['engines']}!={'kingfisher','trufflehog'}
                        or any(e.get('version')!={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}[e['engine']]
                            or e.get('status') not in ('complete','unavailable') for e in part['engines'])
                        or part['complete']!=all(e['status']=='complete' for e in part['engines'])):raise ValueError()
            if merge_leaks([leak for part in parts for leak in part['leaks']])!=b['leaks']:raise ValueError()
            leaks.extend(b['leaks'])
            clean=clean and b['complete'] is True and all(p['complete'] for p in parts)
        merged=merge_leaks(leaks)
        complete=(m['complete'] is True and m['native_stable'] is True and m['listing_stable'] is True
                  and len(m['archives'])==m['archive_count'] and clean and not meta.get(source.KIND+'_redaction_incomplete',False))
        if merged:
            return 'FAIL',{'observed':"A likely secret was found in a ZIP archive in this Function's configured deployment container. Its value is hidden.",
                'secret_leaks':deepcopy(merged),'complete':False,'coverage':'configured_archive_positive'}
        if complete:
            return 'PASS',{'observed':'Both detectors found no supported secret in the inspected ZIP archives, and the configured deployment container remained unchanged.',
                'secret_leaks':[],'complete':True,'coverage':'configured_archive_complete'}
        return 'UNKNOWN',{'observed':'The configured deployment archives could not be fully inspected because their listing or content was incomplete or changed.',
            'complete':False,'coverage':'configured_archive_incomplete'}
    except (KeyError,ValueError,TypeError,AttributeError,IndexError):
        return 'UNKNOWN',{'observed':'The configured deployment container could not be associated with a complete listing and readable archives.',
            'complete':False,'coverage':'unbound'}

def install(register):
    from . import CHECKS
    from .fixtures import CASES
    from pathlib import Path
    import json
    if any(c.id==source.CHECK for c in CHECKS):return
    cases=json.loads(Path(__file__).with_name('azure_flex_deployment_archives_review_20261021_cases.json').read_text())
    if set(cases)!={source.CHECK} or source.CHECK in CASES:raise RuntimeError('Flex archive native fixture collision or absence')
    CASES[source.CHECK]=cases[source.CHECK]
    d=DECLARATIONS[0]
    register(source.CHECK,'azure','exposure',source.KIND,d['title'],'high','security_configuration',d['remediation'],
        dependencies=[source.KIND],allow_incomplete_failure=True)(evaluate)
