"""Pure selected AWS workload source reference and S3 content consumer."""
from copy import deepcopy
import re
from peaso.collectors import aws_workload_referenced_source_indicators as work
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from . import aws_s3_selected_source_secret_review_20261020 as s3_check

DECLARATIONS=[{'id':work.CHECK,'provider':'aws','category':'exposure','kind':work.KIND,
    'finding_type':'secrets','ui_group':'Secrets','severity':'high','requirements':[],
    'dependencies':['aws_account',work.KIND],'allow_incomplete_failure':True,
    'title':'Selected workload referenced source has no detected secrets',
    'remediation':'Remove confirmed exposed credentials from the selected source and rotate them.',
    'scope':'Exact selected native workload reference and bounded S3 object or archive members; no runtime execution claim.'}]


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if ctx['provider']!='aws' or s3.SCOPE.fullmatch(scope) is None or meta[work.KIND+'_authorized'] is not True:
            raise ValueError()
        collection,=[c for c in index['collections'][work.KIND] if c.get('scope')==scope]
        rows=collection['items'];selected=meta[work.KIND+'_selection'][scope]
        if (collection['status'] not in ('collected','partial') or not isinstance(rows,list) or len(rows)>work.MAX_TARGETS
                or len({r['id'] for r in rows})!=len(rows) or set(r['id'] for r in rows)!=set(selected)
                or sum(r==item for r in rows)!=1):raise ValueError()
        ident=item['id'];m=item[work.MARKER]
        expected={'schema','identity','scope','profile','capture','associated',
                'native_request','native_after_request','association','association_coherent','s3_identity','s3_item'}
        if m.get('profile')=='sagemaker_training_script':expected.add('entry_member')
        if (ident not in selected or set(m)!=expected
                or m['schema']!=work.SCHEMA or m['identity']!=ident or m['scope']!=scope
                or m['profile'] not in work.PROFILES or m['capture']!=meta[work.KIND+'_capture']
                or item['_provenance']!={'scope':scope,'capture':m['capture']}
                or m['associated'] is not True or type(m['association_coherent']) is not bool
                or any(not isinstance(m[k],str) or not re.fullmatch('[0-9a-f]{64}',m[k]) for k in ('native_request','association'))
                or m['profile']=='sagemaker_training_script' and (not isinstance(m['entry_member'],str)
                    or not re.fullmatch('[0-9a-f]{64}',m['entry_member']))
                or not isinstance(m['s3_identity'],str) or m['s3_identity'] not in meta[s3.KIND+'_selection'][scope]):
            raise ValueError()
        source=m['s3_item']
        if not isinstance(source,dict) or source.get('id')!=m['s3_identity']:raise ValueError()
        native_meta=deepcopy(meta)
        native_meta[s3.KIND+'_selection'][scope]=[m['s3_identity']]
        refs=source[s3.MARKER]['source_requests']
        native_meta[s3.KIND+'_receipts']=[r for r in meta[s3.KIND+'_receipts'] if r.get('id') in refs]
        native_index={'context':{**ctx,'metadata':native_meta},'collections':{s3.KIND:[{
            'scope':scope,'service':'s3','status':'collected' if collection['status']=='collected' else 'partial','items':[source]}]}}
        status,evidence=s3_check.evaluate(source,native_index)
        if status=='FAIL':
            return 'FAIL',{'observed':'A likely secret was found in the selected workload source. Its value is hidden.',
                'secret_leaks':evidence['secret_leaks'],'complete':False,'coverage':'selected_source_positive','profile':m['profile']}
        coherent=(m['association_coherent'] is True and isinstance(m['native_after_request'],str)
            and re.fullmatch('[0-9a-f]{64}',m['native_after_request']) is not None)
        entry_present=(m['profile']!='sagemaker_training_script' or any(
            p.get('path')==m['s3_identity']+'.member:'+m['entry_member'] and p.get('complete') is True
            for p in source[s3.MARKER].get('parts',()) if isinstance(p,dict)))
        if status=='PASS' and coherent and entry_present:
            return 'PASS',{'observed':'Both detectors found no supported secret in the inspected source, and its workload reference remained unchanged.',
                'secret_leaks':[],'complete':True,'coverage':'selected_source_complete','profile':m['profile']}
        missing=('The declared entry script is absent or incomplete in the selected S3 archive.' if not entry_present
            else 'The selected native source reference changed or lacks a complete after-read record.' if not coherent
            else 'The selected S3 archive contains unsupported or incomplete content.')
        return 'UNKNOWN',{'observed':missing,
            'complete':False,'coverage':'incomplete','profile':m['profile']}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError):
        return 'UNKNOWN',{'observed':'The selected workload has no consistent S3 source association; its content could not be assessed.',
            'complete':False,'coverage':'unbound'}


def install(register):
    from . import CHECKS
    if any(c.id==work.CHECK for c in CHECKS):return
    from .fixtures import CASES
    from pathlib import Path
    import json
    native_cases=json.loads(Path(__file__).with_name('aws_workload_referenced_source_review_cases.json').read_text())
    if set(native_cases)!={work.CHECK} or work.CHECK in CASES:
        raise RuntimeError('Referenced source native fixture collision or absence')
    CASES[work.CHECK]=native_cases[work.CHECK]
    d=DECLARATIONS[0]
    register(work.CHECK,'aws','exposure',work.KIND,d['title'],'high','security_configuration',d['remediation'],
        dependencies=['aws_account',work.KIND],allow_incomplete_failure=True)(evaluate)
