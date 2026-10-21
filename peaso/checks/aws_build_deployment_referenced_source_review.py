"""Pure selected AWS build or deployment source reference and S3 content consumer."""
from copy import deepcopy
import re
from peaso.secret_scanning import merge_leaks
from peaso.collectors import aws_build_deployment_referenced_source_indicators as work
from peaso.collectors import aws_s3_selected_source_secret_indicators as s3
from . import aws_s3_selected_source_secret_review_20261020 as s3_check

DECLARATIONS=[{'id':work.CHECK,'provider':'aws','category':'exposure','kind':work.KIND,
    'finding_type':'secrets','ui_group':'Secrets','severity':'high','requirements':[],
    'dependencies':['aws_account',work.KIND],'allow_incomplete_failure':True,
    'title':'Selected build or deployment referenced source has no detected secrets',
    'remediation':'Remove confirmed exposed credentials from the selected source and rotate them.',
    'scope':'Exact selected native build or deployment reference and bounded S3 object, archive members, or one CodeCommit file at the resolved build commit; no runtime execution claim.'}]


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
        if m.get('profile')=='codebuild_codecommit_source':
            if (ident not in selected or set(m)!={'schema','identity','scope','profile','capture','associated',
                    'native_request','native_after_request','association','association_coherent','codecommit_item'}
                    or m['schema']!=work.SCHEMA or m['identity']!=ident or m['scope']!=scope
                    or m['capture']!=meta[work.KIND+'_capture']
                    or item['_provenance']!={'scope':scope,'capture':m['capture']}
                    or m['associated'] is not True or type(m['association_coherent']) is not bool
                    or any(not isinstance(m[k],str) or re.fullmatch('[0-9a-f]{64}',m[k]) is None
                           for k in ('native_request','association'))):
                raise ValueError()
            source=m['codecommit_item']
            if not isinstance(source,dict) or set(source)!={'leaks','complete','inspected_bytes'} or type(source['complete']) is not bool:
                raise ValueError()
            leaks=merge_leaks(source['leaks'])
            if leaks:
                return 'FAIL',{'observed':'The selected CodeCommit file at the build’s resolved commit contains a likely secret.\n'
                    'That value may be copied into source artifacts.\n'
                    'People or data relying on the value could be exposed.',
                    'secret_leaks':leaks,'complete':False,'coverage':'selected_source_positive','profile':m['profile']}
            if (source['complete'] and m['association_coherent'] and collection['status']=='collected'
                    and isinstance(m['native_after_request'],str) and re.fullmatch('[0-9a-f]{64}',m['native_after_request'])):
                return 'PASS',{'observed':'The selected CodeCommit file at the build’s resolved commit has no supported secret match.\n'
                    'The build, repository, commit, and file identity remained the same during the read.\n'
                    'Other files or commits could contain different values.',
                    'secret_leaks':[],'complete':True,'coverage':'selected_source_complete','profile':m['profile']}
            return 'UNKNOWN',{'observed':'The selected CodeCommit file or its build and repository binding has an incomplete record.\n'
                'Its content or exact revision may differ from the selected source.\n'
                'Possible exposure in that file remains unclear.',
                'complete':False,'coverage':'incomplete','profile':m['profile']}
        if (ident not in selected or set(m)!={'schema','identity','scope','profile','capture','associated',
                'native_request','native_after_request','association','association_coherent','s3_identity','s3_item'}
                or m['schema']!=work.SCHEMA or m['identity']!=ident or m['scope']!=scope
                or m['profile'] not in work.PROFILES or m['capture']!=meta[work.KIND+'_capture']
                or item['_provenance']!={'scope':scope,'capture':m['capture']}
                or m['associated'] is not True or type(m['association_coherent']) is not bool
                or any(not isinstance(m[k],str) or not re.fullmatch('[0-9a-f]{64}',m[k]) for k in ('native_request','association'))
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
            return 'FAIL',{'observed':'The selected build or deployment artifact contains a likely secret.\n'
                'That value may be copied with the artifact.\n'
                'People or data relying on the value could be exposed.',
                'secret_leaks':evidence['secret_leaks'],'complete':False,'coverage':'selected_source_positive','profile':m['profile']}
        coherent=(m['association_coherent'] is True and isinstance(m['native_after_request'],str)
            and re.fullmatch('[0-9a-f]{64}',m['native_after_request']) is not None)
        if status=='PASS' and coherent:
            return 'PASS',{'observed':'The selected artifact has no supported secret match in the inspected content.\n'
                'Its recorded S3 location remained the same during the read.\n'
                'Other artifacts or versions could contain different values.',
                'secret_leaks':[],'complete':True,'coverage':'selected_source_complete','profile':m['profile']}
        return 'UNKNOWN',{'observed':'The selected artifact has an incomplete content or S3 location record.\n'
            'Its source bytes or exact version may differ from the selected artifact.\n'
            'Possible exposure in that artifact remains unclear.',
            'complete':False,'coverage':'incomplete','profile':m['profile']}
    except (ValueError,TypeError,KeyError,IndexError,AttributeError):
        return 'UNKNOWN',{'observed':'The selected build or deployment artifact has no consistent source location record.\n'
            'Its content cannot be tied to the recorded build or deployment reference.\n'
            'Possible exposure in that source remains unclear.',
            'complete':False,'coverage':'unbound'}


def install(register):
    from . import CHECKS
    if any(c.id==work.CHECK for c in CHECKS):return
    from .fixtures import CASES
    from pathlib import Path
    import json
    native_cases=json.loads(Path(__file__).with_name('aws_build_deployment_referenced_source_review_cases.json').read_text())
    if set(native_cases)!={work.CHECK} or work.CHECK in CASES:
        raise RuntimeError('Referenced source native fixture collision or absence')
    CASES[work.CHECK]=native_cases[work.CHECK]
    d=DECLARATIONS[0]
    register(work.CHECK,'aws','exposure',work.KIND,d['title'],'high','security_configuration',d['remediation'],
        dependencies=['aws_account',work.KIND],allow_incomplete_failure=True)(evaluate)
