"""Pure consumer of exact selected immutable ACR image inspection evidence."""
from copy import deepcopy
import json
import re
from peaso.secret_scanning import merge_leaks,KINGFISHER_VERSION,TRUFFLEHOG_VERSION
from peaso.collectors.azure_acr_image_secret_indicators import (
    KIND,CHECK,MARKER,SCHEMA,_SCOPE,MODES,MAX_IMAGES,MAX_LAYERS,MAX_MANIFEST,
    MAX_CONFIG,MAX_LAYER,MAX_IMAGE,MAX_EXPANDED,MAX_MEMBERS,MAX_CALLS,MAX_LEAKS,MAX_LOCATIONS,MAX_PARTS,
    DIGEST,TAR_TYPES,CONFIG_TYPES,_descriptor)

DECLARATIONS=[{'id':CHECK,'provider':'azure','category':'hardening','kind':KIND,
    'finding_type':'secrets','severity':'high','requirements':[],'dependencies':[KIND],
    'title':'Selected immutable ACR images have no detected secrets',
    'remediation':'Remove exposed credential literals from image build inputs and layers, rebuild the image, and rotate confirmed exposed credentials.',
    'evidence_sentences':['A likely secret was detected in a selected immutable ACR image.',
        'The value is hidden; offline detection did not validate the credential.']}]


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure' or not isinstance(scope,str) or not _SCOPE.fullmatch(scope)
                or meta[KIND+'_authorized'] is not True or meta['context_binding']!='scan_local'):
            raise ValueError('authorization')
        own=[c for c in index['collections'][KIND] if c.get('scope')==scope]
        if len(own)!=1 or own[0].get('status')!='collected':raise ValueError('collection')
        own=own[0];selected=meta[KIND+'_selection'][scope]
        if (not isinstance(selected,list) or not 1<=len(selected)<=MAX_IMAGES or len(set(selected))!=len(selected)
                or any(not isinstance(s,str) or not re.fullmatch(KIND+':[0-9a-f]{64}',s) for s in selected)
                or not isinstance(own.get('items'),list) or len(own['items'])!=len(selected)
                or {i.get('id') for i in own['items']}!=set(selected) or sum(i==item for i in own['items'])!=1):
            raise ValueError('selection')
        for row in (own,item):
            if any(not isinstance(meta[k],str) or not meta[k] or row['_provenance'][k]!=meta[k]
                   for k in ('credential_context_id','customer_context_id')):raise ValueError('capture')
        ident=item['id'];m=item[MARKER]
        if m.get('complete') is False and m.get('leaks'):
            return _partial_positive(item,index,scope,meta,ident,m)
        if (set(m)!={'schema','kind','identity','scope','complete','verification','descriptors','layers_scanned','parts','leaks','source_requests','mode','auth_audience','expanded_bytes','members','regular_files','manifest_digest'}
                or m['schema']!=SCHEMA or m['kind']!=KIND or m['identity']!=ident or m['scope']!=scope
                or m['auth_audience'] not in ('arm','acr') or m['complete'] is not True or m['verification']!='not_attempted' or m['mode'] not in MODES
                or m['manifest_digest']!=meta[KIND+'_digests'][ident]
                or not isinstance(m['manifest_digest'],str) or not DIGEST.fullmatch(m['manifest_digest'])
                or item['_provenance']['scope']!=scope):raise ValueError('marker')
        desc=m['descriptors']
        if not isinstance(desc,list) or not 2<=len(desc)<=MAX_LAYERS+1:raise ValueError('descriptors')
        if _descriptor(desc[0],CONFIG_TYPES,MAX_CONFIG)!=desc[0]:raise ValueError('config')
        if any(_descriptor(d,TAR_TYPES,MAX_LAYER)!=d for d in desc[1:]):raise ValueError('layers')
        if len({d['digest'] for d in desc})!=len(desc) or sum(d['size'] for d in desc)>MAX_IMAGE:raise ValueError('descriptor bound')
        if m['layers_scanned']!=[d['digest'] for d in desc[1:]]:raise ValueError('layers incomplete')
        if (type(m['expanded_bytes']) is not int or not 1<=m['expanded_bytes']<=MAX_EXPANDED
                or type(m['members']) is not int or not 1<=m['members']<=MAX_MEMBERS
                or type(m['regular_files']) is not int or not 1<=m['regular_files']<=m['members']):raise ValueError('expanded')
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        if (not isinstance(refs,list) or not 6<=len(refs)<=3+1+2*len(desc)
                or len(set(refs))!=len(refs) or not isinstance(ledger,list) or len(ledger)>MAX_CALLS
                or item['_provenance']['source_requests']!=refs):raise ValueError('receipts')
        receipts=[]
        for ref in refs:
            rows=[r for r in ledger if r.get('id')==ref]
            if not isinstance(ref,str) or not re.fullmatch(r'acr-read-[1-9][0-9]*',ref) or len(rows)!=1:raise ValueError('receipt identity')
            r=rows[0]
            if (set(r)!={'id','identity','scope','method','operation','endpoint','status','http_status','bytes','digest','verified','bound'}
                    or r['identity']!=ident or r['scope']!=scope or r['verified'] is not True or r['bound'] is not True
                    or type(r['http_status']) is not int or type(r['bytes']) is not int or not 0<=r['bytes']<=MAX_LAYER):raise ValueError('receipt binding')
            receipts.append(r)
        for r,operation,method,endpoint in zip(receipts[:3],('registry_identity','oauth_exchange','oauth_pull'),('GET','POST','POST'),('arm','registry','registry')):
            if (r['operation']!=operation or r['method']!=method or r['endpoint']!=endpoint or r['status']!='collected'
                    or r['http_status']!=200 or r['digest'] is not None or not 1<=r['bytes']<=(MAX_CONFIG if operation=='registry_identity' else 32768)):
                raise ValueError('native auth provenance')
        manifest=receipts[3]
        if (manifest['operation']!='manifest' or manifest['endpoint']!='registry' or manifest['method']!='GET'
                or manifest['status']!='collected' or manifest['http_status']!=200 or manifest['digest']!=m['manifest_digest']
                or not 1<=manifest['bytes']<=MAX_MANIFEST):raise ValueError('manifest provenance')
        cursor=4
        for d in desc:
            r=receipts[cursor];cursor+=1
            if r['method']!='GET' or r['operation']!='blob' or r['endpoint']!='registry' or r['digest']!=d['digest']:raise ValueError('blob provenance')
            if r['status']=='redirect':
                if r['http_status']!=307 or r['bytes']!=0:raise ValueError('redirect')
                r=receipts[cursor];cursor+=1
                if r['operation']!='blob_data' or r['endpoint']!='native_dedicated_data' or r['method']!='GET' or r['digest']!=d['digest']:raise ValueError('native data provenance')
            if r['status']!='collected' or r['http_status']!=200 or r['bytes']!=d['size']:raise ValueError('blob completeness')
        if cursor!=len(receipts):raise ValueError('extra requests')
        parts=m['parts'];versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        if not isinstance(parts,list) or not m['regular_files']+2<=len(parts)<=MAX_PARTS or parts[0].get('part')!='manifest' or parts[1].get('part')!='config':raise ValueError('parts')
        names=[]
        for pos,p in enumerate(parts):
            if (set(p)!={'part','bytes','complete','engines'} or type(p['bytes']) is not int or not 0<=p['bytes']<=MAX_LAYER
                    or p['complete'] is not True or not isinstance(p['part'],str)):raise ValueError('part')
            if pos>=2:
                match=re.fullmatch(r'layer-([1-9][0-9]*)\.member-([1-9][0-9]*)\.(?:name|chunk-[1-9][0-9]*)',p['part'])
                if not match or int(match[1])>len(desc)-1 or int(match[2])>m['members']:raise ValueError('member')
            es=p['engines']
            if (not isinstance(es,list) or len(es)!=2 or {e.get('engine') for e in es}!=set(versions)
                    or any(set(e)!={'engine','version','status'} or e.get('version')!=versions.get(e.get('engine')) or e.get('status')!='complete' for e in es)):
                raise ValueError('engines')
            names.append(p['part'])
        if len(names)!=len(set(names)) or parts[0]['bytes']!=manifest['bytes'] or parts[1]['bytes']!=desc[0]['size']:raise ValueError('part binding')
        leaks=m['leaks']
        if (not isinstance(leaks,list) or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(loc['path'] not in {ident+'.'+n for n in names} for l in leaks for loc in l['locations'])):raise ValueError('leaks')
        observed=('A likely secret was detected in a selected immutable ACR image. The value is hidden; offline detection did not validate the credential.' if leaks else
            'Both offline detectors completed without detecting a supported secret in the selected immutable ACR image. Coverage is limited to the observed manifest, config and supported layer files.')
        return ('FAIL' if leaks else 'PASS'),{'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted','complete':True,
            'coverage':'selected_observed_image_content_only','parts':deepcopy(parts),'source_requests':list(refs),'observed':observed}
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError):
        return 'UNKNOWN',{'observed':'The selected ACR image was disabled, unsupported, incomplete or unbound. Secret absence could not be assessed.'}


def _partial_positive(item,index,scope,meta,ident,m):
    """Admit a verified positive prefix without treating incomplete layers as clean."""
    try:
        expected={'schema','kind','identity','scope','complete','verification','descriptors',
            'layers_scanned','parts','leaks','source_requests','mode','auth_audience',
            'expanded_bytes','members','regular_files','manifest_digest','inspected_digests'}
        if (set(m)!=expected or m['schema']!=SCHEMA or m['kind']!=KIND or m['identity']!=ident
                or m['scope']!=scope or m['verification']!='not_attempted'
                or m['manifest_digest']!=meta[KIND+'_digests'][ident]
                or m['auth_audience'] not in ('arm','acr') or m['mode'] not in MODES
                or item['_provenance']['scope']!=scope):raise ValueError('partial marker')
        desc=m['descriptors'];inspected=m['inspected_digests']
        if (not isinstance(desc,list) or not 2<=len(desc)<=MAX_LAYERS+1
                or _descriptor(desc[0],CONFIG_TYPES,MAX_CONFIG)!=desc[0]
                or any(_descriptor(d,TAR_TYPES,MAX_LAYER)!=d for d in desc[1:])
                or sum(d['size'] for d in desc)>MAX_IMAGE
                or len({d['digest'] for d in desc})!=len(desc)
                or not isinstance(inspected,list) or len(inspected)<2
                or inspected[:2]!=[m['manifest_digest'],desc[0]['digest']]
                or inspected[2:]!=[d['digest'] for d in desc[1:1+len(inspected)-2]]
                or m['layers_scanned']!=inspected[2:]):raise ValueError('partial descriptors')
        refs=m['source_requests'];ledger=meta[KIND+'_receipts']
        if (not isinstance(refs,list) or not isinstance(ledger,list) or len(ledger)>MAX_CALLS
                or len(set(refs))!=len(refs) or len(refs)<5
                or item['_provenance']['source_requests']!=refs):raise ValueError('partial receipts')
        rows=[]
        for ref in refs:
            found=[r for r in ledger if r.get('id')==ref]
            if len(found)!=1 or found[0].get('identity')!=ident or found[0].get('scope')!=scope:
                raise ValueError('partial receipt identity')
            rows.append(found[0])
        if [r.get('operation') for r in rows[:4]]!=['registry_identity','oauth_exchange','oauth_pull','manifest']:
            raise ValueError('partial auth receipts')
        for r,operation,method,endpoint in zip(rows[:3],
                ('registry_identity','oauth_exchange','oauth_pull'),
                ('GET','POST','POST'),('arm','registry','registry')):
            if (set(r)!={'id','identity','scope','method','operation','endpoint','status','http_status',
                    'bytes','digest','verified','bound'} or r['operation']!=operation
                    or r['method']!=method or r['endpoint']!=endpoint or r['status']!='collected'
                    or r['http_status']!=200 or r['verified'] is not True or r['bound'] is not True
                    or r['digest'] is not None or type(r['bytes']) is not int or not 1<=r['bytes']<=MAX_CONFIG):
                raise ValueError('partial auth binding')
        manifest=rows[3]
        if (manifest.get('operation')!='manifest' or manifest.get('method')!='GET'
                or manifest.get('endpoint')!='registry' or manifest.get('status')!='collected'
                or manifest.get('http_status')!=200 or manifest.get('verified') is not True
                or manifest.get('bound') is not True or manifest.get('digest')!=m['manifest_digest']
                or type(manifest.get('bytes')) is not int or not 1<=manifest['bytes']<=MAX_MANIFEST):
            raise ValueError('partial manifest binding')
        cursor=4
        for d in desc[:len(inspected)-1]:
            if cursor>=len(rows):raise ValueError('partial blob receipt')
            r=rows[cursor];cursor+=1
            if r.get('status')=='redirect':
                if r.get('operation')!='blob' or cursor>=len(rows):raise ValueError('partial redirect')
                r=rows[cursor];cursor+=1
            if (r.get('status')!='collected' or r.get('verified') is not True
                    or r.get('bound') is not True or r.get('digest')!=d['digest']
                    or r.get('bytes')!=d['size'] or r.get('http_status')!=200):
                raise ValueError('partial blob binding')
        parts=m['parts'];leaks=m['leaks']
        if (not isinstance(parts,list) or not 1<=len(parts)<=MAX_PARTS or not isinstance(leaks,list)
                or not leaks or merge_leaks(leaks)!=leaks or len(leaks)>MAX_LEAKS
                or sum(len(l['locations']) for l in leaks)>MAX_LOCATIONS
                or any(p.get('complete') is not True for p in parts)):
            raise ValueError('partial witness')
        versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
        for part in parts:
            es=part.get('engines')
            if (set(part)!={'part','bytes','complete','engines'} or type(part.get('bytes')) is not int
                    or not 0<=part['bytes']<=MAX_LAYER or not isinstance(es,list) or len(es)!=2
                    or {e.get('engine') for e in es}!=set(versions)
                    or any(set(e)!={'engine','version','status'} or e['version']!=versions[e['engine']]
                           or e['status']!='complete' for e in es)):
                raise ValueError('partial part binding')
        paths={ident+'.'+p['part'] for p in parts if isinstance(p,dict) and isinstance(p.get('part'),str)}
        if any(loc.get('path') not in paths for leak in leaks for loc in leak['locations']):
            raise ValueError('partial location')
        for part in parts:
            name=part['part']
            match=re.fullmatch(r'layer-([1-9][0-9]*)\.member-([1-9][0-9]*)\.(?:name|chunk-[1-9][0-9]*)',name)
            if name not in ('manifest','config') and (match is None or int(match[1])>len(inspected)-2):
                raise ValueError('unverified partial layer')
        return 'FAIL',{'secret_leaks':deepcopy(leaks),'credential_validation':'not_attempted',
            'complete':False,'coverage':'verified_image_prefix_only','parts':deepcopy(parts),
            'source_requests':list(refs),'observed':
            'A likely secret was detected in the verified content of a selected immutable ACR image. The value is hidden; later image content was incomplete.'}
    except (KeyError,TypeError,ValueError,AttributeError,OverflowError,IndexError):
        return 'UNKNOWN',{'observed':'The selected ACR image content was incomplete or unbound, so its secret exposure is unclear.'}


def install():
    from pathlib import Path
    from . import CHECKS,register
    from .fixtures import CASES
    if any(c.id==CHECK for c in CHECKS):return
    d=DECLARATIONS[0]
    register(CHECK,'azure','hardening',KIND,d['title'],'high','security_configuration',d['remediation'],dependencies=[KIND])(evaluate)
    CASES[CHECK]=json.loads(Path(__file__).with_name('azure_acr_image_secret_review_20261020_fixtures.json').read_text()).get(CHECK,{})
