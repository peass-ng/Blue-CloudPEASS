"""Pure consumer for exact native-bound ECR Public image content."""
from copy import deepcopy
import json
from pathlib import Path
import re

from peaso.aws_ecr_public_selection_20261021 import (KIND, OPTION, SECRET_CHECK,
    VULN_CHECK, selected_targets)
from peaso.secret_scanning import KINGFISHER_VERSION, TRUFFLEHOG_VERSION, merge_leaks
from peaso import oci_index_20261021 as oci_index
from peaso import trivy_container_runner_20261020 as trivy
from peaso.collectors import aws_ecr_public_image_native_20261021 as source

DECLARATIONS = (
    {'id':SECRET_CHECK,'category':'exposure','title':'Selected ECR Public image bytes have no detected secrets',
     'ui_group':'Secrets','finding_type':'secrets'},
    {'id':VULN_CHECK,'category':'hardening','title':'Selected ECR Public image has no HIGH or CRITICAL package vulnerabilities',
     'ui_group':'Vulnerabilities','finding_type':'vulnerabilities'},
)


def evaluate(item,index,check_id):
    kind = 'secret' if check_id == SECRET_CHECK else 'vulnerability'
    unknown = ('UNKNOWN', {'observed':'The selected ECR Public image could not be fully inspected or its account, registry alias, or bytes could not be verified.'})
    try:
        ctx=index['context']; meta=ctx['metadata']; scope=ctx['scope']
        if (ctx['provider']!='aws' or meta[KIND+'_'+kind+'_authorized'] is not True
                or type(meta.get(OPTION)) is not list):return unknown
        targets=selected_targets({OPTION:meta[OPTION]},list(dict.fromkeys(t['scope'] for t in meta[OPTION])))
        target,=[t for t in targets if source.identity(t)==item['id']]
        if target['scope']!=scope:return unknown
        own,=[c for c in index['collections'][KIND] if c.get('scope')==scope and item in c.get('items',[])]
        if own.get('status') not in ('collected','partial') or own.get('service')!='ecr-public':return unknown
        m=item['ECRPublicImageContent'];before=m['native_before'];after=m['native_after']
        if (m['schema']!=source.SCHEMA or m['identity']!=item['id'] or m['selection']!=target
                or type(before) is not dict or before.get('account')!=scope.split('/')[0]
                or before.get('registry_alias')!=target['registry_alias']
                or before.get('repository_name')!=target['repository_name']
                or before.get('image_digest')!=target['image_digest']
                or before.get('manifest_media_type') not in oci_index.ALL_MANIFEST_TYPES
                or before.get('registry_arn')!=f'arn:aws:ecr-public::{scope.split("/")[0]}:registry/{scope.split("/")[0]}'
                or before.get('repository_arn')!=f'arn:aws:ecr-public::{scope.split("/")[0]}:repository/{target["repository_name"]}'
                or type(before.get('image_size')) is not int or before['image_size']<=0):return unknown
        native=m['native_receipts']
        if (type(native) is not list or not 3<=len(native)<=source.MAX_NATIVE_CALLS
                or [r.get('operation') for r in native[:3]]!=[
                    'ecr-public:describe_registries','ecr-public:describe_repositories','ecr-public:describe_images']
                or any(type(r) is not dict or set(r)!={'operation','status'}
                       or r['status'] not in ('collected','unavailable') for r in native)
                or any(r['status']!='collected' for r in native[:3])):return unknown
        digest=target['image_digest']
        graph=m.get('graph')
        if graph is None and before['manifest_media_type'] in oci_index.LEAF_TYPES:
            child_digests={digest}  # Accepted pre-index leaf witness.
            graph_complete=True
        else:
            if (type(graph) is not dict or set(graph)!={'parent_digest','media_type','children','complete'}
                    or graph['parent_digest']!=digest or graph['media_type']!=before['manifest_media_type']
                    or type(graph['complete']) is not bool or type(graph['children']) is not list
                    or len(graph['children'])>oci_index.MAX_CHILDREN):return unknown
            children=graph['children']
            if before['manifest_media_type'] in oci_index.LEAF_TYPES:
                if len(children)!=1 or children[0].get('digest')!=digest:return unknown
            child_digests=set()
            for child in children:
                if (type(child) is not dict or set(child)!={'digest','size','mediaType','platform','config_digest'}
                        or child.get('mediaType') not in oci_index.LEAF_TYPES
                        or type(child.get('digest')) is not str or not source.archive.DIGEST.fullmatch(child['digest'])
                        or child['digest'] in child_digests
                        or type(child.get('size')) is not int or not 0<child['size']<=source.archive.MAX_MANIFEST
                        or type(child.get('config_digest')) is not str
                        or not source.archive.DIGEST.fullmatch(child['config_digest'])):return unknown
                if before['manifest_media_type'] in oci_index.INDEX_TYPES:
                    try: oci_index._platform(child.get('platform'))
                    except ValueError: return unknown
                elif child.get('platform') is not None:return unknown
                child_digests.add(child['digest'])
            if graph['complete'] and not child_digests:return unknown
            graph_complete=graph['complete']
        receipts=m['registry_receipts']
        if (type(receipts) is not list or not receipts or len(receipts)>70
                or receipts[0].get('category')!='manifests'
                or receipts[0].get('digest')!=target['image_digest']
                or receipts[0].get('status')!='collected'
                or any(type(r) is not dict or set(r)!={'id','method','category','digest','status','bytes'}
                    or not re.fullmatch(r'registry-read-[0-9a-f]{32}',r.get('id',''))
                    or r['method']!='GET' or r['category'] not in('manifests','blobs')
                    or r['status'] not in('collected','denied','unavailable')
                    or type(r['bytes']) is not int or not 0<=r['bytes']<=source.archive.MAX_LAYER
                    for r in receipts)):return unknown
        manifest_receipts=[r for r in receipts if r['category']=='manifests' and r['status']=='collected']
        if graph is not None and (len(manifest_receipts)!=1+(len(child_digests) if before['manifest_media_type'] in oci_index.INDEX_TYPES else 0)
                or {r['digest'] for r in manifest_receipts[1:]}!=
                    (child_digests if before['manifest_media_type'] in oci_index.INDEX_TYPES else set())
                or any(r['bytes']!=c['size'] for c in graph['children'] for r in manifest_receipts[1:]
                       if r['digest']==c['digest'])):return unknown
        stable=(m['native_stable'] is True and after==before and len(native)>=6
                and all(r['status']=='collected' for r in native)
                and all(r['status']=='collected' for r in receipts) and graph_complete)
        if kind=='secret':
            leaks=m['leaks'];parts=m['parts']
            if (type(leaks) is not list or len(leaks)>256 or merge_leaks(leaks)!=leaks
                    or type(parts) is not list or not parts or len(parts)>8192
                    or any(type(l) is not dict or not re.fullmatch('[0-9a-f]{64}',str(l.get('fingerprint')))
                           or not l.get('detectors') or not l.get('locations') for l in leaks)):
                return unknown
            versions={'kingfisher':KINGFISHER_VERSION,'trufflehog':TRUFFLEHOG_VERSION}
            trusted={(p.get('part'),e.get('engine')) for p in parts if type(p) is dict
                     for e in p.get('engines',[]) if type(e) is dict and e.get('engine') in versions and e.get('status')=='complete'
                     and e.get('version')==versions[e['engine']]}
            # A merged leak stores engine/location unions, not engine-location pairs.
            if any(any(not any((loc.get('path'),d.get('engine')) in trusted
                               for d in leak['detectors']) for loc in leak['locations'])
                   or any(not any((loc.get('path'),d.get('engine')) in trusted
                                  for loc in leak['locations']) for d in leak['detectors'])
                   for leak in leaks):return unknown
            if leaks:
                return 'FAIL',{'observed':'A likely secret was found in the selected ECR Public image. Its value is hidden.',
                    'secret_leaks':deepcopy(leaks),'complete':stable and m.get('secret_complete') is True,
                    'verified_child_manifest_digests':sorted(child_digests)}
            if stable and m.get('secret_complete') is True and all(type(p) is dict and p.get('complete') is True
                    and type(p.get('bytes')) is int and p['bytes']>0 and
                    {e.get('engine') for e in p.get('engines',[])}==set(versions) and
                    all(e.get('status')=='complete' and e.get('version')==versions[e['engine']]
                        for e in p['engines']) for p in parts):
                return 'PASS',{'observed':'Both detectors found no supported secret in the selected ECR Public image.','complete':True}
            return unknown
        vuln=m.get('vulnerability')
        if type(vuln) is not dict or type(vuln.get('findings')) is not list:return unknown
        findings=vuln['findings']
        if (len(findings)>10000 or any(type(f) is not dict or f.get('severity') not in('HIGH','CRITICAL')
                 or f.get('image_digest') not in child_digests for f in findings)):
            return unknown
        if before['manifest_media_type'] in oci_index.INDEX_TYPES:
            reported=vuln.get('children')
            scans=m.get('child_vulnerability_scans')
            if type(scans) is not list or len(scans)>oci_index.MAX_CHILDREN:return unknown
            if (type(reported) is not list or len(reported)>oci_index.MAX_CHILDREN
                    or len(scans)!=len(reported)
                    or not {r.get('digest') for r in reported if type(r) is dict}<=child_digests
                    or any(type(r) is not dict or set(r)!={'digest','status','complete'}
                           or r['status'] not in ('PASS','FAIL','UNKNOWN') or type(r['complete']) is not bool
                           for r in reported)
                    or any(f['image_digest'] not in {r['digest'] for r in reported} for f in findings)
                    or stable and len(reported)!=len(child_digests)):return unknown
            ordered=graph['children'][:len(scans)]
            for child,scan,report in zip(ordered,scans,reported):
                expected_image={'provider':'aws','scope':scope,
                    'immutable_reference':f'{source.HOST}/{target["registry_alias"]}/{target["repository_name"]}@{child["digest"]}',
                    'manifest_digest':child['digest'],'config_digest':child['config_digest']}
                if (type(scan) is not dict or scan.get('schema')!=trivy.SCHEMA
                        or scan.get('image')!=expected_image or type(scan.get('findings')) is not list
                        or report['digest']!=child['digest'] or report['status']!=scan.get('status')
                        or report['complete']!=(scan.get('complete') is True)
                        or any(type(f) is not dict or f.get('image_digest')!=child['digest']
                               for f in scan['findings'])):return unknown
            actual_findings=[f for scan in scans for f in scan['findings']]
            if findings!=actual_findings[:10000]:return unknown
        if findings and vuln.get('status')=='FAIL':
            return 'FAIL',{'observed':'Trivy found HIGH or CRITICAL package vulnerabilities in the selected ECR Public image.',
                'vulnerabilities':deepcopy(findings),'complete':stable and vuln.get('complete') is True}
        if (stable and vuln.get('status')=='PASS' and vuln.get('complete') is True
                and vuln.get('scan_complete') is True and vuln.get('coverage_status')=='COMPLETE'
                and vuln.get('database',{}).get('fresh') is True):
            return 'PASS',{'observed':'Trivy found no HIGH or CRITICAL package vulnerabilities in the selected ECR Public image using a fresh database.','complete':True}
        return unknown
    except (KeyError,ValueError,TypeError,AttributeError,IndexError):
        return unknown


def install(register):
    from .fixtures import CASES
    cases=json.loads(Path(__file__).with_name('aws_ecr_public_image_review_20261021_cases.json').read_text())
    if set(cases)!={SECRET_CHECK,VULN_CHECK} or set(cases)&set(CASES):
        raise ValueError('selected ECR Public case collision')
    for declaration in DECLARATIONS:
        check_id=declaration['id']
        @register(check_id,'aws',declaration['category'],KIND,declaration['title'],'high',
                  'security_configuration','Remove confirmed secrets or update vulnerable packages and publish a new immutable image.',
                  dependencies=(KIND,),allow_incomplete_failure=True)
        def selected_public_image(item,index,check_id=check_id):
            return evaluate(item,index,check_id)
    CASES.update(cases)
