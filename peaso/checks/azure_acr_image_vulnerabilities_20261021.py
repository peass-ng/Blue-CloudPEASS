"""Native defensive check for selected immutable ACR image package findings.

This proposal does not register on import; the normal check registry transaction
must explicitly admit its source, declaration, description and collection route.
"""
from copy import deepcopy
import re
from peaso import container_image_archive_20261020 as archive
from peaso.image_findings import build_report
from peaso.collectors import azure_acr_image_vulnerabilities_20261021 as source

DECLARATION={'id':source.CHECK,'provider':'azure','category':'hardening',
    'kind':source.KIND,'title':'Selected ACR image has no HIGH or CRITICAL package vulnerabilities',
    'severity':'high','control':'security_configuration',
    'remediation':'Update affected packages, rebuild the image, and select a reviewed immutable digest.',
    'target':'resource','dependencies':(source.KIND,),
    'allow_incomplete_failure':True,'service':'containerregistry','ui_group':'Containers'}
DESCRIPTION={'description':'Reviews an explicitly selected immutable ACR image with an offline package vulnerability database. Verified HIGH or CRITICAL findings remain visible when scan coverage is incomplete; a clean result requires a fresh complete scan. The selected digest does not prove a workload runs the image or that a finding is exploitable.',
    'evaluated':['exact selected registry and repository pull identity',
                 'verified manifest, config, compressed layer and rootfs digests',
                 'typed HIGH and CRITICAL findings from the bound offline scan, including incomplete coverage'],
    'pass_when':'The bound image and fresh complete scan have no HIGH or CRITICAL findings.',
    'fail_when':'The bound image has at least one typed HIGH or CRITICAL finding; incomplete coverage stays UNKNOWN for absence.',
    'not_applicable_when':None}
CONTROL_ACTIONS=('Microsoft.ContainerRegistry/registries/read',)
LEGACY_PULL_ACTIONS=('Microsoft.ContainerRegistry/registries/pull/read',)
ABAC_PULL_DATA_ACTIONS=('Microsoft.ContainerRegistry/registries/repositories/content/read',
                        'Microsoft.ContainerRegistry/registries/repositories/metadata/read')
READ_ACTIONS=CONTROL_ACTIONS+LEGACY_PULL_ACTIONS+ABAC_PULL_DATA_ACTIONS


def _observed(status, marker=None):
    if status=='FAIL':
        return ('The selected immutable ACR image has a recorded HIGH or CRITICAL package vulnerability.\n'
                'A workload using this image may expose the affected package.\n'
                'That could put the workload or its data at risk.')
    if status=='PASS':
        return ('The selected immutable ACR image has no HIGH or CRITICAL findings in its fresh completed package scan.\n'
                'Its recorded layers and rootfs match the selected digest.\n'
                'A vulnerability outside this scan coverage could still affect a workload using the image.')
    return ('The selected ACR image lacks a fresh, complete package vulnerability result.\n'
            'Its HIGH or CRITICAL package state remains unclear.\n'
            'An affected package may put a workload or its data at risk if the image is used.')


def evaluate(item,index):
    try:
        ctx=index['context'];scope=ctx['scope'];meta=ctx['metadata']
        if (ctx['provider']!='azure' or type(scope) is not str or not source.acr._SCOPE.fullmatch(scope)
                or meta.get(source.KIND+'_authorized') is not True
                or meta.get('context_binding')!='scan_local'):
            raise ValueError('authorization')
        selected=meta[source.KIND+'_selection'][scope]
        digests=meta[source.KIND+'_digests']
        collection,=[c for c in index['collections'][source.KIND] if c.get('scope')==scope]
        if (collection.get('status') not in ('collected','partial')
                or type(selected) is not list or not 1<=len(selected)<=source.acr.MAX_IMAGES
                or type(collection.get('items')) is not list
                or len(collection['items'])!=len(selected)
                or {r.get('id') for r in collection['items']}!=set(selected)
                or item not in collection['items']):raise ValueError('selection')
        for evidence_row in (collection,item):
            if any(not isinstance(meta.get(key),str) or not meta[key]
                   or evidence_row.get('_provenance',{}).get(key)!=meta[key]
                   for key in ('credential_context_id','customer_context_id')):
                raise ValueError('capture context')
        ident=item['id'];m=item[source.MARKER]
        if (ident not in selected or m.get('schema')!=source.SCHEMA
                or item['_provenance']['scope']!=scope
                or item['_provenance']['source_requests']!=m.get('source_requests')):
            raise ValueError('marker')
        target=m['selection']
        if (source.identity(target)!=ident or target['digest']!=digests[ident]
                or source.selected_targets({source.OPTION:[target]},[scope])!=[target]):
            raise ValueError('target')
        if m['status']=='UNKNOWN':
            return 'UNKNOWN',{'Observed':_observed('UNKNOWN'),'Reason':'selected_image_vulnerability_coverage_incomplete'}
        image=m['image'];archive.identity(image)
        if (image['provider']!='azure' or image['scope']!=scope
                or image['manifest_digest']!=target['digest']
                or image['config_digest']!=m['descriptors'][0]['digest']):
            raise ValueError('image binding')
        ref=image['immutable_reference'];host,rest=ref.split('/',1)
        match=source.acr._REGISTRY.fullmatch(target['registry_id'])
        registry=match[3].lower()
        if (not re.fullmatch(re.escape(registry)+r'(?:-[a-z0-9]{5,32})?\.azurecr\.io',host)
                or rest!=target['repository']+'@'+target['digest']):
            raise ValueError('host binding')
        descriptors=m['descriptors'];diffs=m['rootfs_diff_ids']
        if (type(descriptors) is not list or not 2<=len(descriptors)<=archive.MAX_LAYERS+1
                or archive.descriptor(descriptors[0],archive.CONFIGS,archive.MAX_CONFIG)!=descriptors[0]
                or any(archive.descriptor(d,archive.LAYERS,archive.MAX_LAYER)!=d for d in descriptors[1:])
                or sum(d['size'] for d in descriptors)>archive.MAX_COMPRESSED
                or type(diffs) is not list or len(diffs)!=len(descriptors)-1
                or any(type(d) is not str or not archive.DIGEST.fullmatch(d) for d in diffs)):
            raise ValueError('content graph')
        proof=m['archive']
        if (type(proof) is not dict or proof.get('manifest_digest')!=target['digest']
                or proof.get('config_digest')!=image['config_digest']
                or proof.get('format')!='docker' or type(proof.get('expanded_bytes')) is not int
                or not 0<proof['expanded_bytes']<=archive.MAX_EXPANDED
                or type(proof.get('members')) is not int or not 0<proof['members']<=archive.MAX_MEMBERS
                or m['scratch_removed'] is not True):raise ValueError('archive proof')
        refs=m['source_requests'];ledger=meta[source.KIND+'_receipts']
        if (type(refs) is not list or len(refs)<6 or len(refs)>source.acr.MAX_CALLS
                or len(set(refs))!=len(refs) or type(ledger) is not list
                or len(ledger)>source.acr.MAX_CALLS):raise ValueError('receipts')
        rows=[]
        for ref_id in refs:
            matching=[r for r in ledger if r.get('id')==ref_id]
            if len(matching)!=1:raise ValueError('receipt identity')
            r=matching[0]
            if (r.get('identity')!=ident or r.get('scope')!=scope
                    or r.get('verified') is not True or r.get('bound') is not True
                    or r.get('status') not in ('collected','redirect')):
                raise ValueError('receipt binding')
            rows.append(r)
        if ([r['operation'] for r in rows[:4]]!=['registry_identity','oauth_exchange','oauth_pull','manifest']
                or any(r['status']!='collected' for r in rows[:4])
                or rows[3]['digest']!=target['digest']):raise ValueError('native prefix')
        if sum(r['operation']=='registry_identity' for r in rows)<3 or sum(r['operation']=='manifest' for r in rows)<3:
            raise ValueError('fresh native verification')
        for desc in descriptors:
            expected_count=3 if desc is descriptors[0] else 1
            matching=[r for r in rows if r.get('digest')==desc['digest'] and r.get('status')=='collected'
                      and r.get('bytes')==desc['size'] and r.get('http_status')==200]
            if len(matching)<expected_count:raise ValueError('descriptor receipt')
        observed=m['observation']
        if (type(observed) is not dict or observed.get('provider')!='azure'
                or observed.get('scope')!=scope or observed.get('asset_kind')!='acr_image'
                or observed.get('asset_id')!=target['registry_id']+'/repositories/'
                    +target['repository']+'@'+target['digest']
                or observed.get('scan',{}).get('image')!=image):raise ValueError('observation')
        report=build_report([observed],selected=True)
        if report['invalid_observations'] or report['invalid_vulnerabilities']:
            raise ValueError('report coverage')
        status='FAIL' if report['rows'] else 'PASS'
        if (status!=m['status'] or m['complete'] is not report['complete']
                or status=='PASS' and report['complete'] is not True
                or status=='FAIL' and not report['rows']):raise ValueError('status binding')
        return status,{'Observed':_observed(status,m),'Image':deepcopy(image),
            'Vulnerabilities':deepcopy(report['rows']),'Coverage':report['coverage'],
            'Association':'selected_immutable_image','RuntimeImageProven':False}
    except (KeyError,TypeError,ValueError,AttributeError,IndexError):
        return 'UNKNOWN',{'Observed':_observed('UNKNOWN'),
                          'Reason':'selected_native_image_vulnerability_evidence_unavailable'}


def install():
    """Normal registry entrypoint for a later reviewed, finite admission."""
    from . import CHECKS,register
    if any(check.id==source.CHECK for check in CHECKS):return
    from .provider_content_native_cases_20261021 import native_case
    from .fixtures import CASES
    case = native_case(source.CHECK)
    register(source.CHECK,'azure','hardening',source.KIND,DECLARATION['title'],
             'high','security_configuration',DECLARATION['remediation'],
             dependencies=[source.KIND],allow_incomplete_failure=True)(evaluate)

    CASES[source.CHECK] = case
