"""Bounded, private inspection of one exactly selected ACR image.

Native registry binding and authorization remain in the predecessor Reader. Each
layer is downloaded to an owned scratch file, verified against its descriptor and
rootfs diff ID, then scanned without exporting original TAR paths or bytes.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import time

from peaso import container_image_archive_20261020 as archive
from peaso.secret_evidence import alias_path, scan_with_source, source_context
from peaso.secret_scanning import merge_leaks, scan_content
from . import azure_acr_image_secret_indicators as native

WINDOW = 1024 * 1024
OVERLAP = 4096
MAX_FILE_SCAN = 64 * 1024 * 1024
MAX_IMAGE_SCAN = 512 * 1024 * 1024


def inspect_image(reader):
    marker = {'schema':native.SCHEMA,'kind':native.KIND,'identity':reader.ident,
        'scope':reader.scope,'complete':False,'verification':'not_attempted',
        'manifest_digest':reader.target['digest'],'descriptors':[],
        'layers_scanned':[],'parts':[],'leaks':[],'source_requests':[],
        'mode':None,'auth_audience':None,'expanded_bytes':0,'members':0,
        'regular_files':0}
    start=len(reader.receipts)
    leaks=[];verified=[];scanned=0;scan_bytes=0
    try:
        token=reader.authenticate()
        marker['mode'],marker['auth_audience']=reader.mode,reader.auth_audience
        manifest_raw=reader.blob('manifests',reader.target['digest'],native.MAX_MANIFEST,token)
        manifest=native._json(manifest_raw)
        if (type(manifest) is not dict or set(manifest)-{'schemaVersion','mediaType','config','layers','annotations'}
                or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion']!=2
                or manifest.get('mediaType') not in (native.OCI,native.DOCKER)):
            raise native.Incomplete('single_platform_manifest_required')
        config=native._descriptor(manifest['config'],native.CONFIG_TYPES,native.MAX_CONFIG)
        layers=manifest.get('layers')
        if type(layers) is not list or not 1<=len(layers)<=native.MAX_LAYERS:
            raise native.Incomplete('layers_unavailable')
        layers=[native._descriptor(d,native.TAR_TYPES,native.MAX_LAYER) for d in layers]
        if (len({d['digest'] for d in [config]+layers})!=len(layers)+1
                or sum(d['size'] for d in [config]+layers)>native.MAX_IMAGE):
            raise native.Incomplete('compressed_image_bound')
        marker['descriptors']=deepcopy([config]+layers)
        raw=reader.blob('blobs',config['digest'],native.MAX_CONFIG,token,config['size'])
        decoded=native._json(raw)
        if (type(decoded) is not dict or set(decoded)&{'error','nextLink','partial','_partial','_coverage','resultTruncated'}
                or decoded.get('os')!='linux' or decoded.get('architecture') not in ('amd64','arm64')
                or type(decoded.get('rootfs')) is not dict or decoded['rootfs'].get('type')!='layers'
                or type(decoded['rootfs'].get('diff_ids')) is not list
                or len(decoded['rootfs']['diff_ids'])!=len(layers)
                or any(type(d) is not str or not native.DIGEST.fullmatch(d)
                       for d in decoded['rootfs']['diff_ids'])):
            raise native.Incomplete('unsupported_rootfs')
        image_identity={'provider':'azure','scope':reader.scope,
            'immutable_reference':reader.host+'/'+reader.target['repository']+'@'+reader.target['digest'],
            'manifest_digest':reader.target['digest'],'config_digest':config['digest']}
        archive.identity(image_identity)
        verified=[reader.target['digest'],config['digest']]
        def scan(payload,path,layer,*,native_document=None,original_path=None):
            nonlocal leaks
            reader.check()
            remaining=reader.state['deadline']-time.monotonic()
            if remaining<1:raise native.Incomplete('scanner_deadline')
            from .azure_selected_secret_integration_20261020 import remember
            with source_context(resource_id=reader.ident,scope=reader.scope,
                    image_digest=reader.target['digest'],layer=layer,
                    path=original_path or path,
                    location_kind='configuration' if native_document is not None else 'file',
                    native=native_document):
                if original_path is not None:alias_path(path,original_path)
                outcome=scan_with_source(scan_content,payload,path,source={},
                    timeout=min(30,remaining),
                    _redact_values=lambda values:remember(reader.reader,'acr_image_secret_redactions',values))
            leaks.extend(outcome['leaks'])
            if len(leaks)>native.MAX_LEAKS or sum(len(l['locations']) for l in leaks)>native.MAX_LOCATIONS:
                raise native.Incomplete('leak_bound')
            if len(marker['parts'])>=native.MAX_PARTS:
                raise native.Incomplete('part_bound')
            marker['parts'].append({'part':path.removeprefix(reader.ident+'.'),
                'bytes':len(payload),'complete':outcome['complete'],'engines':outcome['engines']})
            if outcome['complete'] is not True:raise native.Incomplete('scanners_incomplete')
        scan(manifest_raw,reader.ident+'.manifest',reader.target['digest'],native_document=manifest)
        # Decode strings as a separate bounded detector input for escaped values.
        with source_context(resource_id=reader.ident,scope=reader.scope,
                image_digest=reader.target['digest'],layer=config['digest']):
            config_outcome=native._scan_json(raw,decoded,reader.ident+'.config',reader)
        leaks.extend(config_outcome['leaks'])
        marker['parts'].append({'part':'config','bytes':len(raw),'complete':True,'engines':config_outcome['engines']})
        marker['expanded_bytes']=len(raw)
        nodes={};path_budget=[0];budget=[len(raw)]
        with tempfile.TemporaryDirectory(prefix='peaso-azure-acr-') as directory:
            root=Path(directory)
            for number,(layer,diff) in enumerate(zip(layers,decoded['rootfs']['diff_ids'])):
                reader.check()
                blob=root/('blob-'+str(number))
                reader.blob('blobs',layer['digest'],native.MAX_LAYER,token,layer['size'],destination=blob)
                expanded=root/('expanded-'+str(number)+'.tar')
                with expanded.open('xb') as output:
                    size=archive._expand(blob,layer,diff,output,budget,reader.check)
                blob.unlink()
                count=archive._tar_members(expanded,nodes,marker['members'],reader.check,number,path_budget)
                marker['expanded_bytes']+=size
                marker['members']=count
                budget[0]+=size
                verified.append(layer['digest'])
                marker['layers_scanned'].append(layer['digest'])
                for name,node in sorted(nodes.items()):
                    if node[0] not in ('file','hardlink') or node[1][3]!=number:continue
                    marker['regular_files']+=1
                    base=reader.ident+'.layer-'+str(number+1)+'.member-'+str(marker['regular_files'])
                    scan(name.encode('utf-8'),base+'.name',layer['digest'],original_path=name)
                    def observe(original,stream,length,layer_index):
                        nonlocal scanned,scan_bytes
                        if length>MAX_FILE_SCAN or scanned+length>MAX_IMAGE_SCAN:
                            raise native.Incomplete('file_scan_bound')
                        offset=0;overlap=b'';chunk_no=0
                        while offset<length:
                            reader.check();chunk=stream.read(min(WINDOW,length-offset))
                            if type(chunk) is not bytes or not chunk:raise native.Incomplete('file_truncation')
                            if offset==0 and (chunk.startswith((b'PK\x03\x04',b'\x1f\x8b',b'BZh',b'\xfd7zXZ',
                                    b'7z\xbc\xaf',b'Rar!',b'\x28\xb5\x2f\xfd')) or chunk[257:262]==b'ustar'):
                                raise native.Incomplete('nested_archive_uninspected')
                            chunk_no+=1;offset+=len(chunk);scanned+=len(chunk);scan_bytes+=len(chunk)
                            scan(overlap+chunk,base+'.chunk-'+str(chunk_no),layer['digest'],original_path=original)
                            overlap=(overlap+chunk)[-OVERLAP:]
                        if length==0:scan(b'',base+'.chunk-1',layer['digest'],original_path=original)
                    archive._visit_node(name,node,observe,reader.check)
        if not marker['regular_files']:raise native.Incomplete('no_layer_files')
        marker['leaks']=merge_leaks(leaks)
        marker['complete']=True
    except Exception:
        marker['complete']=False
        marker['parts']=[part for part in marker['parts'] if part.get('complete') is True]
        witnessed={reader.ident+'.'+part['part'] for part in marker['parts']}
        retained=[]
        for leak in leaks:
            locations=[loc for loc in leak.get('locations',[]) if loc.get('path') in witnessed]
            if locations:retained.append({**leak,'locations':locations})
        if retained:
            try:marker['leaks']=merge_leaks(retained)
            except (TypeError,ValueError,KeyError,AttributeError):marker['leaks']=[]
    marker['source_requests']=[r['id'] for r in reader.receipts[start:]]
    if not marker['complete']:
        marker['inspected_digests']=verified
    return {'id':reader.ident,native.MARKER:marker,
        '_provenance':{'scope':reader.scope,'source_requests':list(marker['source_requests'])}}
