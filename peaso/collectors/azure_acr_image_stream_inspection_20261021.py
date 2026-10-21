"""Bounded private inspection of an exact ACR leaf or finite OCI index."""
from copy import deepcopy
from pathlib import Path
import tempfile
import time

from peaso import container_image_archive_20261020 as archive
from peaso import oci_index_20261021 as oci_index
from peaso.secret_evidence import alias_path, scan_with_source, source_context
from peaso.secret_scanning import merge_leaks, scan_content
from . import azure_acr_image_secret_indicators as native

WINDOW = 1024 * 1024
OVERLAP = 4096
MAX_FILE_SCAN = 64 * 1024 * 1024
MAX_IMAGE_SCAN = 512 * 1024 * 1024
ABORT_CODES = frozenset(('collection_cancelled', 'intentional_scan_deadline',
    'deadline_exceeded', 'scanner_deadline'))


def _abort_code(exc):
    code = getattr(exc, 'code', None)
    if code is None and isinstance(exc, native.Incomplete) and exc.args:
        code = exc.args[0]
    return type(code) is str and code in ABORT_CODES


def inspect_image(reader):
    parent = reader.target['digest']
    marker = {'schema':native.SCHEMA,'kind':native.KIND,'identity':reader.ident,
        'scope':reader.scope,'complete':False,'verification':'not_attempted',
        'manifest_digest':parent,'descriptors':[], 'layers_scanned':[],
        'parts':[],'leaks':[],'source_requests':[], 'mode':None,
        'auth_audience':None,'expanded_bytes':0,'members':0,'regular_files':0}
    start=len(reader.receipts)
    leaks=[];verified=[];scanned=0;scan_partial=False;skipped_files=0
    index_mode=False
    try:
        token=reader.authenticate()
        marker['mode'],marker['auth_audience']=reader.mode,reader.auth_audience
        parent_raw=reader.blob('manifests',parent,native.MAX_MANIFEST,token)
        parent_doc=archive.decode(parent_raw)
        index_mode=type(parent_doc) is dict and parent_doc.get('mediaType') in oci_index.INDEX_TYPES
        if index_mode:
            marker['graph']={'parent_digest':parent,'media_type':parent_doc['mediaType'],
                             'children':[],'complete':False}
            marker['child_inspections']=[]
        def scan(payload,path,layer,*,native_document=None,original_path=None,child_digest=None):
            reader.check()
            remaining=reader.state['deadline']-time.monotonic()
            if remaining<1:raise native.Incomplete('scanner_deadline')
            from .azure_selected_secret_integration_20261020 import remember
            with source_context(resource_id=reader.ident,scope=reader.scope,image_digest=parent,
                    child_digest=child_digest,layer=layer,path=original_path or path,
                    location_kind='configuration' if native_document is not None else 'file',
                    native=native_document):
                if original_path is not None:alias_path(path,original_path)
                outcome=scan_with_source(scan_content,payload,path,source={},timeout=min(30,remaining),
                    _redact_values=lambda values:remember(reader.reader,'acr_image_secret_redactions',values))
            leaks.extend(outcome['leaks'])
            if len(leaks)>native.MAX_LEAKS or sum(len(l['locations']) for l in leaks)>native.MAX_LOCATIONS:
                raise native.Incomplete('leak_bound')
            if len(marker['parts'])>=native.MAX_PARTS:raise native.Incomplete('part_bound')
            marker['parts'].append({'part':path.removeprefix(reader.ident+'.'),
                'bytes':len(payload),'complete':outcome['complete'],'engines':outcome['engines']})
            if outcome['complete'] is not True:raise native.Incomplete('scanners_incomplete')
        if index_mode:
            scan(parent_raw,reader.ident+'.index',parent,native_document=parent_doc)
        def fetch(child_digest,size,media_type):
            # The Reader constructs the route from the selected repository and
            # exact child digest; no descriptor URL or second origin is accepted.
            return reader.blob('manifests',child_digest,native.MAX_MANIFEST,token,size)
        for child in oci_index.children(parent_raw,parent,fetch,check=reader.check):
            digest=child['digest'];manifest_raw=child['raw']
            manifest=archive.decode(manifest_raw)
            if (type(manifest) is not dict or set(manifest)-{'schemaVersion','mediaType','config','layers','annotations'}
                    or type(manifest.get('schemaVersion')) is not int or manifest['schemaVersion']!=2
                    or manifest.get('mediaType') not in oci_index.LEAF_TYPES):
                raise native.Incomplete('unsupported_leaf_manifest')
            config=native._descriptor(manifest['config'],native.CONFIG_TYPES,native.MAX_CONFIG)
            layers=manifest.get('layers')
            if type(layers) is not list or not 1<=len(layers)<=native.MAX_LAYERS:
                raise native.Incomplete('layers_unavailable')
            layers=[native._descriptor(d,native.TAR_TYPES,native.MAX_LAYER) for d in layers]
            if (len({d['digest'] for d in [config]+layers})!=len(layers)+1
                    or sum(d['size'] for d in [config]+layers)>native.MAX_IMAGE):
                raise native.Incomplete('compressed_image_bound')
            prefix=reader.ident+('.child-'+digest[7:] if index_mode else '')
            record={'digest':digest,'descriptors':deepcopy([config]+layers),
                'layers_scanned':[],'parts':[],'expanded_bytes':0,'members':0,'regular_files':0,
                'scan_partial':False,'skipped_files':0}
            if index_mode:
                marker['graph']['children'].append({'digest':digest,'size':child['size'],
                    'mediaType':child['mediaType'],'platform':child['platform'],
                    'config_digest':config['digest']})
            else:
                marker['descriptors']=deepcopy(record['descriptors'])
            raw=reader.blob('blobs',config['digest'],native.MAX_CONFIG,token,config['size'])
            decoded=archive.decode(raw)
            if (type(decoded) is not dict or set(decoded)&{'error','nextLink','partial','_partial','_coverage','resultTruncated'}
                    or decoded.get('os')!='linux' or decoded.get('architecture') not in ('amd64','arm64')
                    or type(decoded.get('rootfs')) is not dict or decoded['rootfs'].get('type')!='layers'
                    or type(decoded['rootfs'].get('diff_ids')) is not list
                    or len(decoded['rootfs']['diff_ids'])!=len(layers)
                    or any(type(d) is not str or not native.DIGEST.fullmatch(d)
                           for d in decoded['rootfs']['diff_ids'])):
                raise native.Incomplete('unsupported_rootfs')
            if index_mode and (decoded['os']!=child['platform']['os']
                    or decoded['architecture']!=child['platform']['architecture']
                    or 'variant' in child['platform'] and decoded.get('variant')!=child['platform']['variant']):
                raise native.Incomplete('child_platform_config_mismatch')
            image_identity={'provider':'azure','scope':reader.scope,
                'immutable_reference':reader.host+'/'+reader.target['repository']+'@'+digest,
                'manifest_digest':digest,'config_digest':config['digest']}
            archive.identity(image_identity)
            if not index_mode:verified=[parent,config['digest']]
            before_parts=len(marker['parts'])
            scan(manifest_raw,prefix+'.manifest',digest,native_document=manifest,child_digest=digest)
            with source_context(resource_id=reader.ident,scope=reader.scope,
                    image_digest=parent,child_digest=digest,layer=config['digest']):
                config_outcome=native._scan_json(raw,decoded,prefix+'.config',reader)
            leaks.extend(config_outcome['leaks'])
            marker['parts'].append({'part':(prefix+'.config').removeprefix(reader.ident+'.'),
                'bytes':len(raw),'complete':True,'engines':config_outcome['engines']})
            marker['expanded_bytes']+=len(raw);record['expanded_bytes']=len(raw)
            nodes={};path_budget=[0];budget=[len(raw)]
            with tempfile.TemporaryDirectory(prefix='peaso-azure-acr-') as directory:
                root=Path(directory)
                for number,(layer,diff) in enumerate(zip(layers,decoded['rootfs']['diff_ids'])):
                    reader.check();blob=root/('blob-'+str(number))
                    reader.blob('blobs',layer['digest'],native.MAX_LAYER,token,layer['size'],destination=blob)
                    expanded=root/('expanded-'+str(number)+'.tar')
                    with expanded.open('xb') as output:
                        size=archive._expand(blob,layer,diff,output,budget,reader.check)
                    blob.unlink()
                    count=archive._tar_members(expanded,nodes,marker['members'],reader.check,number,path_budget)
                    marker['expanded_bytes']+=size;record['expanded_bytes']+=size
                    marker['members']=count;record['members']=count
                    budget[0]+=size;verified.append(layer['digest'])
                    marker['layers_scanned'].append(layer['digest']);record['layers_scanned'].append(layer['digest'])
                    for name,node in sorted(nodes.items()):
                        if node[0] not in ('file','hardlink') or node[1][3]!=number:continue
                        marker['regular_files']+=1;record['regular_files']+=1
                        base=prefix+'.layer-'+str(number+1)+'.member-'+str(record['regular_files'])
                        before_file_parts=len(marker['parts']);before_file_leaks=len(leaks)
                        try:
                            scan(name.encode('utf-8'),base+'.name',layer['digest'],original_path=name,child_digest=digest)
                            def observe(original,stream,length,layer_index):
                                nonlocal scanned
                                if length>MAX_FILE_SCAN or scanned+length>MAX_IMAGE_SCAN:
                                    raise native.Incomplete('file_scan_bound')
                                offset=0;overlap=b'';chunk_no=0
                                while offset<length:
                                    reader.check();chunk=stream.read(min(WINDOW,length-offset))
                                    if type(chunk) is not bytes or not chunk:raise native.Incomplete('file_truncation')
                                    if offset==0 and (chunk.startswith((b'PK\x03\x04',b'\x1f\x8b',b'BZh',b'\xfd7zXZ',
                                            b'7z\xbc\xaf',b'Rar!',b'\x28\xb5\x2f\xfd')) or chunk[257:262]==b'ustar'):
                                        raise native.Incomplete('nested_archive_uninspected')
                                    if any((value<32 and value not in (9,10,13)) or value==127 for value in chunk):
                                        raise native.Incomplete('binary_file_uninspected')
                                    chunk_no+=1;offset+=len(chunk);scanned+=len(chunk)
                                    scan(overlap+chunk,base+'.chunk-'+str(chunk_no),layer['digest'],
                                         original_path=original,child_digest=digest)
                                    overlap=(overlap+chunk)[-OVERLAP:]
                                if length==0:scan(b'',base+'.chunk-1',layer['digest'],original_path=original,child_digest=digest)
                            archive._visit_node(name,node,observe,reader.check)
                        except native.Incomplete as exc:
                            if str(exc) not in ('nested_archive_uninspected','binary_file_uninspected','scanners_incomplete'):
                                raise
                            # Keep completed prefix chunks and their exact
                            # locations. An incomplete chunk cannot be a
                            # witness, even if a detector emitted a match.
                            complete_parts=[p for p in marker['parts'][before_file_parts:]
                                if p.get('complete') is True]
                            marker['parts'][before_file_parts:]=complete_parts
                            completed_paths={reader.ident+'.'+p['part'] for p in complete_parts}
                            kept=[]
                            for leak in leaks[before_file_leaks:]:
                                locations=[loc for loc in leak.get('locations',())
                                    if loc.get('path') in completed_paths]
                                if locations:kept.append({**leak,'locations':locations})
                            leaks[before_file_leaks:]=kept
                            scan_partial=True;record['scan_partial']=True
                            skipped_files+=1;record['skipped_files']+=1
            if not record['regular_files']:raise native.Incomplete('no_layer_files')
            record['parts']=[p['part'] for p in marker['parts'][before_parts:]]
            if index_mode:marker['child_inspections'].append(record)
        if index_mode:
            marker['graph']['complete']=True
            # Rebind ARM registry identity, tenant and parent bytes after every
            # child. Child bytes are immutable SHA-256 verified by the Reader.
            after=reader.authenticate()
            again=reader.blob('manifests',parent,native.MAX_MANIFEST,after)
            if again!=parent_raw:raise native.Incomplete('parent_manifest_changed')
        elif not marker['regular_files']:
            raise native.Incomplete('no_layer_files')
        marker['leaks']=merge_leaks(leaks);marker['complete']=not scan_partial
        if scan_partial:
            marker['scan_partial']=True;marker['skipped_files']=skipped_files
    except Exception as exc:
        if _abort_code(exc):
            raise
        marker['complete']=False
        marker['parts']=[part for part in marker['parts'] if part.get('complete') is True]
        if index_mode:
            marker['graph']['complete']=False
            # Only complete children can substantiate an incomplete positive.
            witnessed={reader.ident+'.'+name for c in marker['child_inspections'] for name in c['parts']}
            if marker['parts'] and marker['parts'][0].get('part')=='index':witnessed.add(reader.ident+'.index')
        else:
            witnessed={reader.ident+'.'+part['part'] for part in marker['parts']}
        retained=[]
        for leak in leaks:
            locations=[loc for loc in leak.get('locations',[]) if loc.get('path') in witnessed]
            if locations:retained.append({**leak,'locations':locations})
        if retained:
            try:marker['leaks']=merge_leaks(retained)
            except (TypeError,ValueError,KeyError,AttributeError):marker['leaks']=[]
    marker['source_requests']=[r['id'] for r in reader.receipts[start:]]
    if not marker['complete']:marker['inspected_digests']=verified
    return {'id':reader.ident,native.MARKER:marker,
        '_provenance':{'scope':reader.scope,'source_requests':list(marker['source_requests'])}}
