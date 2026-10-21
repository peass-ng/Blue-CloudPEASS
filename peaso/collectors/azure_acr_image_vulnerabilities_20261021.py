"""Explicit selected immutable ACR vulnerability reads and offline Trivy input.

Requires the accepted streaming ACR Reader at installation. No tag discovery,
challenge negotiation, registry credential export, cloud writes, Docker daemon,
or secret-store read is introduced here. The DB is pre-provisioned and read only.
"""
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
import tempfile
import time

from peaso import container_image_archive_20261020 as archive
from peaso import image_findings
from peaso import trivy_container_runner_20261020 as trivy
from . import azure_acr_image_secret_indicators as acr

ENABLE = 'image_vulnerability_scans'
OPTION = 'selected_azure_acr_image_vulnerabilities'
KIND = 'acr_selected_image_vulnerabilities'
CHECK = 'azure.review.acr.selected_image_high_critical_vulnerabilities'
MARKER = 'AcrSelectedImageVulnerabilities'
SCHEMA = 'azure-acr-native-image-vulnerabilities-20261021-v1'
MAX_SECONDS = 600
MAX_TOTAL = acr.MAX_IMAGES * archive.MAX_COMPRESSED
DEFAULT_DB_CACHE = '/tmp/peaso/trivy/current'


def selected_targets(options, scopes):
    """Credential-free exact selector; distinct from content secret scanning."""
    if type(options) is not dict or ENABLE in options and type(options[ENABLE]) is not bool:
        raise ValueError('invalid_acr_vulnerability_selection')
    if OPTION not in options and options.get(ENABLE) is not True:
        return []
    try:
        return acr.selected_targets({acr.OPTION:options.get(OPTION)},scopes)
    except Exception:
        raise ValueError('invalid_acr_vulnerability_selection') from None


def enabled(options):
    return (options.get(ENABLE) is True
        and type(options.get('_image_vulnerability_scan_kinds')) is list
        and KIND in options['_image_vulnerability_scan_kinds'])


def identity(target):
    return KIND + ':' + hashlib.sha256(
        repr((target['registry_id'].casefold(),target['repository'],target['digest'])).encode()).hexdigest()


def selection_metadata(options, scopes):
    targets=selected_targets(options,scopes)
    return {KIND+'_authorized':enabled(options), KIND+'_selection':{
        scope:[identity(t) for t in targets if acr._REGISTRY.fullmatch(t['registry_id'])[1].casefold()==scope.casefold()]
        for scope in scopes},KIND+'_digests':{identity(t):t['digest'] for t in targets},KIND+'_receipts':[]}


def _require(ok, reason='native_image_unavailable'):
    if not ok:raise ValueError(reason)


def _file_hash(path, descriptor, check):
    _require(isinstance(path,Path) and path.is_absolute())
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0))
    with os.fdopen(fd,'rb') as source:
        before=os.fstat(source.fileno())
        _require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
            and before.st_mode & 0o077==0 and before.st_size==descriptor['size'])
        digest=hashlib.sha256();size=0
        while True:
            check();part=source.read(1024*1024)
            if not part:break
            size+=len(part);_require(size<=descriptor['size']);digest.update(part)
        after=os.fstat(source.fileno())
        _require(size==descriptor['size'] and
            (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns)==
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns)
            and 'sha256:'+digest.hexdigest()==descriptor['digest'])
        return digest.hexdigest()


def _descriptors(raw):
    doc=archive.decode(raw)
    _require(type(doc) is dict and not set(doc)-{'schemaVersion','mediaType','config','layers','annotations'}
        and type(doc.get('schemaVersion')) is int and doc['schemaVersion']==2
        and doc.get('mediaType') in (archive.OCI,archive.DOCKER))
    config=archive.descriptor(doc['config'],archive.CONFIGS,archive.MAX_CONFIG)
    layers=doc.get('layers')
    _require(type(layers) is list and 1<=len(layers)<=archive.MAX_LAYERS)
    layers=[archive.descriptor(d,archive.LAYERS,archive.MAX_LAYER) for d in layers]
    _require(len({d['digest'] for d in [config]+layers})==len(layers)+1
        and sum(d['size'] for d in [config]+layers)<=archive.MAX_COMPRESSED)
    return doc,config,layers


def _rootfs(raw, layers):
    doc=archive.decode(raw)
    diffs=doc.get('rootfs',{}).get('diff_ids') if type(doc) is dict else None
    _require(type(doc) is dict and doc.get('os')=='linux'
        and doc.get('architecture') in ('amd64','arm64')
        and type(doc.get('rootfs')) is dict and doc['rootfs'].get('type')=='layers'
        and type(diffs) is list and len(diffs)==len(layers)
        and all(type(d) is str and archive.DIGEST.fullmatch(d) for d in diffs))
    return diffs


def _observation(scope,target,image,scan):
    return {'provider':'azure','scope':scope,'asset_id':target['registry_id']
        +'/repositories/'+target['repository']+'@'+target['digest'],
        'asset_kind':'acr_image','scan':{'image':deepcopy(image),'status':scan['status'],
            'complete':scan['complete'],'scan_complete':scan['scan_complete'],
            'coverage_status':scan['coverage_status'],
            'database':{'fresh':scan.get('database',{}).get('fresh') is True},
            'findings':deepcopy(scan['findings'])}}


def _unknown(reason='image_vulnerability_coverage_incomplete'):
    return {'status':'UNKNOWN','complete':False,'scan_complete':False,
        'coverage_status':'UNKNOWN','database':{'fresh':False},'findings':[],
        'reason':reason}


def _scan_target(outer, transport, receipts, scope, target, state, *, db_cache,
        cli, runner, scratch_parent):
    row={'id':identity(target),MARKER:{'schema':SCHEMA,'selection':deepcopy(target),
        'status':'UNKNOWN','complete':False,'reason':'native_image_unavailable',
        'image':None,'descriptors':[],'rootfs_diff_ids':[],
        'observation':None,'source_requests':[],'archive':None,'scratch_removed':False},
        '_provenance':{'scope':scope,'source_requests':[]}}
    marker=row[MARKER];start=len(receipts)
    scratch=None
    try:
        reader=acr.Reader(outer,transport,receipts,scope,target,state)
        # Persisted CVE receipts must survive collector/evaluator process boundaries.
        # This identity contains resource selectors, never a credential value.
        reader.ident = row['id']
        token=reader.authenticate()
        manifest=reader.blob('manifests',target['digest'],archive.MAX_MANIFEST,token)
        _,config_desc,layers=_descriptors(manifest)
        config=reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,token,config_desc['size'])
        diffs=_rootfs(config,layers)
        image=archive.identity({'provider':'azure','scope':scope,
            'immutable_reference':reader.host+'/'+target['repository']+'@'+target['digest'],
            'manifest_digest':target['digest'],'config_digest':config_desc['digest']})
        marker.update(image=image,descriptors=deepcopy([config_desc]+layers),rootfs_diff_ids=list(diffs))
        scratch=tempfile.TemporaryDirectory(prefix='peaso-azure-acr-vuln-',dir=scratch_parent)
        root=Path(scratch.name);root.chmod(0o700)
        paths=[]
        for number,desc in enumerate(layers):
            reader.check()
            path=root/('layer-'+str(number)+'.blob')
            reader.blob('blobs',desc['digest'],archive.MAX_LAYER,token,desc['size'],destination=path)
            paths.append(path)
        archive.validate(image,manifest,config,paths,reader.check)
        fingerprints=tuple(_file_hash(path,desc,reader.check) for path,desc in zip(paths,layers))
        def verify():
            # Every call obtains a fresh native ARM registry identity and an exact
            # immutable manifest/config observation. Local files are rehashed.
            fresh=reader.authenticate()
            again=reader.blob('manifests',target['digest'],archive.MAX_MANIFEST,fresh)
            _require(again==manifest)
            _,new_config,new_layers=_descriptors(again)
            _require(new_config==config_desc and new_layers==layers)
            new_raw=reader.blob('blobs',config_desc['digest'],archive.MAX_CONFIG,fresh,config_desc['size'])
            _require(new_raw==config and _rootfs(new_raw,layers)==diffs)
            _require(fingerprints==tuple(_file_hash(path,desc,reader.check)
                for path,desc in zip(paths,layers)))
            return dict(image)
        verify()
        raw=(runner or trivy.scan_image)(image,manifest,config,paths,
            native_verifier=verify,enabled=True,db_cache=db_cache,
            cli=cli,archive_format='docker',timeout=min(trivy.MAX_SECONDS,
                max(1,int(state['deadline']-time.monotonic()))),
            cancel=reader.check,scratch_parent=scratch_parent)
        verify()
        _require(type(raw) is dict and raw.get('image')==image and
            raw.get('status') in ('PASS','FAIL','UNKNOWN') and
            type(raw.get('findings')) is list)
        # Full coverage is required for PASS. A verified, typed positive can
        # survive incomplete scanner/DB coverage without asserting clean scope.
        full=(raw.get('complete') is True and raw.get('scan_complete') is True
            and raw.get('coverage_status')=='COMPLETE'
            and type(raw.get('database')) is dict and raw['database'].get('fresh') is True)
        if full:
            scan=deepcopy(raw)
        elif raw['status']=='FAIL' and raw['findings']:
            proof=raw.get('archive')
            _require(type(raw.get('complete')) is bool
                and type(raw.get('scan_complete')) is bool
                and raw.get('coverage_status') in ('COMPLETE','UNKNOWN')
                and type(raw.get('database')) is dict
                and type(raw['database'].get('fresh')) is bool
                and type(proof) is dict and proof.get('format')=='docker'
                and proof.get('manifest_digest')==target['digest']
                and proof.get('config_digest')==config_desc['digest']
                and type(proof.get('expanded_bytes')) is int
                and 0<proof['expanded_bytes']<=archive.MAX_EXPANDED
                and type(proof.get('members')) is int
                and 0<proof['members']<=archive.MAX_MEMBERS)
            scan={'status':'FAIL','complete':False,'scan_complete':False,
                'coverage_status':'UNKNOWN',
                'database':{'fresh':type(raw.get('database')) is dict
                    and raw['database'].get('fresh') is True},
                'findings':deepcopy(raw['findings']),
                'reason':'scanner_or_database_incomplete'}
        else:
            scan=_unknown('scanner_or_database_incomplete')
        _require(scan['status'] in ('PASS','FAIL') if scan['complete'] else scan['status'] in ('FAIL','UNKNOWN'))
        observed=_observation(scope,target,image,scan)
        report=image_findings.build_report([observed],selected=True)
        _require(report['invalid_observations']==report['invalid_vulnerabilities']==0)
        if scan['status']=='FAIL':
            _require(bool(report['rows']))
        if scan['status']=='PASS':
            _require(report['complete'] is True and not report['rows'])
        marker.update(status=scan['status'],complete=report['complete'],
            reason=None if report['complete'] else scan['reason'],
            observation=observed,archive=deepcopy(raw.get('archive')))
    except Exception:
        pass
    finally:
        if scratch is not None:
            try:scratch.cleanup();marker['scratch_removed']=True
            except Exception:
                marker.update(status='UNKNOWN',complete=False,reason='scratch_cleanup_failed')
        marker['source_requests']=[r['id'] for r in receipts[start:]]
        row['_provenance']['source_requests']=list(marker['source_requests'])
    return row


def _unavailable_row(scope,target,reason):
    marker={'schema':SCHEMA,'selection':deepcopy(target),'status':'UNKNOWN','complete':False,
        'reason':reason,'image':None,'descriptors':[],'rootfs_diff_ids':[],
        'observation':None,'source_requests':[],'archive':None,'scratch_removed':True}
    return {'id':identity(target),MARKER:marker,
            '_provenance':{'scope':scope,'source_requests':[]}}


def collect_native(outer,transport,scopes,options,*,db_cache=DEFAULT_DB_CACHE,
        cli=trivy.DEFAULT_CLI,runner=None,scratch_parent=None,
        database_check=None):
    """No credential or network access before an explicit named-check selection."""
    targets=selected_targets(options,scopes)
    result={'schema':SCHEMA,'authorized':enabled(options),'status':'UNKNOWN',
        'complete':False,'rows':[],'receipts':[],'observations':[],
        'reason':'disabled'}
    if not result['authorized']:
        return result
    _require(bool(targets),'exact_acr_vulnerability_selection_required')
    checker=database_check or trivy.database_state
    try:
        state=checker(db_cache)
        _require(type(state) is dict and state.get('fresh') is True,
                 'fresh_offline_database_required')
    except Exception:
        result['reason']='offline_database_unavailable'
        for scope in scopes:
            result['rows'].extend(_unavailable_row(scope,target,result['reason']) for target in targets
                if acr._REGISTRY.fullmatch(target['registry_id'])[1].casefold()==scope.casefold())
        result['observations']=[None for _ in result['rows']]
        return result
    limit={'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0}
    for scope in scopes:
        for target in targets:
            if acr._REGISTRY.fullmatch(target['registry_id'])[1].casefold()!=scope.casefold():continue
            row=_scan_target(outer,transport,result['receipts'],scope,target,limit,
                db_cache=db_cache,cli=cli,runner=runner,scratch_parent=scratch_parent)
            result['rows'].append(row)
    result['observations']=[deepcopy(row[MARKER]['observation']) if row[MARKER]['complete'] is True or row[MARKER]['status']=='FAIL' else None
        for row in result['rows']]
    result['complete']=bool(result['rows']) and all(r[MARKER]['complete'] for r in result['rows'])
    result['status']='FAIL' if any(r[MARKER]['status']=='FAIL' for r in result['rows']) else 'PASS' if result['complete'] else 'UNKNOWN'
    result['reason']=None if result['complete'] else 'selected_image_vulnerability_coverage_incomplete'
    return result


def collect(reader,transport,scopes,wanted,options,*,db_cache=DEFAULT_DB_CACHE,
            cli=trivy.DEFAULT_CLI):
    """Narrow Azure collector hook, entered only for the named selected check."""
    if KIND not in wanted:return
    metadata=selection_metadata(options,scopes)
    reader.acr_image_vulnerability_metadata=metadata
    if not enabled(options):return
    result=collect_native(reader,transport,scopes,options,db_cache=db_cache,cli=cli)
    metadata[KIND+'_receipts']=result['receipts']
    metadata['image_vulnerability_scan']={'selected':True,
        'observations':deepcopy(result['observations'])}
    for scope in scopes:
        rows=[row for row in result['rows'] if row['_provenance']['scope']==scope]
        if not rows:continue
        def fetch(rows=rows):yield rows
        reader.run([(KIND,scope,'Microsoft.ContainerRegistry',fetch)])
