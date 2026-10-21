"""Default-off selected registry image runtime; credentials remain collector-owned."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from weakref import WeakValueDictionary
from peaso import gcp_image_selection_20261021 as selection_api
from peaso.checks import gcp_registry_trivy_review_20261021 as review
CHECK_ID = 'gcp.review.artifact_image.selected_image_vulnerabilities'
KIND = 'artifact_selected_image_vulnerabilities'
OPTION = selection_api.OPTION
ENABLE = selection_api.ENABLE
SERVICE = 'artifactregistry'
GRANT = '_gcp_registry_image_vulnerability_engine_grant'
_SEAL = object()
_ISSUED = WeakValueDictionary()
selections = selection_api.selections

def _selection_hash(targets):
    return hashlib.sha256(json.dumps(targets, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()

class _Grant:
    __slots__ = ('seal', 'scopes', 'selection', 'check', 'enabled', '__weakref__')

    def __init__(self, scopes, targets):
        self.seal = _SEAL
        self.scopes = tuple(scopes)
        self.selection = _selection_hash(targets)
        self.check = CHECK_ID
        self.enabled = True

def issue_engine_grant(options, scopes, named=()):
    """Engine only: issue after actual registry selection of the named check."""
    prior = options.pop(GRANT, None)
    if type(prior) is _Grant and _ISSUED.get(id(prior)) is prior:
        _ISSUED.pop(id(prior))
    if CHECK_ID not in named:
        return
    targets = selections(options, scopes)
    if CHECK_ID not in named or options.get(ENABLE) is not True:
        return
    if not targets:
        raise ValueError('exact_job_image_selectors_required')
    token = _Grant(scopes, targets)
    _ISSUED[id(token)] = token
    options[GRANT] = token

def authorize_collector(options, scopes):
    """Consume once, before credentials, transport, sessions, or scanner I/O."""
    token = options.get(GRANT)
    targets = selections(options, scopes)
    permitted = (type(token) is _Grant and _ISSUED.get(id(token)) is token
        and token.seal is _SEAL and token.scopes == tuple(scopes)
        and token.selection == _selection_hash(targets)
        and token.check == CHECK_ID and token.enabled is True
        and options.get(ENABLE) is True and bool(targets))
    if not permitted:
        raise ValueError('selected_job_image_vulnerability_grant_required')
    _ISSUED.pop(id(token))
    options.pop(GRANT, None)
    return targets


def prepare(options, scopes, wanted):
    if KIND not in wanted:
        return []
    targets = selections(options, scopes)
    if options.get(ENABLE) is not True:
        return []
    if not targets:
        raise ValueError('exact_registry_images_required')
    return authorize_collector(options, scopes)


def collect_selected(transport, *, scope, targets, **kwargs):
    from . import gcp_registry_trivy_20261021 as source
    raw = source.collect_native(transport, scope=scope, selectors=targets, enabled=True, **kwargs)
    rows, observations = [], []
    for row in raw['rows']:
        scan = row.get('scan')
        reference = row['immutable_reference']
        record = review.project(reference, scope, scan) if isinstance(scan, dict) else None
        ids = row['source_requests']
        ledger = [deepcopy(r) for r in raw['source_requests'] if r.get('id') in ids]
        status, _ = review.evaluate(record, {'scope':scope,'selections':targets,'source_requests':ledger})
        rows.append({'immutable_reference':reference,'status':status,
                     'complete':row['complete'] and status != 'UNKNOWN',
                     'reason':row['reason'],'vulnerability_record':record,
                     'source_requests':deepcopy(ids),'source_ledger':ledger})
        observations.append({'asset_id':reference,'asset_kind':KIND,'provider':'gcp','scope':scope,
                             'scan':deepcopy(scan)} if isinstance(scan,dict) else None)
    complete = len(rows) == len(targets) and all(r['complete'] for r in rows)
    status = 'FAIL' if any(r['status']=='FAIL' for r in rows) else 'PASS' if complete else 'UNKNOWN'
    return {'kind':KIND,'check_id':CHECK_ID,'status':status,'complete':complete,
            'rows':rows,'observations':observations}


def enrich(collector):
    targets = getattr(collector, 'registry_image_vulnerability_targets', [])
    if not targets:
        return
    from peaso.trivy_database_20261021 import database_lease, DatabaseUnavailable
    from peaso import trivy_container_runner_20261020 as trivy
    import subprocess
    scope, = collector.scopes
    try:
        with database_lease(enabled=True) as cache:
            cli = next((path for path in (trivy.DEFAULT_CLI, '/opt/homebrew/bin/trivy')
                        if Path(path).is_file()), trivy.DEFAULT_CLI)
            result = collect_selected(collector.transport, scope=scope, targets=targets,
                                      db_cache=cache, cli=cli)
    except (DatabaseUnavailable, OSError, subprocess.SubprocessError):
        result={'kind':KIND,'check_id':CHECK_ID,'status':'UNKNOWN','complete':False,
                'rows':[{'immutable_reference':ref,'status':'UNKNOWN','complete':False,
                         'reason':'database_unavailable','vulnerability_record':None,
                         'source_requests':[],'source_ledger':[]} for ref in targets],
                'observations':[None for _ in targets]}
    collector.registry_image_vulnerability_result = result
    items=[{'name':r['immutable_reference'],'_resource_id':r['immutable_reference'],
            'native_id':r['immutable_reference'],'RegistryImageVulnerabilityReview':deepcopy(r)}
           for r in result['rows']]
    collector.collections[(KIND,scope)]={'type':KIND,'scope':scope,'service':SERVICE,
        'status':'collected' if result['complete'] else 'partial',
        'coverage_status':'collected' if result['complete'] else 'partial','items':items,
        'source_requests':[rid for r in result['rows'] for rid in r['source_requests']]}


def finish_metadata(collector, metadata):
    targets = getattr(collector,'registry_image_vulnerability_targets',[])
    if not targets:
        return
    metadata[OPTION]=list(targets)
    result=getattr(collector,'registry_image_vulnerability_result',None)
    observations=result['observations'] if result is not None else [None for _ in targets]
    old=metadata.get('image_vulnerability_scan',{})
    prior=old.get('observations',[]) if old.get('selected') is True else []
    metadata['image_vulnerability_scan']={'selected':True,'observations':deepcopy(prior+observations)}
