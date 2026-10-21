"""Exact selected ARM job literals; no source URI following or execution."""

from peaso.secret_evidence import scan_with_source, target_source
from copy import deepcopy
import json
import re
import time
from uuid import uuid4
from peaso.secret_scanning import scan_content, merge_leaks, _fingerprint
from .azure_selected_declaration_secret_indicators import GUID, SCOPE, SEG, ARM, _read, _bound, remaining
from .azure_selected_secret_integration_20261020 import remember

KIND = 'azure_ml_selected_command_job'
CHECK = 'azure.review.machine_learning.selected_command_job_secret_indicators'
OPTION = 'selected_azure_ml_command_jobs'
SERVICE = 'Microsoft.MachineLearningServices'
API = '2024-04-01'
WORKSPACE_API = '2026-03-01'
MARKER = 'SelectedMLCommandJobSecretIndicators'
SCHEMA = 'azure-selected-ml-job-literals-v2'
MAX_TARGETS = 4
MAX_CALLS = 12
MAX_WIRE = 2 * 1024 * 1024  # Shared immutable native reader bound.
MAX_TOTAL = 8 * 1024 * 1024
MAX_CONTENT = 256 * 1024
MAX_VALUES = 128
MAX_NODES = 16
MAX_DEPTH = 2
MAX_SECONDS = 120
MAX_LEAKS = 256
MAX_LOCATIONS = 512


def enabled(options):
    return options.get('content_secret_scans') is True and isinstance(options.get('_content_secret_scan_kinds'), list) and KIND in options['_content_secret_scan_kinds']


def parse(target):
    if not isinstance(target, dict) or set(target) != {'resource_id'}:
        raise ValueError('invalid_selection')
    rid = target['resource_id']
    match = re.fullmatch(r'(/subscriptions/' + GUID + r')/resourceGroups/' + SEG + r'/providers/Microsoft\.MachineLearningServices/workspaces/([A-Za-z0-9][A-Za-z0-9_-]{2,32})/jobs/([A-Za-z0-9_][A-Za-z0-9_.-]{0,127})', rid, re.I) if isinstance(rid, str) and len(rid) <= 1024 else None
    if not match or any(p in ('.', '..') for p in rid.split('/')):
        raise ValueError('invalid_selection')
    return match[1], rid, rid.rsplit('/', 2)[0]


def identity(target):
    _, rid, parent = parse(target)
    # Native Jobs Get documents job identifier as case-sensitive.
    return KIND + ':' + _fingerprint(parent.casefold() + '/jobs/' + rid.rsplit('/', 1)[1])


def selected_targets(options, scopes):
    if not isinstance(options, dict) or 'content_secret_scans' in options and type(options['content_secret_scans']) is not bool:
        raise ValueError('invalid_selection')
    if OPTION not in options and not enabled(options): return []
    targets = options.get(OPTION)
    if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 8 or any(not isinstance(s, str) or not SCOPE.fullmatch(s) for s in scopes)
            or len({s.casefold() for s in scopes}) != len(scopes) or not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS):
        raise ValueError('invalid_selection')
    seen = set()
    for target in targets:
        scope, _, _ = parse(target); ident = identity(target)
        if scope.casefold() not in {s.casefold() for s in scopes} or ident in seen: raise ValueError('invalid_selection')
        seen.add(ident)
    return deepcopy(targets)


def _literal_component(component, prefix, values, remaining_values):
    """Project a documented CommandJob or TrialComponent literal only."""
    if not isinstance(component, dict):
        return False, remaining_values
    command = component.get('command'); environment = component.get('environmentVariables')
    complete = True
    if (isinstance(command, str) and command.strip() and len(command.encode('utf-8')) <= MAX_CONTENT
            and '@microsoft.keyvault(' not in command.lower() and '${{' not in command
            and command.strip().lower() not in ('***', '[redacted]', '<redacted>') and remaining_values):
        values.append({'field': prefix + 'command', 'value': command}); remaining_values -= 1
    else:
        complete = False
    if not isinstance(environment, dict):
        return False, remaining_values
    budget = remaining_values
    if len(environment) > budget:
        complete = False
    for index, (key, value) in enumerate(environment.items()):
        if index >= budget:
            break
        if (not isinstance(key, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', key)
                or not isinstance(value, str) or len(value.encode('utf-8')) > MAX_CONTENT
                or '@microsoft.keyvault(' in value.lower() or '${{' in value
                or value.strip().lower() in ('***', '[redacted]', '<redacted>')):
            complete = False; continue
        values.append({'field': prefix + 'environmentVariables', 'name': key, 'value': value})
        remaining_values -= 1
    return complete, remaining_values


def project(properties):
    """Inspect only inline job command and literal environment fields of supported DTOs."""
    if not isinstance(properties, dict): raise ValueError('unsupported_job')
    job_type = properties.get('jobType'); values = []; remaining_values = MAX_VALUES
    if job_type == 'Command':
        complete, remaining_values = _literal_component(properties, '', values, remaining_values)
    elif job_type == 'Sweep':
        complete, remaining_values = _literal_component(properties.get('trial'), 'trial.', values, remaining_values)
    elif job_type == 'Pipeline':
        jobs = properties.get('jobs')
        if not isinstance(jobs, dict) or not jobs: raise ValueError('empty_pipeline_jobs')
        complete = len(jobs) <= MAX_NODES
        for index, (name, child) in enumerate(jobs.items()):
            if index >= MAX_NODES: break
            if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}', name) or not isinstance(child, dict):
                complete = False; continue
            child_type = child.get('jobType')
            if child_type == 'Command':
                part, remaining_values = _literal_component(child, 'jobs.' + name + '.', values, remaining_values)
            elif child_type == 'Sweep' and MAX_DEPTH >= 2:
                part, remaining_values = _literal_component(child.get('trial'), 'jobs.' + name + '.trial.', values, remaining_values)
            else:
                # Component references, nested pipelines and other job DTOs have
                # no proven inline command/environment surface here.
                complete = False; continue
            complete = complete and part
    else:
        raise ValueError('unsupported_job')
    if not values: raise ValueError('empty_projection')
    raw = json.dumps(values, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    if not 0 < len(raw) <= MAX_CONTENT: raise ValueError('content_limit')
    return raw, complete


def _scan(reader, transport, target, scope, state, receipts):
    ident = identity(target); _, rid, workspace = parse(target); start = len(receipts)
    marker = {'schema':SCHEMA,'identity':ident,'scope':scope,'capture':state['capture'],'complete':False,
        'projection_complete':False,'native_stable':False,'job_type':None,'workspace_binding':None,'declared_references':{},
        'parts':[],'leaks':[],'source_requests':[],'verification':'not_attempted'}
    try:
        def read(operation,path):
            if state['calls']>=MAX_CALLS:raise ValueError('call_limit')
            return reader.call(_read,reader,transport,state,receipts,ident,scope,operation,'management.azure.com',path,ARM)
        subscription = read('subscription',scope+'?api-version=2022-12-01')
        tenant = getattr(transport,'verified_tenant',None)
        if (subscription.get('id','').casefold()!=scope.casefold() or subscription.get('subscriptionId','').casefold()!=scope.rsplit('/',1)[1].casefold()
                or subscription.get('state')!='Enabled' or str(subscription.get('tenantId','')).casefold()!=str(tenant).casefold()):raise ValueError('scope_unbound')
        receipts[-1]['identity_bound']=True
        native = read('workspace',workspace+'?api-version='+WORKSPACE_API)
        _bound(native,workspace,SERVICE+'/workspaces'); props=native['properties']; workspace_id=props.get('workspaceId')
        if str(props.get('tenantId','')).casefold()!=str(tenant).casefold() or props.get('provisioningState')!='Succeeded' or not isinstance(workspace_id,str) or not re.fullmatch(GUID,workspace_id,re.I):raise ValueError('workspace_unbound')
        marker['workspace_binding']=_fingerprint(workspace_id.casefold());receipts[-1]['identity_bound']=True;del native,props
        native = read('job',rid+'?api-version='+API)
        _bound(native,rid,SERVICE+'/workspaces/jobs')
        if native['id'].rsplit('/',1)[1]!=rid.rsplit('/',1)[1] or native['name']!=rid.rsplit('/',1)[1]:raise ValueError('job_unbound')
        receipts[-1]['identity_bound']=True;before=native;props=native['properties'];marker['job_type']=props.get('jobType')if props.get('jobType')in('Command','Pipeline','Sweep')else None
        raw,projection_complete=project(props);marker['projection_complete']=projection_complete
        # Native-declared reference strings are opaque declarations, never asset/read proofs.
        marker['declared_references']={k:_fingerprint(props[k])for k in('codeId','environmentId')if isinstance(props.get(k),str)and props[k]}
        del props
        payload_bytes=len(raw)
        result=scan_with_source(scan_content, raw,ident+'.command_environment_literals',timeout=remaining(reader,state)/2,
            _redact_values=lambda values:remember(reader,'configuration_secret_redactions',values), source={**target_source(target, scope=scope, location_kind='configuration'), 'resource_id':ident}, native=native);del raw,native
        marker['parts']=[{'bytes':payload_bytes,'engines':deepcopy(result['engines']),'complete':result['complete']}]
        leaks=merge_leaks(result['leaks']);bounded=[];locations=0
        for leak in leaks:
            if len(bounded)>=MAX_LEAKS or locations+len(leak['locations'])>MAX_LOCATIONS:break
            bounded.append(leak);locations+=len(leak['locations'])
        marker['leaks']=bounded;remaining(reader,state)
        after=read('job_after',rid+'?api-version='+API)
        _bound(after,rid,SERVICE+'/workspaces/jobs')
        if after['id'].rsplit('/',1)[1]!=rid.rsplit('/',1)[1] or after['name']!=rid.rsplit('/',1)[1]:raise ValueError('job_unbound')
        receipts[-1]['identity_bound']=True
        if after!=before:raise ValueError('job_drift')
        marker['native_stable']=True
        marker['complete']=projection_complete and result['complete']is True and len(bounded)==len(leaks)
    except Exception:
        marker['complete']=False
    marker['source_requests']=[r['id']for r in receipts[start:]]
    return {'id':ident,MARKER:marker,'_provenance':{'scope':scope,'capture':state['capture'],'source_requests':marker['source_requests'][:]}}


def collect(reader, transport, scopes, wanted, options):
    targets=selected_targets(options,scopes)
    if not hasattr(reader,'configuration_secret_redactions'):reader.configuration_secret_redactions=set()
    reader.ml_command_job_secret_metadata={}
    if KIND not in wanted:return
    state={'capture':'ml-command-job-capture:'+uuid4().hex,'deadline':time.monotonic()+MAX_SECONDS,'bytes':0,'calls':0};receipts=[]
    reader.ml_command_job_secret_metadata={KIND+'_authorized':enabled(options),KIND+'_capture':state['capture'],KIND+'_receipts':receipts,
        KIND+'_selection':{s:[identity(t)for t in targets if parse(t)[0].casefold()==s.casefold()]for s in scopes}}
    if not enabled(options):return
    for scope in scopes:
        selected=[t for t in targets if parse(t)[0].casefold()==scope.casefold()]
        if selected:
            def fetch(selected=selected,scope=scope):yield [_scan(reader,transport,t,scope,state,receipts)for t in selected]
            reader.run([(KIND,scope,SERVICE,fetch)])


def final_snapshot(reader,snapshot):
    snapshot.setdefault('metadata',{}).update(getattr(reader,'ml_command_job_secret_metadata',{}))
    from .azure_selected_log_sample_secret_indicators import final_snapshot as existing
    return existing(reader,snapshot)
